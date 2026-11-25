"""Run one retained controller for an administrator-defined workspace."""
import base64
import json
import os
from pathlib import Path
import signal

from .adapters import KubernetesResourceVerifier
from .admin_session import GatewaySessions, TrustBundle
from .boundary import verify
from .compiler import compile_profile_files, ContractError
from .controller import ConfigMapClient, Controller, Scope, NAME
from .gateway_ca import read_public_ca
from .reconcile import Reconciler


def main():
    os.umask(0o077)
    config = json.loads(Path("/config/controller.json").read_text())
    scope = Scope(config["namespace"], config["profile"], config["intent"], config["status"], config["ownerID"])
    service_account = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    api = ConfigMapClient("https://kubernetes.default.svc", scope, service_account / "ca.crt", service_account / "token")
    def get(path):
        with api._open("GET", path) as response:
            return api._json(response)

    def read(kind, name, namespace=None):
        if not NAME.fullmatch(name):
            raise ContractError("invalid resource name")
        if (kind == "runtimeclass" and namespace is None and config["mode"] == "kata"
                and name == config["workloadRuntimeClass"]):
            return get("/apis/node.k8s.io/v1/runtimeclasses/" + name)
        if kind == "namespace" and name == scope.namespace:
            return get("/api/v1/namespaces/" + name)
        if kind == "persistentvolumeclaim" and namespace == scope.namespace:
            return get(f"/api/v1/namespaces/{namespace}/persistentvolumeclaims/{name}")
        raise ContractError("resource outside controller scope")

    def boundary(plan):
        verify(config, plan, get)

    allowed = set(config.get("credentialSecrets", []))
    def read_credential(secret, key):
        """A provider credential for OpenShell, from this workspace's own Secrets only."""
        if secret not in allowed or not NAME.fullmatch(secret):
            raise ContractError("credential outside controller scope")
        obj = get(f"/api/v1/namespaces/{config['trustedNamespace']}/secrets/{secret}")
        data = obj.get("data") or {}
        if key not in data:
            raise ContractError("credential is not available yet", safe_reason="ProviderRejected")
        return base64.b64decode(data[key]).decode(), obj["metadata"]["resourceVersion"]
    resources = KubernetesResourceVerifier(read, boundary)
    endpoint = f"https://{config['gateway']}-gateway.{scope.namespace}.svc:17670"
    public_ca = read_public_ca(config["trustedNamespace"], config["gateway"], scope.owner_id, get)
    trust = TrustBundle(api.request, scope.namespace, config["trustedNamespace"], config["gateway"],
                        scope.owner_id, public_ca.encode("ascii"),
                        os.environ["POD_NAME"], os.environ["POD_UID"])
    sessions = GatewaySessions(trust, endpoint)
    state = Path("/state")
    catalog = {}

    def list_profiles(gateway):
        """Platform provider profiles the gateway serves: type -> endpoint hosts."""
        profiles, token = {}, ""
        while True:
            page = gateway.call("ListProviderProfiles", {"page_size": 1000, "page_token": token})
            for profile in page.get("profiles", []):
                profiles[profile["id"]] = [e["host"] for e in profile.get("endpoints", [])]
            token = page.get("next_page_token", "")
            if not token:
                return profiles

    def reconcile(plan, **kwargs):
        with sessions.open() as gateway:
            # Refresh the catalog in the session we already hold: every session
            # mints a client identity the gateway must first trust, so a second
            # session per cycle keeps losing that race.
            catalog["profiles"] = list_profiles(gateway)
            return Reconciler(gateway, state / "core", resources.verify_attachments,
                              verify_shutdown=resources.verify_shutdown,
                              read_credential=read_credential).reconcile(plan, **kwargs)

    def compile_files(files, bindings):
        if "profiles" not in catalog:  # first cycle only
            with sessions.open() as gateway:
                catalog["profiles"] = list_profiles(gateway)
        return compile_profile_files(files, bindings, catalog["profiles"])
    frontend = Controller(api, scope, state, compile_files, reconcile, boundary)
    stopped = False
    def stop(signum, frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    frontend.run(stop=lambda: stopped)


if __name__ == "__main__":
    main()
