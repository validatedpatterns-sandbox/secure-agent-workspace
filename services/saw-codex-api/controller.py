"""kopf controller for CodexSession CRDs."""

import logging
import os
import subprocess

import kopf
from kubernetes import client, config as k8s_config

logger = logging.getLogger(__name__)

MANAGED_NAMESPACE = os.environ.get("MANAGED_NAMESPACE", "openshell-agents")
SAW_CHART_PATH = os.environ.get("SAW_CHART_PATH", "/app/charts/openshell-saw/")
OIDC_ISSUER_URL = os.environ.get("OIDC_ISSUER_URL", "")
MAX_SESSIONS_PER_USER = int(os.environ.get("MAX_SESSIONS_PER_USER", "3"))


def _k8s_api():
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()


_k8s_api()


def _set_status(name: str, namespace: str, phase: str, message: str = ""):
    custom = client.CustomObjectsApi()
    custom.patch_namespaced_custom_object_status(
        group="saw.redhat.com",
        version="v1alpha1",
        namespace=namespace,
        plural="codexsessions",
        name=name,
        body={"status": {"phase": phase, "message": message}},
    )


@kopf.on.create("saw.redhat.com", "v1alpha1", "codexsessions")
def on_create(spec, meta, namespace, **_):
    session_name = spec["name"]
    owner = spec["owner"]
    cr_name = meta["name"]

    custom = client.CustomObjectsApi()
    try:
        vms = custom.list_namespaced_custom_object(
            group="kubevirt.io", version="v1",
            namespace=MANAGED_NAMESPACE,
            plural="virtualmachines",
            label_selector=f"openshell.pattern/owner={owner}",
        )
        count = len(vms.get("items", []))
        if count >= MAX_SESSIONS_PER_USER:
            msg = f"Session limit reached ({MAX_SESSIONS_PER_USER})"
            _set_status(cr_name, namespace, "Error", msg)
            raise kopf.PermanentError(msg)
    except client.ApiException as e:
        logger.warning("Could not check session limit: %s", e)

    _set_status(cr_name, namespace, "Creating", "Running helm install")

    v1 = client.CoreV1Api()
    ssh_pubkey = ""
    try:
        secret = v1.read_namespaced_secret("openshell-ssh-pubkey", MANAGED_NAMESPACE)
        import base64 as b64
        ssh_pubkey = b64.b64decode(secret.data.get("key", "")).decode().strip()
    except client.ApiException:
        logger.warning("SSH public key secret not found")

    oidc_token = spec.get("oidcToken", "")

    cmd = [
        "helm", "upgrade", "--install", session_name, SAW_CHART_PATH,
        "--namespace", MANAGED_NAMESPACE,
        "--set", f"sandboxName={session_name}",
        "--set", f"sshPublicKey={ssh_pubkey}",
        "--set", "agent=codex",
        "--set", "containerRuntime=docker",
        "--set", "route.enabled=true",
        "--set", "route.codex=true",
        "--set", "route.dashboard=true",
        "--set", f"accessControl.owner={owner}",
        "--set", "governance.enabled=true",
        "--set", "internalRegistry.allowAnonymousPull=true",
        "--set", f"oidc.issuerUrl={OIDC_ISSUER_URL}",
        "--set", "oidc.clientId=openshell-cli",
    ]
    if oidc_token:
        cmd += ["--set-string", f"oidc.token={oidc_token}"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        msg = result.stderr.strip()[-200:]
        logger.error("helm install failed for %s: %s", session_name, msg)
        _set_status(cr_name, namespace, "Error", f"helm install failed: {msg}")
        raise kopf.TemporaryError(f"helm install failed: {msg}", delay=60)

    _set_status(cr_name, namespace, "Creating", "Helm install complete, VM provisioning")
    logger.info("helm install succeeded for %s", session_name)


@kopf.on.delete("saw.redhat.com", "v1alpha1", "codexsessions")
def on_delete(spec, meta, namespace, **_):
    session_name = spec["name"]
    cr_name = meta["name"]

    try:
        _set_status(cr_name, namespace, "Deleting", "Running helm uninstall")
    except Exception:
        pass

    result = subprocess.run(
        ["helm", "uninstall", session_name, "--namespace", MANAGED_NAMESPACE],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        msg = result.stderr.strip()[-200:]
        logger.error("helm uninstall failed for %s: %s", session_name, msg)
        raise kopf.TemporaryError(
            f"helm uninstall failed: {msg}", delay=15
        )

    v1 = client.CoreV1Api()
    for suffix in ["-cloudinit", "-codex-secret"]:
        try:
            v1.delete_namespaced_secret(f"{session_name}{suffix}", MANAGED_NAMESPACE)
        except client.ApiException:
            pass

    logger.info("Cleaned up session %s", session_name)


@kopf.timer("saw.redhat.com", "v1alpha1", "codexsessions", interval=30, initial_delay=10)
def check_status(spec, meta, namespace, **_):
    session_name = spec["name"]
    cr_name = meta["name"]
    custom = client.CustomObjectsApi()
    v1 = client.CoreV1Api()

    try:
        vm = custom.get_namespaced_custom_object(
            group="kubevirt.io", version="v1",
            namespace=MANAGED_NAMESPACE,
            plural="virtualmachines", name=session_name,
        )
    except client.ApiException:
        return

    printable = vm.get("status", {}).get("printableStatus", "Unknown")

    has_secret = False
    try:
        v1.read_namespaced_secret(f"{session_name}-codex-secret", MANAGED_NAMESPACE)
        has_secret = True
    except client.ApiException:
        pass

    connectable = False
    if has_secret:
        try:
            route = custom.get_namespaced_custom_object(
                group="route.openshift.io", version="v1",
                namespace=MANAGED_NAMESPACE,
                plural="routes", name=f"{session_name}-codex",
            )
            host = route.get("spec", {}).get("host", "")
            if host:
                import httpx
                r = httpx.get(f"https://{host}/readyz", timeout=5, verify=False)
                connectable = r.status_code == 200
        except Exception:
            pass

    if printable == "Running" and connectable:
        phase, msg = "Running", "Codex app-server ready"
    elif "Error" in printable:
        phase, msg = "Error", f"VM status: {printable}"
    else:
        phase, msg = "Creating", f"VM status: {printable}, app-server not ready"

    _set_status(cr_name, namespace, phase, msg)
