#!/usr/bin/env python3
"""Make entry point for the common GitOps container workspace installation.

Uses the existing saw-users chart and its ApplicationSet projector. Credentials
remain in the configured Vault/External Secrets path; this command does not read
or copy provider keys and never patches a generated runtime resource.
"""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.request import HTTPRedirectHandler, build_opener

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


workspace = load_module("saw_workspace", ROOT / "charts/saw-users/files/workspace.py")
container_topology = load_module("container_topology", ROOT / "scripts/container_topology.py")


class InstallError(ValueError):
    pass


def run(*args, capture=True, input_text=None):
    result = subprocess.run(args, capture_output=capture, text=True, input=input_text, timeout=360)
    if result.returncode:
        # Report the failure class only. Tool stderr can include credentials,
        # manifests, or a URL containing an authorization parameter.
        error = result.stderr or ""
        if args[0] == "oc" and "dial tcp: lookup " in error:
            raise InstallError("OpenShift API DNS lookup failed; check the hostname for the current oc context")
        if args[0] == "oc" and "Error from server (Forbidden)" in error:
            raise InstallError("OpenShift refused this operation (HTTP 403); check access for the current oc identity")
        raise InstallError(f"{args[0]} operation failed; inspect that tool's status before continuing")
    return result.stdout if capture else ""


def get(kind, name, namespace=None):
    args = ["oc", "get", kind, name, "--ignore-not-found", "--request-timeout=20s", "-o", "json"]
    if namespace: args += ["-n", namespace]
    raw = run(*args)
    return json.loads(raw) if raw.strip() else None


def select(values, name):
    """The operator supplies the same public saw-users/site configuration as GitOps."""
    if not isinstance(values, dict):
        raise InstallError("workspace inputs must be a YAML mapping")
    config = copy.deepcopy(values)
    if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,17}[a-z0-9])?", name):
        raise InstallError("OPENSHELL_SAW_NAME must be a DNS label of at most 19 characters")
    entries = config.get("users", [])
    if not isinstance(entries, list) or any(not isinstance(u, dict) for u in entries):
        raise InstallError("workspace inputs require a list of user mappings")
    users = [u for u in entries if u.get("name") == name]
    if len(users) != 1:
        raise InstallError("the inputs must contain exactly one matching user")
    user = users[0]
    if user.get("values", {}).get("deployment", {}).get("mode") != "container":
        raise InstallError("the selected user must explicitly select container deployment")
    config["ownerResolution"] = {**config.get("ownerResolution", {}), "enabled": False}
    for field, pattern in [("registration", r"[a-f0-9]{16}"),
                           ("installationID", r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"),
                           ("ownerSubject", r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")]:
        if not re.fullmatch(pattern, str(user.get(field, ""))):
            raise InstallError("container inputs require a valid "+field)
    site = config.get("containerSites", {}).get(name)
    if not site or site.get("subject") != user["ownerSubject"] or user.get("pruneOnRemove") is not True:
        raise InstallError("container inputs require the matching site identity and foreground cleanup")
    if type(user.get("intentGeneration")) is not int or user["intentGeneration"] < 1:
        raise InstallError("intentGeneration must be a positive integer")
    config["users"] = users
    config["containerSites"] = {name: site}
    config["projection"] = {**config.get("projection", {}), "enabled": True}
    return config, user


def check_existing(existing, user):
    if not existing:
        return
    owners = existing.get("users", [])
    if len(owners) != 1 or any(owners[0].get(k) != user[k]
                              for k in ("name", "registration", "installationID", "ownerSubject")):
        raise InstallError("existing release belongs to another registration; refusing adoption")
    if owners[0].get("values", {}).get("deployment", {}).get("mode") != "container":
        raise InstallError("existing release uses another backend")


def preflight(config, namespace):
    """Check the shared platform without installing or adopting its dependencies."""
    for crd in ("applications.argoproj.io", "applicationsets.argoproj.io",
                "sandboxes.agents.x-k8s.io", "externalsecrets.external-secrets.io",
                "adminnetworkpolicies.policy.networking.k8s.io"):
        if not get("crd", crd):
            raise InstallError("required platform API is absent: " + crd)
    resources = run("oc", "api-resources", "--api-group=admissionregistration.k8s.io", "-o", "name").splitlines()
    if "validatingadmissionpolicies.admissionregistration.k8s.io" not in resources:
        raise InstallError("native ValidatingAdmissionPolicy is required")
    argo = config.get("global", {}).get("vpArgoNamespace") or config.get("argo", {}).get("namespace", "vp-gitops")
    if namespace == argo:
        raise InstallError("workspace installation namespace must be separate from Argo CD")
    existing = get("namespace", namespace)
    if existing:
        labels = existing.get("metadata", {}).get("labels", {})
        if (existing.get("metadata", {}).get("deletionTimestamp")
                or labels.get("argocd.argoproj.io/managed-by") != argo):
            raise InstallError("installation namespace is deleting or is not managed by the selected Argo CD")
    return existing, argo


def ensure_namespace(existing, namespace, argo):
    if existing:
        return
    manifest = {"apiVersion": "v1", "kind": "Namespace", "metadata": {
        "name": namespace, "labels": {"argocd.argoproj.io/managed-by": argo,
                                        "openshell.pattern/component": "workspace-installations"}}}
    # Create, never apply: a concurrent or unrelated installation is not adopted.
    run("oc", "create", "-f", "-", input_text=json.dumps(manifest))


def status(user, config):
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    site = config["containerSites"][user["name"]]
    issuer = site["automaticEnrollment"]["relay"]["issuer"]
    client = build_opener(NoRedirect())
    catalog = json.loads((ROOT/"charts/saw-users/files/profile-catalog.json").read_text())["profiles"]
    def observed(path):
        # Named GET plus --ignore-not-found handles initial provisioning without
        # converting authorization or transport failures into an empty state.
        parts = path.split("/")
        if "/configmaps/" in path:
            return get("configmap", parts[-1], parts[4])
        return get("application", parts[-1], parts[5])
    argo = config.get("global", {}).get("vpArgoNamespace") or config.get("argo", {}).get("namespace", "vp-gitops")
    return workspace.container_status(observed, user, site, argo,
                                      config["global"]["clusterDomain"],
                                      lambda url: workspace.owner_route_available(url, issuer, client), catalog)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("apply", "status", "delete"))
    parser.add_argument("--values", default=os.environ.get("SAW_USERS_VALUES_FILE"))
    parser.add_argument("--name", default=os.environ.get("OPENSHELL_SAW_NAME"))
    parser.add_argument("--namespace", default=os.environ.get("SAW_INSTALL_NAMESPACE", "saw-workspaces"))
    parser.add_argument("--timeout", type=int, default=1200)
    args = parser.parse_args()
    try:
        if not args.values or not args.name:
            raise InstallError("set SAW_USERS_VALUES_FILE and OPENSHELL_SAW_NAME")
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", args.namespace):
            raise InstallError("invalid installation namespace")
        config, user = select(yaml.safe_load(Path(args.values).read_text()), args.name)
        for command in ("oc", "helm"):
            if not shutil.which(command): raise InstallError(command+" is required")
        overlay = os.environ.get("SAW_TOPOLOGY_OVERLAY")
        if not overlay and os.environ.get("SAW_TOPOLOGY_PROBE"):
            raise InstallError("set SAW_TOPOLOGY_OVERLAY to the local reviewed overlay path")
        if overlay:
            container_topology.install_values(config, args.name, overlay,
                                              os.environ.get("SAW_TOPOLOGY_PROBE"),
                                              os.environ.get("SAW_TOPOLOGY_CONTAINER"),
                                              verify=args.action == "apply")
        # Validate chart inputs before contacting or changing the cluster.
        with tempfile.TemporaryDirectory(prefix="saw-container-values-") as directory:
            values_file = Path(directory)/"values.json"
            values_file.write_text(json.dumps(config))
            values_file.chmod(0o600)
            release = "workspace-"+args.name
            run("helm", "template", release, str(ROOT/"charts/saw-users"), "-n", args.namespace, "-f", str(values_file))
            domain = config.get("global", {}).get("clusterDomain")
            ingress = get("ingress.config.openshift.io", "cluster")
            if not domain or (ingress or {}).get("spec", {}).get("domain") != "apps."+domain:
                raise InstallError("current cluster does not match the input clusterDomain")
            runtime = get("namespace", "saw-"+args.name)
            if runtime and runtime.get("metadata", {}).get("labels", {}).get("saw.redhat.com/runtime-owner") != user["installationID"]:
                raise InstallError("existing runtime namespace belongs to another installation")
            releases = json.loads(run("helm", "list", "-n", args.namespace, "--filter", "^"+release+"$", "-o", "json"))
            previous = json.loads(run("helm", "get", "values", release, "-n", args.namespace, "-o", "json")) if releases else None
            check_existing(previous, user)
            foundation_only = config["containerSites"][args.name]["automaticEnrollment"].get("enabled") is False
            if previous and args.action == "apply" and foundation_only and previous["containerSites"][args.name]["automaticEnrollment"].get("enabled") is not False:
                raise InstallError("cannot turn an enrolled installation back into a foundation; use desiredState to stop it")
            if args.action == "status":
                print(json.dumps(status(user, config)))
                return 0
            if args.action == "delete":
                if releases:
                    run("helm", "uninstall", release, "-n", args.namespace, "--cascade", "foreground", "--wait", "--timeout", "5m", capture=False)
                else:
                    print("Installation release is already absent.")
                return 0
            existing_namespace, argo = preflight(config, args.namespace)
            ensure_namespace(existing_namespace, args.namespace, argo)
            run("helm", "upgrade", "--install", release, str(ROOT/"charts/saw-users"),
                "-n", args.namespace, "-f", str(values_file),
                "--wait", "--wait-for-jobs", "--timeout", "5m", capture=False)
        if foundation_only:
            print(json.dumps({"phase": "AwaitingApproval", "ready": False,
                              "message": "Foundation requested; review Argo convergence and approve the site before enabling enrollment."}))
            return 0
        deadline = time.monotonic()+args.timeout
        while time.monotonic() < deadline:
            observed = status(user, config)
            if observed["ready"] or observed["phase"] == "stopped":
                print(json.dumps(observed))
                return 0
            time.sleep(5)
        raise InstallError("workspace has not reached the requested generation; inspect Argo and runtime status")
    except (InstallError, OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, str(exc)+"\n")


if __name__ == "__main__":
    raise SystemExit(main())
