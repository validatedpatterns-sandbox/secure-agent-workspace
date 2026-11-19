#!/usr/bin/env python3
"""Make entry point for the common GitOps container workspace installation.

Uses the existing saw-users chart and its ApplicationSet projector. Credentials
remain in the configured Vault/External Secrets path; this command does not read
or copy provider keys and never patches a generated runtime resource.
"""
import argparse
import copy
import hashlib
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
import uuid
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
preflight_checks = load_module("saw_preflight", ROOT / "charts/saw-portal-container/files/preflight.py")
kata_worker_check = load_module("kata_worker_check", ROOT / "scripts/kata_worker_check.py")


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
        if args[0] == "oc" and "conflict with" in error:
            raise InstallError("OpenShift field ownership conflict during dry run; check the Helm release owner")
        raise InstallError(f"{args[0]} operation failed; inspect that tool's status before continuing")
    return result.stdout if capture else ""


def get(kind, name, namespace=None):
    args = ["oc", "get", kind, name, "--ignore-not-found", "--request-timeout=20s", "-o", "json"]
    if namespace: args += ["-n", namespace]
    raw = run(*args)
    return json.loads(raw) if raw.strip() else None


def deep_merge(base, over):
    out = copy.deepcopy(base)
    for key, value in over.items():
        out[key] = deep_merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) \
            else copy.deepcopy(value)
    return out


def apply_container_defaults(config, user):
    """Same defaults as saw-users.containerUser in charts/saw-users/templates/_helpers.tpl."""
    name = user["name"]
    if not user.get("registration"):
        user["registration"] = hashlib.sha256(f"{name}:{user.get('generation') or 1}".encode()).hexdigest()[:16]
    base = (user.get("vaultPrefix") or config.get("defaults", {}).get("vaultPrefix") or "secret/data/hub").rstrip("/")
    if not re.search(f"/saw-{re.escape(name)}/{re.escape(str(user['registration']))}$", base):
        base = f"{base}/saw-{name}/{user['registration']}"
    user["vaultPrefix"] = base
    user.setdefault("pruneOnRemove", True)
    user.setdefault("intentGeneration", 1)
    if not user.get("installationID") and re.fullmatch(r"[a-f0-9]{16}", str(user["registration"])):
        user["installationID"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"urn:saw:portal:{name}:{user['registration']}"))


def container_site(config, user):
    """Same layering as saw-users.containerSite: containerDefaults under containerSites.<name>."""
    site = deep_merge(config.get("containerDefaults") or {}, config.get("containerSites", {}).get(user["name"]) or {})
    if site and not site.get("subject"):
        site["subject"] = user.get("ownerSubject")
    return site


def resolve_subject(name):
    """The enabled Keycloak account's subject, as `make keycloak-user-info` prints it."""
    try:
        subject = subprocess.run([str(Path(__file__).with_name("keycloak-users.sh")), "resolve-subject", name],
                                 capture_output=True, text=True, timeout=90, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        raise InstallError(f"set ownerSubject for {name}, or create the Keycloak account first "
                           f"(make keycloak-add-user KC_USER={name})") from None
    return subject


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
    mode = user.get("values", {}).get("deployment", {}).get("mode")
    if mode not in {"container", "kata"} or mode != os.environ.get("DEPLOYMENT_MODE", "container"):
        raise InstallError("the selected user must explicitly select the requested Kubernetes deployment mode")
    config["ownerResolution"] = {**config.get("ownerResolution", {}), "enabled": False}
    if not user.get("ownerSubject"):
        user["ownerSubject"] = resolve_subject(name)
    apply_container_defaults(config, user)
    for field, pattern in [("registration", r"[a-f0-9]{16}"),
                           ("installationID", r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"),
                           ("ownerSubject", r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")]:
        if not re.fullmatch(pattern, str(user.get(field, ""))):
            raise InstallError("container inputs require a valid "+field)
    site = container_site(config, user)
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
    if owners[0].get("values", {}).get("deployment", {}).get("mode") != user["values"]["deployment"]["mode"]:
        raise InstallError("existing release uses another backend")


def check_live_boundary_approval(site, mode, user):
    """Check an existing workspace's live admission policies before apply."""
    automatic = site.get("automaticEnrollment", {}) if isinstance(site, dict) else {}
    if not isinstance(automatic, dict) or not automatic or automatic.get("enabled") is False:
        return
    profiles = user.get("profiles", [])
    profile = profiles[0] if len(profiles) == 1 else None
    boundaries = site.get("profileBoundaries", {})
    boundary = boundaries.get(profile) if isinstance(boundaries, dict) else None
    reference = (boundary.get("reference") if isinstance(boundary, dict)
                 else automatic.get("reference"))
    try:
        preflight_checks.verify_boundary_reference(reference, mode)
    except preflight_checks.PreflightError as exc:
        raise InstallError("SAW preflight failed: " + exc.reason) from None

    owner = user["name"]
    namespace_name = "saw-" + owner
    try:
        namespace = get("namespace", namespace_name)
    except InstallError:
        raise InstallError("SAW preflight failed: BoundaryNamespaceUnavailable") from None
    if namespace is None:
        # Argo has not created the first workspace yet. Check the complete
        # site approval now; enrollment verifies the generated policies later.
        return
    labels = namespace.get("metadata", {}).get("labels", {})
    if (labels.get("saw.redhat.com/registration") != user.get("registration")
            or labels.get("saw.redhat.com/runtime-owner") != user.get("installationID")):
        raise InstallError("SAW preflight failed: BoundaryApprovalIdentityMismatch")

    catalog = json.loads((ROOT / "charts/saw-users/files/profile-catalog.json").read_text())["profiles"]
    profile_data = catalog.get(profile)
    if not isinstance(profile_data, dict):
        raise InstallError("SAW preflight failed: BoundaryApprovalInvalid")
    slots = sorted(workspace.sandbox_targets(owner, user["registration"], profile_data))
    if not slots:
        raise InstallError("SAW preflight failed: BoundaryApprovalInvalid")

    def resource(kind, name, key, normalize=False):
        try:
            obj = get(kind, name)
        except InstallError:
            raise preflight_checks.PreflightError("BoundaryPolicyUnavailable") from None
        if not isinstance(obj, dict) or not isinstance(obj.get("spec"), dict):
            raise preflight_checks.PreflightError("BoundaryPolicyUnavailable")
        if normalize:
            digest = preflight_checks.validation_policy_digest(
                obj["spec"], owner, user["registration"], user["installationID"], slots)
        else:
            digest = preflight_checks.fingerprint(obj["spec"])
        preflight_checks.verify_boundary_hash(reference, key, digest)
        if obj.get("kind") == "ValidatingAdmissionPolicy":
            status = obj.get("status", {})
            metadata = obj.get("metadata", {})
            if (status.get("observedGeneration") != metadata.get("generation")
                    or "typeChecking" not in status
                    or status["typeChecking"].get("expressionWarnings")):
                raise preflight_checks.PreflightError("AdmissionUnavailable:" + key)

    policy = "saw-" + namespace_name + "-runtime"
    try:
        resource("validatingadmissionpolicies.admissionregistration.k8s.io",
                 policy, "validation", normalize=True)
        resource("validatingadmissionpolicybindings.admissionregistration.k8s.io",
                 policy, "binding")
        if mode == "kata":
            resource("validatingadmissionpolicies.admissionregistration.k8s.io",
                     policy + "-kata", "sandboxPlacement")
            resource("validatingadmissionpolicybindings.admissionregistration.k8s.io",
                     policy + "-kata", "sandboxPlacementBinding")
    except preflight_checks.PreflightError as exc:
        raise InstallError("SAW preflight failed: " + exc.reason) from None


def preflight(config, namespace, user):
    """Check the shared platform without installing or adopting its dependencies."""
    mode = user["values"]["deployment"]["mode"]
    site = config["containerSites"][user["name"]]
    catalog = json.loads((ROOT / "charts/saw-users/files/profile-catalog.json").read_text())["profiles"]
    try:
        preflight_checks.verify_profile_image_access(site, (user.get("profiles") or [None])[0], catalog)
    except preflight_checks.PreflightError as exc:
        raise InstallError("SAW preflight failed: " + exc.reason) from None
    argo = config.get("global", {}).get("vpArgoNamespace") or config.get("argo", {}).get("namespace", "vp-gitops")
    if namespace == argo:
        raise InstallError("workspace installation namespace must be separate from Argo CD")
    existing = get("namespace", namespace)
    if existing:
        labels = existing.get("metadata", {}).get("labels", {})
        if (existing.get("metadata", {}).get("deletionTimestamp")
                or labels.get("argocd.argoproj.io/managed-by") != argo):
            raise InstallError("installation namespace is deleting or is not managed by the selected Argo CD")
    observations = preflight_checks.configuration_facts(site)
    observations["api"] = True  # The API reads below succeeded.
    try:
        version = get("clusterversion", "version")
        preflight_checks.verify_cluster_version(version)
        observations["version"] = True
        api_readiness = {name: preflight_checks.crd_established(get("crd", name)) for name in (
            "applications.argoproj.io", "applicationsets.argoproj.io", "sandboxes.agents.x-k8s.io",
            "externalsecrets.external-secrets.io", "adminnetworkpolicies.policy.networking.k8s.io",
        )}
        try:
            admission_discovery = json.loads(run("oc", "get", "--raw", "/apis/admissionregistration.k8s.io/v1"))
        except (InstallError, json.JSONDecodeError):
            admission_discovery = {}
        api_readiness["admissionregistration.k8s.io/v1"] = (
            preflight_checks.api_resources_available(
                admission_discovery, "admissionregistration.k8s.io/v1",
                ("validatingadmissionpolicies", "validatingadmissionpolicybindings")))
        observations["agentSandbox"] = api_readiness["sandboxes.agents.x-k8s.io"]
        observations["admission"] = api_readiness["admissionregistration.k8s.io/v1"]
        observations["network"] = (observations.get("network") is True
                                    and api_readiness["adminnetworkpolicies.policy.networking.k8s.io"])
        storage = json.loads(run("oc", "get", "storageclasses", "-o", "json"))["items"]
        preflight_checks.verify_storage_classes(site, storage)
        observations["storage"] = True
        store = get("clustersecretstore", preflight_checks.secret_store_name(site))
        preflight_checks.verify_secret_store(site, [store] if store else [])
        observations["secrets"] = api_readiness["externalsecrets.external-secrets.io"]
        observations["argo"] = (api_readiness["applications.argoproj.io"]
                                and api_readiness["applicationsets.argoproj.io"]
                                and all(
            run("oc", "auth", "can-i", verb, resource, "-n", argo).strip() == "yes"
            for resource in ("applications.argoproj.io", "applicationsets.argoproj.io")
            for verb in ("get", "create", "patch", "delete")))
        preflight_checks.check_observations("container", observations)
    except preflight_checks.PreflightError as exc:
        raise InstallError("SAW preflight failed: " + exc.reason) from None
    if mode == "kata":
        approval = site.get("kataRuntimeClass") or {}
        runtime = get("runtimeclass", approval.get("name")) if approval.get("name") else None
        try:
            configs = json.loads(run("oc", "get", "kataconfigs", "-o", "json"))["items"]
            nodes = json.loads(run("oc", "get", "nodes", "-o", "json"))["items"]
            kata_crd = "kataconfigs.kataconfiguration.openshift.io"
            api_readiness[kata_crd] = preflight_checks.crd_established(get("crd", kata_crd))
            preflight_checks.verify_kata_platform(site, runtime, configs, nodes,
                                                  api_readiness, version)
            placement = (runtime.get("scheduling") or {}).get("nodeSelector") or {}
            selector = ",".join(f"{key}={value}" for key, value in sorted(placement.items()))
            try:
                kata_worker_check.check(run("oc", "whoami", "--show-server").strip(), selector)
            except Exception:
                raise InstallError("Kata preflight failed: KataWorkersNotReady") from None
            observations.update(osc=True, kataConfig=True, workers=True, runtimeClass=True)
            preflight_checks.check_observations("kata", observations)
        except preflight_checks.PreflightError as exc:
            raise InstallError("Kata preflight failed: " + exc.reason) from None
        except (KeyError, TypeError, ValueError):
            raise InstallError("Kata preflight failed: KataPlatformUnavailable") from None
    check_live_boundary_approval(site, mode, user)
    return existing, argo


def ensure_namespace(existing, namespace, argo):
    if existing:
        return
    manifest = {"apiVersion": "v1", "kind": "Namespace", "metadata": {
        "name": namespace, "labels": {"argocd.argoproj.io/managed-by": argo,
                                        "openshell.pattern/component": "workspace-installations"}}}
    # Create, never apply: a concurrent or unrelated installation is not adopted.
    run("oc", "create", "-f", "-", input_text=json.dumps(manifest))


def dry_run_rendered(rendered, namespace, release):
    """Validate Helm manifests without claiming fields owned by Helm."""
    try:
        resources = [item for item in yaml.safe_load_all(rendered) if item is not None]
    except yaml.YAMLError:
        raise InstallError("rendered chart contains invalid YAML") from None
    fresh, owned = [], []
    cluster_scoped = {"Namespace", "ClusterRole", "ClusterRoleBinding",
                      "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}
    for resource in resources:
        if not isinstance(resource, dict) or not isinstance(resource.get("kind"), str):
            raise InstallError("rendered chart contains an invalid resource")
        kind = resource["kind"]
        metadata = resource.get("metadata") or {}
        name = metadata.get("name") if isinstance(metadata, dict) else None
        if not isinstance(name, str) or not name:
            raise InstallError("rendered chart resource has no name")
        resource_namespace = (None if kind in cluster_scoped else
                              metadata.get("namespace") or namespace)
        ownership = ('go-template={{index .metadata.annotations "meta.helm.sh/release-name"}}'
                     '|{{index .metadata.annotations "meta.helm.sh/release-namespace"}}'
                     '|{{index .metadata.labels "app.kubernetes.io/managed-by"}}')
        command = ["oc", "get", kind, name, "--ignore-not-found", "-o", ownership]
        if resource_namespace:
            command += ["-n", resource_namespace]
        live = run(*command).strip()
        if not live:
            fresh.append(resource)
            continue
        fields = live.split("|")
        if len(fields) != 3:
            raise InstallError("OpenShift returned invalid resource ownership metadata")
        if fields != [release, namespace, "Helm"]:
            raise InstallError(f"rendered {kind}/{name} is outside Helm release {release}")
        owned.append(resource)
    for group, force in ((fresh, False), (owned, True)):
        if group:
            command = ["oc", "apply", "--server-side", "--dry-run=server"]
            if force:
                command.append("--force-conflicts")
            run(*command, "-f", "-", input_text=yaml.safe_dump_all(group))


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
    parser.add_argument("action", choices=("apply", "preflight", "status", "delete"))
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
            rendered = run("helm", "template", release, str(ROOT/"charts/saw-users"), "-n", args.namespace, "-f", str(values_file))
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
            existing_namespace, argo = preflight(config, args.namespace, user)
            if not existing_namespace:
                if args.action == "preflight":
                    raise InstallError("read-only server-side preflight requires the Argo-managed installation namespace to exist")
                ensure_namespace(existing_namespace, args.namespace, argo)
            dry_run_rendered(rendered, args.namespace, release)
            if args.action == "preflight":
                print("Read-only SAW preflight passed; no cluster changes were made.")
                return 0
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
