"""Shared, read-only checks for SAW Kubernetes workspace provisioning.

Callers collect facts from their cluster client. This module validates only
public configuration and observed resource metadata. It never reads Secrets.
"""

import hashlib
import json
import re


class PreflightError(ValueError):
    """A failed check with a fixed, safe status code."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


CHECK_REASONS = {
    "api": "ApiUnavailable",
    "version": "ClusterVersionUnavailable",
    "osc": "SandboxedContainersUnavailable",
    "kataConfig": "KataConfigNotReady",
    "workers": "KataWorkersNotReady",
    "runtimeClass": "RuntimeClassRejected",
    "agentSandbox": "AgentSandboxUnavailable",
    "admission": "AdmissionUnavailable",
    "network": "NetworkPolicyRejected",
    "argo": "ArgoAccessDenied",
    "storage": "StorageUnavailable",
    "secrets": "SecretServicesUnavailable",
    "registry": "RegistryUnavailable",
    "providerEgress": "ProviderEgressRejected",
    "revisions": "UnpinnedRevision",
}

COMMON_CHECKS = (
    "api", "version", "agentSandbox", "admission", "network", "argo",
    "storage", "secrets", "registry", "providerEgress", "revisions",
)
KATA_CHECKS = ("osc", "kataConfig", "workers", "runtimeClass")


def runtime_placement(runtime_class):
    """Return the canonical placement payload used by owner approvals."""
    return {key: runtime_class.get(key) for key in ("handler", "overhead", "scheduling")}


def runtime_placement_digest(runtime_class):
    raw = json.dumps(runtime_placement(runtime_class), sort_keys=True,
                     separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()


def check_runtime_class(approved, observed):
    """Check a RuntimeClass and return fixed, safe failure reasons."""
    if not isinstance(approved, dict) or not approved.get("name"):
        raise PreflightError("RuntimeClassApprovalMissing")
    if not isinstance(observed, dict):
        raise PreflightError("RuntimeClassUnavailable")
    metadata = observed.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise PreflightError("RuntimeClassUnavailable")
    if metadata.get("name") != approved["name"]:
        raise PreflightError("RuntimeClassNameMismatch")
    if not approved.get("uid") or metadata.get("uid") != approved["uid"]:
        raise PreflightError("RuntimeClassIdentityMismatch")
    if observed.get("handler") != "kata":
        raise PreflightError("RuntimeClassHandlerMismatch")
    labels = metadata.get("labels") or {}
    if not isinstance(labels, dict):
        raise PreflightError("RuntimeClassNotAttachable")
    if labels.get("openshell.ai/sandbox-attachable") != "true":
        raise PreflightError("RuntimeClassNotAttachable")
    if not isinstance(observed.get("scheduling"), dict) or not observed["scheduling"]:
        raise PreflightError("RuntimeClassSchedulingInvalid")
    approved_digest = approved.get("sha256")
    if not isinstance(approved_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", approved_digest):
        raise PreflightError("RuntimeClassApprovalInvalid")
    if runtime_placement_digest(observed) != approved_digest:
        raise PreflightError("RuntimeClassPlacementChanged")
    return True


def check_observations(mode, observations):
    """Require a complete fact set. Missing facts fail closed with safe codes.

    Values are booleans produced by a read-only cluster adapter. Do not pass
    API responses, exception strings, URLs with credentials, or Secret data.
    """
    if mode not in {"container", "kata"} or not isinstance(observations, dict):
        raise PreflightError("InvalidPreflightRequest")
    required = COMMON_CHECKS + (KATA_CHECKS if mode == "kata" else ())
    for check in required:
        if observations.get(check) is not True:
            raise PreflightError(CHECK_REASONS[check])
    return tuple(required)


def configuration_facts(site):
    """Check site-owned inputs that do not require cluster access."""
    if not isinstance(site, dict):
        return {key: False for key in ("network", "storage", "secrets", "registry",
                                        "providerEgress", "revisions")}
    stack = site.get("stack") if isinstance(site.get("stack"), dict) else {}
    revisions = [item.get("revision") for item in stack.values() if isinstance(item, dict)]
    required_components = ("identity", "policy", "proxy", "gateway", "audit")
    revision_pin = all(isinstance(stack.get(name), dict) for name in required_components) and all(
        isinstance(stack[name].get("revision"), str)
        and re.fullmatch(r"[a-f0-9]{40}", stack[name]["revision"])
        for name in required_components) and bool(revisions) and len(revisions) == len(stack) and all(
        isinstance(value, str) and re.fullmatch(r"[a-f0-9]{40}", value) for value in revisions)
    enrollment = site.get("automaticEnrollment") or {}
    if enrollment and not isinstance(enrollment, dict):
        revision_pin = False
    elif enrollment:
        revision_pin = revision_pin and bool(re.fullmatch(r"[a-f0-9]{40}", str(enrollment.get("revision", ""))))

    image_values = []
    storage_values = []
    def walk(value, path=()):
        if isinstance(value, dict):
            for key, child in value.items():
                next_path = path + (str(key).lower(),)
                if key == "image" and isinstance(child, str) and child:
                    image_values.append(child)
                if key in {"storageClass", "storageClassName"} and isinstance(child, str) and child:
                    storage_values.append(child)
                if key == "className" and "storage" in path and isinstance(child, str) and child:
                    storage_values.append(child)
                walk(child, next_path)
        elif isinstance(value, list):
            for child in value:
                walk(child, path)
    walk(site)

    policy = site.get("providerPolicy") or {}
    hosts = policy.get("allowHosts") if isinstance(policy, dict) else None
    declared_hosts = site.get("providerAllowHosts")
    clean_hosts = (isinstance(hosts, list) and bool(hosts)
                   and all(isinstance(host, str) and host and "*" not in host for host in hosts)
                   and isinstance(declared_hosts, list) and set(hosts) == set(declared_hosts))
    proxy = stack.get("proxy") or {}
    proxy_values = proxy.get("values") or {} if isinstance(proxy, dict) else {}
    bootstrap_egress = ((proxy_values.get("network") or {}).get("bootstrapEgress")
                        if isinstance(proxy_values, dict) else None)
    storage_ok = bool(storage_values) and all(value.strip() for value in storage_values)
    return {
        "network": bool(stack.get("policy")) and isinstance(bootstrap_egress, list)
                   and bool(bootstrap_egress),
        "storage": storage_ok,
        "secrets": isinstance(site.get("secretStore", "vault-backend"), str)
                   and bool(site.get("secretStore", "vault-backend")),
        "registry": bool(image_values) and all("@sha256:" in image for image in image_values),
        "providerEgress": clean_hosts,
        "revisions": revision_pin,
    }


def storage_class_names(site):
    names = set()
    def walk(value, path=()):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"storageClass", "storageClassName"} and isinstance(child, str) and child:
                    names.add(child)
                elif key == "className" and "storage" in path and isinstance(child, str) and child:
                    names.add(child)
                walk(child, path + (str(key).lower(),))
        elif isinstance(value, list):
            for child in value:
                walk(child, path)
    walk(site)
    return tuple(sorted(names))


def verify_storage_classes(site, storage_classes):
    names = storage_class_names(site)
    available = {item.get("metadata", {}).get("name") for item in storage_classes
                 if isinstance(item, dict)}
    default = any((item.get("metadata", {}).get("annotations") or {}).get(
        "storageclass.kubernetes.io/is-default-class") == "true"
        for item in storage_classes if isinstance(item, dict))
    if names and not set(names).issubset(available):
        raise PreflightError("StorageUnavailable")
    if not names and not default:
        raise PreflightError("StorageUnavailable")
    return names


def verify_secret_store(site, stores):
    name = secret_store_name(site)
    for store in stores:
        metadata = store.get("metadata") or {} if isinstance(store, dict) else {}
        if isinstance(metadata, dict) and metadata.get("name") == name and _ready(store):
            return name
    raise PreflightError("SecretServicesUnavailable")


def secret_store_name(site):
    if not isinstance(site, dict):
        return "vault-backend"
    stack = site.get("stack") if isinstance(site.get("stack"), dict) else {}
    identity = stack.get("identity") if isinstance(stack.get("identity"), dict) else {}
    identity_values = identity.get("values") if isinstance(identity.get("values"), dict) else {}
    return site.get("secretStore") or identity_values.get("secretStore") or "vault-backend"


def _ready(obj):
    if not isinstance(obj, dict):
        return False
    status = obj.get("status") or {}
    if not isinstance(status, dict):
        return False
    conditions = status.get("conditions") or []
    return isinstance(conditions, list) and any(
        isinstance(c, dict) and c.get("type") in {"Ready", "Completed"} and c.get("status") == "True"
        for c in conditions)


def kata_config_ready(obj):
    if not isinstance(obj, dict):
        return False
    status = obj.get("status") or {}
    if not isinstance(status, dict):
        return False
    nodes = status.get("kataNodes") or {}
    if not isinstance(nodes, dict):
        return False
    count = nodes.get("nodeCount")
    ready_count = nodes.get("readyNodeCount")
    if (type(count) is not int or count < 1 or type(ready_count) is not int
            or ready_count != count):
        return False
    conditions = status.get("conditions") or []
    return isinstance(conditions, list) and not any(
        isinstance(condition, dict) and condition.get("type") == "InProgress"
        and condition.get("status") == "True" for condition in conditions)


def kata_config_installed_nodes(obj):
    if not isinstance(obj, dict):
        return ()
    status = obj.get("status") or {}
    if not isinstance(status, dict):
        return ()
    nodes = status.get("kataNodes") or {}
    if not isinstance(nodes, dict):
        return ()
    installed = nodes.get("installed")
    if not isinstance(installed, list):
        return ()
    return tuple(name for name in installed if isinstance(name, str) and name)


def crd_established(obj):
    if not isinstance(obj, dict):
        return False
    status = obj.get("status") or {}
    if not isinstance(status, dict):
        return False
    conditions = status.get("conditions") or []
    return isinstance(conditions, list) and any(
        isinstance(condition, dict) and condition.get("type") == "Established"
        and condition.get("status") == "True" for condition in conditions)


def api_resources_available(discovery, group_version, resource_names):
    """Check served API resources from discovery, including built-in APIs."""
    if not isinstance(discovery, dict) or discovery.get("groupVersion") != group_version:
        return False
    resources = discovery.get("resources")
    if not isinstance(resources, list):
        return False
    available = {item.get("name") for item in resources if isinstance(item, dict)}
    return set(resource_names).issubset(available)


def cluster_version_ready(obj):
    try:
        verify_cluster_version(obj)
        return True
    except PreflightError:
        return False


def verify_cluster_version(obj):
    if not isinstance(obj, dict):
        raise PreflightError("ClusterVersionUnavailable")
    status = obj.get("status") or {}
    if not isinstance(status, dict):
        raise PreflightError("ClusterVersionUnavailable")
    conditions = status.get("conditions") or []
    available = isinstance(conditions, list) and any(
        isinstance(condition, dict) and condition.get("type") == "Available"
        and condition.get("status") == "True" for condition in conditions)
    if not available:
        raise PreflightError("ClusterVersionUnavailable")
    desired = status.get("desired") or {}
    version = desired.get("version") if isinstance(desired, dict) else None
    if not isinstance(version, str):
        raise PreflightError("ClusterVersionUnavailable")
    version = version.strip()
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.\d+)?(?:-[A-Za-z0-9.-]+)?", version)
    if not match:
        raise PreflightError("ClusterVersionUnavailable")
    if tuple(map(int, match.groups())) < (4, 22):
        raise PreflightError("UnsupportedOpenShiftVersion")
    return version


def vault_health_ready(obj):
    return isinstance(obj, dict) and obj.get("initialized") is True and obj.get("sealed") is False


def _matches_selector(labels, selector):
    return bool(selector) and all(labels.get(key) == value for key, value in selector.items())


def verify_kata_platform(site, runtime_class, kata_configs, nodes, api_readiness,
                         cluster_version):
    """Check live Kata prerequisites from read-only Kubernetes API snapshots."""
    verify_cluster_version(cluster_version)
    approved = site.get("kataRuntimeClass") if isinstance(site, dict) else None
    check_runtime_class(approved, runtime_class)
    if not isinstance(api_readiness, dict):
        raise PreflightError("AgentSandboxUnavailable")
    if api_readiness.get("kataconfigs.kataconfiguration.openshift.io") is not True:
        raise PreflightError("SandboxedContainersUnavailable")
    if not isinstance(kata_configs, list):
        raise PreflightError("KataConfigNotReady")
    ready_configs = [item for item in kata_configs
                     if isinstance(item, dict) and kata_config_ready(item)]
    if not ready_configs:
        raise PreflightError("KataConfigNotReady")
    installed_nodes = {name for item in ready_configs for name in kata_config_installed_nodes(item)}
    placement = (runtime_class.get("scheduling") or {}).get("nodeSelector") or {}
    if not isinstance(placement, dict) or not placement:
        raise PreflightError("RuntimeClassSchedulingInvalid")
    eligible = []
    if not isinstance(nodes, list):
        raise PreflightError("KataWorkersNotReady")
    for node in nodes:
        if not isinstance(node, dict):
            continue
        metadata = node.get("metadata") or {}
        if not isinstance(metadata, dict):
            continue
        labels = metadata.get("labels") or {}
        if not isinstance(labels, dict):
            continue
        roles = {key.removeprefix("node-role.kubernetes.io/") for key in labels
                 if key.startswith("node-role.kubernetes.io/")}
        status = node.get("status") or {}
        conditions = status.get("conditions", []) if isinstance(status, dict) else []
        ready = isinstance(conditions, list) and any(
            isinstance(c, dict) and c.get("type") == "Ready" and c.get("status") == "True"
            for c in conditions)
        spec = node.get("spec") or {}
        if (ready and isinstance(spec, dict) and not spec.get("unschedulable")
                and labels.get("kubernetes.io/arch") == "amd64"
                and "worker" in roles and not roles.intersection({"master", "control-plane"})
                and _matches_selector(labels, placement)):
            eligible.append(metadata.get("name"))
    if not eligible or not set(eligible).intersection(installed_nodes):
        raise PreflightError("KataWorkersNotReady")
    if api_readiness.get("sandboxes.agents.x-k8s.io") is not True:
        raise PreflightError("AgentSandboxUnavailable")
    if api_readiness.get("externalsecrets.external-secrets.io") is not True:
        raise PreflightError("SecretServicesUnavailable")
    if api_readiness.get("adminnetworkpolicies.policy.networking.k8s.io") is not True:
        raise PreflightError("NetworkPolicyRejected")
    if api_readiness.get("admissionregistration.k8s.io/v1") is not True:
        raise PreflightError("AdmissionUnavailable")
    return tuple(sorted(eligible))
