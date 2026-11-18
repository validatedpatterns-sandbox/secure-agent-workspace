"""Read-only checks of the administrator-approved OpenShift installation."""
import hashlib
import json

import yaml

from . import provider as governed


class BoundaryError(ValueError):
    pass


def fingerprint(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(data.encode()).hexdigest()


def objects(config):
    ns = config["namespace"]
    trusted = config["trustedNamespace"]
    governance = config["governanceNamespace"]
    gateway = config["gateway"]
    policy = f"saw-{ns}-runtime"
    admission = "/apis/admissionregistration.k8s.io/v1"
    apps = "/apis/apps/v1/namespaces"
    net = "/apis/networking.k8s.io/v1/namespaces"
    core = "/api/v1/namespaces"
    placement = {}
    if config.get("mode") == "kata":
        placement = {
            "sandboxPlacement": (f"{admission}/validatingadmissionpolicies/{policy}-kata", "spec"),
            "sandboxPlacementBinding": (f"{admission}/validatingadmissionpolicybindings/{policy}-kata", "spec"),
        }
    return {
        **placement,
        "validation": (f"{admission}/validatingadmissionpolicies/{policy}", "spec"),
        "podDeleteGuard": (f"{admission}/validatingadmissionpolicies/{ns}-pods-driver", "spec"),
        "podDeleteBinding": (f"{admission}/validatingadmissionpolicybindings/{ns}-pods-driver", "spec"),
        "secretGuard": (f"{admission}/validatingadmissionpolicies/{ns}-secrets-driver", "spec"),
        "secretBinding": (f"{admission}/validatingadmissionpolicybindings/{ns}-secrets-driver", "spec"),
        "serviceGuard": (f"{admission}/validatingadmissionpolicies/{ns}-services-driver", "spec"),
        "serviceBinding": (f"{admission}/validatingadmissionpolicybindings/{ns}-services-driver", "spec"),
        "gatewayRole": (f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles/{gateway}-gateway", "rules"),
        "workloadFence": (f"{net}/{ns}/networkpolicies/openshell-sandbox-workloads", "spec"),
        "supervisorFence": (f"{net}/{ns}/networkpolicies/openshell-sandbox-supervisors", "spec"),
        "binding": (f"{admission}/validatingadmissionpolicybindings/{policy}", "spec"),
        "network": (f"/apis/policy.networking.k8s.io/v1alpha1/adminnetworkpolicies/{policy}-egress", "spec"),
        "deny": (f"{net}/{ns}/networkpolicies/{gateway}-default-deny", "spec"),
        "gatewayNetwork": (f"{net}/{ns}/networkpolicies/{gateway}-gateway", "spec"),
        "gateway": (f"{apps}/{ns}/statefulsets/{gateway}-gateway", "spec"),
        "gatewayService": (f"{core}/{ns}/services/{gateway}-gateway", "spec"),
        "gatewayConfig": (f"{core}/{ns}/configmaps/{gateway}-gateway-config", "data"),
        "governance": (f"{apps}/{governance}/deployments/governance-interceptor", "spec"),
        "governanceService": (f"{core}/{governance}/services/governance-interceptor", "spec"),
        "governancePolicy": (f"{core}/{governance}/configmaps/governance-interceptor-policy", "data"),
        "governanceProfiles": (f"{core}/{governance}/configmaps/governance-interceptor-profiles", "data"),
        "proxy": (f"{apps}/{trusted}/deployments/{gateway}-credential-proxy", "spec"),
        "proxyNetwork": (f"{net}/{trusted}/networkpolicies/{gateway}-credential-proxy", "spec"),
        "proxyPolicy": (f"{core}/{trusted}/configmaps/{config['proxyPolicy']}", "data"),
        "publicCA": (f"{core}/{ns}/configmaps/{gateway}-proxy-ca", "data"),
    }


def complete_list(get, path):
    response = get(path)
    if response.get("metadata", {}).get("continue") or not isinstance(response.get("items"), list):
        raise BoundaryError("IncompleteInventory")
    return response["items"]


def excludes_namespace(policy, namespace):
    """Prove disjointness only with the Kubernetes-managed, immutable name label.

    Pod labels, ordinary namespace labels, and unsupported selector forms do
    not establish an isolation boundary. A missing/unknown subject overlaps.
    """
    subject = policy.get("spec", {}).get("subject", {})
    if not isinstance(subject, dict):
        return False
    if set(subject) == {"pods"} and isinstance(subject["pods"], dict):
        selector = subject["pods"].get("namespaceSelector")
    elif set(subject) == {"namespaces"}:
        selector = subject["namespaces"]
    else:
        return False
    labels = selector.get("matchLabels") if isinstance(selector, dict) else None
    name = labels.get("kubernetes.io/metadata.name") if isinstance(labels, dict) else None
    return isinstance(name, str) and bool(name) and name != namespace


def verify(config, plan, get):
    if (config["namespace"], config["namespaceUID"], config["ownerID"], config["mode"]) != (
            plan["namespace"], plan["namespaceUID"], plan["ownerID"], plan["mode"]):
        raise BoundaryError("WrongInstallation")
    refs = objects(config)
    if set(config["approved"]) != set(refs):
        raise BoundaryError("IncompleteApproval")
    observed = {}
    for key, (path, field) in refs.items():
        obj = get(path)
        meta = obj["metadata"]
        expected = config["approved"][key]
        if (meta.get("deletionTimestamp") or meta["uid"] != expected["uid"]
                or fingerprint(obj[field]) != expected["sha256"]):
            raise BoundaryError("ChangedBoundary:" + key)
        observed[key] = obj
    for workspace in plan.get("workspaces", []):
        for provider in workspace["providers"]:
            credentials = provider.get("credentials")
            if credentials:
                policy = json.loads(observed["proxyPolicy"]["data"]["config.json"])
                kind = provider.get("type", "openai")
                if kind not in {"openai", "custom-inference"}:
                    live = observed["governanceProfiles"]["data"].get(kind + ".yaml", "")
                    if yaml.safe_load(live) != governed.document(kind):
                        raise BoundaryError("ProviderGovernanceMismatch")
                if not governed.check_policy(kind, credentials, policy, plan.get("customInferenceURL")):
                    raise BoundaryError("OpenAIProxyBindingMismatch" if kind == "openai"
                                        else "ProviderProxyBindingMismatch")
    checks = ["validation", "secretGuard", "serviceGuard", "podDeleteGuard"]
    if config["mode"] == "kata":
        import tomllib
        driver = tomllib.loads(observed["gatewayConfig"]["data"]["gateway.toml"])["openshell"]["drivers"]["kubernetes"]
        runtime = config.get("workloadRuntimeClass")
        if (not runtime or plan.get("runtimeClass", {}).get("name", runtime) != runtime
                or driver.get("default_runtime_class_name") != runtime):
            raise BoundaryError("WrongWorkloadPlacement")
        checks.append("sandboxPlacement")
    for key in checks:
        vap = observed[key]
        status = vap.get("status", {})
        if (status.get("observedGeneration") != vap["metadata"]["generation"]
                or "typeChecking" not in status or status["typeChecking"].get("expressionWarnings")):
            raise BoundaryError("AdmissionUnavailable:" + key)
    network = observed["network"]
    priority = network["spec"]["priority"]
    policies = complete_list(get, "/apis/policy.networking.k8s.io/v1alpha1/adminnetworkpolicies")
    if any(p["metadata"]["uid"] != network["metadata"]["uid"] and p["spec"]["priority"] <= priority
           and not excludes_namespace(p, config["namespace"])
           for p in policies):
        raise BoundaryError("EarlierNetworkPolicy")
    nodes = complete_list(get, "/api/v1/nodes")
    zones = {n["metadata"]["name"] for n in nodes}
    realized = {c["type"].removeprefix("Ready-In-Zone-")
                for c in network.get("status", {}).get("conditions", [])
                if c["type"].startswith("Ready-In-Zone-") and c["status"] == "True"
                and c.get("reason") == "SetupSucceeded"}
    if not zones or not zones <= realized:
        raise BoundaryError("NetworkNotRealized")
    for key in ("gateway", "governance", "proxy"):
        obj = observed[key]
        status = obj.get("status", {})
        if (status.get("observedGeneration") != obj["metadata"]["generation"]
                or status.get("readyReplicas", 0) != obj["spec"]["replicas"]
                or status.get("updatedReplicas", 0) != obj["spec"]["replicas"]):
            raise BoundaryError("RolloutIncomplete:" + key)
