import pytest

from saw_kubernetes.audit import capture
from saw_kubernetes.boundary import BoundaryError, objects, verify


@pytest.fixture
def installation():
    config = dict(namespace="runtime", namespaceUID="ns-uid", ownerID="owner",
                  mode="container", trustedNamespace="trusted", governanceNamespace="gov",
                  gateway="gateway", proxyPolicy="proxy")
    resources = {}
    for key, (path, field) in objects(config).items():
        resources[path] = {"metadata": {"uid": key, "generation": 1}, field: {}}
    def obj(key):
        return resources[objects(config)[key][0]]
    for key in ("validation", "secretGuard", "serviceGuard", "podDeleteGuard"):
        obj(key)["status"] = {"observedGeneration": 1, "typeChecking": {}}
    for key in ("gateway", "governance", "proxy"):
        obj(key)["spec"]["replicas"] = 1
        obj(key)["status"] = {"observedGeneration": 1, "readyReplicas": 1, "updatedReplicas": 1}
    obj("network")["spec"]["priority"] = 50
    obj("network")["status"] = {"conditions": [
        {"type": "Ready-In-Zone-worker", "status": "True", "reason": "SetupSucceeded"}]}
    resources["/api/v1/nodes"] = {"items": [{"metadata": {"name": "worker"}}]}
    listing = "/apis/policy.networking.k8s.io/v1alpha1/adminnetworkpolicies"
    resources[listing] = {"items": [obj("network")]}
    approved = capture(config, resources.__getitem__)
    return approved, resources, obj, listing


@pytest.mark.parametrize("case,reason", [
    ("replaced", "ChangedBoundary:proxy"), ("drift", "ChangedBoundary:publicCA"),
    ("new-zone", "NetworkNotRealized"), ("precedence", "EarlierNetworkPolicy"),
    ("warning", "AdmissionUnavailable"), ("rollout", "RolloutIncomplete:gateway"),
])
def test_changed_or_unrealized_boundary_blocks(installation, case, reason):
    config, resources, obj, listing = installation
    if case == "replaced":
        obj("proxy")["metadata"]["uid"] = "replacement"
    elif case == "drift":
        obj("publicCA")["data"]["ca.crt"] = "new"
    elif case == "new-zone":
        resources["/api/v1/nodes"]["items"].append({"metadata": {"name": "new"}})
    elif case == "precedence":
        resources[listing]["items"].append({"metadata": {"uid": "other"}, "spec": {"priority": 50}})
    elif case == "warning":
        obj("validation")["status"]["typeChecking"]["expressionWarnings"] = [{"warning": "invalid"}]
    elif case == "rollout":
        obj("gateway")["status"]["updatedReplicas"] = 0
    with pytest.raises(BoundaryError, match=reason):
        verify(config, config, resources.__getitem__)


@pytest.mark.parametrize("subject,disjoint", [
    ({"pods": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "other"}},
               "podSelector": {}}}, True),
    ({"namespaces": {"matchLabels": {"kubernetes.io/metadata.name": "other"}}}, True),
    ({"pods": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "runtime"}}}}, False),
    ({"namespaces": {"matchLabels": {"owner": "other"}}}, False),
    ({"pods": {"podSelector": {"matchLabels": {"kubernetes.io/metadata.name": "other"}}}}, False),
    ({"namespaces": {}, "pods": {}}, False),
])
def test_second_tenant_network_precedence(installation, subject, disjoint):
    config, resources, _, listing = installation
    resources[listing]["items"].append({"metadata": {"uid": "first"},
                                        "spec": {"priority": 10, "subject": subject}})
    if disjoint:
        verify(config, config, resources.__getitem__)
    else:
        with pytest.raises(BoundaryError, match="EarlierNetworkPolicy"):
            verify(config, config, resources.__getitem__)
