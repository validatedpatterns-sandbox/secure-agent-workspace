"""Workspaces enrolled by the removed credential-proxy controller must re-enroll."""
import pytest

from saw_kubernetes import ContractError, Reconciler, compile_profile
from saw_kubernetes.boundary import PROXY_ERA_OBJECTS, BoundaryError, verify
from .test_openclaw import agent
from .test_runtime import FakeGateway, source  # noqa: F401  (fixture)


@pytest.mark.parametrize("key", ["proxyProviderRevisions", "pendingProxyProviders"])
def test_proxy_era_controller_state_is_not_adopted(source, tmp_path, key):
    agent(source)
    plan = compile_profile(*source)
    gateway = FakeGateway()
    reconciler = Reconciler(gateway, tmp_path / "state", lambda _: None,
                            read_credential=lambda secret, name: ("value", "1"))
    identity = {k: plan[k] for k in ["ownerID", "namespaceUID", "ownerSubject", "mode"]}
    reference = plan["workspaces"][0]["name"] + "/" + plan["workspaces"][0]["providers"][0]["metadata"]["name"]
    reconciler.store.save({"identity": identity, key: {reference: {"version": "7"}}})
    with pytest.raises(ContractError, match="re-enroll") as error:
        reconciler.reconcile(plan, generation=1)
    assert error.value.safe_reason == "ReenrollRequired"
    assert not gateway.calls   # nothing adopted, nothing created


def test_proxy_era_approval_requires_reenrollment():
    plan = {"namespace": "saw-alice", "namespaceUID": "u", "ownerID": "o", "mode": "container"}
    config = {**plan, "approved": dict.fromkeys(PROXY_ERA_OBJECTS | {"gateway"}, {})}
    with pytest.raises(BoundaryError, match="ReenrollRequired"):
        verify(config, plan, lambda path: pytest.fail("no object is read before the check"))
