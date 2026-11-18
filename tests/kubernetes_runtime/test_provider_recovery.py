"""CreateProvider ambiguity must use a replay receipt, never redacted Get data."""
import copy

import pytest

from saw_kubernetes import ContractError, Reconciler, RpcError, compile_profile
from .test_openclaw import agent
from .test_runtime import FakeGateway, source


class LostProviderResponse(FakeGateway):
    """Model the pinned gateway's caller/request/payload/revision replay fence."""

    def __init__(self):
        super().__init__()
        self.receipt = None
        self.creations = 0
        self.replays = 0

    def call(self, method, request):
        if method != "CreateProvider":
            return super().call(method, request)
        ws = request["workspace_scope"]["workspace"]
        key = (ws, request["provider"]["metadata"]["name"])
        if self.receipt:
            original, response = self.receipt
            assert request == original
            self.replays += 1
            if self.providers[key] != response["provider"]:
                raise RpcError("FAILED_PRECONDITION")
            return copy.deepcopy(response)
        if key in self.providers:
            raise RpcError("ALREADY_EXISTS")
        response = super().call(method, request)
        response["provider"]["metadata"]["resource_version"] = "1"
        response["provider"]["credentials"] = {k:"REDACTED" for k in request["provider"]["credentials"]}
        self.receipt = copy.deepcopy((request, response))
        self.creations += 1
        raise RpcError("DEADLINE_EXCEEDED")


@pytest.fixture
def interrupted(source, tmp_path):
    agent(source)
    plan = compile_profile(*source)
    ws = plan["workspaces"][0]
    provider = ws["providers"][0]
    gateway = LostProviderResponse()
    core = Reconciler(gateway, tmp_path / "ledger", lambda _: None)
    with pytest.raises(RpcError, match="DEADLINE_EXCEEDED"):
        core._apply_provider(ws, provider, plan, {}, 1, [])
    # Reconstruct the process from durable state; changing intent generation
    # must not change the original CreateProvider request ID.
    core = Reconciler(gateway, tmp_path / "ledger", lambda _: None)
    return core, gateway, ws, provider, plan


def test_lost_provider_response_recovers_across_process_and_generation(interrupted):
    core, gateway, ws, provider, plan = interrupted
    state = core.store.load()
    assert state["pendingProxyProviders"] and not state.get("proxyProviderRevisions")
    assert core._apply_provider(ws, provider, plan, state, 2, [])
    assert gateway.creations == 1 and gateway.replays == 1
    assert not core.store.load()["pendingProxyProviders"]
    assert core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
    assert gateway.replays == 1


@pytest.mark.parametrize("change", ["revision", "replacement", "foreign-owner"])
def test_recovery_refuses_changed_gateway_resource(interrupted, change):
    core, gateway, ws, provider, plan = interrupted
    meta = gateway.providers[(ws["name"], provider["metadata"]["name"])]["metadata"]
    if change == "revision":
        meta["resource_version"] = "2"
    elif change == "replacement":
        meta["id"] = "replacement"
    else:
        meta["labels"] = {}
    with pytest.raises(RpcError, match="FAILED_PRECONDITION"):
        core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
    assert not core.store.load().get("proxyProviderRevisions")


def test_recovery_refuses_changed_marker_or_missing_receipt(interrupted):
    core, gateway, ws, provider, plan = interrupted
    changed = copy.deepcopy(provider)
    changed["credentials"]["OPENAI_API_KEY"] = "saw-cred.other.api_key"
    with pytest.raises(ContractError, match="pending provider creation changed"):
        core._apply_provider(ws, changed, plan, core.store.load(), 2, [])
    assert gateway.replays == 0
    gateway.receipt = None
    with pytest.raises(ContractError, match="receipt unavailable"):
        core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
    # Losing the local intent must not allow adoption based on labels alone.
    with pytest.raises(ContractError, match="credential revision"):
        core._apply_provider(ws, provider, plan, {}, 2, [])
