"""CreateProvider ambiguity must use a replay receipt, never redacted Get data."""
import copy
import json

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
    secrets = {"revision": "1"}
    def read_credential(secret, key):
        return "real-" + secret + "-" + secrets["revision"], secrets["revision"]
    def reconciler():
        core = Reconciler(gateway, tmp_path / "ledger", lambda _: None, read_credential=read_credential)
        core.credential_env[provider["type"]] = "OPENAI_API_KEY"
        return core
    core = reconciler()
    with pytest.raises(RpcError, match="DEADLINE_EXCEEDED"):
        core._apply_provider(ws, provider, plan, {}, 1, [])
    # Reconstruct the process from durable state; changing intent generation
    # must not change the original CreateProvider request ID.
    core = reconciler()
    core.secrets = secrets
    return core, gateway, ws, provider, plan


def test_lost_provider_response_recovers_across_process_and_generation(interrupted):
    core, gateway, ws, provider, plan = interrupted
    state = core.store.load()
    assert state["pendingProviders"] and not state.get("providerRevisions")
    assert core._apply_provider(ws, provider, plan, state, 2, [])
    assert gateway.creations == 1 and gateway.replays == 1
    assert not core.store.load()["pendingProviders"]
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
    assert not core.store.load().get("providerRevisions")


def test_recovery_refuses_changed_reference_or_missing_receipt(interrupted):
    core, gateway, ws, provider, plan = interrupted
    changed = copy.deepcopy(provider)
    changed["credentialRef"]["secret"] = "other"
    with pytest.raises(ContractError, match="pending provider creation changed"):
        core._apply_provider(ws, changed, plan, core.store.load(), 2, [])
    assert gateway.replays == 0
    gateway.receipt = None
    with pytest.raises(ContractError, match="receipt unavailable"):
        core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
    # Losing the local intent must not allow adoption based on labels alone.
    with pytest.raises(ContractError, match="credential revision"):
        core._apply_provider(ws, provider, plan, {}, 2, [])


def test_credential_value_stays_out_of_the_plan_state_and_request_id(interrupted):
    core, gateway, ws, provider, plan = interrupted
    assert "credentials" not in provider and provider["credentialRef"]
    request, _ = gateway.receipt
    assert request["provider"]["credentials"] == {"OPENAI_API_KEY": "real-" + provider["credentialRef"]["secret"] + "-1"}
    assert "real-" not in json.dumps(plan) + json.dumps(core.store.load()) + request["request_id"]


def test_rotated_secret_updates_the_openshell_provider(interrupted):
    core, gateway, ws, provider, plan = interrupted
    assert core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
    updates = []
    original = gateway.call
    def call(method, request):
        if method == "UpdateProvider":
            updates.append(request)
            key = (ws["name"], provider["metadata"]["name"])
            gateway.providers[key]["metadata"]["resource_version"] = "2"
            return {"provider": copy.deepcopy(gateway.providers[key])}
        return original(method, request)
    gateway.call = call
    core.secrets["revision"] = "2"
    pending = []
    assert not core._apply_provider(ws, provider, plan, core.store.load(), 2, pending)
    assert pending and updates[0]["provider"]["credentials"] == {
        "OPENAI_API_KEY": "real-" + provider["credentialRef"]["secret"] + "-2"}
    assert core._apply_provider(ws, provider, plan, core.store.load(), 2, [])



class LostUpdateResponse:
    """UpdateProvider whose reply is lost; it may or may not have applied."""

    def __init__(self, gateway, key, *, apply, error):
        self.gateway, self.key, self.apply, self.error = gateway, key, apply, error
        self.original, self.sent = gateway.call, []
        gateway.call = self.call

    def call(self, method, request):
        if method != "UpdateProvider":
            return self.original(method, request)
        self.sent.append(request["request_id"])
        provider = self.gateway.providers[self.key]
        if self.apply:
            provider["metadata"]["resource_version"] = str(int(provider["metadata"]["resource_version"]) + 1)
            self.apply = False   # a replay of the same request does not apply twice
        if self.error:
            error, self.error = self.error, "ALREADY_EXISTS"   # replays answer with no body
            raise RpcError(error)
        return {"provider": copy.deepcopy(provider)}


def converged(interrupted):
    core, gateway, ws, provider, plan = interrupted
    assert core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
    core.secrets["revision"] = "2"
    return core, gateway, ws, provider, plan, (ws["name"], provider["metadata"]["name"])


def test_applied_update_with_a_lost_reply_is_recorded_not_resent(interrupted):
    core, gateway, ws, provider, plan, key = converged(interrupted)
    lost = LostUpdateResponse(gateway, key, apply=True, error="DEADLINE_EXCEEDED")
    with pytest.raises(RpcError, match="DEADLINE_EXCEEDED"):
        core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
    assert core.store.load()["pendingProviderUpdates"]
    # The next pass sees the provider moved on and records the new source.
    assert core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
    state = core.store.load()
    assert not state["pendingProviderUpdates"]
    recorded = next(iter(state["providerRevisions"].values()))
    assert recorded["source"] == "2" and recorded["version"] == "2"
    assert core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
    assert len(lost.sent) == 1


def test_update_replay_without_a_body_converges(interrupted):
    core, gateway, ws, provider, plan, key = converged(interrupted)
    # First attempt never applied; its replay applies and answers ALREADY_EXISTS.
    lost = LostUpdateResponse(gateway, key, apply=False, error="DEADLINE_EXCEEDED")
    with pytest.raises(RpcError, match="DEADLINE_EXCEEDED"):
        core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
    lost.apply = True
    pending = []
    assert not core._apply_provider(ws, provider, plan, core.store.load(), 2, pending) and pending
    assert lost.sent[0] == lost.sent[1]   # same request ID: the gateway replays it
    assert core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
    assert len(lost.sent) == 2


def test_provider_changed_during_an_update_fails_closed(interrupted):
    core, gateway, ws, provider, plan, key = converged(interrupted)
    LostUpdateResponse(gateway, key, apply=True, error="DEADLINE_EXCEEDED")
    with pytest.raises(RpcError, match="DEADLINE_EXCEEDED"):
        core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
    gateway.providers[key]["credentials"] = {"OTHER_KEY": "REDACTED"}
    with pytest.raises(ContractError, match="changed during a credential update"):
        core._apply_provider(ws, provider, plan, core.store.load(), 2, [])
