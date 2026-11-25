"""OpenShell refreshes OAuth access tokens; the runtime only hands it the material."""
import copy
import json

from saw_kubernetes import Reconciler
from saw_kubernetes.compiler import MANAGED, OWNER
from .test_runtime import FakeGateway

OWNER_ID = "b032b2e4-2cd5-47a7-8ef8-ac73e15700b1"
PLAN = {"ownerID": OWNER_ID}
WS = {"name": "default"}
GMAIL = {"metadata": {"name": "gmail", "labels": {OWNER: OWNER_ID, MANAGED: "kubernetes-runtime"}},
         "type": "gmail", "credentialRef": {"secret": "gmail", "key": "access_token"},
         "refresh": {"strategy": "oauth2_refresh_token",
                     "material": ["client_id", "client_secret", "refresh_token"]}}


class RefreshGateway(FakeGateway):
    def __init__(self):
        super().__init__()
        self.refresh_ok = True
        self.status_ready = True   # False: the gateway has not populated refresh status yet
        self.lose_replies = False  # True: configure/rotate fail as a lost reply (UNAVAILABLE)
        self.already_exists = False  # True: the gateway already has this refresh configuration

    def call(self, method, request):
        if method in ("ConfigureProviderRefresh", "RotateProviderCredential"):
            self.calls.append((method, copy.deepcopy(request)))
            if self.lose_replies or self.already_exists:
                from saw_kubernetes import RpcError
                raise RpcError("UNAVAILABLE" if self.lose_replies else "ALREADY_EXISTS")
            if method == "RotateProviderCredential":
                # As the gateway does: store the minted token, bumping the version.
                provider = self.providers[(request["workspace_scope"]["workspace"], request["provider"])]
                provider["credentials"] = {request["credential_key"]: "REDACTED"}
                provider["metadata"]["resource_version"] = str(int(provider["metadata"]["resource_version"]) + 1)
            return {"status": {}}
        if method == "GetProviderRefreshStatus":
            if not self.status_ready:
                return {"credentials": []}
            status = {"credential_key": request["credential_key"]}
            if not self.refresh_ok:
                status["last_error"] = "invalid_grant"
            return {"credentials": [status]}
        response = super().call(method, request)
        if method == "CreateProvider":
            obj = response["provider"]
            obj["metadata"]["resource_version"] = "1"
            obj["credentials"] = {k: "REDACTED" for k in obj.get("credentials", {})}
        return response


def setup(tmp_path):
    gateway = RefreshGateway()
    secret = {"revision": "1"}
    def read_credential(name, key):
        # Like the portal's Vault object: refresh material only, no access_token.
        assert key in GMAIL["refresh"]["material"], key
        return f"{key}-{secret['revision']}", secret["revision"]
    core = Reconciler(gateway, tmp_path / "ledger", lambda _: None, read_credential=read_credential)
    core.credential_env["gmail"] = "GMAIL_ACCESS_TOKEN"
    return core, gateway, secret


def run(core, state):
    pending = []
    return core._apply_provider(WS, GMAIL, PLAN, state, 1, pending), pending


def methods(gateway, name):
    return [r for m, r in gateway.calls if m == name]


def test_refresh_is_configured_once_per_secret_revision(tmp_path):
    core, gateway, secret = setup(tmp_path)
    state = {}
    assert run(core, state) == (False, ["provider/default/gmail"])   # created
    assert run(core, state) == (False, ["provider/default/gmail"])   # refresh configured
    configure, = methods(gateway, "ConfigureProviderRefresh")
    assert configure["credential_key"] == "GMAIL_ACCESS_TOKEN"
    assert configure["strategy"] == "PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN"
    assert configure["material"] == {"client_id": "client_id-1", "client_secret": "client_secret-1",
                                     "refresh_token": "refresh_token-1"}
    assert set(configure["secret_material_keys"]) == {"client_id", "client_secret", "refresh_token"}
    assert len(methods(gateway, "RotateProviderCredential")) == 1
    assert run(core, state) == (True, [])
    assert len(methods(gateway, "ConfigureProviderRefresh")) == 1   # unchanged Secret: not re-sent

    secret["revision"] = "2"
    assert run(core, state)[0] is False
    assert len(methods(gateway, "ConfigureProviderRefresh")) == 2
    assert not methods(gateway, "UpdateProvider")   # OpenShell owns the refreshed token
    assert run(core, state) == (True, [])

    stored = json.dumps(core.store.load()) + json.dumps(state)
    ids = json.dumps([r.get("request_id") for _, r in gateway.calls])
    assert "refresh_token-" not in stored + ids and "client_secret-" not in stored + ids


def test_failing_refresh_is_reported(tmp_path):
    core, gateway, _ = setup(tmp_path)
    state = {}
    run(core, state); run(core, state)
    gateway.refresh_ok = False
    import pytest
    from saw_kubernetes import ContractError
    with pytest.raises(ContractError, match="refresh is failing"):
        run(core, state)


def test_provider_is_created_from_material_without_an_access_token(tmp_path):
    core, gateway, _ = setup(tmp_path)
    state = {}
    run(core, state)
    create, = methods(gateway, "CreateProvider")
    # OpenShell mints the token: no credential value, and only Provider fields.
    assert "credentials" not in create["provider"] and "refresh" not in create["provider"]
    run(core, state)
    assert len(methods(gateway, "RotateProviderCredential")) == 1
    # The rotation rewrote the provider (new version, minted token); still converged.
    assert run(core, state) == (True, [])
    assert run(core, state) == (True, [])


def test_unpopulated_status_is_pending_and_a_lost_configure_is_resent(tmp_path):
    from saw_kubernetes import RpcError
    core, gateway, _ = setup(tmp_path)
    state = {}
    run(core, state)                                   # create
    gateway.status_ready, gateway.lose_replies = False, True
    for _ in range(2):                                 # configure: reply lost in transit
        try:
            run(core, state)
        except RpcError:
            pass
    first, second = methods(gateway, "ConfigureProviderRefresh")
    assert first["request_id"] == second["request_id"]
    assert not core.store.load().get("refreshConfigured")            # nothing recorded yet

    gateway.lose_replies = False
    assert run(core, state)[0] is False                # acknowledged; status still empty
    assert run(core, state) == (False, ["provider/default/gmail"])   # empty status: pending
    assert len(methods(gateway, "ConfigureProviderRefresh")) == 3    # not re-sent once acknowledged
    assert not core.store.load().get("refreshConfigured")
    gateway.status_ready = True
    assert run(core, state) == (True, [])
    assert core.store.load()["refreshConfigured"] == {"default/gmail": "1"}


def test_refresh_that_disappears_after_working_is_reported(tmp_path):
    core, gateway, _ = setup(tmp_path)
    state = {}
    run(core, state); run(core, state)
    assert run(core, state) == (True, [])
    gateway.status_ready = False
    import pytest
    from saw_kubernetes import ContractError
    with pytest.raises(ContractError, match="no longer configured") as error:
        run(core, state)
    assert error.value.safe_reason == "ProviderRefreshFailed"


def test_already_existing_refresh_is_observed_not_resent(tmp_path):
    """ALREADY_EXISTS means the gateway has the configuration: resending the
    same request can only repeat that answer, so the status decides."""
    core, gateway, _ = setup(tmp_path)
    state = {}
    run(core, state)                                   # create
    gateway.status_ready, gateway.already_exists = False, True
    assert run(core, state) == (False, ["provider/default/gmail"])   # acknowledged
    assert run(core, state) == (False, ["provider/default/gmail"])   # status empty: pending
    assert len(methods(gateway, "ConfigureProviderRefresh")) == 1    # never resent
    gateway.status_ready = True
    assert run(core, state) == (True, [])
    assert core.store.load()["refreshConfigured"] == {"default/gmail": "1"}
