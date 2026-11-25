"""A credentialed provider's profile may list only the approved endpoints.

OpenShell attaches a provider's credential to the endpoints in its profile, and
container supervisors may open public TCP/443, so the reconciler must refuse a
profile that would send the key anywhere else.
"""
import copy

import pytest

from saw_kubernetes import ContractError, Reconciler, compile_profile_files
from saw_kubernetes import provider as governed
from .profile_fixtures import fixture_inputs
from .test_runtime import FakeGateway

ENFORCE = "NETWORK_ENFORCEMENT_MODE_ENFORCE"
SITE_URL = "https://models.fixture.test/v1"


def endpoint(host, port=443, **extra):
    return {"host": host, "port": port, "protocol": "rest", "enforcement": ENFORCE, **extra}


def check(kind, endpoints, url=SITE_URL):
    Reconciler._verify_profile_endpoints({"customInferenceURL": url}, kind, {"endpoints": endpoints})


def test_custom_inference_host_must_be_the_site_url_host():
    check("custom-inference", [endpoint("models.fixture.test")])
    with pytest.raises(ContractError, match="endpoints differ") as error:
        check("custom-inference", [endpoint("api.inference.example.com")])
    assert error.value.safe_reason == "ProviderProfileMismatch"
    # One shared profile cannot list several tenants' hosts either.
    with pytest.raises(ContractError, match="endpoints differ"):
        check("custom-inference", [endpoint("models.fixture.test"), endpoint("api.inference.example.com")])


def live(kind):
    """The shipped profile's endpoints as the gateway returns them: the
    interceptor's YAML-to-NetworkEndpoint conversion, then protobuf JSON (enums
    by name, default fields omitted)."""
    out = []
    for e in governed._shipped(kind)["endpoints"]:
        item = {"host": e["host"], "port": e["port"], "enforcement": ENFORCE}
        for key in ("protocol", "path"):
            if e.get(key):
                item[key] = e[key]
        if governed.ACCESS[e.get("access", "")]:
            item["access"] = governed.ACCESS[e["access"]]
        if e.get("rules"):
            item["rules"] = copy.deepcopy(e["rules"])
        out.append(item)
    return out


def test_stock_profile_must_match_the_shipped_governed_profile():
    check("nvidia", live("nvidia"))
    with pytest.raises(ContractError, match="endpoints differ"):
        check("nvidia", live("nvidia") + [endpoint("evil.example")])
    with pytest.raises(ContractError, match="endpoints differ"):
        check("no-such-provider", live("nvidia"))


@pytest.mark.parametrize("kind", ["github", "gmail", "slack", "nvidia", "openai", "anthropic"])
def test_every_shipped_profile_matches_itself_as_served(kind):
    check(kind, live(kind))


def test_two_entries_on_one_host_and_port_are_not_merged():
    """github lists api.github.com:443 twice: REST, and GraphQL scoped to /graphql."""
    endpoints = live("github")
    graphql, = [e for e in endpoints if e.get("path") == "/graphql"]
    endpoints.remove(graphql)
    with pytest.raises(ContractError, match="endpoints differ"):
        check("github", endpoints)                       # GraphQL entry dropped
    unscoped = dict(graphql)
    del unscoped["path"]
    with pytest.raises(ContractError, match="endpoints differ"):
        check("github", endpoints + [unscoped])          # GraphQL on every path


@pytest.mark.parametrize("change", [
    lambda e: e.update(access="NETWORK_ACCESS_PRESET_READ_WRITE"),
    lambda e: e.update(access="NETWORK_ACCESS_PRESET_FULL"),
    lambda e: e.update(protocol="tcp"),                  # L4 only: no inspection at all
    lambda e: e.update(path="/**"),
])
def test_a_widened_endpoint_on_an_approved_host_is_refused(change):
    endpoints = live("github")
    change(next(e for e in endpoints if e["host"] == "api.github.com" and "path" not in e))
    with pytest.raises(ContractError, match="endpoints differ"):
        check("github", endpoints)


def test_l7_rules_must_match_exactly():
    endpoints = live("gmail")
    rules = next(e for e in endpoints if e.get("rules"))["rules"]
    rules.append({"allow": {"method": "POST", "path": "/gmail/v1/users/me/messages/send"}})
    with pytest.raises(ContractError, match="endpoints differ"):
        check("gmail", endpoints)
    endpoints = live("gmail")
    next(e for e in endpoints if e.get("rules"))["rules"].reverse()
    check("gmail", endpoints)                            # order does not matter


@pytest.mark.parametrize("bad", [
    endpoint("models.fixture.test", enforcement="NETWORK_ENFORCEMENT_MODE_AUDIT"),
    {"host": "models.fixture.test", "port": 443},                      # unspecified = audit
    endpoint("models.fixture.test", allowed_ips=["203.0.113.7"]),
    endpoint("models.fixture.test", ports=[443, 8443]),
])
def test_every_endpoint_is_enforced_without_extra_destinations(bad):
    with pytest.raises(ContractError, match="endpoints differ"):
        check("custom-inference", [bad])


class ProfileGateway(FakeGateway):
    def __init__(self, endpoints):
        super().__init__()
        self.endpoints = endpoints

    def call(self, method, request):
        if method == "GetProviderProfile" and request["id"] == "custom-inference":
            self.calls.append((method, request))
            return {"profile": {"id": "custom-inference", "endpoints": self.endpoints,
                                "credentials": [{"env_vars": ["CUSTOM_INFERENCE_API_KEY"]}]}}
        return super().call(method, request)


def test_mismatched_profile_stops_the_reconciler_before_create_provider(tmp_path):
    files, config = fixture_inputs()
    plan = compile_profile_files(files, config)
    gateway = ProfileGateway([endpoint("api.inference.example.com")])
    reconciler = Reconciler(gateway, tmp_path / "state", lambda _: None,
                            read_credential=lambda secret, key: ("value", "1"))
    with pytest.raises(ContractError) as error:
        reconciler.reconcile(plan, generation=1)
    assert error.value.safe_reason == "ProviderProfileMismatch"
    assert not [m for m, _ in gateway.calls if m == "CreateProvider"]


def test_matching_profile_lets_the_reconciler_create_the_provider(tmp_path):
    files, config = fixture_inputs()
    plan = compile_profile_files(files, config)
    gateway = ProfileGateway([endpoint("models.fixture.test")])
    reconciler = Reconciler(gateway, tmp_path / "state", lambda _: None,
                            read_credential=lambda secret, key: ("value", "1"))
    created = lambda: [m for m, _ in gateway.calls if m == "CreateProvider"]
    for _ in range(4):   # workspace and membership come first
        try:
            reconciler.reconcile(plan, generation=1)
        except ContractError:
            pass   # the bare fake returns no provider revision; the create is what counts
        if created():
            break
    assert created()
