"""The central resolver accepts one enabled exact Keycloak account."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
# The resolver imports saw_tls from its own /scripts mount.
sys.path.insert(0, str(ROOT / "charts/openshell-keycloak/files"))
SCRIPT = ROOT / "charts/openshell-keycloak/files/owner-resolver.py"
SPEC = importlib.util.spec_from_file_location("owner_resolver", SCRIPT)
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)


@pytest.fixture
def bootstrap_api(monkeypatch, tmp_path):
    admin = tmp_path / "admin"
    admin.mkdir()
    (admin / "username").write_text("test-admin")
    (admin / "password").write_text("test-password")
    output = tmp_path / "client-secret"
    for key, value in {"REALM": "openshell", "CLIENT_ID": "resolver",
                       "ADMIN_DIR": str(admin), "OUT": str(output)}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(resolver, "keycloak_endpoint", lambda: ("https://keycloak.test", None))
    monkeypatch.setattr(resolver, "keycloak_token", lambda *_: "test-admin-token")
    state = {
        "client": {"id": "resolver-id", "clientId": "resolver", "protocol": "openid-connect",
                   "publicClient": False, "clientAuthenticatorType": "client-secret",
                   "serviceAccountsEnabled": True, "standardFlowEnabled": False,
                   "directAccessGrantsEnabled": False, "implicitFlowEnabled": False},
        "scopes": [{"id": "admin-scope", "name": "kc-admin-api"}],
        "default_scopes": [],
        "roles": [{"name": "view-users"}],
        "calls": [],
        "output": output,
    }

    def api(url, realm, token, path, method="GET", body=None, ctx=None):
        assert (url, realm, token) == ("https://keycloak.test", "openshell", "test-admin-token")
        state["calls"].append((method, path))
        roles_path = "/users/service-user/role-mappings/clients/management-id"
        if method == "GET":
            return {
                "": {"realm": "openshell"},
                "/clients?clientId=resolver": [state["client"]] if state["client"] else [],
                "/client-scopes": state["scopes"],
                "/clients/resolver-id/default-client-scopes": state["default_scopes"],
                "/clients/resolver-id/service-account-user": {"id": "service-user"},
                "/clients?clientId=realm-management": [
                    {"id": "management-id", "clientId": "realm-management"}],
                roles_path: state["roles"],
                "/clients/management-id/roles/view-users": {"name": "view-users"},
                "/clients/resolver-id/client-secret": {"value": "test-client-secret"},
            }[path]
        if method == "POST" and path == "/clients":
            state["client"] = {**body, "id": "resolver-id"}
        elif method == "POST" and path == roles_path:
            state["roles"].extend(body)
        elif method == "PUT" and path == "/clients/resolver-id/default-client-scopes/admin-scope":
            state["default_scopes"].append(state["scopes"][0])
        else:
            pytest.fail(f"Unexpected bootstrap request: {method} {path}")

    monkeypatch.setattr(resolver, "kc_call", api)
    return state


@pytest.mark.parametrize("existing_client", [False, True], ids=["new-client", "existing-client"])
@pytest.mark.parametrize("scope_state", ["absent", "unassigned", "assigned"])
def test_bootstrap_admin_scope_is_compatible_and_idempotent(bootstrap_api, existing_client, scope_state):
    state = bootstrap_api
    if not existing_client:
        state["client"] = None
        state["roles"] = []
    if scope_state == "absent":
        state["scopes"] = []
    elif scope_state == "assigned":
        state["default_scopes"] = list(state["scopes"])

    resolver.bootstrap()
    resolver.bootstrap()

    assert state["default_scopes"] == state["scopes"]
    scope_assignment = ("PUT", "/clients/resolver-id/default-client-scopes/admin-scope")
    assert state["calls"].count(scope_assignment) == (1 if scope_state == "unassigned" else 0)
    assert state["calls"].count(("POST", "/clients")) == (0 if existing_client else 1)
    assert state["roles"] == [{"name": "view-users"}]
    assert state["output"].read_text() == "test-client-secret"
    assert state["output"].stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("roles", [
    [{"name": "manage-realm"}],
    [{"name": "view-users"}, {"name": "manage-realm"}],
], ids=["unexpected-role", "extra-role"])
def test_bootstrap_rejects_roles_before_granting_admin_scope(bootstrap_api, roles):
    state = bootstrap_api
    state["roles"] = roles

    with pytest.raises(RuntimeError, match="extra realm-management roles"):
        resolver.bootstrap()

    assert state["default_scopes"] == []
    assert all(method == "GET" for method, _ in state["calls"])
    assert not state["output"].exists()



def test_exact_enabled_account_only():
    cases = [
        ([{"username": "alice", "enabled": True, "id": "subject-a"}], ("subject-a", "resolved")),
        ([], ("", "unknown")),
        ([{"username": "alice", "enabled": False, "id": "subject-a"}], ("", "disabled")),
        ([{"username": "bob", "enabled": True, "id": "subject-b"}], ("", "mismatch")),
        ([{"username": "alice", "enabled": True, "id": "subject-a"},
          {"username": "alice", "enabled": True, "id": "subject-b"}], ("", "ambiguous")),
    ]
    for users, expected in cases:
        assert resolver.subject_for(lambda _: users, "alice") == expected


class FakeKube:
    def __init__(self, subject=""):
        self.subject = subject
        self.patches = []

    def call(self, path, method="GET", body=None):
        if path.startswith("/api/v1/namespaces?"):
            return {"items": [{"metadata": {"name": "saw-alice", "labels": {
                "openshell.pattern/owner": "alice"}}},
                              {"metadata": {"name": "saw-other", "labels": {
                                  "openshell.pattern/owner": "alice"}}}]}
        if method == "PATCH":
            self.patches.append((path, body))
            if "data" in body:
                self.subject = body["data"]["subject"]
            return {}
        return {"data": {"subject": self.subject}, "metadata": {"annotations": {}}}


def test_reconcile_updates_only_the_matching_namespace():
    kube = FakeKube()
    resolver.reconcile(kube, lambda _: [{"username": "alice", "enabled": True, "id": "subject-a"}])
    assert len(kube.patches) == 1
    path, body = kube.patches[0]
    assert path == "/api/v1/namespaces/saw-alice/configmaps/saw-owner-subject"
    assert body["data"] == {"subject": "subject-a"}


def test_disabled_account_clears_a_prior_subject():
    kube = FakeKube("subject-old")
    resolver.reconcile(kube, lambda _: [{"username": "alice", "enabled": False, "id": "subject-old"}])
    assert kube.subject == ""


def test_lookup_outage_grants_no_new_subject():
    kube = FakeKube()
    def unavailable(_):
        raise resolver.ApiError(503, "/users")
    resolver.reconcile(kube, unavailable)
    assert len(kube.patches) == 1
    assert "data" not in kube.patches[0][1]
    assert kube.patches[0][1]["metadata"]["annotations"]["saw.redhat.com/owner-resolution"] == "lookup-error"


def test_token_outage_sets_lookup_error(monkeypatch, tmp_path):
    secret = tmp_path / "client-secret"
    secret.write_text("test-value")
    kube = FakeKube()
    def token_unavailable(*_args):
        raise resolver.ApiError(503, "/token")
    def stop_after_one_cycle(_seconds):
        raise StopIteration
    monkeypatch.setattr(resolver, "Kubernetes", lambda: kube)
    monkeypatch.setattr(resolver, "keycloak_token", token_unavailable)
    monkeypatch.setattr(resolver.time, "sleep", stop_after_one_cycle)
    for key, value in {"KC_URL": "https://keycloak.test", "REALM": "test",
                       "CLIENT_ID": "resolver", "SECRET_FILE": str(secret)}.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(StopIteration):
        resolver.run()
    assert kube.subject == ""
    assert kube.patches[0][1]["metadata"]["annotations"]["saw.redhat.com/owner-resolution"] == "lookup-error"


@pytest.mark.parametrize("startup_lookup_error", [False, True], ids=["ca-rotation", "lookup-recovery"])
def test_resolver_recovers_after_ingress_trust_changes(monkeypatch, tmp_path, startup_lookup_error):
    secret = tmp_path / "client-secret"
    secret.write_text("test-value")
    kube = FakeKube()
    contexts = [object(), object()]
    cycle = 0

    def endpoint():
        if startup_lookup_error and cycle == 0:
            raise OSError("ingress metadata temporarily unavailable")
        return "https://keycloak.test", contexts[cycle]

    def request(_url, _method="GET", _body=None, _token=None, form=None, ctx=None):
        if ctx is not contexts[cycle]:
            raise resolver.ssl.SSLCertVerificationError("ingress CA changed")
        if form is not None:
            return {"access_token": "test-token"}
        return [{"username": "alice", "enabled": True, "id": "subject-a"}]

    def next_cycle(_seconds):
        nonlocal cycle
        cycle += 1
        if cycle == 2:
            raise StopIteration
        # A new owner lookup must succeed with the changed ingress trust.
        kube.subject = ""

    monkeypatch.setattr(resolver, "Kubernetes", lambda: kube)
    monkeypatch.setattr(resolver, "keycloak_endpoint", endpoint)
    monkeypatch.setattr(resolver, "request", request)
    monkeypatch.setattr(resolver.time, "sleep", next_cycle)
    for key, value in {"REALM": "test", "CLIENT_ID": "resolver", "SECRET_FILE": str(secret)}.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(StopIteration):
        resolver.run()
    assert kube.subject == "subject-a"


def test_resolver_refuses_plaintext_before_sending_the_admin_credential(monkeypatch):
    sent = []
    monkeypatch.setattr(resolver.urllib.request, "build_opener", lambda *_: sent.append(1))
    with pytest.raises(ValueError, match="HTTPS"):
        resolver.request("http://keycloak.test/realms/master/protocol/openid-connect/token",
                         "POST", form={"username": "admin", "password": "pw"})
    assert sent == []


def test_resolver_discovers_the_operators_https_route(monkeypatch):
    paths = []

    class Kube:
        def call(self, path, method="GET", body=None):
            paths.append(path)
            if path.endswith("/routes"):
                return {"items": [{"metadata": {"name": "sso-ingress"},
                                   "spec": {"host": "sso.apps.example.com",
                                            "to": {"name": "sso-service"},
                                            "tls": {"termination": "edge"}}}]}
            return {"spec": {"domain": "other.example.com"}}

    monkeypatch.delenv("KC_URL", raising=False)
    monkeypatch.delenv("CA_FILE", raising=False)
    monkeypatch.setenv("KEYCLOAK_NAME", "sso")
    monkeypatch.setenv("KEYCLOAK_NAMESPACE", "keycloak")
    monkeypatch.setattr(resolver, "Kubernetes", Kube)
    url, ctx = resolver.keycloak_endpoint()
    assert url == "https://sso.apps.example.com"
    assert ctx.verify_mode == resolver.ssl.CERT_REQUIRED and ctx.check_hostname
    assert paths[0] == "/apis/route.openshift.io/v1/namespaces/keycloak/routes"


def test_kubernetes_requests_use_rotated_service_account_token(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("first-token")
    monkeypatch.setattr(resolver, "SA", str(tmp_path))
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "kubernetes.test")
    monkeypatch.setattr(resolver.ssl, "create_default_context", lambda **_kwargs: object())
    used_tokens = []

    def record_request(_url, _method, _body, token, **_kwargs):
        used_tokens.append(token)
        return {}

    monkeypatch.setattr(resolver, "request", record_request)
    kube = resolver.Kubernetes()
    kube.call("/api/v1/namespaces")
    token_file.write_text("second-token")
    kube.call("/api/v1/namespaces")

    assert used_tokens == ["first-token", "second-token"]
