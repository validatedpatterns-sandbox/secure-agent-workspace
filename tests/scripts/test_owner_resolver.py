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
