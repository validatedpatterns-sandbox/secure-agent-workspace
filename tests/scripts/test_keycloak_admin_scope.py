"""Admin API scope migration is shared, additive and fail-closed on lookup errors."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "charts/openshell-keycloak/files/saw_keycloak_admin.py"
spec = importlib.util.spec_from_file_location("keycloak_admin_scope", SOURCE)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
SCOPE = {"id": "scope-admin", "name": "kc-admin-api", "protocol": "openid-connect"}


def test_rhdh_packages_the_same_helper():
    assert SOURCE.read_bytes() == (ROOT / "charts/openshell-rhdh/files/saw_keycloak_admin.py").read_bytes()


def test_scope_migration_is_additive_and_idempotent():
    defaults = [{"id": "profile-id", "name": "profile"}, {"id": "email-id", "name": "email"}]
    writes = []

    def call(method, path, body=None):
        if method == "GET":
            return [SCOPE] if path == "/client-scopes" else defaults
        writes.append((method, path, body))
        defaults.append(SCOPE)

    assert helper.ensure_admin_api_scope(call, "reader-client") is True
    assert helper.ensure_admin_api_scope(call, "reader-client") is True
    assert writes == [("PUT", "/clients/reader-client/default-client-scopes/scope-admin", None)]
    assert [scope["name"] for scope in defaults] == ["profile", "email", "kc-admin-api"]


def test_older_server_without_builtin_scope_is_unchanged():
    calls = []

    def call(method, path, body=None):
        calls.append((method, path))
        return [{"id": "profile-id", "name": "profile", "protocol": "openid-connect"}]

    assert helper.ensure_admin_api_scope(call, "reader-client") is False
    assert calls == [("GET", "/client-scopes")]


@pytest.mark.parametrize("fail_path", ["/client-scopes", "/clients/reader-client/default-client-scopes"])
def test_lookup_failure_never_becomes_a_compatibility_skip(fail_path):
    def call(method, path, body=None):
        if path == fail_path:
            raise PermissionError("lookup denied")
        assert method == "GET"
        return [SCOPE]

    with pytest.raises(PermissionError, match="lookup denied"):
        helper.ensure_admin_api_scope(call, "reader-client")


@pytest.mark.parametrize("scopes", [None, {}, [SCOPE, SCOPE], [{**SCOPE, "protocol": "saml"}],
                                   [{**SCOPE, "id": ""}]])
def test_invalid_or_ambiguous_scope_fails_without_writes(scopes):
    def call(method, path, body=None):
        assert (method, path) == ("GET", "/client-scopes")
        return scopes

    with pytest.raises(RuntimeError, match="invalid Keycloak"):
        helper.ensure_admin_api_scope(call, "reader-client")


def test_relay_credentials_are_not_granted_admin_api_scope():
    # Relay client-credentials tokens go to OpenShell; only its admin-cli
    # bootstrap token calls Keycloak Admin REST. Keep its exact audience.
    relay = (ROOT / "charts/saw-workspace-relay/files/identity.py").read_text()
    assert '"defaultClientScopes":["basic"]' in relay
    assert "ensure_admin_api_scope" not in relay
