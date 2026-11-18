"""Shared bootstrap of the built-in Keycloak Admin REST API audience scope.

Canonical source here; ``make catalog`` packages the same module for RHDH.
The caller supplies its existing administrator-authenticated API transport.
This helper neither requests credentials nor grants administrative roles.
"""
from urllib.parse import quote

ADMIN_API_SCOPE = "kc-admin-api"


def ensure_admin_api_scope(call, client_uuid):
    """Assign the existing built-in scope without replacing other defaults.

    Keycloak 26.6.8 requires both this scope and its mapped Admin API audience.
    Older servers do not have the scope: leave their configuration unchanged.
    Lookup/authorization failures propagate; they are never treated as absence.
    ``call`` accepts (method, realm-relative path, optional JSON body).
    """
    scopes = call("GET", "/client-scopes")
    if not isinstance(scopes, list):
        raise RuntimeError("invalid Keycloak client scope response")
    matching = [scope for scope in scopes if scope.get("name") == ADMIN_API_SCOPE]
    if not matching:
        return False
    if (len(matching) != 1 or matching[0].get("protocol") != "openid-connect"
            or not isinstance(matching[0].get("id"), str) or not matching[0]["id"]):
        raise RuntimeError("invalid Keycloak Admin API scope")
    scope_id = matching[0]["id"]
    path = "/clients/" + quote(client_uuid, safe="") + "/default-client-scopes"
    assigned = call("GET", path)
    if not isinstance(assigned, list):
        raise RuntimeError("invalid Keycloak default client scope response")
    if not any(scope.get("id") == scope_id for scope in assigned):
        call("PUT", path + "/" + quote(scope_id, safe=""))
    return True
