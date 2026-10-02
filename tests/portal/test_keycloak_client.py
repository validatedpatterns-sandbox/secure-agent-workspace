"""charts/openshell-rhdh/files/keycloak-client.py: creates or updates RHDH's
OIDC client in the realm (the PostSync job), against a small fake Keycloak."""
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "charts" / "openshell-rhdh" / "files" / "keycloak-client.py"


class FakeKeycloak:
    def __init__(self, clients=None, users=(), groups=()):
        self.clients = list(clients or [])
        self.logins = []
        self.puts = []
        self.users = [{"id": f"u-{n}", "username": n} for n in users]
        self.groups = [{"id": f"g-{n}", "name": n} for n in groups]
        self.default_groups, self.members, self.role_mappings = [], set(), []

    def serve(self):
        kc = self

        class H(BaseHTTPRequestHandler):
            def _reply(self, code, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _body(self):
                return self.rfile.read(int(self.headers.get("Content-Length") or 0))

            def _admin(self):
                return self.headers.get("Authorization") == "Bearer admin-token"

            def do_POST(self):
                url = urlsplit(self.path)
                if url.path == "/realms/master/protocol/openid-connect/token":
                    form = {k: v[0] for k, v in parse_qs(self._body().decode()).items()}
                    kc.logins.append(form)
                    if form.get("password") != "kc-admin-pass":
                        return self._reply(401, {"error": "invalid_grant"})
                    return self._reply(200, {"access_token": "admin-token"})
                if url.path == "/admin/realms/openshell/clients" and self._admin():
                    body = json.loads(self._body())
                    kc.clients.append({"id": f"id-{len(kc.clients)}", **body})
                    return self._reply(201)
                if url.path == "/admin/realms/openshell/groups" and self._admin():
                    name = json.loads(self._body())["name"]
                    kc.groups.append({"id": f"g-{name}", "name": name})
                    return self._reply(201)
                if url.path.startswith("/admin/realms/openshell/users/") and "/role-mappings/clients/" in url.path:
                    kc.role_mappings.append((url.path.split("/")[5], json.loads(self._body())))
                    return self._reply(204)
                self._reply(403)

            def do_GET(self):
                url = urlsplit(self.path)
                q = {k: v[0] for k, v in parse_qs(url.query).items()}
                base = "/admin/realms/openshell"
                if not self._admin():
                    return self._reply(403)
                if url.path == f"{base}/clients":
                    if q.get("clientId") == "realm-management":
                        return self._reply(200, [{"id": "rm", "clientId": "realm-management"}])
                    return self._reply(200, [c for c in kc.clients if c["clientId"] == q.get("clientId")])
                if url.path.endswith("/service-account-user"):
                    return self._reply(200, {"id": "sa-1", "username": "service-account-rhdh"})
                if url.path.startswith(f"{base}/clients/rm/roles/"):
                    name = url.path.rsplit("/", 1)[1]
                    return self._reply(200, {"id": f"role-{name}", "name": name})
                if url.path == f"{base}/groups":
                    return self._reply(200, [g for g in kc.groups if q.get("search") in g["name"]])
                if url.path == f"{base}/users":
                    first, size = int(q.get("first", 0)), int(q.get("max", 100))
                    return self._reply(200, kc.users[first:first + size])
                self._reply(404)

            def do_PUT(self):
                url = urlsplit(self.path)
                if url.path.startswith("/admin/realms/openshell/default-groups/") and self._admin():
                    kc.default_groups.append(url.path.rsplit("/", 1)[1])
                    return self._reply(204)
                if "/groups/" in url.path and url.path.startswith("/admin/realms/openshell/users/"):
                    parts = url.path.split("/")
                    kc.members.add((parts[5], parts[7]))
                    return self._reply(204)
                if url.path.startswith("/admin/realms/openshell/clients/") and self._admin():
                    body = json.loads(self._body())
                    kc.puts.append(body)
                    cid = url.path.rsplit("/", 1)[1]
                    kc.clients = [body if c["id"] == cid else c for c in kc.clients]
                    return self._reply(204)
                self._reply(403)

            def do_DELETE(self):
                url = urlsplit(self.path)
                if "/groups/" in url.path and url.path.startswith("/admin/realms/openshell/users/") \
                        and self._admin():
                    parts = url.path.split("/")
                    kc.members.discard((parts[5], parts[7]))
                    return self._reply(204)
                self._reply(403)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def client(monkeypatch):
    spec = importlib.util.spec_from_file_location("keycloak_client", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # The admin credentials come from the operator's Secret through the
    # Kubernetes API; that read is replaced here.
    servers = []

    def run(kc, secret="rhdh-client-secret", password="kc-admin-pass"):
        monkeypatch.setattr(module, "admin_credentials",
                            lambda: {"username": "kc-admin", "password": password})
        server, url = kc.serve()
        servers.append(server)
        for k, v in {"KC_URL": url, "REALM": "openshell", "CLIENT_ID": "rhdh", "CLIENT_SECRET": secret,
                     "RHDH_URL": "https://rhdh.example.com/", "KC_NAMESPACE": "saw-keycloak",
                     "KC_NAME": "openshell-keycloak"}.items():
            monkeypatch.setenv(k, v)
        return module.main()
    yield run
    for s in servers:
        s.shutdown()


def test_creates_the_confidential_client(client):
    kc = FakeKeycloak()
    assert client(kc) == 0
    (c,) = kc.clients
    assert c["clientId"] == "rhdh" and c["publicClient"] is False
    assert c["secret"] == "rhdh-client-secret"
    assert c["redirectUris"] == ["https://rhdh.example.com/api/auth/oidc/handler/frame"]
    assert c["webOrigins"] == ["https://rhdh.example.com"]
    assert c["standardFlowEnabled"] is True and c["directAccessGrantsEnabled"] is False
    assert kc.logins == [{"grant_type": "password", "client_id": "admin-cli",
                          "username": "kc-admin", "password": "kc-admin-pass"}]


def test_updates_an_existing_client_and_keeps_its_other_attributes(client):
    """A realm that existed before the portal: the client is brought in line
    (secret, redirect), attributes it set itself are kept."""
    kc = FakeKeycloak([{"id": "abc", "clientId": "rhdh", "secret": "old", "publicClient": True,
                        "redirectUris": ["https://old/*"], "attributes": {"pkce.code.challenge.method": "S256"}}])
    assert client(kc) == 0
    (c,) = kc.clients
    assert c["id"] == "abc" and c["secret"] == "rhdh-client-secret" and c["publicClient"] is False
    assert c["redirectUris"] == ["https://rhdh.example.com/api/auth/oidc/handler/frame"]
    assert c["attributes"] == {"pkce.code.challenge.method": "S256",
                               "post.logout.redirect.uris": "https://rhdh.example.com/*"}
    assert client(kc) == 0 and len(kc.clients) == 1          # idempotent


def test_without_a_client_secret_nothing_is_changed(client, capsys):
    kc = FakeKeycloak()
    assert client(kc, secret="") == 1
    assert kc.clients == [] and kc.logins == []
    assert "load it into Vault" in capsys.readouterr().err


def test_wrong_admin_credentials_fail(client):
    """main() lets the HTTP error out; the script's __main__ turns it into
    exit 1 and the Job retries."""
    import urllib.error
    kc = FakeKeycloak()
    with pytest.raises(urllib.error.HTTPError):
        client(kc, password="wrong")
    assert kc.clients == []


def test_with_rbac_every_user_is_in_the_users_group(client, monkeypatch):
    """RHDH RBAC gives role saw-user to group saw-users: the group is the
    realm's default group and holds every existing user; the client's service
    account may read users and groups for RHDH's catalog import."""
    monkeypatch.setenv("USERS_GROUP", "saw-users")
    kc = FakeKeycloak(users=["alice", "bob", "service-account-rhdh"])
    assert client(kc) == 0
    (c,) = kc.clients
    assert c["serviceAccountsEnabled"] is True
    assert kc.groups == [{"id": "g-saw-users", "name": "saw-users"}]
    assert kc.default_groups == ["g-saw-users"]
    assert kc.members == {("u-alice", "g-saw-users"), ("u-bob", "g-saw-users")}
    ((sa, roles),) = kc.role_mappings
    assert sa == "sa-1" and [r["name"] for r in roles] == ["view-users", "query-users", "query-groups"]
    assert client(kc) == 0 and len(kc.groups) == 1                     # idempotent


def test_administrators_are_kept_out_of_the_users_group(client, monkeypatch):
    """RHDH RBAC joins the conditions of all a user's roles: an administrator
    in saw-users would also see the user templates."""
    monkeypatch.setenv("USERS_GROUP", "saw-users")
    monkeypatch.setenv("ADMINS", "admin, ops")
    kc = FakeKeycloak(users=["alice", "admin"])
    kc.members.add(("u-admin", "g-saw-users"))        # joined as a default-group member
    assert client(kc) == 0
    assert kc.members == {("u-alice", "g-saw-users")}
