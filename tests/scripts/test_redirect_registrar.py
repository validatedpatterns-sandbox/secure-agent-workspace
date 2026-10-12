"""charts/openshell-keycloak/files/redirect-registrar.py: one registrar per
cluster keeps the dashboard client's redirect URIs in step with the SAW web
UI routes. Runs against a small fake Keycloak and a fake Kubernetes API."""
import importlib.util
import json
import os
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "charts" / "openshell-keycloak" / "files" / "redirect-registrar.py"
SUFFIX = ".apps.example.com"
SAW = "openshell.pattern/saw"
LABEL = "saw.redhat.com/oidc-redirect"


@pytest.fixture
def reg():
    spec = importlib.util.spec_from_file_location("redirect_registrar", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeKeycloak:
    """Master admin and client-credentials tokens; the admin API for the
    clients, roles and role mappings the registrar uses."""

    def __init__(self, dashboard_uris=(), dashboard_origins=()):
        self.clients = {
            "c-dash": {"id": "c-dash", "clientId": "openshell-dashboard", "publicClient": True,
                       "redirectUris": list(dashboard_uris), "webOrigins": list(dashboard_origins),
                       "attributes": {"pkce.code.challenge.method": "S256"}},
            "c-rm": {"id": "c-rm", "clientId": "realm-management"},
        }
        self.secrets = {}
        self.mappings = {}       # user id -> [role names]
        self.realm_ready = True
        self.puts, self.role_posts, self.tokens = [], [], []

    def serve(self):
        kc = self

        class H(BaseHTTPRequestHandler):
            def reply(self, code, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n) if n else b""

            def authorized(self):
                return self.headers.get("Authorization", "").startswith("Bearer tok-")

            def do_POST(self):
                url = urlsplit(self.path)
                if url.path.endswith("/protocol/openid-connect/token"):
                    form = {k: v[0] for k, v in parse_qs(self.body().decode()).items()}
                    realm = url.path.split("/")[2]
                    if realm == "master" and form.get("username") == "admin" and form.get("password") == "pw":
                        kc.tokens.append("master")
                        return self.reply(200, {"access_token": "tok-master"})
                    client = next((c for c in kc.clients.values() if c["clientId"] == form.get("client_id")), None)
                    if (realm == "openshell" and form.get("grant_type") == "client_credentials" and client
                            and kc.secrets.get(client["id"]) == form.get("client_secret")):
                        kc.tokens.append(form["client_id"])
                        return self.reply(200, {"access_token": "tok-" + form["client_id"]})
                    return self.reply(401, {"error": "invalid_client"})
                if not self.authorized():
                    return self.reply(401)
                body = json.loads(self.body() or b"null")
                if url.path == "/admin/realms/openshell/clients":
                    cid = f"c-{len(kc.clients)}"
                    kc.clients[cid] = {**body, "id": cid}
                    kc.secrets[cid] = f"secret-{cid}"
                    return self.reply(201)
                if "/role-mappings/clients/c-rm" in url.path:
                    user = url.path.split("/")[5]
                    kc.role_posts.append(user)
                    kc.mappings.setdefault(user, []).extend(r["name"] for r in body)
                    return self.reply(204)
                self.reply(404)

            def do_GET(self):
                url = urlsplit(self.path)
                if not self.authorized():
                    return self.reply(401)
                p = url.path[len("/admin/realms/openshell"):]
                if url.path == "/admin/realms/openshell":
                    return self.reply(200, {"realm": "openshell"}) if kc.realm_ready else self.reply(404)
                if p == "/clients":
                    want = parse_qs(url.query).get("clientId", [None])[0]
                    return self.reply(200, [c for c in kc.clients.values() if c["clientId"] == want])
                parts = p.strip("/").split("/")
                if parts[0] == "clients" and parts[1] in kc.clients:
                    cid = parts[1]
                    if len(parts) == 2:
                        return self.reply(200, kc.clients[cid])
                    if parts[2] == "service-account-user":
                        return self.reply(200, {"id": f"sa-{cid}"})
                    if parts[2] == "client-secret":
                        return self.reply(200, {"type": "secret", "value": kc.secrets[cid]})
                    if parts[2:] == ["roles", "manage-clients"]:
                        return self.reply(200, {"id": "r-mc", "name": "manage-clients"})
                if parts[0] == "users" and parts[2:] == ["role-mappings", "clients", "c-rm"]:
                    return self.reply(200, [{"name": n} for n in kc.mappings.get(parts[1], [])])
                self.reply(404)

            def do_PUT(self):
                url = urlsplit(self.path)
                if not self.authorized():
                    return self.reply(401)
                cid = url.path.rsplit("/", 1)[1]
                body = json.loads(self.body())
                kc.puts.append((self.headers["Authorization"], cid, body))
                kc.clients[cid] = body
                self.reply(204)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}"


class FakeKube:
    def __init__(self, namespaces, routes, domain="apps.example.com"):
        self.namespaces, self.routes, self.domain = namespaces, routes, domain
        self.fail = False

    def get(self, path):
        url = urlsplit(path)
        if self.fail:
            raise OSError("API server unreachable")
        sel = parse_qs(url.query).get("labelSelector", [""])[0]
        if url.path == "/api/v1/namespaces":
            key, _, val = sel.partition("=")
            return {"items": [{"metadata": {"name": n}} for n, labels in self.namespaces.items()
                              if labels.get(key) == val]}
        if url.path == "/apis/route.openshift.io/v1/routes":
            if not sel:
                return {"items": list(self.routes)}
            key, _, val = sel.partition("=")
            return {"items": [r for r in self.routes if (r["metadata"].get("labels") or {}).get(key) == val]}
        if url.path == "/apis/config.openshift.io/v1/ingresses/cluster":
            return {"spec": {"domain": self.domain}}
        raise AssertionError(path)


def route(ns, host, labelled=True, path=None):
    meta = {"name": host.split(".")[0], "namespace": ns, "labels": {LABEL: "true"} if labelled else {}}
    if path:
        meta["annotations"] = {"saw.redhat.com/oidc-redirect-path": path}
    return {"metadata": meta, "spec": {"host": host}}


@pytest.fixture
def world(reg, monkeypatch, tmp_path):
    kc = FakeKeycloak()
    server, url = kc.serve()
    admin = tmp_path / "admin"
    admin.mkdir()
    (admin / "username").write_text("admin\n")
    (admin / "password").write_text("pw\n")
    for k, v in {"KC_URL": url, "REALM": "openshell", "CLIENT_ID": "saw-redirect-registrar",
                 "ADMIN_DIR": str(admin), "OUT": str(tmp_path / "secret"),
                 "SECRET_FILE": str(tmp_path / "secret"), "DASHBOARD_CLIENT_ID": "openshell-dashboard",
                 "NAMESPACE_SELECTOR": f"{SAW}=true", "ROUTE_SELECTOR": f"{LABEL}=true",
                 "HOST_SUFFIX": "", "INTERVAL": "1"}.items():
        monkeypatch.setenv(k, v)
    kube = FakeKube({"saw-alice": {SAW: "true"}, "saw-bob": {SAW: "true"}, "other": {}}, [])
    monkeypatch.setattr(reg, "Kube", lambda: kube)
    yield reg, kc, kube, tmp_path
    server.shutdown()


def dashboard(kc):
    return kc.clients["c-dash"]


# -- bootstrap ---------------------------------------------------------------------------

def test_bootstrap_makes_a_client_that_may_only_manage_the_realms_clients(world):
    reg, kc, _, tmp = world
    reg.bootstrap()
    (client,) = [c for c in kc.clients.values() if c["clientId"] == "saw-redirect-registrar"]
    assert client["serviceAccountsEnabled"] is True and client["publicClient"] is False
    assert client["standardFlowEnabled"] is False and client["directAccessGrantsEnabled"] is False
    assert kc.mappings == {f"sa-{client['id']}": ["manage-clients"]}
    secret = tmp / "secret"
    assert secret.read_text() == kc.secrets[client["id"]]
    assert stat.S_IMODE(os.stat(secret).st_mode) == 0o600


def test_bootstrap_again_changes_nothing_and_restores_settings(world):
    reg, kc, _, _ = world
    reg.bootstrap()
    cid = next(c["id"] for c in kc.clients.values() if c["clientId"] == "saw-redirect-registrar")
    reg.bootstrap()
    assert len(kc.role_posts) == 1 and kc.puts == []
    kc.clients[cid]["standardFlowEnabled"] = True          # someone turned on a login flow
    reg.bootstrap()
    assert kc.clients[cid]["standardFlowEnabled"] is False


def test_bootstrap_waits_for_the_realm(world, monkeypatch):
    reg, kc, _, _ = world
    kc.realm_ready = False
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            kc.realm_ready = True
    monkeypatch.setattr(reg.time, "sleep", sleep)
    reg.bootstrap()
    assert len(sleeps) == 2


# -- run -----------------------------------------------------------------------------------

def test_routes_in_saw_namespaces_are_registered(world):
    reg, kc, kube, _ = world
    reg.bootstrap()
    kube.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX),
                   route("saw-bob", "bob-notebook-ui-saw-bob" + SUFFIX, path="/sso/callback")]
    reg.run(once=True)
    d = dashboard(kc)
    assert d["redirectUris"] == ["https://alice-webui-saw-alice.apps.example.com/oauth2/callback",
                                 "https://bob-notebook-ui-saw-bob.apps.example.com/sso/callback"]
    assert d["webOrigins"] == ["https://alice-webui-saw-alice.apps.example.com",
                               "https://bob-notebook-ui-saw-bob.apps.example.com"]
    assert d["publicClient"] is True and d["attributes"]["pkce.code.challenge.method"] == "S256"
    # As the registrar's own client, never the master admin.
    assert {auth for auth, _, _ in kc.puts} == {"Bearer tok-saw-redirect-registrar"}


@pytest.mark.parametrize("bad", [
    route("other", "evil-other" + SUFFIX),                         # not a SAW namespace
    route("saw-alice", "evil.attacker.net"),                        # not under the cluster domain
    route("saw-alice", "apps.example.com"),                         # the domain itself
    route("saw-alice", "x-saw-alice" + SUFFIX, path="/a/../b"),     # not a plain path
    route("saw-alice", "x-saw-alice" + SUFFIX, path="https://evil.net/cb"),
    route("saw-alice", "x-saw-alice" + SUFFIX, labelled=False),     # not asking
])
def test_other_routes_are_ignored(world, bad):
    reg, kc, kube, _ = world
    reg.bootstrap()
    kube.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX), bad]
    reg.run(once=True)
    assert dashboard(kc)["redirectUris"] == ["https://alice-webui-saw-alice.apps.example.com/oauth2/callback"]


def test_a_removed_route_is_unregistered_and_manual_entries_stay(world):
    reg, kc, kube, _ = world
    reg.bootstrap()
    dashboard(kc)["redirectUris"] = ["http://localhost:4180/oauth2/callback"]
    kube.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX),
                   route("saw-bob", "bob-webui-saw-bob" + SUFFIX)]
    reg.run(once=True)
    kube.routes = kube.routes[:1]
    reg.run(once=True)
    assert dashboard(kc)["redirectUris"] == ["http://localhost:4180/oauth2/callback",
                                             "https://alice-webui-saw-alice.apps.example.com/oauth2/callback"]
    assert dashboard(kc)["webOrigins"] == ["https://alice-webui-saw-alice.apps.example.com"]


def test_the_first_run_adopts_what_the_per_vm_jobs_registered(world):
    """Before the registrar, each prepare Job added its own URIs and nothing
    removed them. The first run takes over the ones under the cluster domain,
    so those of VMs that are gone are removed; others stay."""
    reg, kc, kube, _ = world
    reg.bootstrap()
    d = dashboard(kc)
    d["redirectUris"] = ["https://old-webui-saw-old.apps.example.com/oauth2/callback",
                         "https://alice-webui-saw-alice.apps.example.com/oauth2/callback",
                         "https://elsewhere.example.net/oauth2/callback"]
    d["webOrigins"] = ["https://old-webui-saw-old.apps.example.com", "https://elsewhere.example.net"]
    kube.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX)]
    reg.run(once=True)
    assert dashboard(kc)["redirectUris"] == ["https://alice-webui-saw-alice.apps.example.com/oauth2/callback",
                                             "https://elsewhere.example.net/oauth2/callback"]
    assert dashboard(kc)["webOrigins"] == ["https://alice-webui-saw-alice.apps.example.com",
                                           "https://elsewhere.example.net"]


def test_nothing_changes_nothing_is_written(world):
    reg, kc, kube, _ = world
    reg.bootstrap()
    kube.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX)]
    reg.run(once=True)
    reg.run(once=True)
    assert len(kc.puts) == 1


def test_a_failed_route_list_removes_nothing(world):
    reg, kc, kube, _ = world
    reg.bootstrap()
    kube.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX)]
    reg.run(once=True)
    kube.fail = True
    with pytest.raises(OSError):
        reg.run(once=True)
    assert dashboard(kc)["redirectUris"] == ["https://alice-webui-saw-alice.apps.example.com/oauth2/callback"]
    assert len(kc.puts) == 1


def test_the_suffix_can_be_set(world, monkeypatch):
    reg, kc, kube, _ = world
    reg.bootstrap()
    monkeypatch.setenv("HOST_SUFFIX", "ui.example.org")
    kube.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX),
                   route("saw-alice", "alice.ui.example.org")]
    reg.run(once=True)
    assert dashboard(kc)["redirectUris"] == ["https://alice.ui.example.org/oauth2/callback"]


def test_without_its_secret_the_registrar_cannot_write(world, tmp_path):
    reg, kc, kube, tmp = world
    reg.bootstrap()
    (tmp / "secret").write_text("wrong")
    kube.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX)]
    with pytest.raises(reg.HttpError):
        reg.run(once=True)
    assert kc.puts == []


def test_a_rollout_keeps_the_entries_of_routes_not_yet_labelled(world):
    """Found live: the registrar came up before the SAW apps relabelled
    their routes, adopted the Jobs' entries, and removed them all, so users
    could not sign in until their app synced. Entries go only when their
    route does."""
    reg, kc, kube, _ = world
    reg.bootstrap()
    alice = "https://alice-webui-saw-alice.apps.example.com"
    d = dashboard(kc)
    d["redirectUris"] = [alice + "/oauth2/callback",
                         "https://dave-webui-saw-dave.apps.example.com/oauth2/callback"]   # dave is gone
    d["webOrigins"] = [alice]
    kube.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX, labelled=False)]
    reg.run(once=True)
    assert dashboard(kc)["redirectUris"] == [alice + "/oauth2/callback"]
    assert dashboard(kc)["webOrigins"] == [alice]
    kube.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX)]       # alice's app synced
    reg.run(once=True)
    assert dashboard(kc)["redirectUris"] == [alice + "/oauth2/callback"]
    kube.routes = []                                                            # alice removed
    reg.run(once=True)
    assert dashboard(kc)["redirectUris"] == [] and dashboard(kc)["webOrigins"] == []


def test_an_unlabelled_route_elsewhere_keeps_nothing(world):
    """Only routes in SAW namespaces count as still in use."""
    reg, kc, kube, _ = world
    reg.bootstrap()
    dashboard(kc)["redirectUris"] = ["https://evil-other.apps.example.com/oauth2/callback"]
    kube.routes = [route("other", "evil-other" + SUFFIX, labelled=False)]
    reg.run(once=True)
    assert dashboard(kc)["redirectUris"] == []

def test_an_entry_removed_by_hand_is_not_put_back(world):
    reg, kc, kube, _ = world
    reg.bootstrap()
    kube.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX)]
    reg.run(once=True)
    kube.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX, labelled=False)]
    dashboard(kc)["redirectUris"] = []
    reg.run(once=True)
    assert dashboard(kc)["redirectUris"] == []
