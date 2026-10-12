"""scripts/keycloak-redirects.py: an administrator registers the SAW web UIs'
redirect URIs on Keycloak's dashboard client (make keycloak-register,
make keycloak-redirects-sync). Runs against a small fake Keycloak and a fake
oc."""
import base64
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "keycloak-redirects.py"
SUFFIX = ".apps.example.com"
SAW = "openshell.pattern/saw"
LABEL = "saw.redhat.com/oidc-redirect"


class FakeKeycloak:
    """The master admin's token, and the admin API for the dashboard client."""

    def __init__(self):
        self.client = {"id": "c-dash", "clientId": "openshell-dashboard", "publicClient": True,
                       "redirectUris": [], "webOrigins": [],
                       "attributes": {"pkce.code.challenge.method": "S256"}}
        self.puts, self.logins = [], []

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

            def do_POST(self):
                if self.path == "/realms/master/protocol/openid-connect/token":
                    form = {k: v[0] for k, v in parse_qs(self.body().decode()).items()}
                    kc.logins.append(form)
                    if form.get("username") == "admin" and form.get("password") == "pw":
                        return self.reply(200, {"access_token": "tok"})
                    return self.reply(401, {"error": "invalid_grant"})
                self.reply(404)

            def do_GET(self):
                if self.headers.get("Authorization") != "Bearer tok":
                    return self.reply(401)
                url = urlsplit(self.path)
                if url.path == "/admin/realms/openshell/clients":
                    want = parse_qs(url.query).get("clientId", [None])[0]
                    return self.reply(200, [kc.client] if want == kc.client["clientId"] else [])
                if url.path == "/admin/realms/openshell/clients/c-dash":
                    return self.reply(200, kc.client)
                self.reply(404)

            def do_PUT(self):
                if self.headers.get("Authorization") != "Bearer tok":
                    return self.reply(401)
                body = json.loads(self.body())
                kc.puts.append(body)
                kc.client = body
                self.reply(204)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}"


def route(ns, host, labelled=True, path=None):
    meta = {"name": host.split(".")[0], "namespace": ns, "labels": {LABEL: "true"} if labelled else {}}
    if path:
        meta["annotations"] = {"saw.redhat.com/oidc-redirect-path": path}
    return {"metadata": meta, "spec": {"host": host}}


class FakeOc:
    def __init__(self, url):
        self.url = url
        self.namespaces = {"saw-alice": {SAW: "true"}, "saw-bob": {SAW: "true"}, "other": {}}
        self.routes = []
        self.calls = []
        self.keycloak_cr = {"status": {"externalURL": url}}
        self.keycloak_routes = []

    def __call__(self, *args):
        self.calls.append(args)
        if args[:2] == ("get", "namespaces"):
            key, _, val = args[args.index("-l") + 1].partition("=")
            return {"items": [{"metadata": {"name": n}} for n, labels in self.namespaces.items()
                              if labels.get(key) == val]}
        if args[:2] == ("get", "routes") and "-n" in args:
            ns = args[args.index("-n") + 1]
            items = [r for r in self.keycloak_routes if r["metadata"]["namespace"] == ns]
            if "-l" in args:
                key, _, val = args[args.index("-l") + 1].partition("=")
                items = [r for r in items if (r["metadata"].get("labels") or {}).get(key) == val]
            return {"items": items}
        if args[:2] == ("get", "routes"):
            return {"items": list(self.routes)}
        if args[:2] == ("get", "ingresses.config.openshift.io"):
            return {"spec": {"domain": "apps.example.com"}}
        if args[:2] == ("get", "keycloak"):
            return self.keycloak_cr
        if args[:2] == ("get", "secret"):
            assert args[2] == "openshell-keycloak-initial-admin" and args[4] == "saw-keycloak"
            return {"data": {"username": base64.b64encode(b"admin").decode(),
                             "password": base64.b64encode(b"pw").decode()}}
        raise AssertionError(args)


@pytest.fixture
def world(monkeypatch):
    spec = importlib.util.spec_from_file_location("keycloak_redirects", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    kc = FakeKeycloak()
    server, url = kc.serve()
    oc = FakeOc(url)
    monkeypatch.setattr(mod, "oc_json", oc)
    for k in ("HOST_SUFFIX", "WAIT", "KEYCLOAK_CA", "KEYCLOAK_INSECURE"):
        monkeypatch.delenv(k, raising=False)
    yield mod, kc, oc
    server.shutdown()


ALICE = "https://alice-webui-saw-alice.apps.example.com"
ALICE_UI = "https://alice-default-notebook-ui.apps.example.com"
BOB = "https://bob-webui-saw-bob.apps.example.com"


def test_register_adds_one_users_web_uis(world, capsys):
    mod, kc, oc = world
    oc.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX),
                 route("saw-alice", "alice-default-notebook-ui" + SUFFIX),
                 route("saw-bob", "bob-webui-saw-bob" + SUFFIX)]
    assert mod.main(["x", "register", "alice"]) == 0
    assert kc.client["redirectUris"] == [ALICE_UI + "/oauth2/callback", ALICE + "/oauth2/callback"]
    assert kc.client["webOrigins"] == [ALICE_UI, ALICE]
    assert kc.client["publicClient"] is True and kc.client["attributes"]["pkce.code.challenge.method"] == "S256"
    assert "added    " + ALICE + "/oauth2/callback" in capsys.readouterr().out
    # As Keycloak's admin, from the admin's own oc session: nothing in the cluster does it.
    assert kc.logins == [{"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "pw"}]
    assert mod.main(["x", "register", "alice"]) == 0
    assert len(kc.puts) == 1, "registering again changes nothing"


def test_register_keeps_what_is_there(world):
    mod, kc, oc = world
    kc.client["redirectUris"] = ["http://localhost:4180/oauth2/callback", BOB + "/oauth2/callback"]
    oc.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX)]
    assert mod.main(["x", "register", "alice"]) == 0
    assert kc.client["redirectUris"] == ["http://localhost:4180/oauth2/callback",
                                         ALICE + "/oauth2/callback", BOB + "/oauth2/callback"]


def test_register_waits_for_the_routes(world):
    mod, kc, oc = world
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            oc.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX)]
    assert mod.cmd_register("alice", wait=600, sleep=sleep) == 0
    assert len(sleeps) == 2 and kc.client["redirectUris"] == [ALICE + "/oauth2/callback"]


def test_register_gives_up_and_says_why(world, capsys):
    mod, kc, oc = world
    clock = iter([0, 0, 700])
    with pytest.raises(mod.Error, match="saw-carol is not a SAW namespace yet"):
        mod.cmd_register("carol", wait=600, sleep=lambda s: None, clock=lambda: next(clock))
    assert kc.puts == [] and kc.logins == []
    assert mod.main(["x", "register", "Not-A-User"]) == 1
    assert "is not a SAW user name" in capsys.readouterr().err


@pytest.mark.parametrize("bad", [
    route("other", "evil-other" + SUFFIX),                         # not a SAW namespace
    route("saw-alice", "evil.attacker.net"),                        # not under the cluster domain
    route("saw-alice", "x-saw-alice" + SUFFIX, path="/a/../b"),     # not a plain path
    route("saw-alice", "x-saw-alice" + SUFFIX, labelled=False),     # not a web UI route
])
def test_other_routes_are_never_registered(world, bad):
    mod, kc, oc = world
    oc.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX), bad]
    assert mod.main(["x", "sync"]) == 0
    assert kc.client["redirectUris"] == [ALICE + "/oauth2/callback"]


def test_sync_removes_what_it_added_once_the_route_is_gone(world):
    mod, kc, oc = world
    kc.client["redirectUris"] = ["http://localhost:4180/oauth2/callback"]
    oc.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX),
                 route("saw-bob", "bob-webui-saw-bob" + SUFFIX)]
    assert mod.main(["x", "sync"]) == 0
    oc.routes = oc.routes[:1]                                         # bob's workspace deleted
    assert mod.main(["x", "sync"]) == 0
    assert kc.client["redirectUris"] == ["http://localhost:4180/oauth2/callback", ALICE + "/oauth2/callback"]
    assert kc.client["webOrigins"] == [ALICE]


def test_the_first_sync_adopts_the_old_per_vm_entries(world):
    """The prepare Jobs added entries and never removed them: the first sync
    takes over those under the cluster domain, so removed workspaces' go,
    while a route that is still there (not labelled yet) keeps its entry."""
    mod, kc, oc = world
    kc.client["redirectUris"] = [ALICE + "/oauth2/callback",
                                 "https://dave-webui-saw-dave.apps.example.com/oauth2/callback",
                                 "https://elsewhere.example.net/oauth2/callback"]
    kc.client["webOrigins"] = [ALICE, "https://dave-webui-saw-dave.apps.example.com"]
    oc.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX, labelled=False)]
    assert mod.main(["x", "sync"]) == 0
    assert kc.client["redirectUris"] == [ALICE + "/oauth2/callback", "https://elsewhere.example.net/oauth2/callback"]
    assert kc.client["webOrigins"] == [ALICE]
    oc.routes = []
    assert mod.main(["x", "sync"]) == 0
    assert kc.client["redirectUris"] == ["https://elsewhere.example.net/oauth2/callback"]


def test_register_then_sync_cleans_up_after_deletion(world):
    mod, kc, oc = world
    oc.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX)]
    assert mod.main(["x", "register", "alice"]) == 0
    oc.routes = []
    assert mod.main(["x", "sync"]) == 0
    assert kc.client["redirectUris"] == [] and kc.client["webOrigins"] == []


def test_an_entry_removed_by_hand_is_not_put_back_by_sync(world):
    mod, kc, oc = world
    oc.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX)]
    assert mod.main(["x", "sync"]) == 0
    oc.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX, labelled=False)]
    kc.client["redirectUris"] = []
    assert mod.main(["x", "sync"]) == 0
    assert kc.client["redirectUris"] == []


def test_list_shows_what_is_missing(world, capsys):
    mod, kc, oc = world
    kc.client["redirectUris"] = [BOB + "/oauth2/callback"]
    oc.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX)]
    assert mod.main(["x", "list"]) == 1
    out = capsys.readouterr().out
    assert BOB + "/oauth2/callback   (no route any more)" in out
    assert "SAW web UI routes without a redirect URI:\n  " + ALICE + "/oauth2/callback" in out
    assert kc.puts == []


def test_keycloak_errors_are_reported_not_raised(world, capsys):
    mod, kc, oc = world
    oc.routes = [route("saw-alice", "alice-webui-saw-alice" + SUFFIX)]
    kc.client["clientId"] = "renamed"
    assert mod.main(["x", "sync"]) == 1
    assert "client openshell-dashboard not found" in capsys.readouterr().err


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("current, managed, want, present", [
    ([], None, {ALICE}, set()),                                                      # first registration
    ([ALICE, "https://dave-webui-saw-dave.apps.example.com"], None, set(),
     {"alice-webui-saw-alice.apps.example.com"}),                                     # adoption during a rollout
    ([ALICE, "http://localhost:4180"], [ALICE], set(), set()),                        # route gone
    ([ALICE, BOB], [ALICE, BOB], {ALICE}, {"bob-webui-saw-bob.apps.example.com"}),   # unlabelled, still there
    ([], [ALICE], set(), {"alice-webui-saw-alice.apps.example.com"}),                # removed by hand
])
def test_the_optional_registrar_follows_the_same_rules_as_sync(current, managed, want, present):
    """The in-cluster registrar (redirectRegistrar.enabled) ships its own copy
    of the rules, inside the chart: it must decide exactly what sync does."""
    script = _load(SCRIPT, "keycloak_redirects_rules")
    registrar = _load(ROOT / "charts" / "openshell-keycloak" / "files" / "redirect-registrar.py", "registrar_rules")
    uris = {u + "/oauth2/callback" for u in want}
    client = {"id": "c", "redirectUris": [u + "/oauth2/callback" for u in current], "webOrigins": list(current)}
    if managed is not None:
        client["attributes"] = {script.MANAGED_ATTRIBUTE: json.dumps(
            {"redirectUris": [u + "/oauth2/callback" for u in managed], "webOrigins": managed})}
    assert script.MANAGED_ATTRIBUTE == registrar.MANAGED_ATTRIBUTE
    assert (script.reconcile(client, uris, set(want), SUFFIX, present, prune=True)
            == registrar.reconcile(client, uris, set(want), SUFFIX, present))


def test_keycloak_is_found_without_status_external_url(world):
    """Found live: the Keycloak CR had no status.externalURL, and every
    command failed. Same fallbacks as scripts/keycloak-host.sh."""
    mod, kc, oc = world
    url = oc.url
    oc.keycloak_cr = {"status": {}}
    oc.keycloak_routes = [{"metadata": {"namespace": "saw-keycloak", "name": "other"}, "spec": {"host": "other.example.com"}},
                          {"metadata": {"namespace": "saw-keycloak", "name": "kc", "labels": {"app": "keycloak"}},
                           "spec": {"host": "openshell-keycloak-ingress-saw-keycloak.apps.example.com"}}]
    assert mod.keycloak_url("saw-keycloak", "openshell-keycloak") == \
        "https://openshell-keycloak-ingress-saw-keycloak.apps.example.com"
    oc.keycloak_cr = {"spec": {"hostname": {"hostname": "https://sso.example.com/"}}}
    assert mod.keycloak_url("saw-keycloak", "openshell-keycloak") == "https://sso.example.com"
    oc.keycloak_cr = {}
    oc.keycloak_routes = [oc.keycloak_routes[0]]                     # one unlabelled route: it
    assert mod.keycloak_url("saw-keycloak", "openshell-keycloak") == "https://other.example.com"
    oc.keycloak_routes = []
    with pytest.raises(mod.Error, match="no URL for Keycloak saw-keycloak/openshell-keycloak"):
        mod.keycloak_url("saw-keycloak", "openshell-keycloak")
    oc.keycloak_cr = {"status": {"externalURL": url + "/"}}
    assert mod.keycloak_url("saw-keycloak", "openshell-keycloak") == url
