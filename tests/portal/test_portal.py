"""The self-service portal's pipeline and plugin generator (charts/openshell-rhdh/files/portal.py).

Runs portal.py against small fake Kubernetes and Vault HTTP servers, with
Backstage tokens signed by a throwaway P-256 key.
"""
import base64
import importlib.util
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
PORTAL = ROOT / "charts" / "openshell-rhdh" / "files" / "portal.py"
CATALOG = ROOT / "charts" / "openshell-rhdh" / "files" / "profile-catalog.json"

from cryptography.hazmat.primitives import hashes  # noqa: E402  (tests/requirements.txt)
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402


@pytest.fixture(scope="module")
def portal():
    spec = importlib.util.spec_from_file_location("portal", PORTAL)
    module = importlib.util.module_from_spec(spec)
    sys.modules["portal"] = module
    spec.loader.exec_module(module)
    return module


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Signer:
    def __init__(self, kid="k1"):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid = kid

    def jwks(self):
        nums = self.key.public_key().public_numbers()
        return {"keys": [{"kty": "EC", "crv": "P-256", "kid": self.kid,
                          "x": b64u(nums.x.to_bytes(32, "big")), "y": b64u(nums.y.to_bytes(32, "big"))}]}

    def sign(self, header, payload):
        h = b64u(json.dumps({"kid": self.kid, **header}).encode())
        pl = b64u(json.dumps(payload).encode())
        der = self.key.sign(f"{h}.{pl}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return f"{h}.{pl}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def token(self, sub="user:default/alice", exp=None, alg="ES256"):
        """A full user token (older backends), signed by the auth backend."""
        return self.sign({"alg": alg, "typ": "vnd.backstage.user"},
                         {"sub": sub, "iss": "https://rhdh.example.com/api/auth", "aud": "backstage",
                          "exp": exp or int(time.time()) + 600})

    def limited(self, sub="user:default/alice", exp=None):
        """A limited user token: {sub, iat, exp} only (UserTokenHandler)."""
        now = int(time.time())
        return self.sign({"alg": "ES256", "typ": "vnd.backstage.limited-user"},
                         {"sub": sub, "iat": now, "exp": exp or now + 600})


def plugin_token(scaffolder, obo, sub="scaffolder", aud="catalog"):
    """What the new backend's scaffolder puts in secrets.backstageToken: a
    plugin token signed by the scaffolder, acting on behalf of the user."""
    now = int(time.time())
    return scaffolder.sign({"alg": "ES256", "typ": "vnd.backstage.plugin"},
                           {"sub": sub, "aud": aud, "iat": now, "exp": now + 600, "obo": obo})


# -- token verification (pure-Python ES256) -------------------------------------------

def test_a_full_user_token_names_its_user(portal):
    signer = Signer()
    assert portal.verify_backstage_token(signer.token(), signer.jwks()) == "alice"


def test_the_scaffolders_plugin_token_names_the_user_it_acts_for(portal):
    auth, scaffolder = Signer("auth"), Signer("scaffolder")
    token = plugin_token(scaffolder, auth.limited())
    assert portal.verify_backstage_token(token, auth.jwks(), scaffolder.jwks()) == "alice"


@pytest.mark.parametrize("make, message", [
    (lambda auth, sc: plugin_token(Signer("x"), auth.limited()), "scaffolder token: its signing key"),
    (lambda auth, sc: plugin_token(sc, Signer("auth").limited()), "user token: the signature"),
    (lambda auth, sc: plugin_token(sc, auth.limited(), sub="catalog"), "not the scaffolder"),
    (lambda auth, sc: plugin_token(sc, auth.limited(), aud="scaffolder"), "not the scaffolder"),
    (lambda auth, sc: plugin_token(sc, ""), "does not act for a user"),
    (lambda auth, sc: plugin_token(sc, auth.limited(sub="group:default/admins")), "not for a user"),
    (lambda auth, sc: plugin_token(sc, auth.limited(exp=int(time.time()) - 5)), "expired"),
])
def test_bad_plugin_tokens_are_refused(portal, make, message):
    auth, scaffolder = Signer("auth"), Signer("scaffolder")
    with pytest.raises(portal.PortalError, match=message):
        portal.verify_backstage_token(make(auth, scaffolder), auth.jwks(), scaffolder.jwks())


@pytest.mark.parametrize("mutate, message", [
    (lambda s: s.token(exp=int(time.time()) - 5), "expired"),
    (lambda s: s.token(sub="user:default/bob")[:-4] + "AAAA", "signature is not valid"),
    (lambda s: s.token(sub="group:default/admins"), "not for a user"),
    (lambda s: s.token(alg="HS256"), "unsupported algorithm"),
    (lambda s: "not-a-jwt", "not a JWT"),
])
def test_bad_tokens_are_refused(portal, mutate, message):
    signer = Signer()
    with pytest.raises(portal.PortalError, match=message):
        portal.verify_backstage_token(mutate(signer), signer.jwks())


def test_a_token_from_another_key_is_refused(portal):
    signer, other = Signer(), Signer()
    with pytest.raises(portal.PortalError, match="signature is not valid"):
        portal.verify_backstage_token(other.token(), signer.jwks())


def test_a_payload_edited_after_signing_is_refused(portal):
    """Changing sub to someone else breaks the signature."""
    signer = Signer()
    header, _, sig = signer.token().split(".")
    forged = b64u(json.dumps({"sub": "user:default/bob", "exp": int(time.time()) + 600}).encode())
    # (same header, same signature, another user)
    with pytest.raises(portal.PortalError, match="signature is not valid"):
        portal.verify_backstage_token(f"{header}.{forged}.{sig}", signer.jwks())


# -- the form -------------------------------------------------------------------------

@pytest.fixture(scope="module")
def catalog(portal):
    return portal.load_catalog(CATALOG)


def test_a_request_gets_the_profiles_secrets(portal, catalog):
    profile, secrets = portal.parse_request({
        "profile": "data-science", "inference.api_key": " nvapi-1 ", "web-search.api_key": "brave-1",
        "inference.url": "https://ignored/v1"}, catalog)
    assert profile == "data-science"
    assert secrets == {"inference": {"api_key": "nvapi-1", "provider": "nvidia"},
                       "web-search": {"api_key": "brave-1", "provider": "brave"}}


def test_missing_fields_are_named(portal, catalog):
    with pytest.raises(portal.PortalError, match="needs: inference.api_key, inference.url, inference.model"):
        portal.parse_request({"profile": "custom-inference", "web-search.api_key": "b"}, catalog)


def test_a_url_with_credentials_is_refused(portal, catalog):
    with pytest.raises(portal.PortalError, match="must be an http"):
        portal.parse_request({"profile": "custom-inference", "inference.api_key": "k",
                              "inference.url": "https://user:pw@vllm/v1", "inference.model": "m",
                              "web-search.api_key": "b"}, catalog)


def test_an_unknown_profile_is_refused(portal, catalog):
    with pytest.raises(portal.PortalError, match="unknown profile"):
        portal.parse_request({"profile": "nope"}, catalog)


@pytest.mark.parametrize("user", ["Alice", "a.b", "x" * 20, "", "alice-bom", "alice-secrets"])
def test_user_names_must_name_a_vm(portal, user):
    with pytest.raises(portal.PortalError, match="cannot name a workspace"):
        portal.check_user(user)


# -- generator and catalog entities -----------------------------------------------------

def test_generator_params_are_one_user_saw_users_values(portal):
    defaults = {"global": {"repoURL": "r"}, "namespaceLabels": {"saw.redhat.com/portal": "true"}}
    ws = {"name": "alice", "profiles": ["data-science"], "vaultPrefix": "secret/data/hub/saw-alice"}
    [params] = portal.generator_params([ws], defaults)
    assert params["name"] == "alice"
    assert json.loads(params["values"]) == {**defaults, "users": [ws]}


def entity_docs(text):
    return [json.loads(part) for part in text.split("\n---\n")]


def the_workspace(text):
    (entity,) = [d for d in entity_docs(text)
                 if d["kind"] == "Component" and d["spec"]["type"] == "agent-workspace"]
    return entity


def test_entities_link_the_web_uis(portal, catalog):
    text = portal.entities_yaml([{"name": "alice", "profiles": ["data-science"]}], catalog,
                                "example.com", "https://rhdh.example.com")
    entity = the_workspace(text)
    assert entity["spec"]["owner"] == "user:default/alice"
    urls = [link["url"] for link in entity["metadata"]["links"]]
    assert "https://alice-webui-saw-alice.apps.example.com" in urls
    assert "https://alice-default-notebook-ui.apps.example.com" in urls


def test_no_workspaces_is_still_a_valid_location(portal, catalog):
    docs = entity_docs(portal.entities_yaml([], catalog, "example.com", ""))
    assert [d["kind"] for d in docs] == ["Group", "Component"] and docs[0]["spec"]["members"] == []


def test_users_without_a_workspace_get_a_get_started_card(portal, catalog):
    """RHDH's empty Workspaces section links to /catalog-import, which the
    portal does not offer; this card, shown only to saw-without-workspace,
    links to the create action instead."""
    docs = entity_docs(portal.entities_yaml([], catalog, "example.com", "https://rhdh.example.com"))
    (card,) = [d for d in docs if d["metadata"]["name"] == "saw-get-started"]
    assert card["metadata"]["labels"] == {"saw.redhat.com/new-users": "true"}
    assert card["spec"]["owner"] == "group:default/saw-without-workspace"
    assert [l["url"] for l in card["metadata"]["links"]] == \
        ["https://rhdh.example.com/create/templates/default/create-saw-workspace"]


def test_users_see_create_or_delete_by_group(portal, catalog, monkeypatch):
    """Group saw-workspace-owners (delete) and saw-without-workspace (create),
    which RHDH RBAC uses so each user sees the action that applies."""
    text = portal.entities_yaml([{"name": "alice", "profiles": ["data-science"]}], catalog, "example.com",
                                "https://rhdh.example.com", users=["alice", "bob", "carol"])
    groups = {d["metadata"]["name"]: d["spec"]["members"] for d in entity_docs(text) if d["kind"] == "Group"}
    assert groups == {"saw-workspace-owners": ["alice"], "saw-without-workspace": ["bob", "carol"]}
    delete = [l["url"] for l in the_workspace(text)["metadata"]["links"] if l["title"] == "Delete workspace"]
    assert delete == ["https://rhdh.example.com/create/templates/default/delete-saw-workspace"
                      "?formData=%7B%22workspace%22%3A%22component%3Adefault/saw-alice%22%7D"]
    # administrators are in neither group: RBAC would join the user roles'
    # conditions to theirs and show them the user templates
    monkeypatch.setenv("PORTAL_ADMINS", "admin")
    text = portal.entities_yaml([{"name": "admin", "profiles": ["data-science"]}], catalog, "example.com",
                                "", users=["alice", "admin"])
    groups = {d["metadata"]["name"]: d["spec"]["members"] for d in entity_docs(text) if d["kind"] == "Group"}
    assert groups == {"saw-workspace-owners": [], "saw-without-workspace": ["alice"]}
    # users unknown (Keycloak unreachable at the first read): no create group at all
    text = portal.entities_yaml([], catalog, "example.com", "", users=None)
    assert [d["metadata"]["name"] for d in entity_docs(text)] == ["saw-workspace-owners", "saw-get-started"]


# -- end to end against fake Kubernetes and Vault -------------------------------------

class Fake:
    """A tiny Kubernetes (secrets, configmaps, namespaces) and Vault."""

    def __init__(self):
        self.objects = {}      # path -> object
        self.rv = 0            # last resourceVersion handed out
        self.deleted = []
        self.vault = {}        # kv path -> data
        self.logins = []
        self.logs = {}         # pod log path -> text

    def serve(self):
        fake = self

        class H(BaseHTTPRequestHandler):
            def _reply(self, code, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n)) if n else None

            def do_GET(self):
                url = urlsplit(self.path)
                if url.path in fake.logs:
                    raw = fake.logs[url.path].encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    return self.wfile.write(raw)
                if "labelSelector" in url.query:
                    sel = parse_qs(url.query)["labelSelector"][0].split("=")
                    items = [o for p, o in fake.objects.items() if p.startswith(url.path + "/")
                             and (o["metadata"].get("labels") or {}).get(sel[0]) == sel[1]]
                    return self._reply(200, {"items": items})
                obj = fake.objects.get(url.path)
                self._reply(200, obj) if obj else self._reply(404, {"reason": "NotFound"})

            def do_POST(self):
                body = self._body()
                if self.path.startswith("/v1/auth/"):
                    fake.logins.append(body)
                    return self._reply(200, {"auth": {"client_token": "vault-token"}})
                if self.path.startswith("/v1/secret/data/"):
                    assert self.headers["X-Vault-Token"] == "vault-token"
                    fake.vault[self.path[len("/v1/secret/data/"):]] = body["data"]
                    return self._reply(200, {})
                path = f"{self.path}/{body['metadata']['name']}"
                if path in fake.objects:
                    return self._reply(409, {"reason": "AlreadyExists"})
                fake.rv += 1
                body.setdefault("metadata", {})["resourceVersion"] = str(fake.rv)
                fake.objects[path] = body
                self._reply(201, body)

            def do_PUT(self):
                body = self._body()
                want = (body.get("metadata") or {}).get("resourceVersion")
                have = ((fake.objects.get(self.path) or {}).get("metadata") or {}).get("resourceVersion")
                if want and want != have:
                    return self._reply(409, {"reason": "Conflict"})
                fake.rv += 1
                body.setdefault("metadata", {})["resourceVersion"] = str(fake.rv)
                fake.objects[self.path] = body
                self._reply(200, fake.objects[self.path])

            def do_DELETE(self):
                if self.path.startswith("/v1/secret/metadata/"):
                    fake.vault.pop(self.path[len("/v1/secret/metadata/"):], None)
                    return self._reply(204)
                fake.deleted.append(self.path)
                self._reply(200 if fake.objects.pop(self.path, None) else 404, {})

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}"

    def request(self, name, data, age=0, labels=None):
        created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - age))
        self.objects[f"/api/v1/namespaces/saw-portal/secrets/{name}"] = {
            "metadata": {"name": name, "labels": {"saw.redhat.com/request": "true"} if labels is None else labels,
                         "creationTimestamp": created},
            "data": {k: base64.b64encode(v.encode()).decode() for k, v in data.items()}}


@pytest.fixture
def world(portal, monkeypatch, tmp_path):
    fake = Fake()
    server, url = fake.serve()
    auth, scaffolder = Signer("auth"), Signer("scaffolder")
    sa = tmp_path / "sa"
    sa.mkdir()
    (sa / "token").write_text("pod-sa-token")
    monkeypatch.setattr(portal, "SA_DIR", str(sa))
    monkeypatch.setattr(portal, "kube", lambda: portal.Http(url, "k8s-token"))
    monkeypatch.setattr(portal, "fetch_json", lambda u, insecure=False:
                        scaffolder.jwks() if "/api/scaffolder/" in u else auth.jwks())
    for k, v in {"NAMESPACE": "saw-portal", "CATALOG_PATH": str(CATALOG), "RHDH_INTERNAL_URL": "http://rhdh",
                 "ARGO_NAMESPACE": "vp-gitops",
                 "VAULT_ADDR": url, "VAULT_AUTH_MOUNT": "hub", "VAULT_ROLE": "saw-portal-writer",
                 "VAULT_KV_MOUNT": "secret", "VAULT_PREFIX_BASE": "hub"}.items():
        monkeypatch.setenv(k, v)
    yield fake, Tokens(auth, scaffolder)
    server.shutdown()


class Tokens:
    def __init__(self, auth, scaffolder):
        self.auth, self.scaffolder = auth, scaffolder

    def token(self, sub="user:default/alice"):
        return plugin_token(self.scaffolder, self.auth.limited(sub=sub))


def ds_request(signer, **extra):
    return {"action": "create", "token": signer.token(), "profile": "data-science",
            "inference.api_key": "nvapi-1", "web-search.api_key": "brave-1", **extra}


def test_create_writes_vault_and_the_registry(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 0
    assert fake.vault == {"hub/saw-alice/inference": {"api_key": "nvapi-1", "provider": "nvidia"},
                          "hub/saw-alice/web-search": {"api_key": "brave-1", "provider": "brave"}}
    assert fake.logins == [{"role": "saw-portal-writer", "jwt": "pod-sa-token"}]
    cm = fake.objects["/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice"]
    assert cm["metadata"]["labels"]["saw.redhat.com/workspace"] == "true"
    assert json.loads(cm["data"]["user.json"]) == {
        "name": "alice", "profiles": ["data-science"], "ownerSubject": "",
        "vaultPrefix": "secret/data/hub/saw-alice", "pruneOnRemove": True}
    assert "/api/v1/namespaces/saw-portal/secrets/saw-req-1" not in fake.objects, "request consumed"


def test_the_owner_comes_from_the_token_not_the_form(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer, owner="bob"))
    assert portal.main(["create", "saw-req-1"]) == 0
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice" in fake.objects
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-bob" not in fake.objects


def test_a_forged_request_changes_nothing_and_is_consumed(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(Tokens(Signer("x"), Signer("y"))))
    assert portal.main(["create", "saw-req-1"]) == 1
    assert fake.vault == {} and not any("configmaps" in p for p in fake.objects)
    assert "/api/v1/namespaces/saw-portal/secrets/saw-req-1" not in fake.objects


def test_an_old_request_is_refused(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer), age=2 * 3600)
    assert portal.main(["create", "saw-req-1"]) == 1
    assert fake.vault == {}


def test_a_git_managed_user_is_refused(portal, world):
    fake, signer = world
    fake.objects["/api/v1/namespaces/saw-alice"] = {"metadata": {"name": "saw-alice", "labels": {}}}
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 1
    assert fake.vault == {}


def test_a_portal_workspace_can_be_updated(portal, world):
    fake, signer = world
    fake.objects["/api/v1/namespaces/saw-alice"] = {
        "metadata": {"name": "saw-alice", "labels": {"saw.redhat.com/portal": "true"}}}
    fake.request("saw-req-1", ds_request(signer))
    fake.request("saw-req-2", ds_request(signer, **{"inference.api_key": "nvapi-2"}))
    assert portal.main(["create", "saw-req-1"]) == 0
    assert portal.main(["create", "saw-req-2"]) == 0
    assert fake.vault["hub/saw-alice/inference"]["api_key"] == "nvapi-2"


def test_delete_removes_the_entry_and_the_keys(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    assert portal.main(["delete", "saw-req-2"]) == 0
    cm = fake.objects["/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice"]
    assert cm["metadata"]["labels"]["saw.redhat.com/deleting"] == "true"
    assert "/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications/portal-ws-alice" in fake.deleted
    assert fake.vault != {}                 # kept until the workspace is gone
    assert [w["name"] for w in portal.list_workspaces(portal.kube(), "saw-portal")] == []
    assert [w["name"] for w in portal.list_workspaces(portal.kube(), "saw-portal", deleting=True)] == ["alice"]
    assert portal.main(["wait-gone", "alice", "60"]) == 0
    assert portal.main(["finish-delete", "alice"]) == 0
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice" not in fake.objects
    assert fake.vault == {}


def test_delete_of_someone_elses_workspace_is_impossible(portal, world):
    """bob's token can only name bob, who has no workspace."""
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    fake.request("saw-req-2", {"action": "delete", "token": signer.token(sub="user:default/bob")})
    assert portal.main(["delete", "saw-req-2"]) == 1
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice" in fake.objects


@pytest.mark.parametrize("workspace, ok", [("component:default/saw-alice", True), ("resource:default/saw-alice", True),
                                           ("saw-alice", True),
                                           ("resource:default/saw-bob", False)])
def test_delete_checks_the_workspace_the_form_names(portal, world, workspace, ok):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    fake.request("saw-req-2", {"action": "delete", "token": signer.token(), "workspace": workspace})
    assert portal.main(["delete", "saw-req-2"]) == (0 if ok else 1)
    cm = fake.objects["/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice"]
    assert ("saw.redhat.com/deleting" in cm["metadata"]["labels"]) == ok


def test_the_generator_lists_the_registry(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    ws = portal.list_workspaces(portal.kube(), "saw-portal")
    assert [w["name"] for w in ws] == ["alice"]


def test_a_create_request_cannot_run_the_delete_pipeline(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    fake.request("saw-req-2", ds_request(signer))
    assert portal.main(["delete", "saw-req-2"]) == 1
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice" in fake.objects


def test_a_secret_that_is_not_a_request_is_left_alone(portal, world):
    fake, signer = world
    fake.request("saw-req-other", ds_request(signer), labels={})
    assert portal.main(["create", "saw-req-other"]) == 1
    assert "/api/v1/namespaces/saw-portal/secrets/saw-req-other" in fake.objects


@pytest.mark.parametrize("name", ["other-secret", "saw-req-../x", "saw-req-A"])
def test_only_request_names_are_read(portal, world, name):
    assert portal.main(["create", name]) == 1


def test_someone_elses_application_blocks_the_workspace(portal, world):
    fake, signer = world
    fake.objects["/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications/saw-alice-bom"] = {
        "metadata": {"name": "saw-alice-bom", "labels": {"openshell.pattern/owner": "alice-bom"}}}
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 1
    assert fake.vault == {}


def test_a_broken_registry_entry_is_skipped_not_fatal(portal, world, capsys):
    """Review (#57): one bad entry used to fail the generator for everyone.
    It is skipped and logged now; the ApplicationSet only creates and
    updates, so a skipped entry does not delete its workspace."""
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    fake.objects["/api/v1/namespaces/saw-portal/configmaps/saw-ws-bob"] = {
        "metadata": {"name": "saw-ws-bob", "labels": {"saw.redhat.com/workspace": "true"}},
        "data": {"user.json": "{not json"}}
    fake.objects["/api/v1/namespaces/saw-portal/configmaps/saw-ws-carol"] = {
        "metadata": {"name": "saw-ws-carol", "labels": {"saw.redhat.com/workspace": "true"}},
        "data": {"user.json": json.dumps({"name": "dave"})}}
    ws = portal.list_workspaces(portal.kube(), "saw-portal")
    assert [w["name"] for w in ws] == ["alice"]
    assert portal.BAD_ENTRIES == ["saw-ws-bob", "saw-ws-carol"]
    assert "registry entry saw-ws-bob is malformed" in capsys.readouterr().out


def test_a_second_create_for_the_same_user_replaces_the_entry(portal, world):
    """Review (#57): two requests at once both create the entry; the second
    used to fail with 409, now it replaces it."""
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 0
    fake.request("saw-req-2", ds_request(signer, **{"inference.api_key": "nvapi-2"}))
    assert portal.main(["create", "saw-req-2"]) == 0
    assert fake.vault["hub/saw-alice/inference"]["api_key"] == "nvapi-2"
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice" in fake.objects


def test_there_is_no_switch_to_trust_the_form(portal, world, monkeypatch):
    """Review (#57): VERIFY_TOKEN=false trusted the form's owner. It is gone:
    a request without a valid token is refused whatever the environment."""
    fake, signer = world
    monkeypatch.setenv("VERIFY_TOKEN", "false")
    fake.request("saw-req-1", {"action": "create", "token": "not-a-jwt", "owner": "alice",
                               "profile": "data-science", "inference.api_key": "k",
                               "web-search.api_key": "k"})
    assert portal.main(["create", "saw-req-1"]) == 1
    assert fake.vault == {}
    assert "VERIFY_TOKEN" not in PORTAL.read_text()


# -- the generator's HTTP server (portal.py serve) ---------------------------------------

@pytest.fixture
def generator(portal, world, monkeypatch, tmp_path):
    import socket
    import urllib.error
    import urllib.request
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 0
    token = tmp_path / "token"
    token.write_text("gen-token\n")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    monkeypatch.setenv("GENERATOR_TOKEN_FILE", str(token))
    monkeypatch.setenv("PORT", str(port))
    monkeypatch.setenv("CLUSTER_DOMAIN", "apps.example.com")
    monkeypatch.setenv("RHDH_BASE_URL", "https://rhdh.example.com")
    monkeypatch.setenv("SAW_USERS_VALUES", json.dumps({"namespaceLabels": {"saw.redhat.com/portal": "true"}}))
    threading.Thread(target=portal.serve, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/healthz", timeout=1)
            break
        except OSError:
            time.sleep(0.05)

    def call(method, path, token=None):
        req = urllib.request.Request(base + path, method=method,
                                     data=b"{}" if method == "POST" else None)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.headers.get("Content-Type"), resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers.get("Content-Type"), exc.read().decode()
    return fake, call


def test_the_generator_needs_its_token_for_the_plugin_api(generator):
    _, call = generator
    assert call("POST", "/api/v1/getparams.execute")[0] == 403
    assert call("POST", "/api/v1/getparams.execute", token="wrong")[0] == 403
    code, ctype, body = call("POST", "/api/v1/getparams.execute", token="gen-token")
    assert (code, ctype) == (200, "application/json")
    params = json.loads(body)["output"]["parameters"]
    assert [p["name"] for p in params] == ["alice"]
    assert json.loads(params[0]["values"])["users"][0]["name"] == "alice"


def test_the_generator_serves_the_catalog_and_health(generator):
    fake, call = generator
    code, ctype, body = call("GET", "/catalog.yaml")
    assert (code, ctype) == (200, "application/yaml")
    assert '"name": "saw-alice"' in body
    fake.objects["/api/v1/namespaces/saw-portal/configmaps/saw-ws-bob"] = {
        "metadata": {"name": "saw-ws-bob", "labels": {"saw.redhat.com/workspace": "true"}},
        "data": {"user.json": "broken"}}
    assert call("GET", "/catalog.yaml")[0] == 200            # still serves alice
    code, _, body = call("GET", "/healthz")
    assert code == 200 and json.loads(body) == {"ok": True, "skippedRegistryEntries": ["saw-ws-bob"]}


@pytest.mark.parametrize("method, path", [("GET", "/"), ("GET", "/api/v1/getparams.execute"),
                                          ("POST", "/catalog.yaml")])
def test_the_generator_refuses_other_paths(generator, method, path):
    _, call = generator
    assert call(method, path, token="gen-token")[0] == 404


def test_cleanup_deletes_only_stale_requests(portal, world):
    fake, signer = world
    fake.request("saw-req-old", ds_request(signer), age=2 * 3600)
    fake.request("saw-req-new", ds_request(signer))
    assert portal.main(["cleanup"]) == 0
    assert "/api/v1/namespaces/saw-portal/secrets/saw-req-old" not in fake.objects
    assert "/api/v1/namespaces/saw-portal/secrets/saw-req-new" in fake.objects


def test_delete_takes_the_entry_off_the_applicationset_first(portal, world, monkeypatch):
    """An entry the ApplicationSet still got would rebuild a fresh VM: it is
    marked deleting before the Application goes, and a create waits."""
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    order = []
    real = portal.Http.call

    def spy(self, method, path, *a, **kw):
        if method in ("PUT", "DELETE") and "saw-req-" not in path:
            order.append((method, path.rsplit("/", 1)[1]))
        return real(self, method, path, *a, **kw)
    monkeypatch.setattr(portal.Http, "call", spy)
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    portal.main(["delete", "saw-req-2"])
    assert order == [("PUT", "saw-ws-alice"), ("DELETE", "portal-ws-alice")]
    fake.request("saw-req-3", ds_request(signer))
    assert portal.main(["create", "saw-req-3"]) == 1    # being deleted


def test_a_half_done_delete_can_be_run_again(portal, world):
    """Entry gone, Application still there: a second delete finishes."""
    fake, signer = world
    fake.objects["/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications/portal-ws-alice"] = {
        "metadata": {"name": "portal-ws-alice", "labels": {"saw.redhat.com/portal": "true"}}}
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    assert portal.main(["delete", "saw-req-2"]) == 0
    assert "/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications/portal-ws-alice" not in fake.objects


# -- progress: the generator's /status and the catalog's status -------------------------

ARGO = "/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications"
VM = "/apis/kubevirt.io/v1/namespaces/saw-alice/virtualmachines/alice"


def add_apps(fake, user="alice", op_phase="Succeeded", message=""):
    for name in (f"portal-ws-{user}", f"saw-{user}-secrets", f"saw-{user}-bom", f"saw-{user}"):
        fake.objects[f"{ARGO}/{name}"] = {
            "metadata": {"name": name, "labels": {"openshell.pattern/owner": user}},
            "status": {"sync": {"status": "Synced"}, "health": {"status": "Healthy"},
                       "operationState": {"phase": op_phase, "message": message}}}


def add_vm(fake, state):
    fake.objects[VM] = {"metadata": {"name": "alice"}, "status": {"printableStatus": state}}


def created(portal, world):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 0
    return fake


def status(portal, catalog, up=False):
    return portal.workspace_status(portal.kube(), "alice", catalog, "saw-portal", "vp-gitops",
                                   "example.com", ping=lambda url: up)


def states(st):
    return {s["id"]: s["state"] for s in st["steps"]}


def test_a_workspace_goes_through_its_stages(portal, world, catalog):
    fake = world[0]
    st = status(portal, catalog)
    assert (st["phase"], st["title"]) == ("none", "Not requested")
    fake = created(portal, world)
    st = status(portal, catalog)
    assert st["phase"] == "registered" and states(st)["apps"] == "active"
    assert "saw-alice not created yet" in st["text"]
    add_apps(fake)
    assert status(portal, catalog)["phase"] == "apps"
    add_vm(fake, "Starting")
    st = status(portal, catalog)
    assert st["phase"] == "vm" and st["message"] == "VM Starting"
    add_vm(fake, "Running")
    st = status(portal, catalog)
    assert (st["phase"], st["title"]) == ("running", "Installing")
    assert "waiting for notebook UI (default)" in st["text"] and not st["ready"]
    st = status(portal, catalog, up=True)
    assert st["ready"] and set(states(st).values()) == {"done"}
    assert "https://alice-default-notebook-ui.apps.example.com" in st["text"]


@pytest.mark.parametrize("setup, message", [
    (lambda f: (add_apps(f), add_vm(f, "CrashLoopBackOff")), "VM alice is CrashLoopBackOff"),
    (lambda f: add_apps(f, op_phase="Failed", message="one or more objects failed"),
     "Argo CD could not sync portal-ws-alice: one or more objects failed"),
])
def test_a_failed_stage_is_reported(portal, world, catalog, setup, message):
    fake = created(portal, world)
    setup(fake)
    st = status(portal, catalog)
    assert st["failed"] and st["phase"] == "failed" and st["message"] == message
    assert "failed" in states(st).values()


def add_run(fake, name, ok, log):
    cond = {"type": "Succeeded", "status": {True: "True", False: "False", None: "Unknown"}[ok],
            "reason": "Running" if ok is None else "", "message": "Tasks Completed: 1 (Failed: 1)"}
    fake.objects[f"/apis/tekton.dev/v1/namespaces/saw-portal/pipelineruns/{name}"] = {
        "metadata": {"name": name}, "status": {"conditions": [cond]}}
    pod = f"{name}-create-pod"
    fake.objects[f"/api/v1/namespaces/saw-portal/pods/{pod}"] = {
        "metadata": {"name": pod, "labels": {"tekton.dev/pipelineRun": name}}}
    fake.logs[f"/api/v1/namespaces/saw-portal/pods/{pod}/log"] = log


ALICE_LOG = ("[saw-portal] create request saw-req-abc from alice\n"
             "[saw-portal] ERROR: profile 'data-science' needs: inference.api_key\n")


def test_a_run_log_is_shown_to_its_user_only(portal, world, monkeypatch):
    """Review: another user's run (its form, its log) is not theirs to read;
    administrators read every run."""
    monkeypatch.setenv("PORTAL_ADMINS", "admin")
    fake = world[0]
    add_run(fake, "saw-create-x1", False, ALICE_LOG)
    mine = portal.run_status(portal.kube(), "saw-portal", "saw-create-x1", "alice")
    assert mine["failed"] and mine["done"]
    assert mine["message"] == "profile 'data-science' needs: inference.api_key"
    assert "from alice" in mine["text"]
    with pytest.raises(portal.HttpError) as refused:
        portal.run_status(portal.kube(), "saw-portal", "saw-create-x1", "bob")
    assert refused.value.code == 404
    assert "from alice" in portal.run_status(portal.kube(), "saw-portal", "saw-create-x1", "admin")["text"]
    add_run(fake, "saw-create-x2", False, "[saw-portal] ERROR: the user token: expired\n")
    early = portal.run_status(portal.kube(), "saw-portal", "saw-create-x2", "alice")
    assert "expired" not in early["text"] and "before it was verified" in early["log"]
    with pytest.raises(portal.HttpError):
        portal.run_status(portal.kube(), "saw-portal", "kube-system-thing", "alice")


def test_waiting_stops_when_done_or_out_of_time(portal):
    now = [0.0]
    results = __import__("itertools").count(1)
    clock = lambda: now[0]  # noqa: E731
    sleep = lambda s: now.__setitem__(0, now[0] + s)  # noqa: E731
    assert portal.wait_for(lambda: next(results), lambda r: r == 3, 50, sleep, clock) == 3
    assert portal.wait_for(lambda: next(results), lambda r: False, 999, sleep, clock) == 4 + 5
    assert now[0] == 10 + 25   # capped at WAIT_LIMIT, one check every 5 s
    assert portal.wait_for(lambda: 0, lambda r: False, 0, sleep, clock) == 0


def test_status_reads_accept_a_recently_expired_token(portal):
    auth, scaffolder = Signer("auth"), Signer("scaffolder")
    old = plugin_token(scaffolder, auth.limited(exp=int(time.time()) - 600))
    with pytest.raises(portal.PortalError, match="expired"):
        portal.verify_backstage_token(old, auth.jwks(), scaffolder.jwks())
    assert portal.verify_backstage_token(old, auth.jwks(), scaffolder.jwks(), leeway=3600) == "alice"


@pytest.fixture
def status_call(generator, world, portal, monkeypatch):
    import urllib.error
    import urllib.request
    fake, call = generator
    monkeypatch.setattr(portal, "ping_url", lambda url, timeout=3: True)
    tokens = world[1]

    def get(path, user="alice"):
        port = int(os.environ["PORT"])
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
        if user:
            req.add_header("X-Saw-Token", tokens.token(sub=f"user:default/{user}"))
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())
    return fake, get


def test_status_needs_the_users_token(status_call):
    _, get = status_call
    assert get("/status/workspace", user=None)[0] == 401


def test_status_reports_the_callers_workspace(status_call):
    fake, get = status_call
    code, body = get("/status/workspace")
    assert code == 200 and body["user"] == "alice" and body["phase"] == "registered"
    code, body = get("/status/workspace?for=ready&assert=ready")
    assert code == 422 and "not ready yet" in body["error"]
    add_apps(fake)
    add_vm(fake, "Running")
    code, body = get("/status/workspace?for=ready&wait=5&assert=ready")
    assert code == 200 and body["ready"]
    # bob has no workspace: he never sees alice's
    code, body = get("/status/workspace", user="bob")
    assert code == 200 and body["user"] == "bob" and body["phase"] == "none"
    assert get("/status/workspace?for=nonsense")[0] == 400


def test_a_failed_workspace_ends_the_wait_at_once(status_call):
    fake, get = status_call
    add_apps(fake)
    add_vm(fake, "DataVolumeError")
    started = time.time()
    code, body = get("/status/workspace?for=ready&wait=50")
    assert code == 200 and body["failed"] and time.time() - started < 5
    assert get("/status/workspace?assert=ready")[0] == 422


def test_status_follows_a_pipeline_run(status_call):
    fake, get = status_call
    add_run(fake, "saw-create-r1", True, "[saw-portal] create request saw-req-abc from alice\n")
    code, body = get("/status/run/saw-create-r1?wait=50&assert=1")
    assert code == 200 and body["phase"] == "Succeeded" and "from alice" in body["text"]
    add_run(fake, "saw-create-r2", False, ALICE_LOG)
    code, body = get("/status/run/saw-create-r2?assert=1")
    assert code == 422 and body["error"] == "profile 'data-science' needs: inference.api_key"
    add_run(fake, "saw-create-r3", None, "")
    code, body = get("/status/run/saw-create-r3?assert=1")
    assert code == 422 and body["phase"] == "Running"
    assert get("/status/run/not-a-run")[0] == 404
    assert get("/status/nothing")[0] == 404


def test_the_catalog_shows_each_workspaces_status(generator):
    fake, call = generator
    _, _, body = call("GET", "/catalog.yaml")
    entity = the_workspace(body)
    assert entity["metadata"]["annotations"]["openshell.pattern/status"] == "registered"
    assert entity["metadata"]["description"].startswith("Requested: waiting for Argo CD.")


# -- the pipelines' tasks: results, waits, the Tekton tab's label ---------------------

def test_the_first_task_hands_the_user_to_the_next(portal, world, tmp_path, monkeypatch):
    fake, signer = world
    result = tmp_path / "user"
    monkeypatch.setenv("RESULT_PATH", str(result))
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 0
    assert result.read_text() == "alice"


@pytest.mark.parametrize("label, ok", [(None, True), ("saw-alice", True), ("saw-bob", False)])
def test_a_run_labelled_for_someone_elses_tab_is_refused(portal, world, monkeypatch, label, ok):
    fake, signer = world
    meta = {"name": "saw-create-l1", "labels": {"backstage.io/kubernetes-id": label} if label else {}}
    fake.objects["/apis/tekton.dev/v1/namespaces/saw-portal/pipelineruns/saw-create-l1"] = {"metadata": meta}
    monkeypatch.setenv("PIPELINE_RUN", "saw-create-l1")
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == (0 if ok else 1)


def test_a_wait_task_logs_each_change_and_ends_when_reached(portal, world, capsys, monkeypatch):
    fake = created(portal, world)
    ticks = []

    def sleep(_):
        ticks.append(1)
        if len(ticks) == 1:
            add_apps(fake)
        elif len(ticks) == 2:
            add_vm(fake, "Starting")
        else:
            add_vm(fake, "Running")
    portal.wait_stage("running", "alice", 600, sleep=sleep, clock=lambda: 0)
    out = capsys.readouterr().out
    assert "no VM yet" in out and "Starting" in out and "done: Running" in out


def test_a_wait_task_fails_on_a_failed_stage_or_timeout(portal, world):
    fake = created(portal, world)
    add_apps(fake)
    add_vm(fake, "DataVolumeError")
    with pytest.raises(portal.PortalError, match="DataVolumeError"):
        portal.wait_stage("running", "alice", 600, sleep=lambda s: None, clock=lambda: 0)
    add_vm(fake, "Starting")
    now = [0]
    with pytest.raises(portal.PortalError, match="not done after 10 minutes"):
        portal.wait_stage("running", "alice", 600, sleep=lambda s: now.__setitem__(0, now[0] + s),
                          clock=lambda: now[0])


def test_the_catalog_shows_a_workspace_being_deleted(portal, world, catalog):
    fake = created(portal, world)
    add_apps(fake)
    fake.request("saw-req-2", {"action": "delete", "token": world[1].token()})
    portal.main(["delete", "saw-req-2"])
    st = status(portal, catalog)
    assert st["phase"] == "deleting" and "saw-alice" in st["message"]
    text = portal.entities_yaml(portal.list_workspaces(portal.kube(), "saw-portal", deleting=True),
                                catalog, "example.com", "", {"alice": st})
    entity = the_workspace(text)
    assert entity["metadata"]["description"].startswith("Deleting: Argo CD is removing")
    ann = entity["metadata"]["annotations"]
    assert ann["backstage.io/kubernetes-id"] == "saw-alice" and ann["janus-idp.io/tekton"] == "saw-alice"
    assert ann["backstage.io/kubernetes-namespace"] == "saw-portal"


def test_status_follows_one_task_of_a_run(status_call):
    fake, get = status_call
    add_run(fake, "saw-create-t1", None, "[saw-portal] create request saw-req-abc from alice\n")
    pod = "/api/v1/namespaces/saw-portal/pods/saw-create-t1-create-pod"
    fake.objects[pod]["metadata"]["labels"]["tekton.dev/pipelineTask"] = "register"
    fake.objects[pod]["status"] = {"phase": "Succeeded"}
    code, body = get("/status/run/saw-create-t1?task=register&wait=50")
    assert code == 200 and body["done"] and body["taskState"] == "Succeeded"
    assert "--- register ---" in body["text"]
    code, body = get("/status/run/saw-create-t1?task=vm&wait=1")
    assert code == 200 and not body["done"] and body["taskState"] == "Waiting"


# -- administrators: one workspace at a time for another user ---------------------------

def test_an_admin_creates_a_workspace_for_another_user(portal, world, monkeypatch, capsys):
    fake, signer = world
    monkeypatch.setenv("PORTAL_ADMINS", "admin, ops")
    fake.request("saw-req-1", {**ds_request(signer), "token": signer.token(sub="user:default/admin"),
                               "forUser": "carol"})
    assert portal.main(["create", "saw-req-1"]) == 0
    entry = json.loads(fake.objects["/api/v1/namespaces/saw-portal/configmaps/saw-ws-carol"]["data"]["user.json"])
    assert entry["name"] == "carol"
    assert "hub/saw-carol/inference" in fake.vault
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-admin" not in fake.objects
    log = capsys.readouterr().out
    assert "create request saw-req-1 from admin for carol" in log
    assert portal.RUN_USER_RE.search(log).group(1) == "admin"     # the admin sees the run's log


def test_only_an_admin_may_act_for_someone_else(portal, world, monkeypatch):
    fake, signer = world
    monkeypatch.setenv("PORTAL_ADMINS", "admin")
    fake.request("saw-req-1", {**ds_request(signer), "forUser": "carol"})      # alice's token
    assert portal.main(["create", "saw-req-1"]) == 1
    assert "/api/v1/namespaces/saw-portal/configmaps/saw-ws-carol" not in fake.objects
    fake.request("saw-req-2", {**ds_request(signer), "forUser": "alice"})      # herself: fine
    assert portal.main(["create", "saw-req-2"]) == 0


def test_an_admin_deletes_another_users_workspace(portal, world, monkeypatch):
    fake, signer = world
    monkeypatch.setenv("PORTAL_ADMINS", "admin")
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 0
    fake.request("saw-req-2", {"action": "delete", "token": signer.token(sub="user:default/bob"),
                               "workspace": "component:default/saw-alice"})
    assert portal.main(["delete", "saw-req-2"]) == 1                     # bob is no admin
    fake.request("saw-req-3", {"action": "delete", "token": signer.token(sub="user:default/admin"),
                               "workspace": "component:default/saw-alice"})
    assert portal.main(["delete", "saw-req-3"]) == 0
    cm = fake.objects["/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice"]
    assert cm["metadata"]["labels"]["saw.redhat.com/deleting"] == "true"


def test_status_of_another_users_workspace_is_for_admins(status_call, monkeypatch):
    fake, get = status_call
    monkeypatch.setenv("PORTAL_ADMINS", "admin")
    assert get("/status/workspace?user=alice", user="bob")[0] == 403
    code, body = get("/status/workspace?user=alice", user="admin")
    assert code == 200 and body["user"] == "alice" and body["phase"] == "registered"


def test_the_realm_users_come_from_the_keycloak_group(portal, tmp_path, monkeypatch):
    class KC(BaseHTTPRequestHandler):
        def _reply(self, code, body):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            ok = form == {"grant_type": ["client_credentials"], "client_id": ["rhdh"], "client_secret": ["s3"]}
            self._reply(200 if ok else 401, {"access_token": "sa-token"} if ok else {})

        def do_GET(self):
            assert self.headers["Authorization"] == "Bearer sa-token"
            url = urlsplit(self.path)
            if url.path.endswith("/groups"):
                return self._reply(200, [{"id": "g1", "name": "saw-users"}, {"id": "g2", "name": "saw-users-x"}])
            if url.path.endswith("/groups/g1/members"):
                return self._reply(200, [{"username": "carol"}, {"username": "alice"},
                                         {"username": "service-account-rhdh"}])
            self._reply(404, {})

        def log_message(self, *a):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), KC)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    secret = tmp_path / "secret"
    secret.write_text("s3\n")
    for k, v in {"KEYCLOAK_URL": f"http://127.0.0.1:{server.server_address[1]}", "USERS_GROUP": "saw-users",
                 "KEYCLOAK_REALM": "openshell", "KEYCLOAK_CLIENT_ID": "rhdh",
                 "KEYCLOAK_SECRET_FILE": str(secret)}.items():
        monkeypatch.setenv(k, v)
    users = portal.RealmUsers()
    assert users() == ["alice", "carol"]
    server.shutdown()
    server.server_close()
    users.at = 0
    assert users() == ["alice", "carol"]          # Keycloak gone: the last list is kept


def test_a_create_does_not_undo_a_delete_that_marked_the_entry_meanwhile(portal, world):
    """Review: create read the entry, a delete marked it deleting, then the
    create's replace dropped the mark and Argo CD rebuilt the workspace."""
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 0
    path = "/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice"
    read = dict(fake.objects[path]["metadata"])
    fake.objects[path]["metadata"]["resourceVersion"] = "changed"     # the delete's mark
    with pytest.raises(portal.PortalError, match="changed while this request ran"):
        portal.put_configmap(portal.kube(), "saw-portal", "saw-ws-alice", {}, {},
                             resource_version=read["resourceVersion"])


def test_without_pruning_a_delete_does_not_wait_for_the_namespace(portal, world, monkeypatch):
    """Review: with pruneOnRemove off the namespace stays, so waiting for it
    never ended and the entry stayed 'deleting' for good."""
    fake = world[0]
    fake.objects["/api/v1/namespaces/saw-alice"] = {"metadata": {"name": "saw-alice"}}
    monkeypatch.setenv("PRUNE_ON_REMOVE", "true")
    assert portal.removal_status(portal.kube(), "alice", "vp-gitops")[0] is False
    monkeypatch.setenv("PRUNE_ON_REMOVE", "false")
    assert portal.removal_status(portal.kube(), "alice", "vp-gitops") == (True, "removed")


def test_an_unreachable_keycloak_is_tried_once_per_ttl(portal, monkeypatch, tmp_path):
    """Review: every catalog read waited for the failing Keycloak again."""
    secret = tmp_path / "secret"
    secret.write_text("s3\n")
    for k, v in {"KEYCLOAK_URL": "http://127.0.0.1:9", "USERS_GROUP": "saw-users",
                 "KEYCLOAK_REALM": "openshell", "KEYCLOAK_CLIENT_ID": "rhdh",
                 "KEYCLOAK_SECRET_FILE": str(secret)}.items():
        monkeypatch.setenv(k, v)
    calls = []

    def failing(*args, **kwargs):
        calls.append(args)
        raise OSError("connection refused")
    monkeypatch.setattr(portal, "keycloak_group_members", failing)
    users = portal.RealmUsers()
    users.users = ["alice"]
    assert users() == ["alice"] and users() == ["alice"]
    assert len(calls) == 1


def test_portal_workspaces_get_their_owners_keycloak_id(portal, monkeypatch, tmp_path):
    """OpenShell's web UI lists only the workspaces the user is a member of;
    the installer adds ownerSubject (the user's Keycloak id), which a portal
    registry entry does not have. The generator fills it in."""
    secret = tmp_path / "secret"
    secret.write_text("s3\n")
    for k, v in {"KEYCLOAK_URL": "https://kc.example.com", "KEYCLOAK_REALM": "openshell",
                 "KEYCLOAK_CLIENT_ID": "rhdh", "KEYCLOAK_SECRET_FILE": str(secret)}.items():
        monkeypatch.setenv(k, v)
    asked = []

    def ids(url, realm, client_id, secret, names, insecure=False):
        asked.append(list(names))
        return {n: f"id-{n}" for n in names if n != "ghost"}
    monkeypatch.setattr(portal, "keycloak_user_ids", ids)
    subjects = portal.OwnerSubjects()
    ws = [{"name": "carol", "ownerSubject": ""}, {"name": "alice", "ownerSubject": "set-in-git"},
          {"name": "ghost", "ownerSubject": ""}]
    filled = subjects.fill(ws)
    assert [w["ownerSubject"] for w in filled] == ["id-carol", "set-in-git", ""]
    assert asked == [["carol", "ghost"]]
    subjects.fill(ws)
    assert asked == [["carol", "ghost"]]           # carol kept, ghost not asked again before the TTL
    monkeypatch.delenv("KEYCLOAK_URL")
    assert portal.OwnerSubjects().fill(ws) == ws    # RBAC off: entries as they are


def test_keycloak_user_ids_match_the_exact_user_name(portal, monkeypatch):
    calls = []

    class KC:
        def call(self, method, path):
            calls.append(path)
            return [{"username": "carol2", "id": "x"}, {"username": "carol", "id": "c-1"}]
    monkeypatch.setattr(portal, "keycloak_admin", lambda *a, **k: KC())
    assert portal.keycloak_user_ids("https://kc", "openshell", "rhdh", "s", ["carol"]) == {"carol": "c-1"}
    assert calls == ["/users?exact=true&briefRepresentation=true&username=carol"]
