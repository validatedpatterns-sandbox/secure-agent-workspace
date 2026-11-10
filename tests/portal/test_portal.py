"""The self-service portal's pipeline and plugin generator (charts/openshell-rhdh/files/portal.py).

Runs portal.py against small fake Kubernetes and Vault HTTP servers, with
Backstage tokens signed by a throwaway P-256 key.
"""
import base64
import importlib.util
import json
import os
import ssl
import subprocess
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
# data-science's sandboxes read their model from the inference Secret (each
# its own key: notebook `model`, cuda-sandbox `cuda_model`); the form submits
# the profile default unless changed.
DS_MODEL = "nvidia/nemotron-3.5-lightning-30b-a3b"

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


@pytest.mark.parametrize("trust,host,status,ready", [
    (True, "127.0.0.1", 200, True),
    (False, "127.0.0.1", 200, False),
    (True, "localhost", 200, False),
    (True, "127.0.0.1", 401, True),
    (True, "127.0.0.1", 503, False),
])
def test_readiness_checks_ingress_certificate_and_hostname(portal, tmp_path, monkeypatch,
                                                         trust, host, status, ready):
    ca, key = tmp_path / "ca.pem", tmp_path / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=Portal test CA", "-keyout", str(key), "-out", str(ca),
        "-addext", "subjectAltName=IP:127.0.0.1",
        "-addext", "basicConstraints=critical,CA:TRUE",
    ], check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca, key)
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(status)
            self.end_headers()

        def log_message(self, *args):
            pass

    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    if trust:
        monkeypatch.setenv("SSL_CERT_FILE", str(ca))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        assert portal.ping_url(f"https://{host}:{server.server_port}") is ready
        if not trust or host == "localhost":
            assert not requests, "an untrusted peer must not receive an HTTP request"
    finally:
        server.shutdown()
        worker.join()
        server.server_close()


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


@pytest.mark.parametrize("url", ["http://rhdh.test/keys", "https://user@rhdh.test/keys"])
def test_signing_keys_require_verified_https(portal, url, monkeypatch):
    monkeypatch.setenv("RHDH_SKIP_VERIFY", "true")
    with pytest.raises(portal.PortalError, match="HTTPS endpoint"):
        portal.fetch_json(url)
    assert portal.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.test") is None


def test_cached_verifier_refreshes_both_rotated_backstage_keys(portal, monkeypatch):
    auth_path = "/api/auth/.well-known/jwks.json"
    scaffolder_path = "/api/scaffolder/.backstage/auth/v1/jwks.json"
    old_auth, old_plugin = Signer("old-auth"), Signer("old-scaffolder")
    new_auth, new_plugin = Signer("new-auth"), Signer("new-scaffolder")
    issued = {auth_path: old_auth, scaffolder_path: old_plugin}
    calls = []
    monkeypatch.setenv("RHDH_INTERNAL_URL", "https://rhdh.test")

    def fetch(url, insecure=False):
        assert not insecure
        path = url.removeprefix("https://rhdh.test")
        calls.append(path)
        return issued[path].jwks()

    monkeypatch.setattr(portal, "fetch_json", fetch)
    cache = portal.JwksCache()
    assert portal.token_user(plugin_token(old_plugin, old_auth.limited()), cache) == "alice"
    issued.update({auth_path: new_auth, scaffolder_path: new_plugin})
    signed = plugin_token(new_plugin, new_auth.limited())
    assert portal.token_user(signed, cache) == "alice"
    assert portal.token_user(signed, cache) == "alice"
    assert calls.count(auth_path) == calls.count(scaffolder_path) == 2
    with pytest.raises(portal.PortalError, match="signature is not valid"):
        portal.token_user(plugin_token(new_plugin, Signer("new-auth").limited()), cache)


def test_unknown_key_ids_do_not_trigger_unbounded_issuer_fetches(portal, monkeypatch):
    real = Signer("published")
    calls = []
    monkeypatch.setenv("RHDH_INTERNAL_URL", "https://rhdh.test")
    monkeypatch.setattr(portal, "fetch_json", lambda url, insecure=False: calls.append(url) or real.jwks())
    cache = portal.JwksCache()
    assert portal.token_user(real.token(), cache) == "alice"
    for kid in ("unknown-a", "unknown-b", "unknown-c"):
        with pytest.raises(portal.PortalError, match="signing key is not in the JWKS"):
            portal.token_user(Signer(kid).token(), cache)
    assert len(calls) == 2
    assert portal.token_user(real.token(), cache) == "alice"


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
    assert secrets == {"inference": {"api_key": "nvapi-1", "model": DS_MODEL, "cuda_model": DS_MODEL, "provider": "nvidia"},
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
    assert json.loads(params["values"]) == {**defaults, "users": [
        {**ws, "values": {"deployment": {"mode": "vm"}}}]}


def test_operator_pin_selects_application_and_child_source_without_changing_other_owners(portal):
    defaults = {"global": {"repoURL": "https://example.com/repo.git", "targetRevision": "legacy"},
                "workspaceRevisions": {"alice": "a"*40}}
    users = [{"name": name, "profiles": ["data-science"], "workspaceRevisions": {name: "b"*40}}
             for name in ("alice", "bob")]
    params = portal.generator_params(users, defaults)
    assert [p["revision"] for p in params] == ["a"*40, "legacy"]
    for p in params:
        values = json.loads(p["values"])
        assert values["global"] == {"repoURL": defaults["global"]["repoURL"], "targetRevision": p["revision"]}
        assert "workspaceRevisions" not in values


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
                body["metadata"]["uid"] = f"uid-{fake.rv}"
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
                pre = (self._body() or {}).get("preconditions") or {}
                meta = (fake.objects.get(self.path) or {}).get("metadata") or {}
                if any(meta.get(k) != v for k, v in pre.items()) and self.path in fake.objects:
                    return self._reply(409, {"reason": "Conflict"})
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


# The generations the world fixture hands out, in order (portal.new_generation).
GEN = [f"{n:016x}" for n in range(1, 10)]
KEYS = "hub/saw-alice/" + GEN[0]       # the first registration's keys
NEW_KEYS = "hub/saw-alice/" + GEN[1]   # a replacement's


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
    generations = iter(GEN)
    monkeypatch.setattr(portal, "new_generation", lambda: next(generations))
    fixture_catalog = json.loads(CATALOG.read_text())
    fixture_catalog["profiles"]["audited-openclaw"] = json.loads((ROOT/"tests/fixtures/audited-profile.json").read_text())
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(json.dumps(fixture_catalog))
    for k, v in {"NAMESPACE": "saw-portal", "CATALOG_PATH": str(catalog_path), "RHDH_INTERNAL_URL": "http://rhdh",
                 "ARGO_NAMESPACE": "vp-gitops",
                 "VAULT_ADDR": url, "VAULT_AUTH_MOUNT": "hub", "VAULT_ROLE": "saw-portal-writer",
                 "VAULT_KV_MOUNT": "secret", "VAULT_PREFIX_BASE": "hub"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("PIPELINE_RUN", "fixture-registration")
    (tmp_path / "directory-secret").write_text("synthetic-directory-client")
    monkeypatch.setenv("KEYCLOAK_URL", "https://directory.test")
    monkeypatch.setenv("KEYCLOAK_REALM", "test")
    monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "directory-test")
    monkeypatch.setenv("KEYCLOAK_SECRET_FILE", str(tmp_path / "directory-secret"))
    monkeypatch.setattr(portal, "keycloak_user_ids", lambda *args, **kwargs: {
        "alice": "478fdd1f-8db9-41e8-97ad-b563215c89e9"})
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
    assert fake.vault == {f"{KEYS}/inference": {"api_key": "nvapi-1", "model": DS_MODEL, "cuda_model": DS_MODEL, "provider": "nvidia"},
                          f"{KEYS}/web-search": {"api_key": "brave-1", "provider": "brave"}}
    assert fake.logins == [{"role": "saw-portal-writer", "jwt": "pod-sa-token"}]
    cm = fake.objects["/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice"]
    assert cm["metadata"]["labels"]["saw.redhat.com/workspace"] == "true"
    assert json.loads(cm["data"]["user.json"]) == {
        "name": "alice", "profiles": ["data-science"], "ownerSubject": "",
        "vaultPrefix": f"secret/data/{KEYS}", "pruneOnRemove": True,
        "values": {"deployment": {"mode": "vm"}}}
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
    assert fake.vault[f"{KEYS}/inference"]["api_key"] == "nvapi-2"       # same generation


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
    assert fake.vault[f"{KEYS}/inference"]["api_key"] == "nvapi-2"       # same generation
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


REGISTRY = "/api/v1/namespaces/saw-portal/configmaps/saw-ws-alice"


def test_the_deletion_mark_stays_until_the_keys_are_gone(portal, world, monkeypatch):
    """Review of #57: finish-delete removed the entry before destroying the
    keys, so a create in between registered a replacement whose new keys the
    delete then destroyed. The keys go first, while the mark still refuses
    a create; a create after the cleanup keeps its keys."""
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 0
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    assert portal.main(["delete", "saw-req-2"]) == 0
    racing = []
    real = portal.Vault.destroy

    def destroy(self, path):
        if not racing:
            fake.request("saw-req-3", ds_request(signer, **{"inference.api_key": "nvapi-new"}))
            racing.append(portal.main(["create", "saw-req-3"]))
        real(self, path)
    monkeypatch.setattr(portal.Vault, "destroy", destroy)
    assert portal.main(["finish-delete", "alice"]) == 0
    assert racing == [1], "a create during the cleanup is refused"
    assert REGISTRY not in fake.objects and fake.vault == {}
    monkeypatch.setattr(portal.Vault, "destroy", real)
    fake.request("saw-req-4", ds_request(signer, **{"inference.api_key": "nvapi-new"}))
    assert portal.main(["create", "saw-req-4"]) == 0
    assert fake.vault == {f"{NEW_KEYS}/inference": {"api_key": "nvapi-new", "model": DS_MODEL, "cuda_model": DS_MODEL, "provider": "nvidia"},
                          f"{NEW_KEYS}/web-search": {"api_key": "brave-1", "provider": "brave"}}


def test_a_stale_cleanup_leaves_a_replacement_alone(portal, world, monkeypatch):
    """A finish-delete that runs again after the workspace was re-created
    (a retried or duplicated task) changes nothing: the entry is no longer
    its deletion."""
    fake, signer = world
    monkeypatch.setenv("PIPELINE_RUN", "saw-workspace-delete-a")
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    assert portal.main(["delete", "saw-req-2"]) == 0
    assert portal.main(["finish-delete", "alice"]) == 0
    monkeypatch.setenv("PIPELINE_RUN", "saw-workspace-create-b")
    fake.request("saw-req-3", ds_request(signer, **{"inference.api_key": "nvapi-new"}))
    assert portal.main(["create", "saw-req-3"]) == 0
    monkeypatch.setenv("PIPELINE_RUN", "saw-workspace-delete-a")
    assert portal.main(["finish-delete", "alice"]) == 1
    assert REGISTRY in fake.objects
    assert fake.vault == {f"{NEW_KEYS}/inference": {"api_key": "nvapi-new", "model": DS_MODEL, "cuda_model": DS_MODEL, "provider": "nvidia"},
                          f"{NEW_KEYS}/web-search": {"api_key": "brave-1", "provider": "brave"}}


def test_a_cleanup_overtaken_after_its_check_leaves_the_replacement_alone(portal, world, monkeypatch):
    """Review of #57: cleanup A passes its ownership check and pauses before
    Vault; delete B takes over and finishes, and a create registers a
    replacement with new keys; then A resumes. A used to destroy the
    replacement's keys (only its final ConfigMap DELETE failed). Keys now
    belong to a registration's generation: A destroys its own only."""
    fake, signer = world
    monkeypatch.setenv("PIPELINE_RUN", "delete-a")
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 0
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    assert portal.main(["delete", "saw-req-2"]) == 0
    real = portal.Vault.destroy
    overtaken = []

    def destroy(self, path):
        if not overtaken:        # A, checked and about to touch Vault
            overtaken.append(path)
            monkeypatch.setenv("PIPELINE_RUN", "delete-b")
            fake.request("saw-req-3", {"action": "delete", "token": signer.token()})
            assert portal.main(["delete", "saw-req-3"]) == 0          # B takes over
            assert portal.main(["finish-delete", "alice"]) == 0       # and finishes
            assert REGISTRY not in fake.objects and fake.vault == {}
            monkeypatch.setenv("PIPELINE_RUN", "create-c")
            fake.request("saw-req-4", ds_request(signer, **{"inference.api_key": "nvapi-new"}))
            assert portal.main(["create", "saw-req-4"]) == 0          # the replacement
            monkeypatch.setenv("PIPELINE_RUN", "delete-a")
        real(self, path)
    monkeypatch.setattr(portal.Vault, "destroy", destroy)
    assert portal.main(["finish-delete", "alice"]) == 1               # A: entry changed, left
    assert len(overtaken) == 1 and overtaken[0].startswith(f"{KEYS}/"), \
        "A only ever reaches its own generation"
    entry = json.loads(fake.objects[REGISTRY]["data"]["user.json"])
    assert entry["vaultPrefix"] == f"secret/data/{NEW_KEYS}"
    assert fake.vault == {f"{NEW_KEYS}/inference": {"api_key": "nvapi-new", "model": DS_MODEL, "cuda_model": DS_MODEL, "provider": "nvidia"},
                          f"{NEW_KEYS}/web-search": {"api_key": "brave-1", "provider": "brave"}}


def test_an_entry_from_before_generations_keeps_and_deletes_its_own_keys(portal, world):
    """Entries written before generations have vaultPrefix <base>/saw-<user>:
    an update writes there, and a delete destroys only those keys."""
    fake, signer = world
    legacy = {**portal.registry_entry("alice", "data-science"), "vaultPrefix": "secret/data/hub/saw-alice"}
    fake.objects[REGISTRY] = {"metadata": {"name": "saw-ws-alice", "resourceVersion": "1", "uid": "u1",
                                           "labels": {"saw.redhat.com/workspace": "true"}},
                              "data": {"user.json": json.dumps(legacy)}}
    fake.vault[f"{KEYS}/inference"] = {"api_key": "someone-elses"}      # another generation
    fake.request("saw-req-1", ds_request(signer, **{"inference.api_key": "nvapi-2"}))
    assert portal.main(["create", "saw-req-1"]) == 0
    assert fake.vault["hub/saw-alice/inference"]["api_key"] == "nvapi-2"
    assert json.loads(fake.objects[REGISTRY]["data"]["user.json"])["vaultPrefix"] == "secret/data/hub/saw-alice"
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    assert portal.main(["delete", "saw-req-2"]) == 0
    assert portal.main(["finish-delete", "alice"]) == 0
    assert fake.vault == {f"{KEYS}/inference": {"api_key": "someone-elses"}}


@pytest.mark.parametrize("prefix", ["secret/data/hub/saw-bob", "secret/data/hub/saw-alice/../saw-bob",
                                    "secret/data/hub/saw-alice/0000000000000001/x", "secret/data/hub"])
def test_a_vault_prefix_outside_the_users_own_is_not_cleaned_up(portal, world, prefix):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 0
    cm = fake.objects[REGISTRY]
    cm["data"]["user.json"] = json.dumps({**json.loads(cm["data"]["user.json"]), "vaultPrefix": prefix})
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    assert portal.main(["delete", "saw-req-2"]) == 0
    before = dict(fake.vault)
    assert portal.main(["finish-delete", "alice"]) == 1
    assert fake.vault == before and REGISTRY in fake.objects


def test_only_the_delete_that_owns_the_mark_cleans_up(portal, world, monkeypatch):
    """A delete run again takes the mark over; the first run's cleanup then
    leaves it to the second."""
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    for run, req in (("delete-a", "saw-req-2"), ("delete-b", "saw-req-3")):
        monkeypatch.setenv("PIPELINE_RUN", run)
        fake.request(req, {"action": "delete", "token": signer.token()})
        assert portal.main(["delete", req]) == 0
    assert fake.objects[REGISTRY]["metadata"]["annotations"]["saw.redhat.com/deletion"] == "delete-b"
    monkeypatch.setenv("PIPELINE_RUN", "delete-a")
    assert portal.main(["finish-delete", "alice"]) == 1
    assert REGISTRY in fake.objects and fake.vault != {}
    monkeypatch.setenv("PIPELINE_RUN", "delete-b")
    assert portal.main(["finish-delete", "alice"]) == 0
    assert REGISTRY not in fake.objects and fake.vault == {}


def test_the_entry_is_removed_only_in_the_version_checked(portal, world, monkeypatch):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    portal.main(["delete", "saw-req-2"])
    real = portal.Vault.destroy

    def destroy(self, path):
        fake.objects[REGISTRY]["metadata"]["resourceVersion"] = "changed"
        real(self, path)
    monkeypatch.setattr(portal.Vault, "destroy", destroy)
    assert portal.main(["finish-delete", "alice"]) == 1
    assert REGISTRY in fake.objects


def test_a_stale_create_does_not_clear_a_deletion_mark(portal, world):
    """Review of #57: a create that found no entry, then hit 409 on POST,
    replaced the entry unconditionally and so cleared a deletion mark made
    meanwhile. It now reads the entry again and refuses a deleting one."""
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    portal.main(["create", "saw-req-1"])
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    portal.main(["delete", "saw-req-2"])
    with pytest.raises(portal.PortalError, match="changed while this request ran"):
        portal.put_configmap(portal.kube(), "saw-portal", "saw-ws-alice",
                             {"user.json": json.dumps(portal.registry_entry("alice", "data-science"))},
                             {"saw.redhat.com/workspace": "true"})    # no resourceVersion: it read nothing
    assert fake.objects[REGISTRY]["metadata"]["labels"]["saw.redhat.com/deleting"] == "true"


def test_a_half_done_delete_can_be_run_again(portal, world):
    """Entry gone, Application still there: a second delete finishes."""
    fake, signer = world
    fake.objects["/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications/portal-ws-alice"] = {
        "metadata": {"name": "portal-ws-alice", "labels": {"saw.redhat.com/portal": "true"}}}
    fake.request("saw-req-2", {"action": "delete", "token": signer.token()})
    assert portal.main(["delete", "saw-req-2"]) == 0
    assert "/apis/argoproj.io/v1alpha1/namespaces/vp-gitops/applications/portal-ws-alice" not in fake.objects
    # A mark stands in for the entry: a create waits, and the cleanup runs.
    assert fake.objects[REGISTRY]["metadata"]["labels"]["saw.redhat.com/deleting"] == "true"
    assert portal.main(["finish-delete", "alice"]) == 0
    assert REGISTRY not in fake.objects


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


@pytest.mark.parametrize("webui_up", [False, True])
def test_a_profile_without_sandbox_ui_waits_for_the_openshell_webui(
        portal, world, catalog, webui_up):
    fake, signer = world
    fake.request("saw-req-custom", {"action": "create", "token": signer.token(),
                 "profile": "custom-inference", "inference.api_key": "dummy",
                 "inference.url": "https://example.com/v1", "inference.model": "model",
                 "web-search.api_key": "dummy"})
    assert portal.main(["create", "saw-req-custom"]) == 0
    add_apps(fake)
    add_vm(fake, "Running")
    checked = []

    def ping(url):
        checked.append(url)
        return webui_up

    st = portal.workspace_status(portal.kube(), "alice", catalog, "saw-portal",
                                 "vp-gitops", "example.com", ping=ping)
    assert st["ready"] is webui_up
    assert st["phase"] == ("ready" if webui_up else "running")
    assert checked == ["https://alice-webui-saw-alice.apps.example.com"]


def test_sandbox_uis_do_not_hide_an_unavailable_openshell_webui(portal, world):
    fake = world[0]
    fake.objects[REGISTRY] = {"metadata": {"name": "saw-ws-alice"},
                              "data": {"user.json": json.dumps({"profiles": ["ui-profile"]})}}
    catalog = {"ui-profile": {"workspaces": [{"name": "default", "enabled": True,
               "sandboxes": [{"name": "notebook", "enabled": True, "uiRoute": True}]}]}}
    add_apps(fake)
    add_vm(fake, "Running")
    st = portal.workspace_status(portal.kube(), "alice", catalog, "saw-portal",
                                 "vp-gitops", "example.com",
                                 ping=lambda url: "-webui-" not in url)
    assert not st["ready"] and st["phase"] == "running"
    assert "OpenShell web UI" in st["steps"][-1]["detail"]


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
    assert "waiting for OpenShell web UI, notebook UI (default)" in st["text"] and not st["ready"]
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
    assert f"hub/saw-carol/{GEN[0]}/inference" in fake.vault
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
            return [{"username": "carol", "id": "c-1", "enabled": True}]
    monkeypatch.setattr(portal, "keycloak_admin", lambda *a, **k: KC())
    assert portal.keycloak_user_ids("https://kc", "openshell", "rhdh", "s", ["carol"]) == {"carol": "c-1"}
    assert calls == ["/users?exact=true&username=carol"]


def test_keycloak_user_ids_reject_disabled_or_ambiguous_users(portal, monkeypatch):
    class KC:
        users = []
        def call(self, method, path):
            return self.users
    kc = KC()
    monkeypatch.setattr(portal, "keycloak_admin", lambda *a, **k: kc)
    for users in ([{"username": "carol", "id": "c-1", "enabled": False}],
                  [{"username": "carol", "id": "c-1", "enabled": True},
                   {"username": "carol", "id": "c-2", "enabled": True}],
                  [{"username": "carol2", "id": "c-1", "enabled": True}]):
        kc.users = users
        assert portal.keycloak_user_ids("https://kc", "openshell", "rhdh", "s", ["carol"]) == {}


def test_owner_subject_cache_rechecks_account_recreation(portal, monkeypatch, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("s3\n")
    for key, value in {"KEYCLOAK_URL": "https://kc.example.com", "KEYCLOAK_REALM": "openshell",
                       "KEYCLOAK_CLIENT_ID": "rhdh", "KEYCLOAK_SECRET_FILE": str(secret)}.items():
        monkeypatch.setenv(key, value)
    ids = {"carol": "old"}
    monkeypatch.setattr(portal, "keycloak_user_ids", lambda *a, **k: dict(ids))
    subjects = portal.OwnerSubjects(ttl=0)
    workspaces = [{"name": "carol", "ownerSubject": ""}]
    assert subjects.fill(workspaces)[0]["ownerSubject"] == "old"
    ids["carol"] = "new"
    assert subjects.fill(workspaces)[0]["ownerSubject"] == "new"
    ids.clear()
    assert subjects.fill(workspaces)[0]["ownerSubject"] == ""


@pytest.mark.parametrize("failure", [401, "network"])
def test_owner_lookup_failure_holds_vm_and_container_projection_until_recovery(
        portal, monkeypatch, tmp_path, failure):
    secret = tmp_path / "secret"
    secret.write_text("test-client-secret\n")
    for key, value in {"KEYCLOAK_URL": "https://kc.example.com", "KEYCLOAK_REALM": "openshell",
                       "KEYCLOAK_CLIENT_ID": "rhdh", "KEYCLOAK_SECRET_FILE": str(secret)}.items():
        monkeypatch.setenv(key, value)
    now = [1000]
    monkeypatch.setattr(portal.time, "time", lambda: now[0])
    failed, calls = [False], []

    def lookup(*args, **kwargs):
        calls.append(list(args[4]))
        if failed[0]:
            if failure == "network":
                raise OSError("connection refused")
            raise portal.HttpError(failure, "Keycloak users: HTTP 401")
        return {name: "id-" + name for name in args[4]}

    monkeypatch.setattr(portal, "keycloak_user_ids", lookup)
    subjects = portal.OwnerSubjects(ttl=60)
    workspaces = [{"name": "vm-owner", "ownerSubject": "", "values": {"deployment": {"mode": "vm"}}},
                  {"name": "container-owner", "ownerSubject": "", "values": {"deployment": {"mode": "container"}}}]
    assert [w["ownerSubject"] for w in subjects.fill(workspaces)] == ["id-vm-owner", "id-container-owner"]
    failed[0] = True
    now[0] += 60
    with pytest.raises(portal.PortalError, match="workspace projection held"):
        subjects.fill(workspaces)
    # No stale identities, empty owner fields or partial generator response
    # may escape while the failed request is being throttled.
    now[0] += 1
    for selected in (workspaces, workspaces[:1], workspaces[1:]):
        with pytest.raises(portal.PortalError, match="workspace projection held"):
            subjects.fill(selected)
    assert len(calls) == 2
    failed[0] = False
    now[0] += 60
    assert [w["ownerSubject"] for w in subjects.fill(workspaces)] == ["id-vm-owner", "id-container-owner"]
    assert len(calls) == 3


def test_initial_owner_lookup_failure_is_not_cached_as_missing_user(portal, monkeypatch, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("test-client-secret\n")
    for key, value in {"KEYCLOAK_URL": "https://kc.example.com", "KEYCLOAK_REALM": "openshell",
                       "KEYCLOAK_CLIENT_ID": "rhdh", "KEYCLOAK_SECRET_FILE": str(secret)}.items():
        monkeypatch.setenv(key, value)
    def unavailable(*args, **kwargs):
        raise portal.HttpError(401, "Keycloak users: HTTP 401")

    monkeypatch.setattr(portal, "keycloak_user_ids", unavailable)
    subjects = portal.OwnerSubjects(ttl=60)
    workspaces = [{"name": "alice", "ownerSubject": ""}]
    for _ in range(2):
        with pytest.raises(portal.PortalError, match="workspace projection held"):
            subjects.fill(workspaces)
    # A separately pinned explicit owner does not depend on failed discovery.
    explicit = [{"name": "bob", "ownerSubject": "operator-resolved-subject"}]
    assert subjects.fill(explicit) == explicit


def test_the_ca_bundle_holds_every_source_found(tmp_path, monkeypatch):
    """files/ca-bundle.py: system CAs, then the cluster's, the extra ones;
    a missing source is skipped (no service account here)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("ca_bundle", PORTAL.parent / "ca-bundle.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pem = "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n"
    (tmp_path / "system.crt").write_text(pem.format("SYSTEM"))
    (tmp_path / "trusted.crt").write_text(pem.format("TRUSTED"))
    (tmp_path / "extra.crt").write_text(pem.format("EXTRA"))
    monkeypatch.setattr(mod, "SYSTEM", (str(tmp_path / "system.crt"),))
    monkeypatch.setattr(mod, "SA_DIRS", (str(tmp_path / "no-sa"),))
    monkeypatch.setenv("TRUSTED_CA_FILE", str(tmp_path / "trusted.crt"))
    monkeypatch.setenv("EXTRA_CA_FILE", str(tmp_path / "extra.crt"))
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    out = tmp_path / "bundle.crt"
    assert mod.main(str(out)) == 0
    text = out.read_text()
    assert text.index("SYSTEM") < text.index("TRUSTED") < text.index("EXTRA")
    assert text.count("BEGIN CERTIFICATE") == 3


# -- deployment selection ------------------------------------------------------

def test_deployment_request_defaults_to_vm(portal, monkeypatch):
    monkeypatch.delenv("SAW_DEPLOYMENT_MODES", raising=False)
    assert portal.request_deployment_mode({}) == "vm"


@pytest.mark.parametrize("mode", ["container"])
def test_mode_requires_administrator_allowlist(portal, monkeypatch, mode):
    monkeypatch.delenv("SAW_DEPLOYMENT_MODES", raising=False)
    with pytest.raises(portal.PortalError, match="not enabled"):
        portal.request_deployment_mode({"deploymentMode": mode})
    monkeypatch.setenv("SAW_DEPLOYMENT_MODES", '["vm", "container"]')
    assert portal.request_deployment_mode({"deploymentMode": mode}) == mode


@pytest.mark.parametrize("mode", ["kata", "confidential", "typo", "", None, False, [], {}])
def test_unknown_or_malformed_mode_is_rejected(portal, mode):
    with pytest.raises(portal.PortalError):
        portal.request_deployment_mode({"deploymentMode": mode})


@pytest.mark.parametrize("raw", ["vm", "{}", "[]", '["container"]', '["vm","vm"]',
                                  '["vm",{}]', '["vm","confidential"]'])
def test_invalid_administrator_mode_policy_fails_closed(portal, monkeypatch, raw):
    monkeypatch.setenv("SAW_DEPLOYMENT_MODES", raw)
    with pytest.raises(portal.PortalError, match="SAW_DEPLOYMENT_MODES"):
        portal.request_deployment_mode({})


@pytest.mark.parametrize("mode", ["container"])
def test_unqualified_mode_refused_before_vault_even_when_allowlisted(portal, world, monkeypatch, mode):
    fake, signer = world
    monkeypatch.setenv("SAW_DEPLOYMENT_MODES", '["vm", "container"]')
    fake.request("saw-req-mode", ds_request(signer, deploymentMode=mode))
    assert portal.main(["create", "saw-req-mode"]) == 1
    assert not fake.vault and not fake.logins
    assert REGISTRY not in fake.objects


def test_mode_change_is_refused_before_any_credential_update(portal, world, monkeypatch):
    fake, signer = world
    fake.request("saw-req-1", ds_request(signer))
    assert portal.main(["create", "saw-req-1"]) == 0
    previous = json.dumps(fake.vault, sort_keys=True)
    monkeypatch.setenv("SAW_DEPLOYMENT_MODES", '["vm", "container"]')
    fake.request("saw-req-2", ds_request(signer, deploymentMode="container",
                                       **{"inference.api_key": "replacement"}))
    assert portal.main(["create", "saw-req-2"]) == 1
    assert json.dumps(fake.vault, sort_keys=True) == previous
    assert len(fake.logins) == 1
    assert portal.entry_deployment_mode(portal.read_entry(fake.objects[REGISTRY])) == "vm"


def test_concurrent_create_cannot_replace_a_different_mode(portal, world):
    fake, _ = world
    winner = portal.registry_entry("alice", "data-science", GEN[0], "container")
    portal.put_configmap(portal.kube(), "saw-portal", "saw-ws-alice",
                         {"user.json": json.dumps(winner)}, {portal.WORKSPACE_LABEL: "true"})
    stale = portal.registry_entry("alice", "data-science", GEN[1], "vm")
    with pytest.raises(portal.PortalError, match="immutable"):
        portal.put_configmap(portal.kube(), "saw-portal", "saw-ws-alice",
                             {"user.json": json.dumps(stale)}, deployment_mode="vm")
    assert portal.read_entry(fake.objects[REGISTRY]) == winner


@pytest.mark.parametrize("mode", ["vm", "container"])
def test_mode_serializes_through_registry_to_gitops(portal, mode):
    entry = portal.registry_entry("alice", "data-science", GEN[0], mode)
    if mode == "container":
        with pytest.raises(portal.PortalError, match="container site is missing"):
            portal.generator_params([entry], {})
        return
    [params] = portal.generator_params([entry], {"defaults": {"openshellSaw": {
        "deployment": {"mode": "container"}}}})
    values = json.loads(params["values"])
    assert values["users"][0]["values"]["deployment"]["mode"] == mode


def test_legacy_registry_mode_does_not_inherit_changed_chart_default(portal):
    entry = {"name": "alice", "profiles": ["data-science"]}
    [params] = portal.generator_params([entry], {"defaults": {"openshellSaw": {
        "deployment": {"mode": "container"}}}})
    assert json.loads(params["values"])["users"][0]["values"]["deployment"]["mode"] == "vm"
    assert "values" not in entry, "normalization must not mutate the input"


@pytest.mark.parametrize("mode", ["container"])
def test_unqualified_runtime_never_uses_vm_readiness(portal, mode):
    entry = portal.registry_entry("alice", "data-science", GEN[0], mode)
    class RegistryOnly:
        def call(self, method, path, **kwargs):
            assert method == "GET" and path == REGISTRY
            return {"metadata": {"name": "saw-ws-alice"},
                    "data": {"user.json": json.dumps(entry)}}
    status = portal.workspace_status(RegistryOnly(), "alice", {}, "saw-portal", "vp-gitops", "example.test")
    assert status["phase"] == "runtime-not-qualified"
    assert status["ready"] is False and status["failed"] is True
    assert not status["links"]


def test_linked_container_catalog_entry_is_owned_and_links_only_to_the_site(portal, catalog, monkeypatch):
    monkeypatch.setenv("SAW_LINKED_WORKSPACES", json.dumps([{"owner":"alice","routeLabel":"alice-agent-ui","title":"OpenClaw"}]))
    docs = entity_docs(portal.entities_yaml([], catalog, "example.com", ""))
    entry = next(d for d in docs if d["metadata"]["name"] == "linked-alice-agent-ui")
    assert entry["spec"]["owner"] == "user:default/alice"
    assert entry["metadata"]["links"] == [{"title":"OpenClaw UI","icon":"web","url":"https://alice-agent-ui.apps.example.com"}]


def test_linked_runtime_tracks_owner_and_current_generation(portal):
    ref = {"namespace":"runtime", "intent":"intent", "status":"status", "installationID":"instance",
           "ownerSubject":"subject", "mode":"container"}
    status = {"phase":"GenericReady", "observedGeneration":3}
    intent = {"generation":3, "desiredState":"Running", "bindings":{
        "namespace":"runtime", "ownerID":"instance", "ownerSubject":"subject", "mode":"container"}}
    class Reader:
        def call(self, method, path, ok404):
            assert method == "GET" and ok404
            assert path in ["/api/v1/namespaces/runtime/configmaps/" + n for n in ("intent","status")]
            n = path.rsplit("/", 1)[1]
            labels = {"saw.redhat.com/runtime-owner":"instance"}
            if n == "status":
                labels["saw.redhat.com/managed-by"] = "kubernetes-runtime-controller"
            return {"metadata":{"labels":labels}, "data":{n+".json":json.dumps(intent if n=="intent" else status)}}
    reader = Reader()
    assert portal.linked_runtime_phase(reader, {"runtime":ref}) == "Running"
    intent["generation"] += 1
    assert portal.linked_runtime_phase(reader, {"runtime":ref}) == "Reconciling"
    intent["bindings"]["ownerSubject"] = "someone-else"
    assert portal.linked_runtime_phase(reader, {"runtime":ref}) == "Unknown"


@pytest.mark.parametrize("fault,expected", [
    ("profile", "approved profiles: audited-openclaw"),
    ("cleanup", "enable portal.pruneOnRemove"),
])
def test_container_preflight_explains_profile_and_cleanup_failures(portal, world, monkeypatch, capsys, fault, expected):
    fake, signer = world
    monkeypatch.setenv("SAW_DEPLOYMENT_MODES", '["vm","container"]')
    monkeypatch.setenv("SAW_CONTAINER_SITES", json.dumps({"alice": {
        "subject": "478fdd1f-8db9-41e8-97ad-b563215c89e9", "automaticEnrollment": {"approvedProfiles": {"audited-openclaw": "a"*64}}}}))
    monkeypatch.setenv("PRUNE_ON_REMOVE", "false" if fault == "cleanup" else "true")
    fake.request("saw-req-rejected", ds_request(signer, deploymentMode="container",
        profile="data-science" if fault == "profile" else "audited-openclaw"))
    assert portal.main(["create", "saw-req-rejected"]) != 0
    captured = capsys.readouterr()
    assert expected in captured.out + captured.err
    assert not fake.vault and REGISTRY not in fake.objects


def test_container_portal_register_update_delete(portal, world, monkeypatch):
    fake, signer = world
    subject = "478fdd1f-8db9-41e8-97ad-b563215c89e9"
    monkeypatch.setenv("SAW_DEPLOYMENT_MODES", '["vm","container"]')
    monkeypatch.setenv("SAW_CONTAINER_SITES", json.dumps({"alice":{"subject":subject,"automaticEnrollment":{"approvedProfiles":{"audited-openclaw":"a"*64}}}}))
    for i in [1, 2]:
        fake.request("saw-req-" + str(i), ds_request(signer, deploymentMode="container",
                    profile="audited-openclaw", **{"inference.api_key":f"test-{i}"}))
        assert portal.main(["create", "saw-req-" + str(i)]) == 0
        entry = portal.read_entry(fake.objects[REGISTRY])
        assert entry["intentGeneration"] == i and portal.entry_generation("alice", entry) == GEN[0]
        assert fake.vault == {f"{KEYS}/inference":{"api_key":f"test-{i}", "provider":"openai"}}
        assert portal.generator_params([{**entry,"ownerSubject":"other-subject"}], {}) == []
        output = portal.generator_params([{**entry,"ownerSubject":subject}], {},
                                         catalog=portal.load_catalog(os.environ["CATALOG_PATH"]))[0]
        user = json.loads(output["values"])["users"][0]
        assert user["installationID"] == portal.installation_id("alice", GEN[0])
        assert "test-" not in output["values"]
    fake.request("saw-req-3", {"token":signer.token(), "action":"delete", "workspace":"component:default/saw-alice"})
    assert portal.main(["delete","saw-req-3"]) == 0
    ns = f"/api/v1/namespaces/saw-ctl-{GEN[0]}"
    fake.objects[ns] = {"metadata":{"name":ns.split("/")[-1]}}
    gone, detail = portal.removal_status(portal.kube(), "alice", "vp-gitops", entry)
    assert not gone and ns.split("/")[-1] in detail
    del fake.objects[ns]
    assert portal.removal_status(portal.kube(), "alice", "vp-gitops", entry)[0]
    assert portal.main(["finish-delete","alice"]) == 0
    assert not fake.vault and REGISTRY not in fake.objects

@pytest.mark.parametrize("mode,ready", [("registered",True),("pending",False),("wrong-client",False),("foreign",False),("anonymous-chat",False)])
def test_chat_readiness_requires_registered_owner_callback(portal, monkeypatch, mode, ready):
    import io
    from urllib.error import HTTPError
    from urllib.parse import urlencode
    origin, issuer = "https://chat.test", "https://id.test"
    monkeypatch.setenv("KEYCLOAK_URL",issuer)
    monkeypatch.setenv("KEYCLOAK_REALM","openshell")
    class Response(io.BytesIO):
        status = 200
    class Opener:
        def open(self, url, timeout):
            if url==origin:
                if mode=="anonymous-chat": return Response(b"chat")
                params=urlencode(dict(client_id=("wrong" if mode=="wrong-client" else "openshell-dashboard"),redirect_uri=origin+"/oauth2/callback"))
                host="https://other.test" if mode=="foreign" else issuer
                raise HTTPError(url,302,"",{"Location":host+"/realms/openshell/protocol/openid-connect/auth?"+params},None)
            assert url.startswith(issuer)
            if mode=="pending": raise HTTPError(url,400,"Invalid redirect URI",{},None)
            return Response(b'<form id="kc-form-login">')
    monkeypatch.setattr(portal.urllib.request,"build_opener",lambda *args:Opener())
    assert portal.owner_route_available(origin) is ready


def test_generator_publishes_only_immutable_owner_bound_data(portal):
    reg="a"*16; owner="9aaea20f-245f-407a-a0c3-fbd894615b90"
    sub="e05c1559-5009-4663-81fb-3c5facb5ced8"
    ws=dict(name="ada",registration=reg,installationID=owner,ownerSubject=sub)
    a=dict(image="pinned@sha256:abc",revision="fixed",buildNamespace="trust",profileSHA256="bom",
           reference={"gateway":{}},relay={"issuer":"https://issuer","revision":"fixed"})
    site={"automaticEnrollment":a}
    intent=dict(bindings=dict(ownerID=owner,namespace="saw-ada",ownerSubject=sub),profileRef=dict(sha256="bom"))
    body=dict(registration=reg,intent=intent,approved={"gateway":{}},gatewayCA="public")
    meta={"labels":{"saw.redhat.com/runtime-owner":owner}}
    cm=dict(immutable=True,metadata=meta,data={})
    relay=dict(immutable=True,metadata=meta,data={"subject":"e5ed3695-4476-4b1f-8e5d-daf5f6ccfae3"})
    def read(path):
        assert path.startswith("/api/v1/namespaces/saw-ctl-"+reg+"/configmaps/")
        cm["data"]={"binding.json":json.dumps(body)}
        return relay if path.endswith("relay-subject") else cm
    assert portal.enrolled_site(site,ws,read)["enrollment"]["relay"]["subject"]==relay["data"]["subject"]
    body["revision"]="caller-controlled"
    with pytest.raises(portal.PortalError):portal.enrolled_site(site,ws,read)
    del body["revision"]
    cm["immutable"]=False
    with pytest.raises(portal.PortalError):portal.enrolled_site(site,ws,read)
    cm["immutable"]=True;intent["bindings"]["ownerID"]="foreign"
    with pytest.raises(portal.PortalError):portal.enrolled_site(site,ws,read)

def test_model_input_cannot_publish_a_submitted_credential(portal):
    profile={"workspaces":[{"name":"research","enabled":True,"sandboxes":[
        {"name":"notebook","enabled":True,"modelInput":"provider.choice"}]}],
        "secrets":{"provider":{"fields":[{"key":"choice","kind":"text"},{"key":"api_key","kind":"secret"}]}}}
    inputs={"provider":{"api_key":"synthetic-private-value","choice":"model-x"}}
    assert portal.public_model_inputs(profile, inputs)=={"provider.choice":"model-x"}
    inputs["provider"]["choice"]=inputs["provider"]["api_key"]
    with pytest.raises(portal.PortalError,match="invalid public model selector"):
        portal.public_model_inputs(profile, inputs)


@pytest.mark.parametrize("field", ["model", "cuda_model"])
def test_public_nvidia_selector_uses_its_catalog_field(portal, field):
    catalog = json.loads((PORTAL.parent / "profile-catalog.json").read_text())
    profile = catalog["profiles"]["data-science"]
    default = next(f["default"] for f in profile["secrets"]["inference"]["fields"]
                   if f["key"] == field)
    assert "/" in default
    inputs = {"inference": {field: default, "api_key": "private-test-key"}}
    assert portal.public_model_inputs(profile, inputs) == {"inference." + field: default}
    for invalid in ("unapproved/model", "https://malicious.test/model", inputs["inference"]["api_key"]):
        inputs["inference"][field] = invalid
        with pytest.raises(portal.PortalError, match="invalid public model selector"):
            portal.public_model_inputs(profile, inputs)


def test_owner_state_change_is_generation_scoped_and_does_not_touch_vault(portal, world, monkeypatch):
    fake, signer = world
    site = {"subject": "478fdd1f-8db9-41e8-97ad-b563215c89e9", "modelLifecycle": True, "automaticEnrollment":{"approvedProfiles":{"audited-openclaw":"a"*64}}}
    monkeypatch.setenv("SAW_DEPLOYMENT_MODES", '["vm","container"]')
    monkeypatch.setenv("SAW_CONTAINER_SITES", json.dumps({"alice": site}))
    fake.request("saw-req-1", ds_request(signer, deploymentMode="container", profile="audited-openclaw"))
    assert portal.main(["create", "saw-req-1"]) == 0
    entry = portal.read_entry(fake.objects[REGISTRY])
    registration = portal.entry_generation("alice", entry)
    vault_before = json.dumps(fake.vault, sort_keys=True)
    def state(name, operation, generation, **extra):
        fake.request(name, {"action": "create", "token": signer.token(), "runtimeAction": operation,
                            "registration": registration, "expectedGeneration": "g-" + str(generation), **extra})
        return portal.main(["create", name])
    assert state("saw-req-2", "stop", 1, forUser="bob") != 0
    assert state("saw-req-3", "stop", 1, registration="0"*16) != 0
    assert state("saw-req-4", "stop", 1) == 0
    assert portal.read_entry(fake.objects[REGISTRY])["desiredState"] == "Stopped"
    assert state("saw-req-5", "start", 1) != 0
    assert state("saw-req-6", "start", 2) == 0
    assert portal.read_entry(fake.objects[REGISTRY]) == {**entry, "intentGeneration": 3}
    assert json.dumps(fake.vault, sort_keys=True) == vault_before


def test_custom_endpoint_is_approved_before_writing_vault(portal, world, monkeypatch):
    fake, signer = world
    url="https://models.fixture.test/v1"
    boundary={"allowHosts":["models.fixture.test"],"inferenceBaseURL":url}
    site={"subject":"478fdd1f-8db9-41e8-97ad-b563215c89e9","profileBoundaries":{"custom-inference":boundary},
          "automaticEnrollment":{"approvedProfiles":{"custom-inference":"a"*64}}}
    monkeypatch.setenv("SAW_DEPLOYMENT_MODES",'["vm","container"]')
    monkeypatch.setenv("SAW_CONTAINER_SITES",json.dumps({"alice":site}))
    def submit(name,endpoint):
        request = ds_request(signer,deploymentMode="container",profile="custom-inference",
                             **{"inference.url":endpoint,"inference.model":"org/model","inference.api_key":"private-test-key"})
        request.pop("web-search.api_key")
        fake.request(name,request)
        return portal.main(["create",name])
    assert submit("saw-req-bad","https://elsewhere.example/v1") != 0
    assert not fake.vault and REGISTRY not in fake.objects
    assert submit("saw-req-good",url) == 0
    entry=portal.read_entry(fake.objects[REGISTRY])
    assert entry["customInferenceURL"]==url and entry["modelInputs"]=={"inference.model":"org/model"}
    assert "private-test-key" not in json.dumps(entry)
    assert entry["webSearch"] == {"enabled":False} and not any("web-search" in k for k in fake.vault)


def test_headless_container_requires_current_runtime_and_healthy_argo(portal, monkeypatch):
    import hashlib
    reg="0123456789abcdef"
    subject="478fdd1f-8db9-41e8-97ad-b563215c89e9"
    monkeypatch.setenv("SAW_CONTAINER_SITES",json.dumps({"alice":{"subject":subject,"automaticEnrollment":{"approvedProfiles":{"audited-openclaw":"a"*64}}}}))
    entry=portal.registry_entry("alice","custom-inference",reg,"container")
    entry["intentGeneration"]=1
    install=portal.installation_id("alice",reg)
    digest=lambda value: hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    files={"fixture":"profile"}
    intent={"generation":1,"desiredState":"Running","profileRef":{"name":"saw-bom-profiles","uid":"bom","sha256":digest(files)},
            "bindings":{"ownerSubject":subject,"namespace":"saw-alice","mode":"container","ownerID":install}}
    state={"phase":"GenericReady","observedGeneration":1,"inputRevision":digest({"intent":intent,"files":files})}
    def cm(key,value):
        return {"metadata":{"labels":{"saw.redhat.com/runtime-owner":install,"saw.redhat.com/managed-by":"kubernetes-runtime-controller"}},
                "data":{key:json.dumps(value)}}
    objects={"saw-alice":{"metadata":{"labels":{"openshell.pattern/owner":"alice"}},
                          "status":{"sync":{"status":"Synced"},"health":{"status":"Healthy"}}},
             "saw-runtime-intent":cm("intent.json",intent),"saw-runtime-status":cm("status.json",state),
             "saw-bom-profiles":{"metadata":{"uid":"bom"},"data":files}}
    class Reader:
        def call(self,method,path,ok404):
            return objects[path.rsplit("/",1)[1]]
    profile=json.loads((ROOT/"charts/saw-users/files/profile-catalog.json").read_text())["profiles"]
    def status():
        return portal.container_status(Reader(),"alice",entry,"argo","example.test",
                                       lambda _: pytest.fail("headless registration has no route"),profile)
    assert status()["ready"] and not status()["links"]
    objects["saw-runtime-status"]=cm("status.json",{**state,"observedGeneration":0})
    assert not status()["ready"]


def test_recycled_container_login_cannot_write_or_delete(portal, world, monkeypatch):
    fake, signer = world
    monkeypatch.setenv("SAW_DEPLOYMENT_MODES", '["vm","container"]')
    monkeypatch.setenv("SAW_CONTAINER_SITES", json.dumps({"alice":{
        "subject":"478fdd1f-8db9-41e8-97ad-b563215c89e9",
        "automaticEnrollment":{"approvedProfiles":{"audited-openclaw":"a"*64}}}}))
    fake.request("saw-req-owner", ds_request(signer, deploymentMode="container", profile="audited-openclaw"))
    assert portal.main(["create","saw-req-owner"]) == 0
    before = json.dumps([fake.vault, fake.objects[REGISTRY]], sort_keys=True)
    monkeypatch.setattr(portal, "keycloak_user_ids", lambda *a, **kw: {"alice":"different-subject"})
    for action in ["create","delete"]:
        data = ds_request(signer, deploymentMode="container", profile="audited-openclaw")
        fake.request("saw-req-reused", {**data, "action":action})
        assert portal.main([action,"saw-req-reused"]) == 1
        assert json.dumps([fake.vault, fake.objects[REGISTRY]], sort_keys=True) == before


def test_failed_vault_write_retains_reserved_generation(portal, world, monkeypatch):
    fake, signer = world
    monkeypatch.setenv("SAW_DEPLOYMENT_MODES", '["vm","container"]')
    monkeypatch.setenv("SAW_CONTAINER_SITES", json.dumps({"alice":{
        "subject":"478fdd1f-8db9-41e8-97ad-b563215c89e9",
        "automaticEnrollment":{"approvedProfiles":{"audited-openclaw":"a"*64}}}}))
    real = portal.vault_client
    def unavailable():
        raise portal.PortalError("simulated Vault outage")
    monkeypatch.setattr(portal, "vault_client", unavailable)
    data = ds_request(signer, deploymentMode="container", profile="audited-openclaw")
    fake.request("saw-req-reserve", data)
    assert portal.main(["create","saw-req-reserve"]) == 1
    entry = portal.read_entry(fake.objects[REGISTRY])
    assert portal.entry_generation("alice", entry) == GEN[0]
    assert not fake.vault
    assert portal.list_workspaces(portal.kube(), "saw-portal") == []
    assert portal.list_workspaces(portal.kube(), "saw-portal", deleting=True) == [entry]
    monkeypatch.setattr(portal, "vault_client", real)
    fake.request("saw-req-resume", data)
    assert portal.main(["create","saw-req-resume"]) == 0
    assert portal.entry_generation("alice", portal.read_entry(fake.objects[REGISTRY])) == GEN[0]
    assert list(fake.vault) == [f"{KEYS}/inference"]


def test_incomplete_update_holds_last_committed_projection_and_exposes_retry(portal, world, monkeypatch):
    fake, signer = world
    fake.request("saw-req-initial", ds_request(signer))
    assert portal.main(["create", "saw-req-initial"]) == 0
    previous = portal.read_entry(fake.objects[REGISTRY])
    update = {**previous, "profiles": ["different"]}  # only public registration data
    pending = portal.reserve_credentials(portal.kube(), "saw-portal", "saw-ws-alice", fake.objects[REGISTRY], update, "alice")
    assert portal.list_workspaces(portal.kube(), "saw-portal") == [previous]
    assert portal.list_workspaces(portal.kube(), "saw-portal", deleting=True) == [update]
    holder = pending["metadata"]["annotations"][portal.CREDENTIAL_WRITER]
    run_path = "/apis/tekton.dev/v1/namespaces/saw-portal/pipelineruns/" + holder
    for run, phase in [({}, "failed"), ({"metadata":{"name":holder}}, "publishing"),
                       ({"status":{"conditions":[{"type":"Succeeded","status":"False"}]}}, "failed")]:
        if run:
            fake.objects[run_path] = run
        assert portal.workspace_status(portal.kube(), "alice", {}, "saw-portal", "argo", "")["phase"] == phase
    retry = portal.reserve_credentials(portal.kube(), "saw-portal", "saw-ws-alice", pending, update, "alice")
    assert portal.committed_entry(retry) == previous


def test_catalog_probe_is_async_bounded_and_scoped_to_registration(portal):
    cache = portal.CatalogRouteCache(workers=2, capacity=4, ttl=30)
    release = threading.Event()
    calls = []
    def slow(url):
        calls.append(url)
        return release.wait(5)
    try:
        for n in range(40):
            assert not cache.probe(("owner","registration"), f"https://route-{n}", slow)
        assert len(cache.entries) == 4
        release.set()
        for future in cache.entries.values():
            assert future.result(timeout=5)[1]
        assert cache.probe(("owner","registration"), "https://route-0", slow)
        assert not cache.probe(("owner","new-registration"), "https://route-0", slow)
    finally:
        release.set()
        cache.pool.shutdown()


def test_dedicated_endpoint_excludes_renamed_and_additional_tool_secrets(portal, monkeypatch):
    monkeypatch.setenv("SAW_DEPLOYMENT_MODES", '["vm","container"]')
    profile = {"workspaces": [], "dedicatedEndpointSecrets":["model"],
               "secrets":{key:{"provider":"test","providers":["test"],"fields":[
                   {"key":"api_key","kind":"secret","required":True}]}
                   for key in ("model","search-renamed","another-tool")}}
    data = {"profile":"p","deploymentMode":"container","model.api_key":"fixture"}
    _, values = portal.parse_request(data, {"p":profile})
    assert set(values) == {"model"}
    with pytest.raises(portal.PortalError, match="search-renamed"):
        portal.parse_request({**data,"deploymentMode":"vm"}, {"p":profile})


@pytest.mark.parametrize("mode,stage,expected", [
    ("container", "vm", 1800), ("vm", "vm", 600), ("container", "running", 600)
])
def test_enrollment_budget_only_extends_the_container_intent_wait(portal, world, monkeypatch, mode, stage, expected):
    created(portal, world)
    monkeypatch.setenv("SAW_CONTAINER_ENROLLMENT_SECONDS", "1800")
    monkeypatch.setattr(portal, "workspace_status", lambda *args: {
        "deploymentMode": mode, "failed": False, "message": "pending",
        "steps": [{"id": stage, "state": "active", "detail": "pending"}],
    })
    now = [0]
    with pytest.raises(portal.PortalError, match=f"not done after {expected // 60} minutes"):
        portal.wait_stage(stage, "alice", 600, sleep=lambda _: now.__setitem__(0, now[0] + 600), clock=lambda: now[0])
    assert now == [expected]
