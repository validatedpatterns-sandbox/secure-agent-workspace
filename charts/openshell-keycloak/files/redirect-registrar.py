#!/usr/bin/env python3
"""Keep the dashboard client's redirect URIs in step with the SAW web UIs.

Every SAW web UI (a VM's OpenShell dashboard) has its own route host, and
Keycloak matches redirect URIs exactly except for a trailing wildcard, so
each host must be registered on the shared dashboard client. This runs once
per cluster, in Keycloak's namespace, instead of in every user's namespace:
no user namespace needs Keycloak admin credentials.

  bootstrap  (init container) As the master admin: make sure the realm has
             the confidential client CLIENT_ID with a service account that
             may manage the realm's clients (realm-management/manage-clients,
             nothing in the master realm), and write its secret to OUT.
  run        As that service account, every INTERVAL seconds: the redirect
             URIs and web origins of the routes labelled ROUTE_SELECTOR in
             namespaces labelled NAMESPACE_SELECTOR, whose host is under
             HOST_SUFFIX (default: the cluster's ingress domain), are set on
             DASHBOARD_CLIENT_ID. Entries this registrar added for routes
             that are gone are removed; entries it did not add are kept.

A route's redirect path is /oauth2/callback (oauth2-proxy), or its
annotation saw.redhat.com/oidc-redirect-path.

Env: KC_URL, REALM, CLIENT_ID; bootstrap: ADMIN_DIR (username, password
files), OUT; run: SECRET_FILE, DASHBOARD_CLIENT_ID, NAMESPACE_SELECTOR,
ROUTE_SELECTOR, HOST_SUFFIX, INTERVAL. Standard library only.
"""
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import saw_tls

SA = "/var/run/secrets/kubernetes.io/serviceaccount"
# The URIs and origins this registrar set, so it removes only its own.
MANAGED_ATTRIBUTE = "saw.redhat.com/managed-redirects"
PATH_ANNOTATION = "saw.redhat.com/oidc-redirect-path"
DEFAULT_PATH = "/oauth2/callback"
HOST_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")
PATH_RE = re.compile(r"(/[A-Za-z0-9._~-]+)+")


def log(msg):
    print(f"[redirect-registrar] {msg}", flush=True)


class HttpError(OSError):
    """An OSError so saw_tls.tls_context treats it as a failed cluster read."""

    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def call(url, method="GET", body=None, token=None, form=None, ctx=None, ok404=False):
    require_https(url)
    req = urllib.request.Request(url, method=method)
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    elif body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                             saw_tls.NoRedirect())
        with opener.open(req, data=data, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        if ok404 and exc.code == 404:
            return None
        # The URL only: a body could hold a secret.
        raise HttpError(exc.code, f"{method} {url.split('?')[0]}: HTTP {exc.code}") from None


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None or value == "":
        if default is not None:
            return default
        raise SystemExit(f"{name} is not set")
    return value


def require_https(url):
    return saw_tls.require_https(url)


def tls_context(url):
    return saw_tls.tls_context(url, Kube().get, log, os.environ.get("CA_FILE"))


def keycloak_url():
    return saw_tls.keycloak_url(env("KEYCLOAK_NAME"), env("KEYCLOAK_NAMESPACE"), Kube().get)


class Keycloak:
    """The admin API of one realm, with a token from `grant`."""

    def __init__(self, url, realm, token_realm, form):
        self.url, self.realm = (url or keycloak_url()).rstrip("/"), realm
        self.ctx = tls_context(self.url)
        self.token = call(f"{self.url}/realms/{token_realm}/protocol/openid-connect/token", "POST",
                          form=form, ctx=self.ctx)["access_token"]

    def __call__(self, method, path, body=None, ok404=False):
        return call(f"{self.url}/admin/realms/{self.realm}{path}", method, body, self.token,
                    ctx=self.ctx, ok404=ok404)

    def client(self, client_id):
        found = [c for c in self("GET", "/clients?clientId=" + urllib.parse.quote(client_id)) or []
                 if c.get("clientId") == client_id]
        return found[0] if found else None


# -- bootstrap -------------------------------------------------------------------------

REGISTRAR_CLIENT = {
    "protocol": "openid-connect", "publicClient": False, "clientAuthenticatorType": "client-secret",
    "serviceAccountsEnabled": True, "standardFlowEnabled": False, "implicitFlowEnabled": False,
    "directAccessGrantsEnabled": False,
    "description": "SAW redirect registrar: keeps the dashboard client's redirect URIs in step "
                   "with the SAW web UI routes",
}


def bootstrap():
    url, realm, client_id = env("KC_URL", ""), env("REALM"), env("CLIENT_ID")
    admin = env("ADMIN_DIR")
    user = open(os.path.join(admin, "username"), encoding="utf-8").read().strip()
    password = open(os.path.join(admin, "password"), encoding="utf-8").read().strip()
    deadline = time.monotonic() + int(env("BOOTSTRAP_TIMEOUT", "1800"))
    while True:
        try:
            kc = Keycloak(url, realm, "master", {"grant_type": "password", "client_id": "admin-cli",
                                                 "username": user, "password": password})
            if kc("GET", "", ok404=True) is None:
                raise HttpError(404, f"realm {realm} is not imported yet")
            break
        except (HttpError, OSError, KeyError, ValueError) as exc:
            if time.monotonic() > deadline:
                raise SystemExit(f"Keycloak at {url} not ready: {exc}") from None
            log(f"waiting for Keycloak: {exc}")
            time.sleep(10)
    client = kc.client(client_id)
    if client is None:
        kc("POST", "/clients", {"clientId": client_id, **REGISTRAR_CLIENT})
        client = kc.client(client_id)
        log(f"client {client_id} created")
    elif any(client.get(k) != v for k, v in REGISTRAR_CLIENT.items() if k != "description"):
        kc("PUT", f"/clients/{client['id']}", {**client, **REGISTRAR_CLIENT})
        log(f"client {client_id} settings restored")
    account = kc("GET", f"/clients/{client['id']}/service-account-user")
    management = kc.client("realm-management")
    role = kc("GET", f"/clients/{management['id']}/roles/manage-clients")
    have = kc("GET", f"/users/{account['id']}/role-mappings/clients/{management['id']}") or []
    if not any(r.get("name") == "manage-clients" for r in have):
        kc("POST", f"/users/{account['id']}/role-mappings/clients/{management['id']}", [role])
        log(f"{client_id} may manage the clients of realm {realm}")
    secret = kc("GET", f"/clients/{client['id']}/client-secret")["value"]
    out = env("OUT")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secret)
    log(f"{client_id} ready")


# -- run ---------------------------------------------------------------------------------

class Kube:
    def __init__(self):
        host, port = os.environ["KUBERNETES_SERVICE_HOST"], os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.base = f"https://{host}:{port}"
        self.token = open(f"{SA}/token", encoding="utf-8").read().strip()
        self.ctx = ssl.create_default_context(cafile=f"{SA}/ca.crt")

    def get(self, path):
        return call(self.base + path, token=self.token, ctx=self.ctx)


def selector(value):
    key, _, val = value.partition("=")
    if not key or not val:
        raise SystemExit(f"selector {value!r} is not key=value")
    return urllib.parse.quote(f"{key}={val}")


def wanted(kube, namespace_selector, route_selector, suffix):
    """The redirect URIs and web origins of the labelled routes in SAW
    namespaces whose host is under `suffix`, and the hosts of all routes in
    SAW namespaces, labelled or not (still in use: see reconcile)."""
    namespaces = {n["metadata"]["name"] for n in
                  kube.get(f"/api/v1/namespaces?labelSelector={selector(namespace_selector)}").get("items", [])}
    present = {(r.get("spec") or {}).get("host", "")
               for r in kube.get("/apis/route.openshift.io/v1/routes").get("items", [])
               if (r.get("metadata") or {}).get("namespace") in namespaces}
    routes = kube.get(f"/apis/route.openshift.io/v1/routes?labelSelector={selector(route_selector)}")
    uris, origins = set(), set()
    for route in routes.get("items", []):
        meta = route.get("metadata") or {}
        where = f"{meta.get('namespace')}/{meta.get('name')}"
        if meta.get("namespace") not in namespaces:
            log(f"route {where}: not in a SAW namespace ({namespace_selector}); ignored")
            continue
        host = (route.get("spec") or {}).get("host", "")
        if not (HOST_RE.fullmatch(host) and host.endswith(suffix) and len(host) > len(suffix)):
            log(f"route {where}: host {host!r} is not under {suffix}; ignored")
            continue
        path = (meta.get("annotations") or {}).get(PATH_ANNOTATION) or DEFAULT_PATH
        if not PATH_RE.fullmatch(path) or "/../" in path + "/" or "/./" in path + "/":
            log(f"route {where}: redirect path {path!r} is not a plain path; ignored")
            continue
        uris.add(f"https://{host}{path}")
        origins.add(f"https://{host}")
    return uris, origins, present - {""}


def under(entry, suffix):
    parsed = urllib.parse.urlsplit(entry)
    return parsed.scheme == "https" and (parsed.hostname or "").endswith(suffix)


def reconcile(client, uris, origins, suffix, present=frozenset()):
    """The client with its redirect URIs and web origins brought in step,
    or None when nothing changes. The first run adopts the entries under
    `suffix` that the per-VM Jobs registered before, so the ones of VMs
    that are gone get removed too.

    An entry is removed only when no route in a SAW namespace has its host
    any more (`present`). A route that is there but not (yet) labelled
    keeps its entry: during a rollout the registrar starts before the SAW
    apps relabel their routes, and dropping their entries then would break
    those users' sign-in until their app synced."""
    attributes = dict(client.get("attributes") or {})
    current_uris, current_origins = client.get("redirectUris") or [], client.get("webOrigins") or []
    try:
        managed = json.loads(attributes[MANAGED_ATTRIBUTE])
    except (KeyError, ValueError, TypeError):
        managed = {"redirectUris": [u for u in current_uris if under(u, suffix)],
                   "webOrigins": [o for o in current_origins if under(o, suffix)]}

    def kept(current, mine, want):
        # Mine and still on the client, not wanted, but its route is still there.
        return {e for e in set(mine) & set(current) - want
                if urllib.parse.urlsplit(e).hostname in present}

    keep_uris = kept(current_uris, managed.get("redirectUris") or [], uris)
    keep_origins = kept(current_origins, managed.get("webOrigins") or [], origins)
    new_uris = sorted((set(current_uris) - set(managed.get("redirectUris") or [])) | uris | keep_uris)
    new_origins = sorted((set(current_origins) - set(managed.get("webOrigins") or [])) | origins | keep_origins)
    record = json.dumps({"redirectUris": sorted(uris | keep_uris),
                         "webOrigins": sorted(origins | keep_origins)}, sort_keys=True)
    if (new_uris == sorted(current_uris) and new_origins == sorted(current_origins)
            and attributes.get(MANAGED_ATTRIBUTE) == record):
        return None
    attributes[MANAGED_ATTRIBUTE] = record
    return {**client, "redirectUris": new_uris, "webOrigins": new_origins, "attributes": attributes}


def ingress_domain(kube):
    return saw_tls.ingress_domain(kube.get)


def sync(kube, suffix):
    uris, origins, present = wanted(kube, env("NAMESPACE_SELECTOR"), env("ROUTE_SELECTOR"), suffix)
    secret = open(env("SECRET_FILE"), encoding="utf-8").read().strip()
    kc = Keycloak(env("KC_URL", ""), env("REALM"), env("REALM"),
                  {"grant_type": "client_credentials", "client_id": env("CLIENT_ID"), "client_secret": secret})
    name = env("DASHBOARD_CLIENT_ID")
    found = kc.client(name)
    if found is None:
        raise HttpError(404, f"client {name} not found in realm {env('REALM')}")
    client = kc("GET", f"/clients/{found['id']}")
    updated = reconcile(client, uris, origins, suffix, present)
    if updated is None:
        return False
    added = sorted(set(updated["redirectUris"]) - set(client.get("redirectUris") or []))
    removed = sorted(set(client.get("redirectUris") or []) - set(updated["redirectUris"]))
    kc("PUT", f"/clients/{found['id']}", updated)
    log(f"{name}: {len(uris)} SAW redirect URIs"
        + (f"; added {', '.join(added)}" if added else "") + (f"; removed {', '.join(removed)}" if removed else ""))
    return True


def run(once=False):
    kube = Kube()
    interval = int(env("INTERVAL", "15"))
    suffix = os.environ.get("HOST_SUFFIX", "")
    if suffix and not suffix.startswith("."):
        suffix = "." + suffix
    while True:
        try:
            if not suffix:
                suffix = "." + ingress_domain(kube)
                log(f"route hosts must be under {suffix}")
            sync(kube, suffix)
        except (HttpError, OSError, KeyError, ValueError) as exc:
            # Nothing is removed on an error: a failed list is not an empty one.
            log(f"WARN: {exc}; retrying in {interval}s")
            if once:
                raise
        if once:
            return
        time.sleep(interval)


def main(argv):
    if argv[1:2] == ["bootstrap"]:
        bootstrap()
    elif argv[1:2] == ["run"]:
        run(once="--once" in argv)
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
