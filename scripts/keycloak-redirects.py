#!/usr/bin/env python3
"""Redirect URIs of the SAW web UIs on Keycloak's dashboard client, set by an
administrator (make keycloak-register, make keycloak-redirects-sync).

Every web UI (a VM's dashboard, each sandbox UI) has its own route host, and
Keycloak matches redirect URIs exactly except for a trailing wildcard, so
each host is registered on the dashboard client. The redirect registrar in
Keycloak's namespace does it by default, with the same rules as `sync`; with
it off (redirectRegistrar.enabled: false), an administrator runs this, with
their own oc session and Keycloak's admin Secret, as for
scripts/keycloak-users.sh. With another OIDC issuer, `list` shows what to
register there.

  list             The client's redirect URIs, and the SAW web UI routes that
                   have none yet.
  register USER    Add the redirect URIs of saw-USER's web UI routes, waiting
                   up to WAIT seconds (default 600) for the routes to exist.
  sync             Every SAW workspace: add what is missing, and remove the
                   entries this script added whose route is gone from every
                   SAW namespace. Entries it did not add are kept; the first
                   sync adopts the ones under the cluster domain, so those of
                   removed workspaces are cleaned up.

A web UI route is a route labelled ROUTE_SELECTOR in a namespace labelled
NAMESPACE_SELECTOR whose host is under the cluster's ingress domain. Its
redirect URI is https://<host>/oauth2/callback (oauth2-proxy), or its
annotation saw.redhat.com/oidc-redirect-path; its web origin https://<host>.

Env: KEYCLOAK_NS (saw-keycloak), KEYCLOAK_NAME (openshell-keycloak),
KEYCLOAK_REALM (openshell), DASHBOARD_CLIENT_ID (openshell-dashboard),
NAMESPACE_SELECTOR (openshell.pattern/saw=true), ROUTE_SELECTOR
(saw.redhat.com/oidc-redirect=true), HOST_SUFFIX (default: the ingress
domain), WAIT (600), OIDC_CA_BUNDLE (an explicit CA bundle; KEYCLOAK_CA
is also accepted). Cluster ingress CAs are discovered through oc.
"""
import base64
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli" / "src"))
from openshell_saw import tls

MANAGED_ATTRIBUTE = "saw.redhat.com/managed-redirects"
PATH_ANNOTATION = "saw.redhat.com/oidc-redirect-path"
DEFAULT_PATH = "/oauth2/callback"
HOST_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")
PATH_RE = re.compile(r"(/[A-Za-z0-9._~-]+)+")
USER_RE = re.compile(r"[a-z]([a-z0-9-]{0,17}[a-z0-9])?")


def env(name, default):
    return os.environ.get(name) or default


class Error(Exception):
    pass


# -- the cluster (oc) ----------------------------------------------------------------------

def oc_json(*args):
    out = subprocess.run(["oc", *args, "-o", "json"], capture_output=True, text=True)
    if out.returncode != 0:
        raise Error(f"oc {' '.join(args)}: {out.stderr.strip()}")
    return json.loads(out.stdout)


def host_suffix():
    suffix = os.environ.get("HOST_SUFFIX", "")
    if not suffix:
        suffix = oc_json("get", "ingresses.config.openshift.io", "cluster")["spec"]["domain"]
    return suffix if suffix.startswith(".") else "." + suffix


def saw_routes():
    """(namespaces labelled NAMESPACE_SELECTOR, every route in them)."""
    namespaces = {n["metadata"]["name"] for n in
                  oc_json("get", "namespaces", "-l", env("NAMESPACE_SELECTOR", "openshell.pattern/saw=true"))
                  .get("items", [])}
    routes = [r for r in oc_json("get", "routes", "-A").get("items", [])
              if (r.get("metadata") or {}).get("namespace") in namespaces]
    return namespaces, routes


def wanted(routes, suffix, only_namespace=None):
    """The redirect URIs and web origins of the labelled web UI routes (of
    one namespace, or all), and the hosts of all the routes given."""
    key, _, value = env("ROUTE_SELECTOR", "saw.redhat.com/oidc-redirect=true").partition("=")
    uris, origins, notes = set(), set(), []
    present = {(r.get("spec") or {}).get("host", "") for r in routes} - {""}
    for route in routes:
        meta = route.get("metadata") or {}
        if (meta.get("labels") or {}).get(key) != value:
            continue
        if only_namespace and meta.get("namespace") != only_namespace:
            continue
        where = f"{meta.get('namespace')}/{meta.get('name')}"
        host = (route.get("spec") or {}).get("host", "")
        if not (HOST_RE.fullmatch(host) and host.endswith(suffix) and len(host) > len(suffix)):
            notes.append(f"route {where}: host {host!r} is not under {suffix}; skipped")
            continue
        path = (meta.get("annotations") or {}).get(PATH_ANNOTATION) or DEFAULT_PATH
        if not PATH_RE.fullmatch(path) or "/../" in path + "/" or "/./" in path + "/":
            notes.append(f"route {where}: redirect path {path!r} is not a plain path; skipped")
            continue
        uris.add(f"https://{host}{path}")
        origins.add(f"https://{host}")
    return uris, origins, present, notes


# -- Keycloak ------------------------------------------------------------------------------

def tls_context(url):
    if os.environ.get("KEYCLOAK_INSECURE") == "true":
        raise Error("KEYCLOAK_INSECURE is no longer supported; set OIDC_CA_BUNDLE")
    with tempfile.TemporaryDirectory(prefix="saw-redirect-ca-") as directory:
        bundle = tls.prepare_ca_bundle(url, Path(directory) / "ca.pem",
                                       os.environ.get("OIDC_CA_BUNDLE") or os.environ.get("KEYCLOAK_CA"))
        return ssl.create_default_context(cafile=bundle)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def call(url, method="GET", body=None, token=None, form=None, ctx=None):
    tls.require_https(url)
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
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect())
        with opener.open(req, data=data, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raise Error(f"{method} {url.split('?')[0]}: HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        hint = (" (set KEYCLOAK_CA to the CA bundle that signed it)"
                if "CERTIFICATE_VERIFY_FAILED" in str(exc.reason) else "")
        raise Error(f"{url.split('?')[0]}: {exc.reason}{hint}") from None


class Keycloak:
    """The OpenShell realm's admin API, as Keycloak's admin (its Secret)."""

    def __init__(self, url, realm, user, password, ctx):
        self.url, self.realm, self.ctx = url.rstrip("/"), realm, ctx
        self.token = call(f"{self.url}/realms/master/protocol/openid-connect/token", "POST", ctx=ctx,
                          form={"grant_type": "password", "client_id": "admin-cli",
                                "username": user, "password": password})["access_token"]

    def __call__(self, method, path, body=None):
        return call(f"{self.url}/admin/realms/{self.realm}{path}", method, body, self.token, ctx=self.ctx)

    def client(self, client_id):
        found = [c for c in self("GET", "/clients?clientId=" + urllib.parse.quote(client_id)) or []
                 if c.get("clientId") == client_id]
        if not found:
            raise Error(f"client {client_id} not found in realm {self.realm}")
        return self("GET", f"/clients/{found[0]['id']}")


def keycloak_url(ns, name):
    """Keycloak's URL, found as scripts/keycloak-host.sh does: the CR's
    status.externalURL (not every RHBK version sets it), its
    spec.hostname.hostname, the route labelled app=keycloak, or the
    namespace's only route."""
    cr = oc_json("get", "keycloak", name, "-n", ns)
    url = (cr.get("status") or {}).get("externalURL") or ""
    if url:
        return url.rstrip("/")
    host = ((cr.get("spec") or {}).get("hostname") or {}).get("hostname") or ""
    if not host:
        routes = oc_json("get", "routes", "-n", ns, "-l", "app=keycloak").get("items") or []
        if not routes:
            routes = oc_json("get", "routes", "-n", ns).get("items") or []
            if len(routes) != 1:
                routes = []
        host = ((routes[0].get("spec") or {}).get("host") or "") if routes else ""
    host = re.sub(r"^https?://", "", host).split("/")[0]
    if not host:
        raise Error(f"no URL for Keycloak {ns}/{name}: no status.externalURL, spec.hostname or route "
                    "(set KEYCLOAK_NS / KEYCLOAK_NAME)")
    return f"https://{host}"


def keycloak():
    ns, name = env("KEYCLOAK_NS", "saw-keycloak"), env("KEYCLOAK_NAME", "openshell-keycloak")
    url = keycloak_url(ns, name)
    data = oc_json("get", "secret", f"{name}-initial-admin", "-n", ns).get("data") or {}
    user, password = (base64.b64decode(data.get(k, "")).decode() for k in ("username", "password"))
    return Keycloak(url, env("KEYCLOAK_REALM", "openshell"), user, password, tls_context(url))


# -- the client's lists ----------------------------------------------------------------------

def under(entry, suffix):
    parsed = urllib.parse.urlsplit(entry)
    return parsed.scheme == "https" and (parsed.hostname or "").endswith(suffix)


def reconcile(client, uris, origins, suffix, present=frozenset(), prune=True):
    """The client with the given redirect URIs and web origins added, or
    None when nothing changes.

    prune (sync): the entries this script added (recorded in the client
    attribute MANAGED_ATTRIBUTE) that are not wanted any more are removed,
    unless a route in a SAW namespace still has their host (`present`: not
    labelled yet, e.g. during an upgrade). Without a record, the entries
    under `suffix` are adopted. Entries it did not add are kept, and an entry
    removed by hand is not put back unless wanted again."""
    attributes = dict(client.get("attributes") or {})
    current_uris, current_origins = client.get("redirectUris") or [], client.get("webOrigins") or []
    try:
        managed = json.loads(attributes[MANAGED_ATTRIBUTE])
    except (KeyError, ValueError, TypeError):
        managed = None
    if not prune:
        managed = managed or {"redirectUris": [], "webOrigins": []}
        new_uris = sorted(set(current_uris) | uris)
        new_origins = sorted(set(current_origins) | origins)
        record_uris = set(managed.get("redirectUris") or []) | uris
        record_origins = set(managed.get("webOrigins") or []) | origins
    else:
        if managed is None:
            managed = {"redirectUris": [u for u in current_uris if under(u, suffix)],
                       "webOrigins": [o for o in current_origins if under(o, suffix)]}

        def kept(current, mine, want):
            return {e for e in set(mine) & set(current) - want
                    if urllib.parse.urlsplit(e).hostname in present}

        keep_uris = kept(current_uris, managed.get("redirectUris") or [], uris)
        keep_origins = kept(current_origins, managed.get("webOrigins") or [], origins)
        new_uris = sorted((set(current_uris) - set(managed.get("redirectUris") or [])) | uris | keep_uris)
        new_origins = sorted((set(current_origins) - set(managed.get("webOrigins") or []))
                             | origins | keep_origins)
        record_uris, record_origins = uris | keep_uris, origins | keep_origins
    record = json.dumps({"redirectUris": sorted(record_uris), "webOrigins": sorted(record_origins)},
                        sort_keys=True)
    if (new_uris == sorted(current_uris) and new_origins == sorted(current_origins)
            and attributes.get(MANAGED_ATTRIBUTE) == record):
        return None
    attributes[MANAGED_ATTRIBUTE] = record
    return {**client, "redirectUris": new_uris, "webOrigins": new_origins, "attributes": attributes}


def apply(kc, client, updated):
    added = sorted(set(updated["redirectUris"]) - set(client.get("redirectUris") or []))
    removed = sorted(set(client.get("redirectUris") or []) - set(updated["redirectUris"]))
    kc("PUT", f"/clients/{client['id']}", updated)
    for u in added:
        print(f"  added    {u}")
    for u in removed:
        print(f"  removed  {u}")
    if not added and not removed:
        print("  (web origins or the record updated)")


# -- commands --------------------------------------------------------------------------------

def cmd_list():
    suffix = host_suffix()
    _, routes = saw_routes()
    uris, _, _, notes = wanted(routes, suffix)
    client = keycloak().client(env("DASHBOARD_CLIENT_ID", "openshell-dashboard"))
    have = set(client.get("redirectUris") or [])
    print(f"{client['clientId']} redirect URIs:")
    for u in sorted(have):
        print(f"  {u}{'' if u in uris or not under(u, suffix) else '   (no route any more)'}")
    missing = sorted(uris - have)
    print("SAW web UI routes without a redirect URI:" if missing else "Every SAW web UI route is registered.")
    for u in missing:
        print(f"  {u}")
    for n in notes:
        print(f"note: {n}")
    return 1 if missing else 0


def cmd_register(user, wait=None, sleep=time.sleep, clock=time.monotonic):
    if not USER_RE.fullmatch(user or ""):
        raise Error(f"{user!r} is not a SAW user name")
    ns = f"saw-{user}"
    suffix = host_suffix()
    wait = int(env("WAIT", "600")) if wait is None else wait
    deadline = clock() + wait
    while True:
        namespaces, routes = saw_routes()
        uris, origins, _, notes = wanted(routes, suffix, only_namespace=ns)
        if uris:
            break
        if clock() >= deadline:
            where = "is not a SAW namespace" if ns not in namespaces else "has no web UI route"
            raise Error(f"{ns} {where} yet (waited {wait}s); create the workspace first, or run again")
        print(f"waiting for the web UI routes of {ns}...", flush=True)
        sleep(10)
    for n in notes:
        print(f"note: {n}")
    kc = keycloak()
    client = kc.client(env("DASHBOARD_CLIENT_ID", "openshell-dashboard"))
    updated = reconcile(client, uris, origins, suffix, prune=False)
    print(f"{client['clientId']}: {user}'s web UIs")
    if updated is None:
        print("  already registered")
    else:
        apply(kc, client, updated)
    return 0


def cmd_sync():
    suffix = host_suffix()
    _, routes = saw_routes()
    uris, origins, present, notes = wanted(routes, suffix)
    for n in notes:
        print(f"note: {n}")
    kc = keycloak()
    client = kc.client(env("DASHBOARD_CLIENT_ID", "openshell-dashboard"))
    updated = reconcile(client, uris, origins, suffix, present, prune=True)
    print(f"{client['clientId']}: {len(uris)} SAW web UI redirect URIs")
    if updated is None:
        print("  up to date")
    else:
        apply(kc, client, updated)
    return 0


def main(argv):
    try:
        if argv[1:2] == ["list"]:
            return cmd_list()
        if argv[1:2] == ["register"] and len(argv) == 3:
            return cmd_register(argv[2])
        if argv[1:2] == ["sync"]:
            return cmd_sync()
    except (Error, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
