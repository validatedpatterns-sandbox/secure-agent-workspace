#!/usr/bin/env python3
"""Self-service workspaces for the Secure Agent Workspace pattern.

Standard library only; one file:

  portal.py create REQUEST        pipeline saw-workspace-create, task register
  portal.py wait-<stage> USER [S] its later tasks: wait for apps, vm, running,
                                  ready (the sandbox UIs answer)
  portal.py delete REQUEST        pipeline saw-workspace-delete, task unregister
  portal.py wait-gone USER [S]    then: wait until Argo CD removed the workspace
  portal.py finish-delete USER    then: the registry entry and the Vault keys
  portal.py serve                 the ApplicationSet plugin generator
  portal.py cleanup               CronJob: requests nobody handled

A request is a Secret the RHDH template creates in the portal namespace. It
holds the user's Backstage token and the form: the profile and the values of
the Secrets that profile's providers read. Who the request is for is taken
only from the token, after its signature is checked against RHDH's JWKS: a
signed-in user who calls the RHDH proxy directly can only act for
themselves.

create  checks the request against the profile catalog, writes each Secret
        to Vault at <kv>/data/<base>/saw-<user>/<secret> (External Secrets
        copies them into namespace saw-<user>), then writes the workspace
        registry entry: ConfigMap saw-ws-<user>, label
        saw.redhat.com/workspace=true.
delete  marks the registry entry as deleting (the ApplicationSet stops
        getting it) and deletes the user's Application; finish-delete
        removes the entry and the user's Vault entries once Argo CD has
        removed the workspace.
serve   answers Argo CD's ApplicationSet plugin generator: one parameter set
        per registry entry, `values` being the saw-users chart values for
        that one user. The generated Application renders saw-users, so a
        portal workspace is built exactly like one in overrides/saw-users.yaml.

The generator also serves GET /catalog.yaml, the RHDH catalog entities of
the registered workspaces with their status (an RHDH url location), and
GET /status/..., the progress of a pipeline run and of the caller's
workspace, which the create template waits on. create and delete always
delete the request Secret.
"""
import base64
import calendar
import hashlib
import http.server
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
NAME_LIMIT = 19            # the VM name, and OpenShell's name limit
WORKSPACE_LABEL = "saw.redhat.com/workspace"
REQUEST_LABEL = "saw.redhat.com/request"
# A registry entry being deleted: the ApplicationSet no longer gets it (so
# it does not rebuild the Application), the catalog still shows it until the
# delete pipeline has removed the workspace.
DELETING_LABEL = "saw.redhat.com/deleting"
# RHDH's Kubernetes and Tekton plugins find a workspace's pipeline runs by
# this label (the catalog entity's backstage.io/kubernetes-id).
KUBERNETES_ID_LABEL = "backstage.io/kubernetes-id"
REQUEST_MAX_AGE = 3600     # seconds a request Secret stays valid
REQUEST_NAME_RE = re.compile(r"^saw-req-[a-z0-9]{1,20}$")
# The Applications saw-users makes for user <u> are saw-<u>, saw-<u>-bom and
# saw-<u>-secrets, and the portal's parent is portal-ws-<u>: these suffixes
# would make one user's app name another user's.
RESERVED_SUFFIXES = ("-bom", "-secrets")


class PortalError(Exception):
    """A request that must be refused; the message is shown in the PipelineRun."""


class NotARequest(PortalError):
    """The named Secret is not a request: it is not deleted."""


def log(msg):
    print(f"[saw-portal] {msg}", flush=True)


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None:
        raise PortalError(f"environment variable {name} is not set")
    return value


# -- ES256 (ECDSA P-256, SHA-256), for Backstage user tokens --------------------

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k, point):
    result = None
    while k:
        if k & 1:
            result = _add(result, point)
        point = _add(point, point)
        k >>= 1
    return result


def _on_curve(pt):
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def es256_verify(pub, message, signature):
    """True when signature (64 bytes, r||s) is valid for message under pub (x, y)."""
    if len(signature) != 64 or not _on_curve(pub):
        return False
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (0 < r < N and 0 < s < N):
        return False
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, N - 2, N)
    point = _add(_mul(z * w % N, G), _mul(r * w % N, pub))
    return point is not None and point[0] % N == r


def b64url(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def decode_jwt(token):
    """(header, payload, signing input, signature) of a compact JWS."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        return (json.loads(b64url(header_b64)), json.loads(b64url(payload_b64)),
                f"{header_b64}.{payload_b64}".encode(), b64url(sig_b64))
    except (ValueError, UnicodeDecodeError, AttributeError):
        raise PortalError("the request's Backstage token is not a JWT") from None


def verify_jwt(token, jwks, what, now=None, leeway=0):
    """The (header, payload) of a token signed by a key of `jwks`, not
    expired (more than `leeway` seconds ago)."""
    header, payload, signed, signature = decode_jwt(token)
    if header.get("alg") != "ES256":
        raise PortalError(f"{what}: unsupported algorithm {header.get('alg')!r} (expected ES256)")
    keys = [k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")
            and k.get("kty") == "EC" and k.get("crv") == "P-256"]
    if not keys:
        raise PortalError(f"{what}: its signing key is not in the JWKS")
    pub = (int.from_bytes(b64url(keys[0]["x"]), "big"), int.from_bytes(b64url(keys[0]["y"]), "big"))
    if not es256_verify(pub, signed, signature):
        raise PortalError(f"{what}: the signature is not valid")
    if payload.get("exp", 0) + leeway < (now or time.time()):
        raise PortalError(f"{what}: expired")
    return header, payload


PLUGIN_TYP = "vnd.backstage.plugin"
USER_TYPS = ("vnd.backstage.user", "vnd.backstage.limited-user")


def verify_backstage_token(token, auth_jwks, scaffolder_jwks=None, now=None, leeway=0):
    """The user name ("alice" for user:default/alice) a request is for.

    The scaffolder's `secrets.backstageToken` is, on the new backend, a
    plugin token: signed by the scaffolder's own key (its JWKS at
    /api/scaffolder/.backstage/auth/v1/jwks.json), typ vnd.backstage.plugin,
    sub "scaffolder", aud "catalog", carrying the user in `obo`, a limited
    user token signed by the auth backend (/api/auth/.well-known/jwks.json).
    Both are verified. A full user token (older backends) is verified
    against the auth backend's keys alone."""
    header, _, _, _ = decode_jwt(token)
    user_token = token
    if header.get("typ") == PLUGIN_TYP:
        if scaffolder_jwks is None:
            raise PortalError("a plugin token needs the scaffolder's JWKS")
        _, outer = verify_jwt(token, scaffolder_jwks, "the scaffolder token", now, leeway)
        if outer.get("sub") != "scaffolder" or outer.get("aud") != "catalog":
            raise PortalError(f"the plugin token is from {outer.get('sub')!r} for {outer.get('aud')!r}, "
                              "not the scaffolder for the catalog")
        user_token = outer.get("obo") or ""
        if not user_token:
            raise PortalError("the scaffolder token does not act for a user (no obo)")
    uheader, payload = verify_jwt(user_token, auth_jwks, "the user token", now, leeway)
    if uheader.get("typ", USER_TYPS[0]) not in USER_TYPS:
        raise PortalError(f"the user token has type {uheader.get('typ')!r}")
    sub = payload.get("sub", "")
    if not sub.startswith("user:default/"):
        raise PortalError(f"the token is not for a user (sub {sub!r})")
    return sub.split("/", 1)[1]


# -- Kubernetes and Vault over HTTPS ---------------------------------------------

class HttpError(PortalError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Http:
    def __init__(self, base, token="", cafile=None, insecure=False):
        self.base = base.rstrip("/")
        self.token = token
        self.ctx = ssl.create_default_context(cafile=cafile) if base.startswith("https") else None
        if self.ctx and insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def call(self, method, path, body=None, headers=None, ok404=False, raw=False, timeout=30):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=timeout) as resp:
                data = resp.read()
                if raw:
                    return data.decode("utf-8", errors="replace")
                return json.loads(data) if data else {}
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and ok404:
                return None
            detail = exc.read().decode(errors="replace")[:300]
            raise HttpError(exc.code, f"{method} {path}: HTTP {exc.code} {detail}") from None


def kube():
    host, port = env("KUBERNETES_SERVICE_HOST"), env("KUBERNETES_SERVICE_PORT", "443")
    with open(f"{SA_DIR}/token", encoding="utf-8") as f:
        token = f.read().strip()
    return Http(f"https://{host}:{port}", token, cafile=f"{SA_DIR}/ca.crt")


def fetch_json(url, insecure=False):
    return Http(url, insecure=insecure).call("GET", "")


class Vault:
    """KV v2 through the Kubernetes auth method, as this pod's service account."""

    def __init__(self, addr, mount, role, kv="secret"):
        self.http = Http(addr, insecure=os.environ.get("VAULT_SKIP_VERIFY") == "true",
                         cafile=os.environ.get("VAULT_CACERT") or None)
        with open(f"{SA_DIR}/token", encoding="utf-8") as f:
            jwt = f.read().strip()
        auth = self.http.call("POST", f"/v1/auth/{mount}/login", {"role": role, "jwt": jwt})
        self.token = auth["auth"]["client_token"]
        self.kv = kv

    def _h(self):
        return {"X-Vault-Token": self.token}

    def write(self, path, data):
        self.http.call("POST", f"/v1/{self.kv}/data/{path}", {"data": data}, headers=self._h())

    def destroy(self, path):
        self.http.call("DELETE", f"/v1/{self.kv}/metadata/{path}", headers=self._h(), ok404=True)


# -- requests ---------------------------------------------------------------------

def load_catalog(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)["profiles"]


def check_user(user):
    if not NAME_RE.match(user) or len(user) > NAME_LIMIT:
        raise PortalError(
            f"user name {user!r} cannot name a workspace: it must be a lowercase DNS label of at "
            f"most {NAME_LIMIT} characters (it names the VM and the namespace saw-{user})")
    if user.endswith(RESERVED_SUFFIXES):
        raise PortalError(f"user name {user!r} cannot name a workspace: its Argo CD applications "
                          "would take another user's names (-bom, -secrets)")
    return user


def parse_request(data, catalog):
    """The chosen profile and, for each Secret it reads, the field values.

    `data` is the request Secret's decoded data: `profile`, and one key per
    form field, `<secret>.<field>`. Fields of other profiles are ignored; a
    required field left empty is refused."""
    profile = data.get("profile", "")
    if profile not in catalog:
        raise PortalError(f"unknown profile {profile!r}; available: {', '.join(sorted(catalog))}")
    secrets, missing = {}, []
    for name, spec in sorted(catalog[profile].get("secrets", {}).items()):
        values = {}
        for field in spec.get("fields", []):
            value = (data.get(f"{name}.{field['key']}") or "").strip()
            if not value and field.get("default"):
                value = field["default"]
            if not value:
                if field.get("required"):
                    missing.append(f"{name}.{field['key']}")
                continue
            if field.get("kind") == "url" and not re.match(r"^https?://[^\s/?#@]+(/[^\s?#]*)?$", value):
                raise PortalError(f"{name}.{field['key']} must be an http(s) URL without credentials")
            values[field["key"]] = value
        if spec.get("provider"):
            values["provider"] = spec["provider"]
        secrets[name] = values
    if missing:
        raise PortalError(f"profile {profile!r} needs: {', '.join(missing)}")
    return profile, secrets


def decode_secret(obj):
    return {k: base64.b64decode(v).decode("utf-8") for k, v in (obj.get("data") or {}).items()}


def request_path(ns, name):
    if not REQUEST_NAME_RE.match(name):
        raise PortalError(f"{name!r} is not a request name (saw-req-*)")
    return f"/api/v1/namespaces/{ns}/secrets/{urllib.parse.quote(name, safe='')}"


def read_request(k8s, ns, name):
    """The request's data. A Secret that is not a request is refused and
    left alone; a request is deleted by handle() whatever happens."""
    obj = k8s.call("GET", request_path(ns, name), ok404=True)
    if obj is None:
        raise PortalError(f"request {name} not found (already used?)")
    if (obj["metadata"].get("labels") or {}).get(REQUEST_LABEL) != "true":
        raise NotARequest(f"secret {name} is not a portal request")
    created = obj["metadata"].get("creationTimestamp", "")
    if created:
        age = time.time() - calendar.timegm(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ"))
        if age > REQUEST_MAX_AGE:
            raise PortalError(f"request {name} is older than {REQUEST_MAX_AGE // 60} minutes")
    return decode_secret(obj)


def token_user(token, jwks=None, leeway=0):
    """The user a Backstage token is for, after checking it against RHDH's
    published keys. `jwks(path)` fetches a JWKS (the generator caches)."""
    if jwks is None:
        rhdh = env("RHDH_INTERNAL_URL").rstrip("/")
        insecure = os.environ.get("RHDH_SKIP_VERIFY") == "true"
        jwks = lambda path: fetch_json(rhdh + path, insecure=insecure)  # noqa: E731
    scaffolder_jwks = None
    if decode_jwt(token)[0].get("typ") == PLUGIN_TYP:
        scaffolder_jwks = jwks("/api/scaffolder/.backstage/auth/v1/jwks.json")
    return check_user(verify_backstage_token(token, jwks("/api/auth/.well-known/jwks.json"),
                                             scaffolder_jwks, leeway=leeway))


def requester(data):
    """The user a request is for: only ever from its verified Backstage
    token (there is no switch to trust the form instead)."""
    return token_user(data.get("token", ""))


def vault_prefix(user):
    return f"{env('VAULT_PREFIX_BASE', 'hub')}/saw-{user}"


def registry_entry(user, profile):
    """The saw-users list entry for a portal workspace."""
    return {"name": user, "profiles": [profile], "ownerSubject": "",
            "vaultPrefix": f"{env('VAULT_KV_MOUNT', 'secret')}/data/{vault_prefix(user)}",
            "pruneOnRemove": os.environ.get("PRUNE_ON_REMOVE", "true") == "true"}


def put_configmap(k8s, ns, name, data, labels=None, resource_version=None):
    body = {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": ns, "labels": labels or {}}, "data": data}
    path = f"/api/v1/namespaces/{ns}/configmaps"
    if resource_version:
        # Replace the version that was read: a delete that marked the entry
        # meanwhile makes this fail (409) instead of being undone.
        body["metadata"]["resourceVersion"] = resource_version
        try:
            k8s.call("PUT", f"{path}/{name}", body)
        except HttpError as exc:
            if exc.code != 409:
                raise
            raise PortalError(f"{name} changed while this request ran (a delete?); request it again") from None
        return
    # Create, or replace when it exists. Two requests for the same user at
    # once both end here: the later one wins instead of failing with 409.
    try:
        k8s.call("POST", path, body)
    except HttpError as exc:
        if exc.code != 409:
            raise
        k8s.call("PUT", f"{path}/{name}", body)


# Registry entries the last listing skipped (shown on the generator's /healthz).
BAD_ENTRIES = []


def list_workspaces(k8s, ns, deleting=False):
    """The registry's workspaces (with deleting=True also those being
    deleted). A malformed entry is skipped and logged, so it cannot stop
    updates to everyone else's workspace. Skipping is safe: the
    ApplicationSet only creates and updates Applications (an entry that
    disappears does not delete its Application) and preserves resources on
    deletion, and the delete pipeline is what removes a workspace."""
    items = k8s.call("GET", f"/api/v1/namespaces/{ns}/configmaps?labelSelector="
                     + urllib.parse.quote(f"{WORKSPACE_LABEL}=true")).get("items", [])
    out, bad = [], []
    for cm in items:
        name = cm["metadata"]["name"]
        try:
            entry = json.loads((cm.get("data") or {}).get("user.json", ""))
        except ValueError:
            entry = None
        if not (isinstance(entry, dict) and NAME_RE.match(str(entry.get("name", "")))
                and name == f"saw-ws-{entry['name']}"):
            log(f"ERROR: registry entry {name} is malformed (no valid user.json); skipped")
            bad.append(name)
            continue
        if (cm["metadata"].get("labels") or {}).get(DELETING_LABEL) == "true" and not deleting:
            continue
        out.append(entry)
    BAD_ENTRIES[:] = sorted(bad)
    return sorted(out, key=lambda e: e["name"])


def ui_links(user, profiles, catalog, domain):
    """(title, url) of the OpenShell web UI and each sandbox UI route."""
    if not domain:
        return []
    links = [("OpenShell web UI", f"https://{user}-webui-saw-{user}.apps.{domain}")]
    return links + sandbox_ui_links(user, profiles, catalog, domain)


def sandbox_ui_links(user, profiles, catalog, domain):
    out = []
    for profile in profiles:
        for w in catalog.get(profile, {}).get("workspaces", []):
            for sb in w.get("sandboxes", []):
                if w.get("enabled") and sb.get("enabled") and sb.get("uiRoute"):
                    out.append((f"{sb['name']} UI ({w['name']})",
                                f"https://{user}-{w['name']}-{sb['name']}-ui.apps.{domain}"))
    return out


# Groups for RHDH RBAC, so a user sees only the action that applies to them:
# create (no workspace yet) or delete (they have one).
OWNERS_GROUP = "saw-workspace-owners"
NEW_USERS_GROUP = "saw-without-workspace"


def audience_groups(owners, users):
    """Group entities: the users with a workspace, and (when the realm's
    users are known) the users without one; administrators in neither."""
    def group(name, title, members):
        return {"apiVersion": "backstage.io/v1alpha1", "kind": "Group",
                "metadata": {"name": name, "title": title},
                "spec": {"type": "team", "children": [], "members": sorted(members)}}
    # Administrators are in neither: RHDH RBAC joins the roles' conditions,
    # so these groups' roles would show them the user templates too.
    staff = set(admins())
    docs = [group(OWNERS_GROUP, "Users with an agent workspace", set(owners) - staff)]
    if users is not None:
        docs.append(group(NEW_USERS_GROUP, "Users without an agent workspace",
                          set(users) - set(owners) - staff))
    return docs


def entities_yaml(workspaces, catalog, domain, rhdh_url, statuses=None, portal_ns="saw-portal", users=None):
    """RHDH catalog entities: one Component per workspace (the kind RHDH's
    catalog lists first, and the one its CI tab is made for), owned by its user,
    linking the OpenShell web UI and each sandbox UI route, with the
    workspace's status (workspace_status) when known. JSON documents (valid
    YAML) separated by ---."""
    docs = []
    for ws in workspaces:
        user = ws["name"]
        links = [{"url": url, "title": title, "icon": "dashboard" if i == 0 else "web"}
                 for i, (title, url) in enumerate(ui_links(user, ws.get("profiles", []), catalog, domain))]
        if rhdh_url:
            # The delete form, with this workspace already chosen.
            form = urllib.parse.quote(json.dumps({"workspace": f"component:default/saw-{user}"},
                                                 separators=(",", ":")))
            links.append({"url": f"{rhdh_url}/create/templates/default/delete-saw-workspace?formData={form}",
                          "title": "Delete workspace", "icon": "delete"})
        description = "Secure Agent Workspace (profiles: " + ", ".join(ws.get("profiles", [])) + ")"
        annotations = {"openshell.pattern/namespace": f"saw-{user}",
                       # The Tekton tab: the create and delete pipeline runs
                       # labelled with this id in the portal namespace.
                       "backstage.io/kubernetes-id": f"saw-{user}",
                       "backstage.io/kubernetes-namespace": portal_ns,
                       "janus-idp.io/tekton": f"saw-{user}",
                       "tekton.dev/cicd": "true"}
        status = (statuses or {}).get(user)
        if status:
            description = f"{status['title']}: {status['message']}. {description}"
            annotations["openshell.pattern/status"] = status["phase"]
        docs.append({"apiVersion": "backstage.io/v1alpha1", "kind": "Component",
                     "metadata": {"name": f"saw-{user}", "title": f"Agent workspace: {user}",
                                  "description": description,
                                  "annotations": annotations,
                                  "links": links},
                     "spec": {"type": "agent-workspace", "owner": f"user:default/{user}",
                              "lifecycle": "production"}})
    docs += audience_groups([ws["name"] for ws in workspaces], users)
    docs.append(get_started(rhdh_url))
    return "\n---\n".join(json.dumps(d, indent=2, sort_keys=True) for d in docs) + "\n"


def get_started(rhdh_url):
    """The card a user without a workspace sees in the home page's Workspaces
    section (RBAC: label saw.redhat.com/new-users), instead of RHDH's empty
    state, whose 'register a component' button leads to a page the portal
    does not offer."""
    link = f"{rhdh_url}/create/templates/default/create-saw-workspace" if rhdh_url else \
        "/create/templates/default/create-saw-workspace"
    return {"apiVersion": "backstage.io/v1alpha1", "kind": "Component",
            "metadata": {"name": "saw-get-started", "title": "Get started: create your agent workspace",
                         "description": "You have no agent workspace yet. Use 'Create or update my agent workspace' "
                                        "under Actions: pick a profile, enter its keys, and it is ready in "
                                        "about 15 minutes.",
                         "labels": {"saw.redhat.com/new-users": "true"},
                         "links": [{"url": link, "title": "Create my agent workspace", "icon": "add"}]},
            "spec": {"type": "guide", "owner": f"group:default/{NEW_USERS_GROUP}", "lifecycle": "production"}}


class RealmUsers:
    """The realm's users (members of the Keycloak group every user is in),
    read with the rhdh client's service account. The last good list is kept
    when Keycloak cannot be reached; None until one has been read."""

    def __init__(self, ttl=60):
        self.ttl, self.at, self.users = ttl, 0.0, None

    def __call__(self):
        url, group = os.environ.get("KEYCLOAK_URL", ""), os.environ.get("USERS_GROUP", "")
        if not url or not group:
            return None
        if self.users is not None and time.time() - self.at < self.ttl:
            return self.users
        try:
            self.users = keycloak_group_members(url.rstrip("/"), env("KEYCLOAK_REALM"), env("KEYCLOAK_CLIENT_ID"),
                                                open(env("KEYCLOAK_SECRET_FILE"), encoding="utf-8").read().strip(),
                                                group, os.environ.get("KEYCLOAK_SKIP_VERIFY") == "true")
            self.at = time.time()
        except (PortalError, OSError, ValueError, KeyError, IndexError) as exc:
            # Wait a full TTL before trying again: an unreachable Keycloak
            # must not slow every catalog read.
            self.at = time.time()
            log(f"WARN: realm users not read ({exc}); keeping {len(self.users or [])} known")
        return self.users


def keycloak_admin(url, realm, client_id, secret, insecure=False):
    """The realm's admin API as the client's service account (client
    credentials)."""
    req = urllib.request.Request(f"{url}/realms/{realm}/protocol/openid-connect/token", method="POST",
                                 data=urllib.parse.urlencode({"grant_type": "client_credentials",
                                                              "client_id": client_id,
                                                              "client_secret": secret}).encode())
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            token = json.loads(resp.read())["access_token"]
    except urllib.error.HTTPError as exc:
        raise HttpError(exc.code, f"Keycloak token: HTTP {exc.code}") from None
    return Http(f"{url}/admin/realms/{realm}", token, insecure=insecure)


def keycloak_group_members(url, realm, client_id, secret, group, insecure=False):
    """User names in a Keycloak group."""
    kc = keycloak_admin(url, realm, client_id, secret, insecure)
    found = [g for g in kc.call("GET", "/groups?exact=true&search=" + urllib.parse.quote(group))
             if g.get("name") == group]
    if not found:
        raise PortalError(f"Keycloak group {group} not found")
    users, first = [], 0
    while True:
        page = kc.call("GET", f"/groups/{found[0]['id']}/members?first={first}&max=100&briefRepresentation=true")
        users += [u["username"] for u in page if not u["username"].startswith("service-account-")]
        if len(page) < 100:
            return sorted(users)
        first += 100


def keycloak_user_ids(url, realm, client_id, secret, names, insecure=False):
    """{user name: Keycloak user id} for the names the realm has. The id is
    the `sub` of the user's tokens, which OpenShell knows them by."""
    kc = keycloak_admin(url, realm, client_id, secret, insecure)
    out = {}
    for name in names:
        users = kc.call("GET", "/users?exact=true&briefRepresentation=true&username="
                        + urllib.parse.quote(name)) or []
        out.update({u["username"]: u["id"] for u in users if u.get("username") == name and u.get("id")})
    return out


class OwnerSubjects:
    """Fills a portal workspace's ownerSubject (empty in its registry
    entry) with the user's Keycloak id, so the installer makes them a member
    of their OpenShell workspaces and OpenShell's web UI lists them. Ids do
    not change: kept once found; a user not found is asked again after
    `ttl`. Without Keycloak settings (RBAC off) entries stay as they are."""

    def __init__(self, ttl=60):
        self.ttl, self.ids, self.tried = ttl, {}, {}

    def fill(self, workspaces):
        url = os.environ.get("KEYCLOAK_URL", "")
        if not url:
            return workspaces
        now = time.time()
        missing = [w["name"] for w in workspaces if not w.get("ownerSubject") and w["name"] not in self.ids
                   and now - self.tried.get(w["name"], 0) >= self.ttl]
        if missing:
            for name in missing:
                self.tried[name] = now
            try:
                self.ids.update(keycloak_user_ids(
                    url.rstrip("/"), env("KEYCLOAK_REALM"), env("KEYCLOAK_CLIENT_ID"),
                    open(env("KEYCLOAK_SECRET_FILE"), encoding="utf-8").read().strip(), missing,
                    os.environ.get("KEYCLOAK_SKIP_VERIFY") == "true"))
            except (PortalError, OSError, ValueError, KeyError) as exc:
                log(f"WARN: Keycloak ids not read ({exc}); {', '.join(missing)} not members yet")
        return [{**w, "ownerSubject": self.ids[w["name"]]}
                if not w.get("ownerSubject") and w["name"] in self.ids else w for w in workspaces]


# -- progress, for the RHDH template and the catalog --------------------------------
#
# The create template waits on these (through the RHDH proxy endpoint
# /saw-status, which passes the user's Backstage token in X-Saw-Token) so
# its run page shows each stage, and the catalog shows each workspace's
# status. A caller sees only their own workspace and their own pipeline log.

# Stages of a new workspace, in order: (id, title).
STAGES = (("registered", "Workspace registered"),
          ("apps", "Argo CD applications created"),
          ("vm", "VM defined"),
          ("running", "VM running"),
          ("ready", "OpenShell and the sandboxes installed"))
STAGE_IDS = tuple(s for s, _ in STAGES)
PHASE_TITLES = {"none": "Not requested", "registered": "Requested", "apps": "Creating",
                "vm": "Starting the VM", "running": "Installing", "ready": "Ready", "failed": "Failed",
                "deleting": "Deleting"}
# VM states that will not get better by waiting.
VM_FAILED = ("CrashLoopBackOff", "DataVolumeError", "ErrorPvcNotFound", "ErrorDataVolumeNotFound")
RUN_NAME_RE = re.compile(r"^saw-(create|delete)-[a-z0-9]{1,20}$")
RUN_USER_RE = re.compile(
    r"\] (?:create|delete) request saw-req-[a-z0-9]+ from ([a-z0-9-]+)(?: for [a-z0-9-]+)?$", re.M)
# The template's token was issued when the run started; status reads (no
# changes) accept it for this long after it expires, so a slow VM does not
# turn the run red.
STATUS_TOKEN_LEEWAY = 2 * 3600
WAIT_LIMIT = 25            # seconds one status call may wait (the router cuts at 30)
POLL_SECONDS = 5


def ping_url(url, timeout=3):
    """True when the URL answers with a non-5xx status. The router answers
    503 until the VM's UI proxy listens. No credentials are sent, so the
    route's certificate is not checked (often the cluster's own CA)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), context=ctx,
                                    timeout=timeout) as resp:
            return resp.status < 500
    except urllib.error.HTTPError as exc:
        return exc.code < 500
    except (OSError, ValueError):
        return False


def app_summary(app):
    st = app.get("status") or {}
    sync = (st.get("sync") or {}).get("status") or "Unknown"
    health = (st.get("health") or {}).get("status") or "Unknown"
    return f"{app['metadata']['name']} {sync}/{health}"


def workspace_status(k8s, user, catalog, ns, argo_ns, domain, ping=None):
    """Where a workspace is: each stage done, active, waiting or failed.

    `phase` is the last stage reached in order ("none" before the registry
    entry exists, "failed" when a stage failed); `text` is a short report
    for the template's log and output."""
    ping = ping or ping_url
    reached, details, failure = {}, {}, ""
    cm = k8s.call("GET", f"/api/v1/namespaces/{ns}/configmaps/saw-ws-{user}", ok404=True)
    try:
        entry = json.loads(((cm or {}).get("data") or {}).get("user.json", "")) if cm else {}
    except ValueError:
        entry = {}
    profiles = entry.get("profiles", []) if isinstance(entry, dict) else []
    if cm is not None and (cm["metadata"].get("labels") or {}).get(DELETING_LABEL) == "true":
        gone, detail = removal_status(k8s, user, argo_ns)
        return {"user": user, "phase": "deleting", "title": PHASE_TITLES["deleting"],
                "message": detail, "ready": False, "failed": False, "steps": [], "links": [],
                "text": f"Deleting: {detail}"}
    reached["registered"] = cm is not None
    details["registered"] = (f"ConfigMap saw-ws-{user}, profile {', '.join(profiles)}" if cm
                             else f"no registry entry saw-ws-{user} yet")

    apps, missing = [], []
    for name in (f"portal-ws-{user}", f"saw-{user}-secrets", f"saw-{user}-bom", f"saw-{user}"):
        app = k8s.call("GET", f"/apis/argoproj.io/v1alpha1/namespaces/{argo_ns}/applications/{name}",
                       ok404=True)
        if app is None:
            missing.append(name)
            continue
        apps.append(app_summary(app))
        op = (app.get("status") or {}).get("operationState") or {}
        if op.get("phase") in ("Failed", "Error"):
            failure = failure or f"Argo CD could not sync {name}: {(op.get('message') or '').strip()[:300]}"
    reached["apps"] = not missing
    details["apps"] = ", ".join(apps + [f"{m} not created yet" for m in missing])

    vm = k8s.call("GET", f"/apis/kubevirt.io/v1/namespaces/saw-{user}/virtualmachines/{user}", ok404=True)
    vm_state = ((vm or {}).get("status") or {}).get("printableStatus") or ("Unknown" if vm else "")
    reached["vm"] = vm is not None
    details["vm"] = f"VirtualMachine {user} in saw-{user}" if vm else "not created yet"
    reached["running"] = vm_state == "Running"
    details["running"] = vm_state or "no VM yet"
    if vm_state in VM_FAILED:
        failure = failure or f"VM {user} is {vm_state}"

    uis = sandbox_ui_links(user, profiles, catalog, domain)
    if not reached["running"]:
        reached["ready"] = False
        details["ready"] = "after the VM starts (about 10 minutes)"
    elif not uis:
        reached["ready"] = True
        details["ready"] = "no sandbox UI to check (see the OpenShell web UI)"
    else:
        down = [title for title, url in uis if not ping(url)]
        reached["ready"] = not down
        details["ready"] = ("UIs answer: " + ", ".join(t for t, _ in uis) if not down else
                            "installing; waiting for " + ", ".join(down))

    phase = "none"
    for stage in STAGE_IDS:
        if not reached[stage]:
            break
        phase = stage
    steps = []
    for i, (stage, title) in enumerate(STAGES):
        current = STAGE_IDS.index(phase) + 1 if phase != "none" else 0
        state = ("done" if i < current else
                 ("failed" if failure else "active") if i == current else "waiting")
        steps.append({"id": stage, "title": title, "state": state, "detail": details[stage]})
    if failure:
        phase = "failed"
    message = (failure or {"none": "not registered", "registered": "waiting for Argo CD",
                           "apps": "Argo CD is creating the VM", "vm": f"VM {vm_state or 'starting'}",
                           "running": "installing OpenShell and the sandboxes",
                           "ready": "all sandbox UIs answer"}[phase])
    links = [{"title": t, "url": u} for t, u in ui_links(user, profiles, catalog, domain)]
    marks = {"done": "[x]", "active": "[ ]", "waiting": "[ ]", "failed": "[!]"}
    lines = [f"{PHASE_TITLES[phase]}: {message}", ""]
    lines += [f"- {marks[s['state']]} {s['title']}: {s['detail']}" for s in steps]
    if links and phase == "ready":
        lines += ["", "Open: " + ", ".join(f"[{l['title']}]({l['url']})" for l in links)]
    return {"user": user, "phase": phase, "title": PHASE_TITLES[phase], "message": message,
            "ready": phase == "ready", "failed": bool(failure), "steps": steps, "links": links,
            "text": "\n".join(lines)}


def removal_status(k8s, user, argo_ns):
    """(gone, what is left) of a workspace being deleted: its Argo CD
    applications and, with pruneOnRemove, namespace saw-<user> (without it
    the namespace and the VM stay on purpose)."""
    left = [a for a in (f"portal-ws-{user}", f"saw-{user}", f"saw-{user}-bom", f"saw-{user}-secrets")
            if k8s.call("GET", f"/apis/argoproj.io/v1alpha1/namespaces/{argo_ns}/applications/{a}",
                        ok404=True) is not None]
    prune = os.environ.get("PRUNE_ON_REMOVE", "true") == "true"
    ns = k8s.call("GET", f"/api/v1/namespaces/saw-{user}", ok404=True) if prune else None
    if ns is not None:
        left.append(f"namespace saw-{user} ({(ns.get('status') or {}).get('phase', 'Active')})")
    return not left, ("removed" if not left else "Argo CD is removing " + ", ".join(left))


def run_status(k8s, ns, name, caller, task=None):
    """A portal PipelineRun's state, each task's state and its log, for the
    user who made the request and for administrators. With `task`, `done`
    means that task ended."""
    if not RUN_NAME_RE.match(name):
        raise HttpError(404, f"{name!r} is not a portal pipeline run")
    run = k8s.call("GET", f"/apis/tekton.dev/v1/namespaces/{ns}/pipelineruns/{name}", ok404=True)
    if run is None:
        return {"run": name, "phase": "NotFound", "done": True, "failed": True, "tasks": {},
                "message": f"pipeline run {name} not found", "log": "", "text": f"Pipeline run {name} not found"}
    cond = next((c for c in (run.get("status") or {}).get("conditions") or []
                 if c.get("type") == "Succeeded"), {})
    status = cond.get("status", "Unknown")
    phase = {"True": "Succeeded", "False": "Failed"}.get(status, cond.get("reason") or "Pending")
    pods = k8s.call("GET", f"/api/v1/namespaces/{ns}/pods?labelSelector="
                    + urllib.parse.quote(f"tekton.dev/pipelineRun={name}")).get("items", [])
    pods.sort(key=lambda p: p["metadata"].get("creationTimestamp", ""))
    tasks, text = {}, ""
    for pod in pods:
        tname = (pod["metadata"].get("labels") or {}).get("tekton.dev/pipelineTask", pod["metadata"]["name"])
        tasks[tname] = (pod.get("status") or {}).get("phase", "Pending")
        try:
            out = k8s.call("GET", f"/api/v1/namespaces/{ns}/pods/{pod['metadata']['name']}/log"
                           "?container=step-run&tailLines=200", raw=True)
        except HttpError:
            out = ""            # not started yet
        if out.strip():
            text += f"--- {tname} ---\n{out.rstrip()}\n"
    owner = RUN_USER_RE.search(text)
    if owner and owner.group(1) != caller and caller not in admins():
        raise HttpError(404, f"{name} is not a run you requested")
    if owner:
        log_text = text.strip()
    elif status == "False":
        log_text = (f"(the request failed before it was verified; an administrator can see "
                    f"PipelineRun {name} in namespace {ns})")
    else:
        log_text = ""
    message = cond.get("message", "") if status == "False" else ""
    errors = [l.split("ERROR: ", 1)[1] for l in log_text.splitlines() if "ERROR: " in l]
    if errors:
        message = errors[-1]
    summary = f"Pipeline run {name}: {phase}" + (f" - {message}" if message else "")
    run_done = status in ("True", "False")
    body = {"run": name, "phase": phase, "done": run_done, "failed": status == "False",
            "tasks": tasks, "message": message, "log": log_text,
            "text": summary + ("\n\n" + log_text if log_text else "")}
    if task:
        state = tasks.get(task, "Waiting")
        body["task"], body["taskState"] = task, state
        body["done"] = run_done or state in ("Succeeded", "Failed")
    return body


def wait_for(check, done, seconds, sleep=time.sleep, clock=time.monotonic):
    """check() until done(result) or `seconds` pass; the last result."""
    deadline = clock() + max(0, min(seconds, WAIT_LIMIT))
    result = check()
    while not done(result) and clock() < deadline:
        sleep(min(POLL_SECONDS, max(0.0, deadline - clock())))
        result = check()
    return result


class JwksCache:
    """RHDH's JWKS documents, refetched every few minutes."""

    def __init__(self, ttl=300):
        self.ttl, self.docs = ttl, {}

    def __call__(self, path):
        now = time.time()
        hit = self.docs.get(path)
        if hit and now - hit[0] < self.ttl:
            return hit[1]
        rhdh = env("RHDH_INTERNAL_URL").rstrip("/")
        doc = fetch_json(rhdh + path, insecure=os.environ.get("RHDH_SKIP_VERIFY") == "true")
        self.docs[path] = (now, doc)
        return doc


PORTAL_NS_LABEL = "saw.redhat.com/portal"


def check_applications_are_ours(k8s, user):
    """None of the Applications this user's workspace needs may belong to
    someone else (a name that collides). A Git-declared user's own apps
    carry their label too; check_namespace_is_ours refuses those."""
    argo = env("ARGO_NAMESPACE")
    for app in (f"saw-{user}", f"saw-{user}-bom", f"saw-{user}-secrets", f"portal-ws-{user}"):
        obj = k8s.call("GET", f"/apis/argoproj.io/v1alpha1/namespaces/{argo}/applications/{app}", ok404=True)
        if obj is not None and (obj["metadata"].get("labels") or {}).get("openshell.pattern/owner") != user:
            raise PortalError(f"Argo CD application {app} exists and is not {user}'s")


def check_namespace_is_ours(k8s, user):
    """A user whose workspace is declared in Git (overrides/saw-users.yaml)
    already has namespace saw-<user> without the portal's label: a portal
    entry for them would fight over the same Applications."""
    ns = k8s.call("GET", f"/api/v1/namespaces/saw-{user}", ok404=True)
    if ns is not None and (ns["metadata"].get("labels") or {}).get(PORTAL_NS_LABEL) != "true":
        raise PortalError(f"namespace saw-{user} exists and is not managed by the portal "
                          "(is the workspace declared in overrides/saw-users.yaml?)")


def delete_application(k8s, user):
    """The ApplicationSet only creates and updates (a registry hiccup must
    not delete VMs), so delete removes the user's Application itself; its
    finalizer takes the user's apps (and, with pruneOnRemove, the VM) along."""
    argo = env("ARGO_NAMESPACE")
    path = f"/apis/argoproj.io/v1alpha1/namespaces/{argo}/applications/portal-ws-{user}"
    if k8s.call("DELETE", path, ok404=True) is None:
        log(f"no Application portal-ws-{user} (not built yet?)")
    else:
        log(f"Application portal-ws-{user} deleted; Argo CD removes the workspace")


def write_result(user):
    """The user, as the Tekton result the pipeline's later tasks read."""
    path = os.environ.get("RESULT_PATH")
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(user)


def check_run_label(k8s, ns, user):
    """The PipelineRun's backstage.io/kubernetes-id label puts it on a
    workspace's Tekton tab. The template sets it to the user's workspace;
    a run labelled with someone else's is refused, so it cannot pose as
    theirs."""
    run = os.environ.get("PIPELINE_RUN")
    if not run:
        return
    obj = k8s.call("GET", f"/apis/tekton.dev/v1/namespaces/{ns}/pipelineruns/{run}", ok404=True) or {}
    label = ((obj.get("metadata") or {}).get("labels") or {}).get(KUBERNETES_ID_LABEL)
    if label and label != f"saw-{user}":
        raise PortalError(f"pipeline run {run} is labelled {KUBERNETES_ID_LABEL}={label}, "
                          f"not saw-{user}")


def vault_client():
    return Vault(env("VAULT_ADDR"), env("VAULT_AUTH_MOUNT"), env("VAULT_ROLE"), env("VAULT_KV_MOUNT", "secret"))


def admins():
    """Users who may create or delete another user's workspace
    (portal.admins in the chart)."""
    return {a.strip() for a in os.environ.get("PORTAL_ADMINS", "").split(",") if a.strip()}


def workspace_user(ref):
    """The user of a workspace reference: component:default/saw-carol,
    resource:default/saw-carol (older entities) or saw-carol."""
    name = ref.strip().split("/")[-1]
    if not name.startswith("saw-"):
        raise PortalError(f"{ref!r} is not an agent workspace (saw-<user>)")
    return name[len("saw-"):]


def target_user(action, data, caller):
    """Whose workspace a request is for. The caller's own, unless the form
    names someone else's (create: forUser; delete: the chosen workspace),
    which only an administrator may do."""
    asked = (data.get("forUser") or "").strip()
    if action == "delete" and data.get("workspace", "").strip():
        asked = workspace_user(data["workspace"])
    if not asked or asked == caller:
        return caller
    if caller not in admins():
        raise PortalError(f"{caller} may only {action} their own workspace (saw-{caller}); "
                          f"saw-{asked} needs an administrator")
    return check_user(asked)


def handle(action, request_name):
    ns = env("NAMESPACE")
    k8s = kube()
    catalog = load_catalog(env("CATALOG_PATH"))
    if action not in ("create", "delete"):
        raise PortalError(f"unknown action {action}")
    path = request_path(ns, request_name)
    try:
        data = read_request(k8s, ns, request_name)
        if data.get("action", "") != action:
            raise PortalError(f"request {request_name} is a {data.get('action') or '?'} request, "
                              f"not {action}")
        caller = requester(data)
        user = target_user(action, data, caller)
        log(f"{action} request {request_name} from {caller}" + (f" for {user}" if user != caller else ""))
        check_run_label(k8s, ns, user)
        name = f"saw-ws-{user}"
        cm = k8s.call("GET", f"/api/v1/namespaces/{ns}/configmaps/{name}", ok404=True)
        deleting = cm is not None and (cm["metadata"].get("labels") or {}).get(DELETING_LABEL) == "true"
        if action == "create":
            if deleting:
                raise PortalError(f"workspace saw-{user} is being deleted; request it again when "
                                  "the delete pipeline has finished")
            profile, secrets = parse_request(data, catalog)
            check_namespace_is_ours(k8s, user)
            check_applications_are_ours(k8s, user)
            vault = vault_client()
            for secret, values in secrets.items():
                vault.write(f"{vault_prefix(user)}/{secret}", values)
                log(f"Vault: {vault_prefix(user)}/{secret} ({', '.join(sorted(values))})")
            entry = registry_entry(user, profile)
            put_configmap(k8s, ns, name, {"user.json": json.dumps(entry, sort_keys=True)},
                          {WORKSPACE_LABEL: "true", "openshell.pattern/owner": user},
                          resource_version=cm["metadata"].get("resourceVersion") if cm else None)
            log(f"workspace saw-{user} registered with profile {profile}; Argo CD builds it next")
        else:
            argo_app = f"/apis/argoproj.io/v1alpha1/namespaces/{env('ARGO_NAMESPACE')}/applications/portal-ws-{user}"
            if cm is None and k8s.call("GET", argo_app, ok404=True) is None:
                raise PortalError(f"{user} has no portal workspace")
            # Mark the entry first: the ApplicationSet (create and update
            # only) then stops getting it, so it does not rebuild the
            # Application, while the catalog keeps showing the workspace
            # (Deleting) until finish-delete removes the entry.
            if cm is not None and not deleting:
                cm["metadata"].setdefault("labels", {})[DELETING_LABEL] = "true"
                k8s.call("PUT", f"/api/v1/namespaces/{ns}/configmaps/{name}", cm)
            log(f"workspace saw-{user} marked for deletion")
            delete_application(k8s, user)
        write_result(user)
    except NotARequest:
        raise
    except BaseException:
        k8s.call("DELETE", path, ok404=True)
        raise
    k8s.call("DELETE", path, ok404=True)


def finish_delete(user):
    """The delete pipeline's last task, once the workspace is gone: the
    registry entry and (by default) the user's keys in Vault."""
    ns = env("NAMESPACE")
    check_user(user)
    k8s = kube()
    catalog = load_catalog(env("CATALOG_PATH"))
    k8s.call("DELETE", f"/api/v1/namespaces/{ns}/configmaps/saw-ws-{user}", ok404=True)
    log(f"workspace saw-{user} removed from the registry")
    if os.environ.get("DELETE_VAULT_SECRETS", "true") == "true":
        vault = vault_client()
        for secret in sorted({s for p in catalog.values() for s in p.get("secrets", {})}):
            vault.destroy(f"{vault_prefix(user)}/{secret}")
        log(f"Vault: {vault_prefix(user)}/* deleted")
    write_result(user)


def wait_stage(stage, user, timeout, sleep=time.sleep, clock=time.monotonic, ping=None):
    """A create pipeline task: wait until the workspace reaches `stage`
    (or, for "gone", until Argo CD has removed it), logging each change.
    Fails when a stage fails or `timeout` seconds pass."""
    ns, argo_ns = env("NAMESPACE"), env("ARGO_NAMESPACE")
    check_user(user)
    k8s = kube()
    catalog = load_catalog(env("CATALOG_PATH"))
    domain = os.environ.get("CLUSTER_DOMAIN", "")
    if stage != "gone" and stage not in STAGE_IDS:
        raise PortalError(f"unknown stage {stage}; one of {', '.join(STAGE_IDS)}, gone")
    deadline, last = clock() + timeout, None
    while True:
        if stage == "gone":
            done, detail = removal_status(k8s, user, argo_ns)
            failed = False
        else:
            st = workspace_status(k8s, user, catalog, ns, argo_ns, domain, ping)
            current = next((x for x in st["steps"] if x["id"] == stage), {})
            detail = current.get("detail") or st["message"]
            done = current.get("state") == "done"
            failed = st["failed"]
            if failed:
                detail = st["message"]
        if detail != last:
            log(("done: " if done else "") + detail)
            last = detail
        if done:
            write_result(user)
            return
        if failed:
            raise PortalError(detail)
        if clock() >= deadline:
            raise PortalError(f"not done after {timeout // 60} minutes: {detail}")
        sleep(POLL_SECONDS * 2)


def cleanup(max_age=REQUEST_MAX_AGE):
    """Delete request Secrets nobody handled (a failed or never-started run,
    or a request posted without a run), which still hold keys."""
    ns = env("NAMESPACE")
    k8s = kube()
    items = k8s.call("GET", f"/api/v1/namespaces/{ns}/secrets?labelSelector="
                     + urllib.parse.quote(f"{REQUEST_LABEL}=true")).get("items", [])
    now = time.time()
    for obj in items:
        name = obj["metadata"]["name"]
        created = obj["metadata"].get("creationTimestamp", "")
        if not REQUEST_NAME_RE.match(name) or not created:
            continue
        if now - calendar.timegm(time.strptime(created, "%Y-%m-%dT%H:%M:%SZ")) > max_age:
            k8s.call("DELETE", request_path(ns, name), ok404=True)
            log(f"deleted stale request {name}")


# -- ApplicationSet plugin generator --------------------------------------------

def generator_params(workspaces, defaults):
    """One parameter set per workspace: `name`, and `values`, the saw-users
    chart values for that user alone (JSON, which is YAML)."""
    out = []
    for ws in workspaces:
        values = {**defaults, "users": [ws]}
        out.append({"name": ws["name"], "values": json.dumps(values, sort_keys=True)})
    return out


def serve():
    token = open(env("GENERATOR_TOKEN_FILE"), encoding="utf-8").read().strip()
    ns = env("NAMESPACE")
    defaults = json.loads(os.environ.get("SAW_USERS_VALUES", "{}"))
    catalog = load_catalog(env("CATALOG_PATH"))
    argo_ns = env("ARGO_NAMESPACE")
    domain = os.environ.get("CLUSTER_DOMAIN", "")
    jwks = JwksCache()
    realm_users = RealmUsers()
    owner_subjects = OwnerSubjects()

    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, code, body):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_text(self, code, text, ctype):
            raw = text.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            if url.path == "/healthz":
                # Still 200 with bad entries: restarting the pod fixes nothing.
                return self._send(200, {"ok": True, "skippedRegistryEntries": list(BAD_ENTRIES)})
            if url.path.startswith("/status/"):
                return self._status(url)
            if url.path != "/catalog.yaml":
                return self._send(404, {"error": "not found"})
            # No token on purpose: RHDH's catalog reads it as a plain URL
            # location. It lists user and profile names and each workspace's
            # stage (the same as the namespace names), and a NetworkPolicy
            # lets only RHDH and Argo CD reach this pod.
            try:
                k8s = kube()
                workspaces = list_workspaces(k8s, ns, deleting=True)
                statuses = {}
                for ws in workspaces:
                    try:
                        statuses[ws["name"]] = workspace_status(k8s, ws["name"], catalog, ns, argo_ns, domain)
                    except PortalError as exc:
                        log(f"WARN: status of saw-{ws['name']}: {exc}")
                text = entities_yaml(workspaces, catalog, domain,
                                     os.environ.get("RHDH_BASE_URL", ""), statuses, ns, realm_users())
            except PortalError as exc:
                log(f"ERROR: {exc}")
                return self._send(500, {"error": str(exc)})
            self._send_text(200, text, "application/yaml")

        def _status(self, url):
            """GET /status/run/<pipelinerun>[?wait=S][&assert=1]
            GET /status/workspace[?for=<stage>&wait=S][&assert=ready][&user=<u>, admins]

            For the caller named by the Backstage token in X-Saw-Token. wait
            holds the answer until the run ends / the stage is reached / it
            fails (at most WAIT_LIMIT s). assert answers 422 when the run
            failed or did not end / the workspace failed or is not ready, so
            a template step fails with it."""
            query = urllib.parse.parse_qs(url.query)
            arg = lambda k, d="": (query.get(k) or [d])[0]  # noqa: E731
            try:
                caller = token_user(self.headers.get("X-Saw-Token", ""), jwks, STATUS_TOKEN_LEEWAY)
            except PortalError as exc:
                return self._send(401, {"error": str(exc)})
            try:
                wait = int(arg("wait", "0") or 0)
            except ValueError:
                return self._send(400, {"error": "wait must be a number of seconds"})
            try:
                k8s = kube()
                parts = url.path.split("/")
                if len(parts) == 4 and parts[2] == "run":
                    task = arg("task") or None
                    body = wait_for(lambda: run_status(k8s, ns, parts[3], caller, task),
                                    lambda r: r["done"], wait)
                    bad = bool(arg("assert")) and (body["failed"] or not body["done"])
                    if bad:
                        body["error"] = body["message"] or f"pipeline run {body['run']} is {body['phase']}"
                elif url.path == "/status/workspace":
                    stage = arg("for", "ready")
                    if stage not in STAGE_IDS:
                        return self._send(400, {"error": f"for must be one of {', '.join(STAGE_IDS)}"})
                    target = STAGE_IDS.index(stage)

                    def reached(st):
                        return st["phase"] in STAGE_IDS and STAGE_IDS.index(st["phase"]) >= target
                    who = arg("user") or caller
                    if who != caller and caller not in admins():
                        return self._send(403, {"error": f"{caller} may only see their own workspace"})
                    try:
                        who = check_user(who)
                    except PortalError as exc:
                        return self._send(400, {"error": str(exc)})
                    body = wait_for(lambda: workspace_status(k8s, who, catalog, ns, argo_ns, domain),
                                    lambda st: st["failed"] or reached(st), wait)
                    bad = bool(arg("assert")) and (body["failed"] or not reached(body))
                    if bad:
                        body["error"] = (body["message"] if body["failed"] else
                                         f"the workspace is not {stage} yet: {body['message']}")
                else:
                    return self._send(404, {"error": "not found"})
            except HttpError as exc:
                return self._send(exc.code if exc.code == 404 else 502, {"error": str(exc)})
            except PortalError as exc:
                log(f"ERROR: {exc}")
                return self._send(500, {"error": str(exc)})
            self._send(422 if bad else 200, body)

        def do_POST(self):
            if self.path != "/api/v1/getparams.execute":
                return self._send(404, {"error": "not found"})
            if self.headers.get("Authorization", "") != f"Bearer {token}":
                return self._send(403, {"error": "forbidden"})
            try:
                params = generator_params(owner_subjects.fill(list_workspaces(kube(), ns)), defaults)
            except PortalError as exc:
                log(f"ERROR: {exc}")
                return self._send(500, {"error": str(exc)})
            self._send(200, {"output": {"parameters": params}})

        def log_message(self, fmt, *args):
            log(fmt % args)

    port = int(os.environ.get("PORT", "4355"))
    log(f"plugin generator listening on :{port}")
    http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


def main(argv):
    argv = list(argv)
    while argv and argv[-1] == "":     # an unset optional Tekton parameter
        argv.pop()
    try:
        if argv[:1] == ["serve"]:
            serve()
        elif argv[:1] == ["cleanup"]:
            cleanup()
        elif len(argv) == 2 and argv[0] in ("create", "delete"):
            handle(argv[0], argv[1])
        elif len(argv) == 2 and argv[0] == "finish-delete":
            finish_delete(argv[1])
        elif len(argv) in (2, 3) and argv[0].startswith("wait-"):
            wait_stage(argv[0][len("wait-"):], argv[1], int(argv[2]) if len(argv) == 3 else 1800)
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except PortalError as exc:
        log(f"ERROR: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
