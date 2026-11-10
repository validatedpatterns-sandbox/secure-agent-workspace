#!/usr/bin/env python3
"""Self-service workspaces for the Secure Agent Workspace pattern.

Standard library only; packaged with the shared workspace projector:

  portal.py create REQUEST        pipeline saw-workspace-create, task register
  portal.py wait-<stage> USER [S] its later tasks: wait for apps, vm, running,
                                  ready (OpenShell and sandbox UIs answer)
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
delete  marks the registry entry as deleting, owned by its pipeline run
        (the ApplicationSet stops getting it, and a create is refused), and
        deletes the user's Application; finish-delete, once Argo CD has
        removed the workspace, destroys the user's Vault entries and only
        then removes the entry, and only if it is still that run's: a
        replacement workspace or a newer delete is left alone.
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
from concurrent.futures import ThreadPoolExecutor
import threading
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
# The delete pipeline run that owns a deleting entry: only its finish-delete
# may destroy the keys and remove the entry.
DELETION_ANNOTATION = "saw.redhat.com/deletion"
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


# Packaged from charts/saw-users/files/workspace.py by make catalog.
import importlib.util as _importlib
from pathlib import Path as _Path
_workspace_spec = _importlib.spec_from_file_location("saw_workspace", _Path(__file__).with_name("workspace.py"))
_workspace = _importlib.module_from_spec(_workspace_spec)
_workspace_spec.loader.exec_module(_workspace)


def _project(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except _workspace.WorkspaceError as exc:
        raise PortalError(str(exc)) from exc


def enabled_catalog_sandboxes(profile):
    return _workspace.enabled_catalog_sandboxes(profile)


def sandbox_targets(user, registration, profile, *, model_lifecycle=False):
    return _workspace.sandbox_targets(user, registration, profile, model_lifecycle=model_lifecycle)


def public_model_inputs(profile, secrets):
    return _project(_workspace.public_model_inputs, profile, secrets)


def approved_endpoint(profile, secrets, boundary):
    return _project(_workspace.approved_endpoint, profile, secrets, boundary)


def enrolled_site(site, workspace, read):
    def observed(path):
        try:
            return read(path)
        except HttpError as exc:
            if exc.code == 403:  # first sync, before the named reader grant exists
                return {}
            raise
    return _project(_workspace.enrolled_site, site, workspace, observed if read else None)


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
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise PortalError(f"{what}: missing signing key ID")
    if callable(jwks):
        jwks = jwks(kid)
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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def fetch_json(url):
    """Read RHDH signing keys over verified TLS without following redirects."""
    endpoint = urllib.parse.urlsplit(url)
    if (endpoint.scheme != "https" or not endpoint.hostname or endpoint.username is not None
            or endpoint.password is not None or endpoint.query or endpoint.fragment):
        raise PortalError("RHDH signing keys require a configured HTTPS endpoint")
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(
        context=ssl.create_default_context()))
    try:
        with opener.open(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=15) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise PortalError("RHDH signing key response is too large")
        data = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise PortalError("could not fetch RHDH signing keys from the configured HTTPS endpoint") from exc
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list) or not all(
            isinstance(key, dict) for key in data["keys"]):
        raise PortalError("invalid RHDH signing key response")
    return data


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


# Request policy is operator-owned, never taken from a form or registry entry.
DEPLOYMENT_MODES = ("vm", "container")
# A renderable foundation is not a qualified provisioning/readiness adapter.
# Expand only when runtime lifecycle, BOM and readiness are implemented.
PROVISIONABLE_MODES = ("vm",)


def container_site(user):
    """Trusted site inventory, never names/URLs supplied by the request."""
    sites = json.loads(os.environ.get("SAW_CONTAINER_SITES", "{}"))
    site = sites.get(user)
    if not isinstance(site, dict) or not re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", str(site.get("subject", ""))):
        return None
    return site


def container_profiles(site):
    automatic = site.get("automaticEnrollment", {})
    return automatic.get("approvedProfiles", {})


def registered_links(entry, catalog, domain):
    if entry_deployment_mode(entry) == "container":
        if entry.get("desiredState") == "Stopped":
            return []
        return sandbox_ui_links(entry["name"], entry.get("profiles", []), catalog, domain) if domain else []
    return ui_links(entry["name"], entry.get("profiles", []), catalog, domain)


def container_status(k8s, user, entry, argo_ns, domain, ping, catalog=None):
    reg = entry_generation(user, entry)
    normalized = {**entry, "name": user, "registration": reg,
                  "installationID": installation_id(user, reg) if reg else ""}
    def read(path):
        try:
            return k8s.call("GET", path, ok404=True)
        except HttpError as exc:
            if exc.code == 403:
                return {}
            raise
    return _workspace.container_status(read, normalized, container_site(user), argo_ns, domain, ping, catalog)


def installation_id(user, registration):
    import uuid
    if not GENERATION_RE.fullmatch(registration):
        raise PortalError("container requires a generation-scoped registration")
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "urn:saw:portal:" + check_user(user) + ":" + registration))


def deployment_modes():
    try:
        modes = json.loads(os.environ.get("SAW_DEPLOYMENT_MODES", '["vm"]'))
    except ValueError:
        raise PortalError("SAW_DEPLOYMENT_MODES must be a JSON list") from None
    if (not isinstance(modes, list) or not modes or "vm" not in modes
            or any(not isinstance(m, str) or m not in DEPLOYMENT_MODES for m in modes)
            or len(set(modes)) != len(modes)):
        raise PortalError("SAW_DEPLOYMENT_MODES must contain vm and unique supported modes: vm, container")
    return tuple(modes)


def validate_deployment_mode(mode):
    if not isinstance(mode, str) or mode not in DEPLOYMENT_MODES:
        raise PortalError("deploymentMode must be one of vm, container")
    return mode


def request_deployment_mode(data):
    mode = validate_deployment_mode(data.get("deploymentMode", "vm"))
    if mode not in deployment_modes():
        raise PortalError(f"deploymentMode={mode} is not enabled by the administrator")
    return mode


def entry_deployment_mode(entry):
    """Legacy registry entries are VMs, independently of later chart defaults."""
    values = entry.get("values", {})
    if not isinstance(values, dict):
        raise PortalError("registry values must be an object")
    deployment = values.get("deployment", {})
    if not isinstance(deployment, dict) or set(deployment) - {"mode"}:
        raise PortalError("registry deployment must be an object with only mode")
    return validate_deployment_mode(deployment.get("mode", "vm"))


def assert_mode_unchanged(entry, mode):
    if entry_deployment_mode(entry) != mode:
        raise PortalError("workspace deployment mode is immutable; an explicit migration is required")


def parse_request(data, catalog):
    """The chosen profile and, for each Secret it reads, the field values.

    `data` is the request Secret's decoded data: `profile`, and one key per
    form field, `<secret>.<field>`. Fields of other profiles are ignored; a
    required field left empty is refused."""
    profile = data.get("profile", "")
    if profile not in catalog:
        raise PortalError(f"unknown profile {profile!r}; available: {', '.join(sorted(catalog))}")
    secrets, missing = {}, []
    allowed = catalog[profile].get("dedicatedEndpointSecrets") if request_deployment_mode(data) == "container" else None
    for name, spec in sorted(catalog[profile].get("secrets", {}).items()):
        if allowed is not None and name not in allowed:
            continue
        values = {}
        for field in spec.get("fields", []):
            value = (data.get(f"{name}.{field['key']}") or "").strip()
            if not value and "default" in field:
                value = field["default"]
            if not value:
                # Absent: an error when required, else left out of the Secret
                # (the installer then uses the profile's default, if any).
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
        jwks = lambda path: fetch_json(rhdh + path)  # noqa: E731
    def keys_for(path):
        if isinstance(jwks, JwksCache):
            return lambda kid: jwks(path, kid)
        return lambda kid: jwks(path)

    return check_user(verify_backstage_token(token, keys_for("/api/auth/.well-known/jwks.json"),
                                             keys_for("/api/scaffolder/.backstage/auth/v1/jwks.json"),
                                             leeway=leeway))


def requester(data):
    """The user a request is for: only ever from its verified Backstage
    token (there is no switch to trust the form instead)."""
    return token_user(data.get("token", ""))


GENERATION_RE = re.compile(r"[0-9a-f]{16}")


def vault_prefix(user, generation=""):
    """Where a workspace's keys are in Vault: <base>/saw-<user>/<generation>.
    Each registration (a create with no entry) gets a new generation, which
    stays for as long as the entry lives, so the cleanup of a deleted
    workspace destroys only that registration's keys, never a replacement's.
    Entries from before generations keep <base>/saw-<user>."""
    base = f"{env('VAULT_PREFIX_BASE', 'hub')}/saw-{user}"
    return f"{base}/{generation}" if generation else base


def new_generation():
    return os.urandom(8).hex()


def entry_generation(user, entry):
    """The generation of a registry entry, from its vaultPrefix: "" for an
    entry from before generations (or a deletion mark that stands in for a
    missing entry). A vaultPrefix outside the user's own is refused."""
    prefix = (entry or {}).get("vaultPrefix")
    if not prefix:
        return ""
    base = f"{env('VAULT_KV_MOUNT', 'secret')}/data/{vault_prefix(user)}"
    if prefix == base:
        return ""
    generation = prefix[len(base) + 1:] if prefix.startswith(base + "/") else ""
    if not GENERATION_RE.fullmatch(generation):
        raise PortalError(f"registry entry saw-ws-{user} has vaultPrefix {prefix!r}, "
                          f"not under {base}")
    return generation


def read_entry(cm):
    """The registry entry a ConfigMap saw-ws-<user> holds; {} when its
    user.json is missing or broken."""
    try:
        entry = json.loads(((cm or {}).get("data") or {}).get("user.json", ""))
    except ValueError:
        return {}
    return entry if isinstance(entry, dict) else {}


def registry_entry(user, profile, generation="", mode="vm"):
    """The saw-users list entry for a portal workspace."""
    mode = validate_deployment_mode(mode)
    return {"name": user, "profiles": [profile], "ownerSubject": "",
            "values": {"deployment": {"mode": mode}},
            "vaultPrefix": f"{env('VAULT_KV_MOUNT', 'secret')}/data/{vault_prefix(user, generation)}",
            "pruneOnRemove": os.environ.get("PRUNE_ON_REMOVE", "true") == "true"}


def put_configmap(k8s, ns, name, data, labels=None, resource_version=None, deployment_mode=None):
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
    # Create. Two requests for the same user at once can both end here; the
    # later one finds the entry and replaces it, but only after checking it
    # again and only the version it checked: a delete may have marked it
    # since this request first looked.
    try:
        k8s.call("POST", path, body)
        return
    except HttpError as exc:
        if exc.code != 409:
            raise
    current = k8s.call("GET", f"{path}/{name}", ok404=True)
    if current is None or is_deleting(current):
        raise PortalError(f"{name} changed while this request ran (a delete?); request it again")
    if deployment_mode is not None:
        assert_mode_unchanged(read_entry(current), deployment_mode)
        if deployment_mode == "container":
            raise PortalError("concurrent container registration; refusing to replace its identity")
    put_configmap(k8s, ns, name, data, labels, current["metadata"]["resourceVersion"], deployment_mode)


CREDENTIAL_WRITER = "saw.redhat.com/credential-writer"
WRITER_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def credential_writer_state(k8s, namespace, holder):
    if not WRITER_NAME.fullmatch(holder):
        raise PortalError("invalid registration credential writer")
    run = k8s.call("GET", f"/apis/tekton.dev/v1/namespaces/{namespace}/pipelineruns/{holder}", ok404=True)
    if not run:
        return "missing"
    terminal = any(c.get("type") == "Succeeded" and c.get("status") in ("True", "False")
                       for c in run.get("status", {}).get("conditions", []))
    return "incomplete" if terminal else "running"


def check_credential_writer(k8s, namespace, cm):
    """Serialize Vault changes with registration publication and deletion."""
    holder = (cm or {}).get("metadata", {}).get("annotations", {}).get(CREDENTIAL_WRITER)
    if not holder or holder == os.environ.get("PIPELINE_RUN"):
        return
    state = credential_writer_state(k8s, namespace, holder)
    if state == "missing":
        raise PortalError("credential writer PipelineRun is missing; operator recovery required")
    if state == "running":
        raise PortalError("another pipeline is publishing this registration's credentials")


def committed_entry(cm):
    """Legacy interrupted writers have no proven previous publication."""
    if (cm or {}).get("metadata", {}).get("annotations", {}).get(CREDENTIAL_WRITER):
        try:
            data = json.loads(cm.get("data", {}).get("committed.json", "{}"))
        except (TypeError, ValueError):
            raise PortalError("invalid committed registration") from None
        if not isinstance(data, dict):
            raise PortalError("invalid committed registration")
        return data
    return read_entry(cm)


def reserve_credentials(k8s, ns, name, previous, entry, user):
    """A failed/crashed write always has a registered generation for recovery."""
    writer = env("PIPELINE_RUN")
    if not WRITER_NAME.fullmatch(writer):
        raise PortalError("credential publication requires a named PipelineRun")
    path = f"/api/v1/namespaces/{ns}/configmaps"
    body = {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": ns,
                         "labels": {WORKSPACE_LABEL: "true", "openshell.pattern/owner": user},
                         "annotations": {CREDENTIAL_WRITER: writer}},
            "data": {"user.json": json.dumps(entry, sort_keys=True)}}
    if previous:
        committed = committed_entry(previous)
        if committed:
            body["data"]["committed.json"] = json.dumps(committed, sort_keys=True)
        meta = body["metadata"] = dict(previous["metadata"])
        meta["annotations"] = {**meta.get("annotations", {}), CREDENTIAL_WRITER: writer}
    try:
        return k8s.call("PUT" if previous else "POST", path + ("/"+name if previous else ""), body)
    except HttpError as exc:
        if exc.code != 409:
            raise
        raise PortalError("concurrent registration changed before credential publication") from None


def check_container_identity(user, site):
    """Resolve the authenticated catalog login in the configured issuer before any write."""
    if not site or not site.get("subject"):
        raise PortalError("missing enrolled container owner")
    issuer = env("KEYCLOAK_URL").rstrip("/") + "/realms/" + env("KEYCLOAK_REALM")
    relay_issuer = site.get("automaticEnrollment", {}).get("relay", {}).get("issuer")
    if relay_issuer and relay_issuer.rstrip("/") != issuer:
        raise PortalError("workspace relay and owner directory must use the same issuer")
    path = env("KEYCLOAK_SECRET_FILE")
    with open(path, encoding="utf-8") as credential:
        ids = keycloak_user_ids(env("KEYCLOAK_URL"), env("KEYCLOAK_REALM"), env("KEYCLOAK_CLIENT_ID"),
                                credential.read().strip(), [user], insecure=False)
    if ids.get(user) != site["subject"]:
        raise PortalError("current identity does not match the enrolled container owner")


def is_deleting(cm):
    return (cm["metadata"].get("labels") or {}).get(DELETING_LABEL) == "true"


def pipeline_run():
    """This task's pipeline run (the lifecycle id of a delete), or "manual"."""
    return os.environ.get("PIPELINE_RUN") or "manual"


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
        if cm["metadata"].get("annotations", {}).get(CREDENTIAL_WRITER) and not deleting:
            try:
                entry = committed_entry(cm)
                if entry and name != f"saw-ws-{entry.get('name')}":
                    raise PortalError("committed registration has a different owner")
            except PortalError:
                log(f"ERROR: registry entry {name} has an invalid committed registration; skipped")
                bad.append(name)
                continue
            if not entry:
                continue
        if (cm["metadata"].get("labels") or {}).get(DELETING_LABEL) == "true" and not deleting:
            continue
        try:
            entry_deployment_mode(entry)
        except PortalError:
            log(f"ERROR: registry entry {name} has an invalid deployment mode; skipped")
            bad.append(name)
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
    return _workspace.sandbox_ui_links(user, profiles, catalog, domain)


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


def linked_runtime_phase(k8s, link):
    """Read only the installation's two named objects; a stale generation cannot be Ready."""
    ref = link["runtime"]
    ns = ref["namespace"]
    if not all(re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", ref[key])
               for key in ("namespace", "intent", "status")):
        raise PortalError("invalid runtime status reference")
    def read(name, key):
        cm = k8s.call("GET", f"/api/v1/namespaces/{ns}/configmaps/{name}", ok404=True)
        if not cm or cm.get("metadata", {}).get("deletionTimestamp"):
            return {}, {}
        return json.loads(cm.get("data", {}).get(key, "{}")), cm["metadata"].get("labels", {})
    try:
        intent, il = read(ref["intent"], "intent.json")
        status, sl = read(ref["status"], "status.json")
        owner_label = "saw.redhat.com/runtime-owner"
        binding = intent.get("bindings", {})
        if (il.get(owner_label) != ref["installationID"] or sl.get(owner_label) != ref["installationID"]
                or sl.get("saw.redhat.com/managed-by") != "kubernetes-runtime-controller"
                or binding.get("ownerID") != ref["installationID"] or binding.get("ownerSubject") != ref["ownerSubject"]
                or binding.get("namespace") != ns or binding.get("mode") != ref["mode"]):
            return "Unknown"
        if type(intent.get("generation")) is not int or status.get("observedGeneration") != intent["generation"]:
            return "Reconciling"
        phase = status.get("phase")
        if phase == "GenericReady" and intent.get("desiredState") == "Running":
            return "Running"
        if phase == "Stopped" and intent.get("desiredState") == "Stopped":
            return "Stopped"
        return "Blocked" if phase == "Blocked" else "Reconciling"
    except (PortalError, ValueError, TypeError, AttributeError):
        return "Unknown"


def entities_yaml(workspaces, catalog, domain, rhdh_url, statuses=None, portal_ns="saw-portal", users=None, runtime_reader=None):
    """RHDH catalog entities: one Component per workspace (the kind RHDH's
    catalog lists first, and the one its CI tab is made for), owned by its user,
    linking the OpenShell web UI and each sandbox UI route, with the
    workspace's status (workspace_status) when known. JSON documents (valid
    YAML) separated by ---."""
    docs = []
    for ws in workspaces:
        user = ws["name"]
        links = [{"url": url, "title": title, "icon": "dashboard" if i == 0 else "web"}
                 for i, (title, url) in enumerate(registered_links(ws, catalog, domain))]
        if rhdh_url:
            # The delete form, with this workspace already chosen.
            form = urllib.parse.quote(json.dumps({"workspace": f"component:default/saw-{user}"},
                                                 separators=(",", ":")))
            links.append({"url": f"{rhdh_url}/create/templates/default/delete-saw-workspace?formData={form}",
                          "title": "Delete workspace", "icon": "delete"})
        description = "Secure Agent Workspace (profiles: " + ", ".join(ws.get("profiles", [])) + ")"
        annotations = {"openshell.pattern/namespace": f"saw-{user}",
                       "openshell.pattern/deployment-mode": entry_deployment_mode(ws),
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
    # Operator-linked workspaces have their own lifecycle outside the portal registry.
    # Publish only a catalog link. Existing create/delete templates still own VM entries.
    for linked in json.loads(os.environ.get("SAW_LINKED_WORKSPACES", "[]")):
        owner, slug = linked["owner"], linked["routeLabel"]
        check_user(owner)
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", slug) or not domain:
            raise PortalError("linked workspace requires an ingress DNS label and cluster domain")
        runtime_metadata = {}
        if "runtime" in linked:
            mode = linked["runtime"]["mode"]
            phase = linked_runtime_phase(runtime_reader, linked) if runtime_reader else "Unknown"
            runtime_metadata = {"annotations": {"openshell.pattern/deployment-mode": mode, "openshell.pattern/status": phase},
                                "description": f"OpenShell {mode} workspace. Runtime status: {phase}."}
        docs.append({"apiVersion": "backstage.io/v1alpha1", "kind": "Component",
                     "metadata": {"name": f"linked-{slug}", "title": linked["title"], **runtime_metadata,
                                  "links": [{"url": f"https://{slug}.apps.{domain}",
                                             "title": "OpenClaw UI", "icon": "web"}]},
                     "spec": {"type": "agent-workspace", "owner": f"user:default/{owner}",
                              "lifecycle": "experimental"}})
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
    cafile = os.environ.get("KEYCLOAK_CA_FILE") or None
    ctx = ssl.create_default_context(cafile=cafile)
    if insecure:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            token = json.loads(resp.read())["access_token"]
    except urllib.error.HTTPError as exc:
        raise HttpError(exc.code, f"Keycloak token: HTTP {exc.code}") from None
    return Http(f"{url}/admin/realms/{realm}", token, cafile=cafile, insecure=insecure)


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
        users = kc.call("GET", "/users?exact=true&username="
                        + urllib.parse.quote(name)) or []
        if len(users) == 1 and users[0].get("username") == name and users[0].get("enabled") is True:
            subject = users[0].get("id")
            if isinstance(subject, str) and subject:
                out[name] = subject
    return out


class OwnerSubjects:
    """Fills a portal workspace's ownerSubject (empty in its registry
    entry) with the user's Keycloak id, so the installer makes them a member
    of their OpenShell workspaces and OpenShell's web UI lists them. Cached
    IDs are checked again after `ttl`, including recreated or disabled users.
    Without Keycloak settings (RBAC off) entries stay as they are."""

    def __init__(self, ttl=60):
        self.ttl, self.ids, self.tried, self.failed = ttl, {}, {}, set()

    def fill(self, workspaces):
        url = os.environ.get("KEYCLOAK_URL", "")
        if not url:
            return workspaces
        now = time.time()
        missing = [w["name"] for w in workspaces if not w.get("ownerSubject")
                   and now - self.tried.get(w["name"], 0) >= self.ttl]
        if missing:
            for name in missing:
                self.tried[name] = now
            try:
                found = keycloak_user_ids(
                    url.rstrip("/"), env("KEYCLOAK_REALM"), env("KEYCLOAK_CLIENT_ID"),
                    open(env("KEYCLOAK_SECRET_FILE"), encoding="utf-8").read().strip(), missing,
                    os.environ.get("KEYCLOAK_SKIP_VERIFY") == "true")
                for name in missing:
                    self.ids.pop(name, None)
                self.ids.update(found)
                self.failed.difference_update(missing)
            except (PortalError, OSError, ValueError, KeyError) as exc:
                log(f"WARN: Keycloak owner lookup failed ({exc}); projection held")
                for name in missing:
                    self.ids.pop(name, None)
                self.failed.update(missing)
        # An unavailable identity service is not an empty or disabled owner.
        # Hold the entire VM/container projection, including during the retry
        # backoff, rather than silently omitting entries or clearing membership.
        if any(not w.get("ownerSubject") and w["name"] in self.failed for w in workspaces):
            raise PortalError("Keycloak owner lookup unavailable; workspace projection held")
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
    """True when a verified URL answers with a non-5xx status. The router
    answers 503 until the VM's UI proxy listens. SSL_CERT_FILE supplies the
    cluster's ingress CA alongside the public roots."""
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), context=ctx,
                                    timeout=timeout) as resp:
            return resp.status < 500
    except urllib.error.HTTPError as exc:
        return exc.code < 500
    except (OSError, ValueError):
        return False


def owner_route_available(url, timeout=3):
    issuer = os.environ.get("KEYCLOAK_URL", "").rstrip("/")
    if not issuer:
        return False
    issuer += "/realms/" + os.environ.get("KEYCLOAK_REALM", "openshell")
    return _workspace.owner_route_available(url, issuer, urllib.request.build_opener(NoRedirect()), timeout)


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
    vm_ping = ping or ping_url
    reached, details, failure = {}, {}, ""
    cm = k8s.call("GET", f"/api/v1/namespaces/{ns}/configmaps/saw-ws-{user}", ok404=True)
    try:
        entry = json.loads(((cm or {}).get("data") or {}).get("user.json", "")) if cm else {}
    except ValueError:
        entry = {}
    profiles = entry.get("profiles", []) if isinstance(entry, dict) else []
    if cm is not None and (cm["metadata"].get("labels") or {}).get(DELETING_LABEL) == "true":
        try:
            _, detail = removal_status(k8s, user, argo_ns, entry)
        except HttpError as exc:
            if exc.code != 403:
                raise
            # The read-only catalog has no cluster namespace inventory. Only
            # wait-gone, running as the provisioner, can attest full removal.
            detail = "The deletion pipeline is verifying workspace removal"
        return {"user": user, "phase": "deleting", "title": PHASE_TITLES["deleting"],
                "message": detail, "ready": False, "failed": False, "steps": [], "links": [],
                "text": f"Deleting: {detail}"}
    holder = (cm or {}).get("metadata", {}).get("annotations", {}).get(CREDENTIAL_WRITER)
    if holder:
        state = credential_writer_state(k8s, ns, holder)
        message = {"running": "Publishing credentials",
                   "incomplete": "Credential publication incomplete. Retry the create form or delete the workspace.",
                   "missing": "Credential writer is missing. Ask the operator to recover the registration."}[state]
        return {"user": user, "deploymentMode": entry_deployment_mode(entry), "phase": "publishing" if state == "running" else "failed",
                "title": message, "text": message, "message": message, "ready": False,
                "failed": state != "running", "steps": [], "links": []}
    mode = entry_deployment_mode(entry)
    if mode == "container" and container_site(user):
        return container_status(k8s, user, entry, argo_ns, domain, ping or owner_route_available, catalog)
    if mode not in PROVISIONABLE_MODES:
        message = f"{mode} workspace lifecycle and readiness are not qualified in this release"
        return {"user": user, "deploymentMode": mode, "phase": "runtime-not-qualified",
                "title": "Runtime not available", "message": message, "ready": False,
                "failed": True, "steps": [], "links": [], "text": message}
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

    # The OpenShell web UI starts after profile apply, including for sandboxes
    # without a dedicated UI route. A running VM alone is not ready.
    uis = ui_links(user, profiles, catalog, domain)
    if not reached["running"]:
        reached["ready"] = False
        details["ready"] = "after the VM starts (about 10 minutes)"
    elif not uis:
        reached["ready"] = False
        details["ready"] = "installing; waiting for workspace routes"
    else:
        down = [title for title, url in uis if not vm_ping(url)]
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
                           "ready": "OpenShell and sandbox UIs answer"}[phase])
    links = [{"title": t, "url": u} for t, u in ui_links(user, profiles, catalog, domain)]
    marks = {"done": "[x]", "active": "[ ]", "waiting": "[ ]", "failed": "[!]"}
    lines = [f"{PHASE_TITLES[phase]}: {message}", ""]
    lines += [f"- {marks[s['state']]} {s['title']}: {s['detail']}" for s in steps]
    if links and phase == "ready":
        lines += ["", "Open: " + ", ".join(f"[{l['title']}]({l['url']})" for l in links)]
    return {"user": user, "phase": phase, "title": PHASE_TITLES[phase], "message": message,
            "ready": phase == "ready", "failed": bool(failure), "steps": steps, "links": links,
            "text": "\n".join(lines)}


def removal_status(k8s, user, argo_ns, entry=None):
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
    if entry and entry_deployment_mode(entry) == "container":
        reg = entry_generation(user, entry)
        if not reg:
            raise PortalError("refusing container cleanup without a registration")
        ui_names=entry.get("uiNamespaces",[f"saw-ui-{reg}"])
        if any(not re.fullmatch("saw-ui-[a-f0-9]{16}", n) for n in ui_names):
            raise PortalError("invalid portal UI namespace reference")
        for scoped in [f"saw-ctl-{reg}", *ui_names]:
            if k8s.call("GET", "/api/v1/namespaces/" + scoped, ok404=True) is not None:
                left.append("namespace " + scoped)
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
    """Cache RHDH keys, with bounded on-demand refetches for rotating key IDs."""

    def __init__(self, ttl=300):
        self.ttl, self.docs = ttl, {}
        self.next_miss_refresh = {}
        self.lock = threading.Lock()

    def __call__(self, path, kid=None):
        # The verifier chooses one of two fixed paths. No token field selects
        # the issuer or URL. Coalesce misses per issuer, not per untrusted kid.
        with self.lock:
            now = time.monotonic()
            hit = self.docs.get(path)
            if hit and now - hit[0] < self.ttl:
                if kid is None or any(k.get("kid") == kid for k in hit[1].get("keys", [])):
                    return hit[1]
                if now < self.next_miss_refresh.get(path, 0):
                    return hit[1]
                self.next_miss_refresh[path] = now + 5
            rhdh = env("RHDH_INTERNAL_URL").rstrip("/")
            doc = fetch_json(rhdh + path)
            self.docs[path] = (time.monotonic(), doc)
            if kid is not None and not any(k.get("kid") == kid for k in doc.get("keys", [])):
                self.next_miss_refresh[path] = time.monotonic() + 5
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
        deleting = cm is not None and is_deleting(cm)
        mode = entry_deployment_mode(read_entry(cm)) if cm else None
        if mode == "container" or (action == "create" and data.get("deploymentMode") == "container"):
            check_container_identity(user, container_site(user))
            if caller != user:
                pins = json.loads(os.environ.get("SAW_PORTAL_ADMIN_SUBJECTS", "{}"))
                check_container_identity(caller, {"subject": pins.get(caller)})
        check_credential_writer(k8s, ns, cm)
        if action == "create" and "runtimeAction" in data:
            if (cm or {}).get("metadata", {}).get("annotations", {}).get(CREDENTIAL_WRITER):
                raise PortalError("finish credential publication before changing the runtime state")
            entry = read_entry(cm)
            operation = data["runtimeAction"]
            if (operation not in ("start", "stop") or caller != user or deleting or not cm
                    or entry_deployment_mode(entry) != "container" or entry.get("lifecycleVersion") != 1
                    or entry_generation(user, entry) != data.get("registration")
                    or f"g-{entry.get('intentGeneration')}" != data.get("expectedGeneration")):
                raise PortalError("lifecycle request does not match the current owner registration and generation")
            desired = "Running" if operation == "start" else "Stopped"
            if entry["desiredState"] != desired:
                entry["desiredState"] = desired
                entry["intentGeneration"] += 1
                cm["data"]["user.json"] = json.dumps(entry, sort_keys=True)
                k8s.call("PUT", f"/api/v1/namespaces/{ns}/configmaps/{name}", cm)
            log(f"workspace {user} requested {desired}")
        elif action == "create":
            if deleting:
                raise PortalError(f"workspace saw-{user} is being deleted; request it again when "
                                  "the delete pipeline has finished")
            mode = request_deployment_mode(data)
            if cm is not None:
                assert_mode_unchanged(read_entry(cm), mode)
            if mode == "container" and container_site(user):
                approved = container_profiles(container_site(user))
                if data.get("profile") not in approved:
                    raise PortalError("selected profile is not approved for your container workspace; "
                                      "approved profiles: " + (", ".join(sorted(approved)) or "none") +
                                      ". Ask the site administrator to enable another profile")
                if os.environ.get("PRUNE_ON_REMOVE", "true") != "true":
                    raise PortalError("container provisioning requires foreground cleanup; "
                                      "the site administrator must enable portal.pruneOnRemove")
            elif mode not in PROVISIONABLE_MODES:
                raise PortalError(f"{mode} workspace provisioning is not available in this release")
            profile, secrets = parse_request(data, catalog)
            if mode == "container":
                if cm and read_entry(cm)["profiles"] != [profile]:
                    raise PortalError("changing the profile requires a new container registration")
                endpoint = approved_endpoint(catalog[profile], secrets,
                                             container_site(user).get("profileBoundaries", {}).get(profile, {}))
                if cm and endpoint != read_entry(cm).get("customInferenceURL"):
                    raise PortalError("changing the endpoint requires a new registration")
                models = public_model_inputs(catalog[profile], secrets)
                previous = committed_entry(cm)
                lifecycle = previous.get("lifecycleVersion") == 1 if previous else container_site(user).get("modelLifecycle") is True
                if previous and not lifecycle and previous.get("modelInputs", {}) != models:
                    raise PortalError("changing model selection requires a new container registration")
            check_namespace_is_ours(k8s, user)
            check_applications_are_ours(k8s, user)
            # An update keeps the entry's keys where they are; a new
            # registration gets its own generation (see vault_prefix).
            generation = entry_generation(user, read_entry(cm)) if cm else new_generation()
            prefix = vault_prefix(user, generation)
            entry = registry_entry(user, profile, generation, mode)
            if mode == "container":
                if lifecycle:
                    entry["lifecycleVersion"] = 1
                    entry["initialModelInputs"] = previous.get("initialModelInputs", models)
                    entry["desiredState"] = previous.get("desiredState", "Running")
                    changed = bool(previous and previous.get("modelInputs", {}) != models)
                    entry["restartGeneration"] = (previous["intentGeneration"] + 1 if changed
                                                  else previous.get("restartGeneration", 0))
                if endpoint:
                    entry["customInferenceURL"] = endpoint
                if "dedicatedEndpointSecrets" in catalog[profile]:
                    entry["webSearch"] = {"enabled": False}
                if models:
                    entry["modelInputs"] = models
                if "approvedProfiles" in container_site(user).get("automaticEnrollment",{}):
                    slots=sandbox_targets(user,generation,catalog[profile])
                    entry["uiNamespaces"]=sorted({"saw-ui-"+slot["relayID"] for slot in slots.values() if slot["ui"]})
                entry["intentGeneration"] = previous.get("intentGeneration", 0) + 1
            cm = reserve_credentials(k8s, ns, name, cm, entry, user)
            vault = vault_client()
            for secret, values in secrets.items():
                vault.write(f"{prefix}/{secret}", values)
                log(f"Vault: {prefix}/{secret} ({', '.join(sorted(values))})")
            put_configmap(k8s, ns, name, {"user.json": json.dumps(entry, sort_keys=True)},
                          {WORKSPACE_LABEL: "true", "openshell.pattern/owner": user},
                          resource_version=cm["metadata"].get("resourceVersion") if cm else None,
                          deployment_mode=mode)
            log(f"workspace saw-{user} registered with profile {profile}; Argo CD builds it next")
        else:
            argo_app = f"/apis/argoproj.io/v1alpha1/namespaces/{env('ARGO_NAMESPACE')}/applications/portal-ws-{user}"
            if cm is None and k8s.call("GET", argo_app, ok404=True) is None:
                raise PortalError(f"{user} has no portal workspace")
            # Mark the entry first: the ApplicationSet (create and update
            # only) then stops getting it, so it does not rebuild the
            # Application, while the catalog keeps showing the workspace
            # (Deleting) until finish-delete removes the entry. The mark
            # names this run: finish-delete of an older or a later run
            # leaves the entry (and the keys) alone. A delete run again
            # takes over. Without an entry (a half-done delete), a mark is
            # made, so a create waits and finish-delete still cleans up.
            run = pipeline_run()
            if cm is None:
                marker = {"apiVersion": "v1", "kind": "ConfigMap",
                          "metadata": {"name": name, "namespace": ns,
                                       "labels": {WORKSPACE_LABEL: "true", DELETING_LABEL: "true",
                                                  "openshell.pattern/owner": user},
                                       "annotations": {DELETION_ANNOTATION: run}},
                          "data": {"user.json": json.dumps({"name": user, "profiles": []})}}
                put = ("POST", f"/api/v1/namespaces/{ns}/configmaps", marker)
            else:
                cm["metadata"].setdefault("labels", {})[DELETING_LABEL] = "true"
                cm["metadata"].setdefault("annotations", {})[DELETION_ANNOTATION] = run
                put = ("PUT", f"/api/v1/namespaces/{ns}/configmaps/{name}", cm)  # cm has its resourceVersion
            try:
                k8s.call(*put)
            except HttpError as exc:
                if exc.code != 409:
                    raise
                raise PortalError(f"{name} changed while this request ran (a create?); request it again") from None
            log(f"workspace saw-{user} marked for deletion by {run}")
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
    user's keys in Vault (by default), then the registry entry.

    The entry stays marked deleting until the keys are gone, so no create
    can register a replacement and write new keys in between. Only the run
    that marked it cleans up (DELETION_ANNOTATION): an entry that was
    re-created, or that a later delete took over, is left alone with its
    keys, and the entry is removed only in the version that was checked.

    The keys destroyed are the checked entry's generation only. A cleanup
    can pass its check and then be overtaken (a later delete takes over and
    finishes, and a create registers a replacement) before it reaches
    Vault; the replacement has a new generation, so nothing this cleanup
    does can touch its keys. A marked entry never becomes live again (a
    create refuses it), so its generation is dead once marked."""
    ns = env("NAMESPACE")
    check_user(user)
    k8s = kube()
    catalog = load_catalog(env("CATALOG_PATH"))
    name = f"saw-ws-{user}"
    cm = k8s.call("GET", f"/api/v1/namespaces/{ns}/configmaps/{name}", ok404=True)
    if cm is None:
        log(f"no registry entry {name}: already cleaned up; the keys are left alone")
        write_result(user)
        return
    run = pipeline_run()
    owner = (cm["metadata"].get("annotations") or {}).get(DELETION_ANNOTATION)
    if not is_deleting(cm) or (owner is not None and owner != run):
        raise PortalError(f"{name} is not this run's deletion any more "
                          f"({'re-created' if not is_deleting(cm) else 'taken over by ' + owner}); "
                          "its entry and keys are left alone")
    prefix = vault_prefix(user, entry_generation(user, read_entry(cm)))
    if os.environ.get("DELETE_VAULT_SECRETS", "true") == "true":
        vault = vault_client()
        for secret in sorted({s for p in catalog.values() for s in p.get("secrets", {})}):
            vault.destroy(f"{prefix}/{secret}")
        log(f"Vault: {prefix}/* deleted")
    meta = cm["metadata"]
    try:
        k8s.call("DELETE", f"/api/v1/namespaces/{ns}/configmaps/{name}",
                 {"apiVersion": "v1", "kind": "DeleteOptions",
                  "preconditions": {k: meta[k] for k in ("uid", "resourceVersion") if meta.get(k)}},
                 ok404=True)
    except HttpError as exc:
        if exc.code != 409:
            raise
        raise PortalError(f"{name} changed during the cleanup; left in place") from None
    log(f"workspace saw-{user} removed from the registry")
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
    started, last = clock(), None
    while True:
        budget = timeout
        if stage == "gone":
            marker = k8s.call("GET", f"/api/v1/namespaces/{ns}/configmaps/saw-ws-{user}", ok404=True)
            done, detail = removal_status(k8s, user, argo_ns, read_entry(marker))
            failed = False
        else:
            st = workspace_status(k8s, user, catalog, ns, argo_ns, domain, ping)
            if stage == "vm" and st.get("deploymentMode") == "container":
                # The initial intent can only be published after the new registration is reviewed.
                budget = max(timeout, int(os.environ.get("SAW_CONTAINER_ENROLLMENT_SECONDS", timeout)))
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
        if clock() >= started + budget:
            raise PortalError(f"not done after {budget // 60} minutes: {detail}")
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


def generator_params(workspaces, defaults, read=None, catalog=None, previous=None):
    """Adapt authenticated registry entries to the common workspace projector."""
    out = []
    for entry in workspaces:
        ws = {**entry, "values": {**entry.get("values", {}),
                                  "deployment": {"mode": entry_deployment_mode(entry)}}}
        site = container_site(ws["name"]) if entry_deployment_mode(ws) == "container" else {}
        if site:
            if not ws.get("ownerSubject") or ws["ownerSubject"] != site["subject"]:
                continue
            reg = entry_generation(ws["name"], ws)
            ws.update(registration=reg, installationID=installation_id(ws["name"], reg))
        def observed(path):
            try:
                return read(path)
            except HttpError as exc:
                if exc.code == 403:  # named reader grant is not installed yet
                    return {}
                raise
        try:
            values = _workspace.project_workspace(ws, defaults, site, catalog or {},
                                                  observed if read else None, previous)
        except _workspace.WorkspaceError as exc:
            raise PortalError(str(exc)) from exc
        out.append({"name": ws["name"], "revision": values.get("global", {}).get("targetRevision", ""),
                    "values": json.dumps(values, sort_keys=True)})
    return out


class CatalogRouteCache:
    """A catalog read never waits for an endpoint. Explicit owner checks bypass this cache."""
    def __init__(self, workers=4, capacity=512, ttl=30):
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="catalog-route")
        self.capacity, self.ttl = capacity, ttl
        self.lock = threading.Lock()
        self.entries = {}

    def probe(self, scope, url, check):
        key = (*scope, url)
        now = time.monotonic()
        with self.lock:
            current = self.entries.get(key)
            if current:
                if not current.done():
                    return False
                finished, ready = current.result()
                if now - finished < self.ttl:
                    return ready
            self.entries = {k: f for k, f in self.entries.items()
                            if not f.done() or now - f.result()[0] < self.ttl}
            if len(self.entries) >= self.capacity:
                return False
            future = self.pool.submit(self._check, check, url)
            self.entries[key] = future
        return False

    @staticmethod
    def _check(check, url):
        try:
            ready = check(url)
        except (ValueError, OSError):
            ready = False
        return time.monotonic(), ready


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
    route_cache = CatalogRouteCache()

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
                        mode = entry_deployment_mode(ws)
                        scope = (ws["name"], mode, entry_generation(ws["name"], ws),
                                 ws.get("intentGeneration", 0), os.environ.get("KEYCLOAK_URL"),
                                 os.environ.get("KEYCLOAK_REALM"))
                        check = owner_route_available if mode == "container" else ping_url
                        statuses[ws["name"]] = workspace_status(k8s, ws["name"], catalog, ns, argo_ns, domain,
                            ping=lambda url: route_cache.probe(scope, url, check))
                    except PortalError as exc:
                        log(f"WARN: status of saw-{ws['name']}: {exc}")
                text = entities_yaml(workspaces, catalog, domain,
                                     os.environ.get("RHDH_BASE_URL", ""), statuses, ns, realm_users(), runtime_reader=k8s)
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
                params = generator_params(owner_subjects.fill(list_workspaces(kube(), ns)), defaults,
                                          lambda path:kube().call("GET",path,ok404=True),catalog,
                                          lambda owner: _workspace.previous_child(kube().call("GET",
                                              f"/apis/argoproj.io/v1alpha1/namespaces/{argo_ns}/applications/portal-ws-{owner['name']}",
                                              ok404=True), "saw-portal-workspaces", owner))
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
