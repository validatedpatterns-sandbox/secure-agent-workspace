#!/usr/bin/env python3
"""Resolve Pattern workspace owners in Keycloak without tenant admin secrets.

bootstrap creates a realm client with view-users and writes its credential to
an in-memory file. run reads SAW namespaces and patches only the subject field
of each namespace's saw-owner-subject ConfigMap.
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
USER_RE = re.compile(r"[a-z0-9]([-a-z0-9]{0,17}[a-z0-9])?")
SUBJECT_RE = re.compile(r"[A-Za-z0-9._:@/-]{1,255}")


class ApiError(OSError):
    """An OSError so saw_tls.tls_context treats it as a failed cluster read."""

    def __init__(self, code, path):
        super().__init__(f"{path}: HTTP {code}")
        self.code = code


def log(msg):
    print(f"[owner-resolver] {msg}", flush=True)


def request(url, method="GET", body=None, token=None, form=None, ctx=None):
    saw_tls.require_https(url)
    headers = {}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/merge-patch+json" if method == "PATCH" else "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                             saw_tls.NoRedirect())
        with opener.open(req, timeout=20) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        # Response bodies can contain identity data or credentials.
        raise ApiError(exc.code, urllib.parse.urlsplit(url).path) from None


def keycloak_token(url, realm, form, ctx):
    result = request(f"{url}/realms/{realm}/protocol/openid-connect/token",
                     "POST", form=form, ctx=ctx)
    return result["access_token"]


def kc_call(url, realm, token, path, method="GET", body=None, ctx=None):
    return request(f"{url}/admin/realms/{realm}{path}", method, body, token, ctx=ctx)


def exact_client(url, realm, token, name, ctx):
    matches = kc_call(url, realm, token, "/clients?clientId=" + urllib.parse.quote(name), ctx=ctx) or []
    matches = [item for item in matches if item.get("clientId") == name]
    if len(matches) > 1:
        raise RuntimeError("duplicate resolver clients")
    return matches[0] if matches else None


def keycloak_endpoint():
    """The verified Keycloak base URL and its TLS context.

    KC_URL is optional: with it empty, use the operator's HTTPS Route rather
    than the plaintext Service, so the admin credential is never sent in the
    clear.
    """
    kube = Kubernetes()
    url = (os.environ.get("KC_URL") or saw_tls.keycloak_url(
        os.environ["KEYCLOAK_NAME"], os.environ["KEYCLOAK_NAMESPACE"], kube.call)).rstrip("/")
    return url, saw_tls.tls_context(url, kube.call, log, os.environ.get("CA_FILE"))


def bootstrap():
    realm, client_id = os.environ["REALM"], os.environ["CLIENT_ID"]
    admin_dir = os.environ["ADMIN_DIR"]
    with open(f"{admin_dir}/username", encoding="utf-8") as stream:
        username = stream.read().strip()
    with open(f"{admin_dir}/password", encoding="utf-8") as stream:
        password = stream.read().strip()
    deadline = time.monotonic() + 1800
    while True:
        try:
            url, ctx = keycloak_endpoint()
            token = keycloak_token(url, "master", {"grant_type": "password", "client_id": "admin-cli",
                                                    "username": username, "password": password}, ctx)
            kc_call(url, realm, token, "", ctx=ctx)
            break
        except (ApiError, OSError, KeyError, ValueError) as exc:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Keycloak did not become ready: {type(exc).__name__}") from None
            time.sleep(10)
    spec = {"protocol": "openid-connect", "publicClient": False,
            "clientAuthenticatorType": "client-secret", "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
            "implicitFlowEnabled": False}
    client = exact_client(url, realm, token, client_id, ctx)
    if client is None:
        kc_call(url, realm, token, "/clients", "POST", {"clientId": client_id, **spec}, ctx)
        client = exact_client(url, realm, token, client_id, ctx)
    elif any(client.get(key) != value for key, value in spec.items()):
        raise RuntimeError("resolver client has unexpected settings")
    account = kc_call(url, realm, token, f"/clients/{client['id']}/service-account-user", ctx=ctx)
    management = exact_client(url, realm, token, "realm-management", ctx)
    management_id = management["id"]
    path = f"/users/{account['id']}/role-mappings/clients/{management_id}"
    roles = kc_call(url, realm, token, path, ctx=ctx) or []
    if any(role.get("name") != "view-users" for role in roles):
        raise RuntimeError("resolver client has extra realm-management roles")
    if not roles:
        role = kc_call(url, realm, token, f"/clients/{management_id}/roles/view-users", ctx=ctx)
        kc_call(url, realm, token, path, "POST", [role], ctx)
    secret = kc_call(url, realm, token, f"/clients/{client['id']}/client-secret", ctx=ctx)["value"]
    fd = os.open(os.environ["OUT"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(secret)


class Kubernetes:
    def __init__(self):
        host = os.environ["KUBERNETES_SERVICE_HOST"]
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.url = f"https://{host}:{port}"
        self.ctx = ssl.create_default_context(cafile=f"{SA}/ca.crt")

    def call(self, path, method="GET", body=None):
        with open(f"{SA}/token", encoding="utf-8") as stream:
            token = stream.read().strip()
        return request(self.url + path, method, body, token, ctx=self.ctx)


def subject_for(kc, owner):
    users = kc("/users?exact=true&username=" + urllib.parse.quote(owner)) or []
    if len(users) != 1:
        return "", "unknown" if not users else "ambiguous"
    user = users[0]
    if user.get("username") != owner:
        return "", "mismatch"
    if user.get("enabled") is not True:
        return "", "disabled"
    subject = user.get("id")
    if not isinstance(subject, str) or not SUBJECT_RE.fullmatch(subject):
        return "", "invalid-subject"
    return subject, "resolved"


def reconcile(kube, kc):
    selected = os.environ.get("NAMESPACE_SELECTOR", "openshell.pattern/saw=true")
    key, separator, value = selected.partition("=")
    if not separator or not key or not value:
        raise ValueError("NAMESPACE_SELECTOR must be key=value")
    selector = urllib.parse.quote(selected)
    namespaces = kube.call(f"/api/v1/namespaces?labelSelector={selector}").get("items", [])
    for namespace in namespaces:
        meta = namespace.get("metadata") or {}
        name = meta.get("name", "")
        owner = (meta.get("labels") or {}).get("openshell.pattern/owner", "")
        if not USER_RE.fullmatch(owner) or name != f"saw-{owner}":
            continue
        path = f"/api/v1/namespaces/{name}/configmaps/saw-owner-subject"
        try:
            current = kube.call(path)
            old = (current.get("data") or {}).get("subject", "")
            old_status = (current.get("metadata", {}).get("annotations") or {}).get(
                "saw.redhat.com/owner-resolution", "")
            try:
                subject, status = subject_for(kc, owner)
            except (ApiError, OSError, KeyError, ValueError) as exc:
                if old_status != "lookup-error":
                    kube.call(path, "PATCH", {"metadata": {"annotations": {
                        "saw.redhat.com/owner-resolution": "lookup-error"}}})
                print(f"[owner-resolver] {name}: lookup pending ({type(exc).__name__})", flush=True)
                continue
            if old != subject or old_status != status:
                kube.call(path, "PATCH", {"data": {"subject": subject},
                                          "metadata": {"annotations": {
                                              "saw.redhat.com/owner-resolution": status}}})
                print(f"[owner-resolver] {name}: {status}", flush=True)
        except (ApiError, OSError, KeyError, ValueError) as exc:
            print(f"[owner-resolver] {name}: update pending ({type(exc).__name__})", flush=True)


def run():
    realm, client_id = os.environ["REALM"], os.environ["CLIENT_ID"]
    interval = int(os.environ.get("INTERVAL", "30"))
    if not 5 <= interval <= 300:
        raise ValueError("INTERVAL must be 5 to 300 seconds")
    kube = Kubernetes()
    url, ctx = keycloak_endpoint()
    while True:
        try:
            with open(os.environ["SECRET_FILE"], encoding="utf-8") as stream:
                secret = stream.read().strip()
            token = keycloak_token(url, realm, {"grant_type": "client_credentials",
                                                 "client_id": client_id, "client_secret": secret}, ctx)
            def lookup(path):
                return kc_call(url, realm, token, path, ctx=ctx)
            reconcile(kube, lookup)
        except (ApiError, OSError, KeyError, ValueError) as exc:
            print(f"[owner-resolver] sync pending ({type(exc).__name__})", flush=True)
            def unavailable(_path):
                raise exc
            try:
                reconcile(kube, unavailable)
            except (ApiError, OSError, KeyError, ValueError) as kube_exc:
                print(f"[owner-resolver] status pending ({type(kube_exc).__name__})", flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    {"bootstrap": bootstrap, "run": run}[sys.argv[1]]()
