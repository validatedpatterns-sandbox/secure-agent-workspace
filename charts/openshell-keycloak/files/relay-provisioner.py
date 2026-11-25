#!/usr/bin/env python3
"""Keep the workspace relay registrar in place for container-mode SAW sites.

Each container workspace's browser relay registers its own Keycloak client
(charts/saw-workspace-relay/files/identity.py). It does that with the
registrar this helper maintains, so no relay Job needs the master admin:

  - the client scope SCOPE (OpenShell audience plus the openshell-user role),
    allowed for authenticated dynamic client registration;
  - the confidential client NAME whose service account holds only
    realm-management/create-client in REALM;
  - its credential in the Secret NAME in this namespace, which relay Jobs mount.

Runs in Keycloak's namespace and re-verifies every INTERVAL seconds, so a
cluster comes up without a manual step and drift is repaired. The Secret is
created here, not by Helm, so a GitOps self-heal never clears the generated
credential. Errors are retried; nothing is deleted.

Env: REALM, KEYCLOAK_NAME, KEYCLOAK_NAMESPACE, KC_URL (empty: discover the
operator's HTTPS Route), CA_FILE, ADMIN_DIR (username, password), AUDIENCE,
INTERVAL. Standard library only.
"""
import base64
import json
import os
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import saw_tls

SA = "/var/run/secrets/kubernetes.io/serviceaccount"
NAME = "saw-relay-provisioner"
SCOPE = "saw-workspace-relay"
LABEL = "saw.redhat.com/component"


def log(msg):
    print(f"[relay-provisioner] {msg}", flush=True)


class HttpError(OSError):
    """An OSError so saw_tls.tls_context treats it as a failed cluster read."""

    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def call(url, method="GET", *, token=None, body=None, form=None, ctx=None, patch=False):
    headers, data = {}, None
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(form).encode()
    if body is not None:
        headers["Content-Type"] = "application/merge-patch+json" if patch else "application/json"
        data = json.dumps(body).encode()
    if token:
        headers["Authorization"] = "Bearer " + token
    opener = urllib.request.build_opener(saw_tls.NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(urllib.request.Request(url, data=data, method=method, headers=headers),
                         timeout=20) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise HttpError(exc.code, f"HTTP {exc.code} at {urllib.parse.urlsplit(url).path}") from None
    return json.loads(raw) if raw else None


class Kube:
    def __init__(self):
        host, port = os.environ["KUBERNETES_SERVICE_HOST"], os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.base = f"https://{host}:{port}"
        self.ctx = ssl.create_default_context(cafile=f"{SA}/ca.crt")

    def __call__(self, path, method="GET", body=None, patch=False):
        token = open(f"{SA}/token", encoding="utf-8").read().strip()
        return call(self.base + path, method, token=token, body=body, ctx=self.ctx, patch=patch)

    def get(self, path):
        return self(path)


def credential(kube, namespace, issuer):
    """The registrar's client ID and secret, kept in a Secret only this helper writes."""
    path = f"/api/v1/namespaces/{namespace}/secrets/{NAME}"
    fresh = {"client-id": NAME, "client-secret": secrets.token_urlsafe(40), "issuer": issuer}
    try:
        state = kube(path)
    except HttpError as exc:
        if exc.code != 404:
            raise
        kube(f"/api/v1/namespaces/{namespace}/secrets", "POST", {
            "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": NAME, "labels": {LABEL: NAME}}, "stringData": fresh})
        log(f"Secret {NAME} created")
        state = kube(path)
    if (state["metadata"].get("labels") or {}).get(LABEL) != NAME:
        raise ValueError(f"Secret {NAME} exists but is not this helper's")
    if not state.get("data"):
        state = kube(path, "PATCH", {"metadata": {"resourceVersion": state["metadata"]["resourceVersion"]},
                                     "stringData": fresh}, patch=True)
    values = {k: base64.b64decode(v, validate=True).decode() for k, v in state["data"].items()}
    if set(values) != {"issuer", "client-id", "client-secret"} or values["client-id"] != NAME:
        raise ValueError(f"Secret {NAME} has unexpected contents")
    if values["issuer"] != issuer:
        raise ValueError(f"Secret {NAME} is for issuer {values['issuer']}, not {issuer}")
    return values


def setup(kube, ctx, issuer, namespace):
    base, realm = issuer.rsplit("/realms/", 1)
    admin = os.environ["ADMIN_DIR"]
    token = call(base + "/realms/master/protocol/openid-connect/token", "POST", ctx=ctx, form={
        "client_id": "admin-cli", "grant_type": "password",
        "username": open(os.path.join(admin, "username"), encoding="utf-8").read().strip(),
        "password": open(os.path.join(admin, "password"), encoding="utf-8").read().strip()})["access_token"]

    def kc(path, method="GET", body=None):
        return call(base + "/admin/realms/" + realm + path, method, token=token, body=body, ctx=ctx)

    if kc("") is None:
        raise ValueError(f"realm {realm} is not imported yet")
    values = credential(kube, namespace, issuer)
    audience = os.environ["AUDIENCE"]
    mappers = [
        {"name": "relay-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
         "config": {"included.client.audience": audience, "access.token.claim": "true"}},
        {"name": "relay-user", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
         "config": {"claim.name": "realm_access.roles", "claim.value": '["openshell-user"]',
                    "jsonType.label": "JSON", "access.token.claim": "true"}}]
    if not any(s["name"] == SCOPE for s in kc("/client-scopes")):
        kc("/client-scopes", "POST", {"name": SCOPE, "protocol": "openid-connect",
                                      "description": "SAW registration-scoped workspace relay",
                                      "protocolMappers": mappers})
        log(f"client scope {SCOPE} created")
    scope = next(s for s in kc("/client-scopes") if s["name"] == SCOPE)
    actual = kc("/client-scopes/" + scope["id"] + "/protocol-mappers/models")
    if {m["name"] for m in actual} != {m["name"] for m in mappers}:
        raise ValueError("unexpected relay scope mappers")
    for desired in mappers:
        found = next(m for m in actual if m["name"] == desired["name"])
        if found["protocolMapper"] != desired["protocolMapper"] or \
                any(found["config"].get(k) != v for k, v in desired["config"].items()):
            raise ValueError("foreign relay scope configuration")
    # Allow this pre-approved scope for authenticated registration. Clients
    # never author their own role or audience mappers.
    policies = kc("/components?" + urllib.parse.urlencode(
        {"type": "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"}))
    allowed = [p for p in policies if p.get("providerId") == "allowed-client-templates"
               and p.get("subType") == "authenticated"]
    if len(allowed) != 1:
        raise ValueError("expected one authenticated client-scope registration policy")
    policy = allowed[0]
    permitted = policy.setdefault("config", {}).setdefault("allowed-client-scopes", [])
    if SCOPE not in permitted:
        permitted.append(SCOPE)
        kc("/components/" + policy["id"], "PUT", policy)
        log(f"{SCOPE} allowed for authenticated registration")

    def lookup(client_id):
        return next((c for c in kc("/clients?" + urllib.parse.urlencode({"clientId": client_id}))
                     if c["clientId"] == client_id), None)
    settings = dict(clientId=NAME, enabled=True, protocol="openid-connect", publicClient=False,
                    serviceAccountsEnabled=True, standardFlowEnabled=False, implicitFlowEnabled=False,
                    directAccessGrantsEnabled=False, fullScopeAllowed=False)
    if not lookup(NAME):
        kc("/clients", "POST", {**settings, "secret": values["client-secret"], "attributes": {LABEL: NAME},
                                "defaultClientScopes": ["basic", "roles"], "optionalClientScopes": []})
        log(f"client {NAME} created")
    client = kc("/clients/" + lookup(NAME)["id"])
    if client.get("attributes", {}).get(LABEL) != NAME and \
            client.get("attributes", {}).get("saw.component") != NAME:
        raise ValueError("refusing to adopt a foreign provisioning client")
    if any(client.get(k) != v for k, v in settings.items()):
        raise ValueError("provisioning client settings drifted")
    prefix = "/clients/" + client["id"]
    management = lookup("realm-management")["id"]
    role = kc("/clients/" + management + "/roles/create-client")
    user = kc(prefix + "/service-account-user")["id"]
    for path in [prefix + "/scope-mappings/clients/" + management,
                 "/users/" + user + "/role-mappings/clients/" + management]:
        current = kc(path)
        if {r["name"] for r in current} - {"create-client"}:
            raise ValueError("provisioner has unexpected realm-management privileges")
        if not current:
            kc(path, "POST", [role])
    result = call(issuer + "/protocol/openid-connect/token", "POST", ctx=ctx, form={
        "client_id": NAME, "client_secret": values["client-secret"], "grant_type": "client_credentials"})
    part = result["access_token"].split(".")[1]
    claim = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    if set(claim.get("resource_access", {}).get("realm-management", {}).get("roles", [])) != {"create-client"}:
        raise ValueError("unexpected effective registrar privilege")


def main(argv):
    kube = Kube()
    namespace, name = os.environ["KEYCLOAK_NAMESPACE"], os.environ["KEYCLOAK_NAME"]
    realm, interval = os.environ["REALM"], int(os.environ.get("INTERVAL", "300"))
    once = "--once" in argv
    while True:
        try:
            url = os.environ.get("KC_URL") or saw_tls.keycloak_url(name, namespace, kube.get)
            ctx = saw_tls.tls_context(url, kube.get, log, os.environ.get("CA_FILE") or None)
            issuer = url.rstrip("/") + "/realms/" + realm
            setup(kube, ctx, issuer, namespace)
            log(f"registrar verified for {issuer}: create-client only")
            wait = interval
        except (HttpError, OSError, KeyError, ValueError) as exc:
            if once:
                raise
            log(f"WARN: {exc}; retrying in 15s")
            wait = 15
        if once:
            return 0
        time.sleep(wait)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
