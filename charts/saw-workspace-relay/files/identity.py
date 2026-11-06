"""Bootstrap one dedicated confidential client. Never log HTTP bodies or credentials."""
import base64
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, HTTPSHandler
from urllib.error import HTTPError


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def api(url, *, ca=None, method="GET", token=None, body=None, form=None, patch=False):
    headers = {}
    if urlsplit(url).scheme != "https":
        raise RuntimeError("HTTPS is required")
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if form is not None:
        data = urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/merge-patch+json" if patch else "application/json"
    client = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=ca)))
    with client.open(Request(url, data, headers, method=method), timeout=15) as response:
        raw = response.read()
    return json.loads(raw) if raw else None


def claims(token):
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def main():
    issuer = os.environ["ISSUER"].rstrip("/")
    base, realm = issuer.rsplit("/realms/", 1)
    cid = os.environ["CLIENT_ID"]
    admin = Path("/kc-admin")
    token = api(base + "/realms/master/protocol/openid-connect/token", method="POST", form={
        "grant_type":"password", "client_id":"admin-cli", "username":(admin/"username").read_text().strip(),
        "password":(admin/"password").read_text().strip()})["access_token"]

    def kc(path, method="GET", body=None):
        return api(base + "/admin/realms/" + realm + path, method=method, token=token, body=body)

    def lookup():
        found = kc("/clients?" + urlencode({"clientId": cid}))
        return next((c for c in found if c["clientId"] == cid), None)

    if os.environ.get("DELETE_BOUND_CLIENT") == "true":
        expected = "saw-portal-" + os.environ["REGISTRATION"]
        if cid != expected or not __import__("re").fullmatch(r"saw-portal-[0-9a-f]{16}", cid):
            raise RuntimeError("refusing non-registration client cleanup")
        client = lookup()
        if not client:
            return
        # Keycloak deletes by immutable ID, not by the reusable client name.
        found = kc("/clients/" + client["id"])
        if (found.get("clientId") != cid or found.get("attributes", {}).get("saw.scope")
                != os.environ["INSTALLATION"] + "/" + os.environ["WORKSPACE"]):
            raise RuntimeError("refusing foreign relay client cleanup")
        kc("/clients/" + client["id"], "DELETE")
        if lookup():
            raise RuntimeError("client still exists")
        print("registration-scoped relay client removed")
        return

    sa = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    address = "https://kubernetes.default.svc/api/v1/namespaces/" + os.environ["UI_NAMESPACE"] + "/secrets/relay-credentials"
    def secret(method="GET", body=None):
        return api(address, method=method, token=(sa/"token").read_text(), ca=str(sa/"ca.crt"), body=body, patch=bool(body))
    obj = secret()
    marker = os.environ["INSTALLATION"] + "/" + os.environ["WORKSPACE"]
    if obj["metadata"]["labels"].get("saw.redhat.com/runtime-owner") != os.environ["INSTALLATION"]:
        raise RuntimeError("foreign credential Secret")
    client = lookup()
    if not obj.get("data"):
        if client:
            raise RuntimeError("existing client without retained credential")
        obj = secret("PATCH", {"metadata":{"resourceVersion":obj["metadata"]["resourceVersion"]},
                               "stringData":{"client-secret":secrets.token_urlsafe(40),
                                             "cookie-secret":base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()}})
    password = base64.b64decode(obj["data"]["client-secret"]).decode()
    settings = dict(protocol="openid-connect", clientAuthenticatorType="client-secret", publicClient=False,
                    enabled=True, serviceAccountsEnabled=True, standardFlowEnabled=False, implicitFlowEnabled=False,
                    directAccessGrantsEnabled=False, fullScopeAllowed=False)
    if not client:
        kc("/clients", "POST", {**settings,"clientId":cid,"secret":password,"redirectUris":[],"webOrigins":[],
            "defaultClientScopes":["basic"],"optionalClientScopes":[], "attributes":{"saw.scope":marker},
            "protocolMappers":[
                {"name":"relay-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper",
                 "config":{"included.client.audience":os.environ["AUDIENCE"],"access.token.claim":"true"}},
                {"name":"relay-role","protocol":"openid-connect","protocolMapper":"oidc-usermodel-realm-role-mapper",
                 "config":{"claim.name":"realm_access.roles","jsonType.label":"String","multivalued":"true","access.token.claim":"true"}}]})
        client = lookup()
    prefix = "/clients/" + client["id"]
    client = kc(prefix)
    if (client.get("attributes",{}).get("saw.scope") != marker or any(client.get(k) != v for k,v in settings.items())
            or client.get("redirectUris") or client.get("webOrigins")):
        raise RuntimeError("unexpected existing client settings")
    role = kc("/roles/openshell-user")
    account = kc(prefix + "/service-account-user")
    sub = account["id"]
    for path in (prefix + "/scope-mappings/realm", "/users/"+sub+"/role-mappings/realm"):
        mapped = kc(path)
        if role["id"] not in {r["id"] for r in mapped}:
            kc(path, "POST", [role])
    access = api(issuer + "/protocol/openid-connect/token", method="POST", form={
        "grant_type":"client_credentials","client_id":cid,"client_secret":password})["access_token"]
    c = claims(access)
    aud = c["aud"] if isinstance(c["aud"],list) else [c["aud"]]
    if (c["sub"] != sub or c["azp"] != cid or c["iss"] != issuer or set(aud) != {os.environ["AUDIENCE"]}
            or set(c.get("realm_access",{}).get("roles",[])) != {"openshell-user"} or c.get("resource_access")):
        raise RuntimeError("unexpected relay token scope")
    if public_ns := os.environ.get("PUBLIC_SUBJECT_NAMESPACE"):
        name=os.environ.get("PUBLIC_SUBJECT_MAP","saw-portal-relay-subject")
        suffix=cid.removeprefix("saw-portal-")
        permitted=(name=="saw-portal-relay-subject" and suffix==public_ns[8:]) or name=="saw-portal-relay-"+suffix
        if not __import__("re").fullmatch("saw-ctl-[a-f0-9]{16}",public_ns) or not __import__("re").fullmatch("saw-portal-[a-f0-9]{16}",cid) or not permitted:
            raise RuntimeError("invalid registration identity")
        path="https://kubernetes.default.svc/api/v1/namespaces/"+public_ns+"/configmaps/"+name
        opts=dict(token=(sa/"token").read_text(),ca=str(sa/"ca.crt"))
        cm=api(path,**opts)
        if cm["metadata"]["labels"].get("saw.redhat.com/runtime-owner")!=os.environ["INSTALLATION"] or cm.get("data",{}).get("subject",sub)!=sub:
            raise RuntimeError("foreign public subject binding")
        api(path,method="PATCH",patch=True,body={"metadata":{"resourceVersion":cm["metadata"]["resourceVersion"]},"immutable":True,"data":{"subject":sub}},**opts)
    print(json.dumps({"clientID":cid,"subject":sub,"workspace":os.environ["WORKSPACE"],
                      "audience":aud,"roles":["openshell-user"]}))


if __name__ == "__main__":
    try:
        main()
    except HTTPError as e:
        sys.exit("Identity bootstrap HTTP " + str(e.code))
    except Exception as e:
        sys.exit("Relay check failed: " + (str(e) if type(e) is RuntimeError else type(e).__name__))
