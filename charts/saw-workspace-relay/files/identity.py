"""Bootstrap one dedicated confidential client. Never log HTTP bodies or credentials."""
import base64
import json
import os
import re
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
    credential = Path("/kc-provisioner")
    if not realm or realm == "master":
        raise RuntimeError("a dedicated workspace realm is required")
    deleting = os.environ.get("DELETE_BOUND_CLIENT") == "true"
    if not deleting and (credential/"issuer").read_text().strip().rstrip("/") != issuer:
        raise RuntimeError("provisioning credential belongs to a different issuer")
    marker = os.environ["INSTALLATION"] + "/" + os.environ["WORKSPACE"]
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", cid):
        raise RuntimeError("expected a registration-scoped relay client ID")
    registration_url = issuer + "/clients-registrations/default"
    sa = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    address = "https://kubernetes.default.svc/api/v1/namespaces/" + os.environ["UI_NAMESPACE"] + "/secrets/relay-credentials"
    def secret(method="GET", body=None):
        return api(address, method=method, token=(sa/"token").read_text(), ca=str(sa/"ca.crt"), body=body, patch=bool(body))
    opts = dict(token=(sa/"token").read_text(), ca=str(sa/"ca.crt"))
    state_url = ("https://kubernetes.default.svc/api/v1/namespaces/" + os.environ["PROVISIONER_NAMESPACE"]
                 + "/secrets/" + os.environ["REGISTRATION_STATE"])
    state = api(state_url, **opts)
    if state["metadata"]["labels"].get("saw.redhat.com/runtime-owner") != os.environ["INSTALLATION"]:
        raise RuntimeError("foreign client registration state")
    raw = state.get("data", {}).get("registration-token")
    registration_token = base64.b64decode(raw, validate=True).decode() if raw else None
    if registration_token and (state["data"].get("issuer") != base64.b64encode(issuer.encode()).decode()
                               or state["data"].get("attempt") != base64.b64encode(cid.encode()).decode()):
        raise RuntimeError("client registration receipt belongs to a different issuer or client")
    if deleting:
        if cid != "saw-portal-" + os.environ["REGISTRATION"]:
            raise RuntimeError("refusing foreign client deletion")
        if not registration_token:
            if state.get("data", {}).get("attempt"):
                raise RuntimeError("ambiguous client create: restore its registration receipt")
            return
        try:
            api(registration_url + "/" + cid, method="DELETE", token=registration_token)
        except HTTPError as exc:
            if exc.code != 404:
                raise
        print("registration-scoped relay client removed")
        return
    obj = secret()
    if obj["metadata"]["labels"].get("saw.redhat.com/runtime-owner") != os.environ["INSTALLATION"]:
        raise RuntimeError("foreign credential Secret")
    if not obj.get("data"):
        if registration_token:
            raise RuntimeError("registered client without retained credential")
        obj = secret("PATCH", {"metadata":{"resourceVersion":obj["metadata"]["resourceVersion"]},
                               "stringData":{"client-secret":secrets.token_urlsafe(40),
                                             "cookie-secret":base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()}})
    if "relay-proof" not in obj["data"]:
        obj = secret("PATCH", {"metadata":{"resourceVersion":obj["metadata"]["resourceVersion"]},
                               "stringData":{"relay-proof":secrets.token_hex(32)}})
    proof = obj["data"]["relay-proof"]
    if not re.fullmatch(r"[0-9a-f]{64}", base64.b64decode(proof, validate=True).decode()):
        raise RuntimeError("invalid relay proof")
    proof_url = ("https://kubernetes.default.svc/api/v1/namespaces/" + os.environ["RUNTIME_NAMESPACE"]
                 + "/secrets/" + os.environ["PROOF_NAME"])
    opts = dict(token=(sa/"token").read_text(), ca=str(sa/"ca.crt"))
    target = api(proof_url, **opts)
    if target["metadata"]["labels"].get("saw.redhat.com/runtime-owner") != os.environ["INSTALLATION"]:
        raise RuntimeError("foreign proof projection")
    if target.get("data") and target["data"] != {"relay-proof":proof}:
        raise RuntimeError("relay proof projection differs")
    api(proof_url, method="PATCH", patch=True, body={"metadata":{"resourceVersion":target["metadata"]["resourceVersion"]},
        "immutable":True, "data":{"relay-proof":proof}}, **opts)
    password = base64.b64decode(obj["data"]["client-secret"]).decode()
    if not registration_token:
        # The registrar needs create-client only. An administrator-defined
        # client scope supplies the audience and sole openshell-user role.
        token = api(issuer + "/protocol/openid-connect/token", method="POST", form={
            "grant_type":"client_credentials", "client_id":(credential/"client-id").read_text().strip(),
            "client_secret":(credential/"client-secret").read_text().strip()})["access_token"]
        settings = dict(clientId=cid, protocol="openid-connect", clientAuthenticatorType="client-secret",
                        publicClient=False, enabled=True, serviceAccountsEnabled=True, standardFlowEnabled=False,
                        implicitFlowEnabled=False, directAccessGrantsEnabled=False, fullScopeAllowed=False,
                        secret=password, redirectUris=[], webOrigins=[], optionalClientScopes=[],
                        defaultClientScopes=["basic", "saw-workspace-relay"], attributes={"saw.scope":marker})
        if state.get("data", {}).get("attempt"):
            raise RuntimeError("previous client creation may have committed; operator recovery required")
        state = api(state_url, method="PATCH", patch=True, **opts, body={
            "metadata":{"resourceVersion":state["metadata"]["resourceVersion"]},
            "stringData":{"attempt":cid, "issuer":issuer}})
        try:
            created = api(registration_url, method="POST", token=token, body=settings)
        except HTTPError as exc:
            if exc.code in (400, 401, 403):
                api(state_url, method="PATCH", patch=True, **opts, body={
                    "metadata":{"resourceVersion":state["metadata"]["resourceVersion"]},
                    "data":{"attempt":None}})
            raise
        registration_token = created.get("registrationAccessToken")
        if (not registration_token or created.get("clientId") != cid
                or created.get("attributes", {}).get("saw.scope") != marker):
            raise RuntimeError("client registration receipt unavailable")
        state = api(state_url, method="PATCH", patch=True, body={
            "metadata":{"resourceVersion":state["metadata"]["resourceVersion"]},
            "stringData":{"registration-token":registration_token, "client-secret":created.get("secret") or password}}, **opts)
    password = base64.b64decode(state["data"]["client-secret"], validate=True).decode()
    if obj["data"]["client-secret"] != state["data"]["client-secret"]:
        obj = secret("PATCH", {"metadata":{"resourceVersion":obj["metadata"]["resourceVersion"]},
                              "data":{"client-secret":state["data"]["client-secret"]}})
    access = api(issuer + "/protocol/openid-connect/token", method="POST", form={
        "grant_type":"client_credentials","client_id":cid,"client_secret":password})["access_token"]
    c = claims(access)
    sub = c["sub"]
    if not re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", sub):
        raise RuntimeError("invalid relay subject")
    aud = c["aud"] if isinstance(c["aud"],list) else [c["aud"]]
    if (c["azp"] != cid or c["iss"] != issuer or set(aud) != {os.environ["AUDIENCE"]}
            or set(c.get("realm_access",{}).get("roles",[])) != {"openshell-user"} or c.get("resource_access")):
        raise RuntimeError("unexpected relay token scope")
    if public_ns := os.environ.get("PUBLIC_SUBJECT_NAMESPACE"):
        name=os.environ.get("PUBLIC_SUBJECT_MAP","saw-portal-relay-subject")
        suffix=cid.removeprefix("saw-portal-")
        permitted=(name=="saw-portal-relay-subject" and suffix==public_ns[8:]) or name=="saw-portal-relay-"+suffix
        if not re.fullmatch("saw-ctl-[a-f0-9]{16}",public_ns) or not re.fullmatch("saw-portal-[a-f0-9]{16}",cid) or not permitted:
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
