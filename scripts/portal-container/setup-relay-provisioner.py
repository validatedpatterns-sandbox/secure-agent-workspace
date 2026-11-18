#!/usr/bin/env python3
"""Render or run the one-time, platform-owned Keycloak relay registrar setup."""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, Request

NAME = "saw-relay-provisioner"
SCOPE = "saw-workspace-relay"
IMAGE = "registry.access.redhat.com/ubi9/python-311@sha256:a0bdb55576fc5b8d6704279307817828ef027e1065533ceba133fe9516003a6c"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def call(url, method="GET", *, token=None, body=None, form=None, ca=None, patch=False):
    headers = {}
    data = None
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urlencode(form).encode()
    if body is not None:
        headers["Content-Type"] = "application/merge-patch+json" if patch else "application/json"
        data = json.dumps(body).encode()
    if token:
        headers["Authorization"] = "Bearer " + token
    client = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=ca)))
    with client.open(Request(url, data=data, method=method, headers=headers), timeout=20) as response:
        raw = response.read()
    return json.loads(raw) if raw else None


def setup():
    issuer = os.environ["ISSUER"].rstrip("/")
    base, realm = issuer.rsplit("/realms/", 1)
    if urlsplit(issuer).scheme != "https" or not realm or realm == "master":
        raise ValueError("expected a dedicated HTTPS realm")
    admin = Path("/bootstrap")
    token = call(base + "/realms/master/protocol/openid-connect/token", "POST",
                 form={"client_id":"admin-cli", "grant_type":"password",
                       "username":(admin/"username").read_text().strip(),
                       "password":(admin/"password").read_text().strip()})["access_token"]
    def kc(path, method="GET", body=None):
        return call(base + "/admin/realms/" + realm + path, method, token=token, body=body)

    sa = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    secret_url = ("https://kubernetes.default.svc/api/v1/namespaces/" + os.environ["NAMESPACE"]
                  + "/secrets/" + NAME)
    opts = dict(ca=str(sa/"ca.crt"), token=(sa/"token").read_text().strip())
    state = call(secret_url, **opts)
    if state["metadata"]["labels"].get("saw.redhat.com/component") != NAME:
        raise ValueError("unexpected destination Secret")
    if not state.get("data"):
        state = call(secret_url, "PATCH", patch=True, **opts, body={
            "metadata":{"resourceVersion":state["metadata"]["resourceVersion"]},
            "stringData":{"client-id":NAME, "client-secret":secrets.token_urlsafe(40), "issuer":issuer}})
    values = {k:base64.b64decode(v,validate=True).decode() for k,v in state["data"].items()}
    if set(values) != {"issuer","client-id","client-secret"} or values["issuer"] != issuer or values["client-id"] != NAME:
        raise ValueError("incompatible provisioner Secret")
    audience = os.environ["AUDIENCE"]
    mappers = [
        {"name":"relay-audience", "protocol":"openid-connect", "protocolMapper":"oidc-audience-mapper",
         "config":{"included.client.audience":audience, "access.token.claim":"true"}},
        {"name":"relay-user", "protocol":"openid-connect", "protocolMapper":"oidc-hardcoded-claim-mapper",
         "config":{"claim.name":"realm_access.roles","claim.value":'["openshell-user"]',
                   "jsonType.label":"JSON","access.token.claim":"true"}}]
    scopes = {s["name"]:s for s in kc("/client-scopes")}
    if SCOPE not in scopes:
        kc("/client-scopes","POST",{"name":SCOPE, "protocol":"openid-connect",
            "description":"SAW registration-scoped workspace relay", "protocolMappers":mappers})
    scope = next(s for s in kc("/client-scopes") if s["name"]==SCOPE)
    actual = kc("/client-scopes/"+scope["id"]+"/protocol-mappers/models")
    if {m["name"] for m in actual} != {m["name"] for m in mappers}:
        raise ValueError("unexpected relay scope mappers")
    for desired in mappers:
        found=next(m for m in actual if m["name"]==desired["name"])
        if found["protocolMapper"]!=desired["protocolMapper"] or any(found["config"].get(k)!=v for k,v in desired["config"].items()):
            raise ValueError("foreign relay scope configuration")
    # Add this specific pre-approved scope to authenticated DCR. Never allow
    # clients to author their own role or audience mappers.
    policies=kc("/components?"+urlencode({"type":"org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"}))
    allowed=[p for p in policies if p.get("providerId")=="allowed-client-templates" and p.get("subType")=="authenticated"]
    if len(allowed)!=1:
        raise ValueError("expected one authenticated client-scope registration policy")
    policy=allowed[0]
    config=policy.setdefault("config",{})
    permitted=config.setdefault("allowed-client-scopes",[])
    if SCOPE not in permitted:
        permitted.append(SCOPE)
        kc("/components/"+policy["id"],"PUT",policy)

    def lookup(client_id):
        return next((c for c in kc("/clients?"+urlencode({"clientId":client_id})) if c["clientId"]==client_id), None)
    settings=dict(clientId=NAME, enabled=True, protocol="openid-connect", publicClient=False,
                  serviceAccountsEnabled=True,standardFlowEnabled=False,implicitFlowEnabled=False,
                  directAccessGrantsEnabled=False,fullScopeAllowed=False)
    if not lookup(NAME):
        kc("/clients","POST",{**settings,"secret":values["client-secret"],"attributes":{"saw.component":NAME},
                              "defaultClientScopes":["basic","roles"],"optionalClientScopes":[]})
    client=kc("/clients/"+lookup(NAME)["id"])
    if client.get("attributes",{}).get("saw.component")!=NAME or any(client.get(k)!=v for k,v in settings.items()):
        raise ValueError("refusing to adopt a foreign provisioning client")
    prefix="/clients/"+client["id"]
    management=lookup("realm-management")["id"]
    role=kc("/clients/"+management+"/roles/create-client")
    user=kc(prefix+"/service-account-user")["id"]
    for path in [prefix+"/scope-mappings/clients/"+management,
                 "/users/"+user+"/role-mappings/clients/"+management]:
        current=kc(path)
        if {r["name"] for r in current} - {"create-client"}:
            raise ValueError("provisioner has unexpected realm-management privileges")
        if not current:
            kc(path,"POST",[role])
    result=call(issuer+"/protocol/openid-connect/token","POST",form={
        "client_id":NAME,"client_secret":values["client-secret"],"grant_type":"client_credentials"})
    part=result["access_token"].split(".")[1]
    claim=json.loads(base64.urlsafe_b64decode(part+"="*(-len(part)%4)))
    if set(claim.get("resource_access",{}).get("realm-management",{}).get("roles",[]))!={"create-client"}:
        raise ValueError("unexpected effective registrar privilege")
    print("Realm registrar verified: create-client in the workspace realm.")


def render(args):
    ns=args.namespace
    metadata={"name":NAME,"namespace":ns}
    subject={"kind":"ServiceAccount","name":NAME,"namespace":ns}
    objects=[
        {"apiVersion":"v1","kind":"Secret","metadata":{**metadata,"labels":{"saw.redhat.com/component":NAME}},"type":"Opaque"},
        {"apiVersion":"v1","kind":"ServiceAccount","metadata":metadata},
        {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":metadata,"rules":[
            {"apiGroups":[""],"resources":["secrets"],"verbs":["get","patch"],"resourceNames":[NAME]}]},
        {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":metadata,"subjects":[subject],
         "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":NAME}},
        {"apiVersion":"v1","kind":"ConfigMap","metadata":metadata,"data":{"setup.py":Path(__file__).read_text()}}]
    volumes=[{"name":"script","configMap":{"name":NAME}},{"name":"bootstrap","secret":{
        "secretName":args.bootstrap_secret,"items":[{"key":k,"path":k} for k in ("username","password")]}}]
    mounts=[{"name":v["name"],"mountPath":"/"+v["name"],"readOnly":True} for v in volumes]
    env={"ISSUER":args.issuer,"NAMESPACE":ns,"AUDIENCE":args.audience}
    if args.ca_configmap:
        volumes.append({"name":"trust","configMap":{"name":args.ca_configmap}})
        mounts.append({"name":"trust","mountPath":"/trust","readOnly":True})
        env["SSL_CERT_FILE"]="/trust/ca-bundle.crt"
    objects.append({"apiVersion":"batch/v1","kind":"Job","metadata":metadata,"spec":{
        "activeDeadlineSeconds":180,"backoffLimit":1,"ttlSecondsAfterFinished":900,
        "template":{"spec":{"serviceAccountName":NAME,"restartPolicy":"Never","volumes":volumes,
        "securityContext":{"runAsNonRoot":True,"seccompProfile":{"type":"RuntimeDefault"}},
        "containers":[{"name":"setup","image":IMAGE,"command":["python3","/script/setup.py","run"],
        "volumeMounts":mounts,"env":[{"name":k,"value":v} for k,v in env.items()],
        "securityContext":{"readOnlyRootFilesystem":True,"allowPrivilegeEscalation":False,"capabilities":{"drop":["ALL"]}}}]}}}})
    print(json.dumps({"apiVersion":"v1","kind":"List","items":objects}))


if __name__=="__main__":
    if sys.argv[1:]==["run"]:
        try:
            setup()
        except HTTPError as exc:
            sys.exit(f"Setup API failed: HTTP {exc.code} at {urlsplit(exc.url).path}")
    else:
        parser=argparse.ArgumentParser(description=__doc__)
        for flag in ("namespace","issuer","bootstrap-secret"):
            parser.add_argument("--"+flag,required=True)
        parser.add_argument("--audience",default="openshell-cli")
        parser.add_argument("--ca-configmap")
        render(parser.parse_args())
