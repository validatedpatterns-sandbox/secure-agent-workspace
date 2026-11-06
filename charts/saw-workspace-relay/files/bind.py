"""Grant the relay the stock workspace user role after checking the live owner and IDs."""
import json
import os
import uuid
import time
from pathlib import Path
from saw_kubernetes.reconcile import RpcError
from saw_kubernetes.admin_session import GatewaySessions, TrustBundle
from saw_kubernetes.controller import KubernetesClient


def main():
    ws, wid = os.environ["WORKSPACE"], os.environ["WORKSPACE_ID"]
    relay, owner = os.environ["SUBJECT"], os.environ["OWNER"]
    if (any(uuid.UUID(v).int == 0 for v in (relay, owner, os.environ["INSTALLATION"]))
            or relay == owner):
        raise ValueError("invalid relay scope")
    service_account = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    api = KubernetesClient("https://kubernetes.default.svc", service_account/"ca.crt", service_account/"token")
    trust = TrustBundle(api.request, os.environ["GATEWAY_NAMESPACE"], os.environ["TRUSTED_NAMESPACE"],
                        os.environ["GATEWAY"], os.environ["INSTALLATION"], Path("/identity/ca.crt").read_bytes(),
                        os.environ["POD_NAME"], os.environ["POD_UID"])
    with GatewaySessions(trust, os.environ["ENDPOINT"]).open() as g:
        for attempt in range(30):
            try:
                meta = g.call("GetWorkspace", {"name":ws})["workspace"]["metadata"]
                break
            except RpcError as exc:
                if exc.code not in ("NOT_FOUND","UNAVAILABLE") or attempt == 29: raise
                time.sleep(2)
        # The built-in workspace is created by this registration's dedicated
        # gateway. Its mTLS CA, active workspace UUID and owner membership
        # anchor the binding; custom workspaces also carry installer labels.
        builtin = ws == "default" and os.environ.get("DISCOVER_ID")=="true" and not meta.get("labels")
        managed = (meta.get("labels",{}).get("saw.redhat.com/managed-by")=="kubernetes-runtime" and
                   meta.get("labels",{}).get("saw.redhat.com/runtime-owner")==os.environ["INSTALLATION"])
        if not wid and os.environ.get("DISCOVER_ID")=="true" and (managed or builtin):
            wid=meta["id"]
        if not wid or uuid.UUID(wid).int==0:
            raise ValueError("invalid workspace ID")
        if (meta["id"] != wid or meta["name"] != ws or meta.get("deletion_time") or
                not (managed or builtin)):
            raise ValueError("workspace identity mismatch")
        scope = {"workspace_scope":{"workspace":ws}}
        def members():
            result, page = {}, ""
            while True:
                response = g.call("ListWorkspaceMembers", {**scope, "page_size":100, "page_token":page})
                for m in response.get("members", []):
                    result[m["principal_subject"]] = m["role"]
                page = response.get("next_page_token")
                if not page:
                    return result
        roles = members()
        if builtin and set(roles) - {owner,relay}:
            raise ValueError("unexpected membership in dedicated default workspace")
        if roles.get(owner) != "WORKSPACE_ROLE_ADMIN":
            raise ValueError("owner mismatch")
        if relay not in roles:
            g.call("AddWorkspaceMember", {**scope,"principal_subject":relay, "role":"WORKSPACE_ROLE_USER",
                "request_id":str(uuid.uuid5(uuid.UUID(wid), "relay-user/" + relay))})
        if members().get(relay) != "WORKSPACE_ROLE_USER":
            raise ValueError("unexpected relay role")
        print(json.dumps({"workspace":ws, "workspaceID":wid, "subject":relay,"role":"WORKSPACE_ROLE_USER"}))


if __name__ == "__main__":
    main()
