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
        bind(g, ws, wid, relay, owner, os.environ["INSTALLATION"], os.environ.get("DISCOVER_ID") == "true")


def bind(gateway, workspace, expected_id, relay, owner, installation, discover, *,
         timeout=210, monotonic=time.monotonic, sleep=time.sleep):
    scope = {"workspace_scope": {"workspace": workspace}}

    def members():
        roles, seen = {}, set()
        page = ""
        while True:
            response = gateway.call("ListWorkspaceMembers", {**scope, "page_size": 100, "page_token": page})
            for member in response.get("members", []):
                roles[member["principal_subject"]] = member["role"]
            page = response.get("next_page_token", "")
            if not page:
                return roles
            if page in seen or len(seen) >= 100:
                raise ValueError("invalid membership pagination")
            seen.add(page)

    # The reconciler creates the workspace and assigns its owner in separate passes.
    # Pin the first accepted UUID across observations before granting any access.
    deadline = monotonic() + timeout
    while True:
        try:
            meta = gateway.call("GetWorkspace", {"name": workspace})["workspace"]["metadata"]
            labels = meta.get("labels", {})
            builtin = discover and workspace == "default" and not labels
            managed = (labels.get("saw.redhat.com/managed-by") == "kubernetes-runtime"
                       and labels.get("saw.redhat.com/runtime-owner") == installation)
            if not expected_id and discover:
                expected_id = meta["id"]
            if (not expected_id or not uuid.UUID(expected_id).int or meta["id"] != expected_id
                    or meta["name"] != workspace or meta.get("deletion_time") or not (managed or builtin)):
                raise ValueError("workspace identity mismatch")
            roles = members()
            if builtin and set(roles) - {owner, relay}:
                raise ValueError("unexpected membership in dedicated default workspace")
            if relay in roles and roles[relay] != "WORKSPACE_ROLE_USER":
                raise ValueError("unexpected relay role")
            if owner in roles:
                if roles[owner] != "WORKSPACE_ROLE_ADMIN":
                    raise ValueError("owner mismatch")
                break
        except RpcError as exc:
            if exc.code not in {"NOT_FOUND", "UNAVAILABLE"}:
                raise
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("verified workspace and owner membership were not ready")
        sleep(min(2, remaining))

    if relay not in roles:
        gateway.call("AddWorkspaceMember", {**scope, "principal_subject": relay, "role": "WORKSPACE_ROLE_USER",
                     "request_id": str(uuid.uuid5(uuid.UUID(expected_id), "relay-user/" + relay))})
    if members().get(relay) != "WORKSPACE_ROLE_USER":
        raise ValueError("unexpected relay role")
    print(json.dumps({"workspace": workspace, "workspaceID": expected_id, "subject": relay, "role": "WORKSPACE_ROLE_USER"}))


if __name__ == "__main__":
    main()
