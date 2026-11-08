#!/usr/bin/env python3
"""Read the public objects that form a site approval. No Kubernetes writes or Secret reads."""
import argparse
from functools import lru_cache
import json
from pathlib import Path
import re
import subprocess
import sys
from uuid import UUID, uuid5, NAMESPACE_URL

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "kubernetes-runtime"))
from saw_kubernetes.audit import capture
from saw_kubernetes.boundary import fingerprint, objects
from saw_kubernetes.portal_contract import contract


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("owner", "registration", "governance-namespace", "api-server"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--installation-id", help="Explicit installation UUID for static values; defaults to the portal registration identity")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--show-objects", action="store_true", help="print the underlying public specs/data for review")
    output.add_argument("--profile-digest", action="store_true", help="print the rendered public BOM data digest for review")
    a = parser.parse_args()
    if not re.fullmatch("[a-z0-9]([-a-z0-9]{0,17}[a-z0-9])?", a.owner) or not re.fullmatch("[a-f0-9]{16}", a.registration):
        parser.error("invalid owner or registration")
    if not re.fullmatch("[a-z0-9]([-a-z0-9]*[a-z0-9])?", a.governance_namespace):
        parser.error("invalid governance namespace")
    if subprocess.check_output(["oc", "whoami", "--show-server"], text=True).strip() != a.api_server:
        parser.error("unexpected cluster")

    @lru_cache(maxsize=None)
    def read(path):
        return json.loads(subprocess.check_output(["oc", "get", "--raw", path, "--request-timeout=20s"]))

    ns = "saw-" + a.owner
    meta = read("/api/v1/namespaces/" + ns)["metadata"]
    ident = a.installation_id or str(uuid5(NAMESPACE_URL, "urn:saw:portal:" + a.owner + ":" + a.registration))
    try:
        if str(UUID(ident)) != ident or UUID(ident).int == 0:
            raise ValueError()
    except ValueError:
        parser.error("invalid installation identity")
    if meta.get("deletionTimestamp") or meta.get("labels", {}).get("saw.redhat.com/runtime-owner") != ident:
        parser.error("runtime namespace does not belong to this live registration")
    config = dict(namespace=ns, namespaceUID=meta["uid"], trustedNamespace="saw-ctl-" + a.registration,
                  ownerID=ident, mode="container", governanceNamespace=a.governance_namespace,
                  gateway=a.owner, proxyPolicy=a.owner + "-proxy-policy")
    capture(config, read)  # same health, admission and network checks as enrollment
    if a.profile_digest:
        print(fingerprint(read(f"/api/v1/namespaces/{ns}/configmaps/saw-bom-profiles")["data"]))
        return
    from saw_kubernetes.core import shared
    files = read(f"/api/v1/namespaces/{ns}/configmaps/saw-bom-profiles")["data"]
    documents, _, _ = shared.split_bom_files(files)
    config["slotKeys"] = sorted(ws.name+"/"+sb.name
        for _, ws in shared.enabled_workspaces(shared.parse_profiles(documents))
        for sb in ws.sandboxes if sb.enabled)
    reference = contract(config, read)
    result = ({key: {"path":path, field:read(path)[field]} for key,(path,field) in objects(config).items()}
              if a.show_objects else reference)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
