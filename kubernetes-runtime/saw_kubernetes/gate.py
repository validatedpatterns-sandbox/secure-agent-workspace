"""Render the VM tool gate as an immutable Kubernetes ConfigMap and its projection."""

import argparse
import json
import sys
from pathlib import Path

from .compiler import name
from .core import shared


def projection(namespace, owner, subject, workspace, sandbox):
    name(namespace, "namespace", 63)
    name(workspace, "workspace")
    name(sandbox, "sandbox")
    identity = shared.tool_gate_identity(owner, subject, workspace, sandbox)
    assets = Path(__file__).resolve().parents[2] / "charts/openshell-saw/files/installer"
    tree, _, digest, _ = shared.tool_gate_bundle(assets, identity)
    cm_name = "saw-tool-gate-" + digest.removeprefix("sha256:")[:32]
    # The volume projects the six regular files at the same paths as the VM.
    items = [{"key": path.replace("/", "__"), "path": path} for path in sorted(tree)]
    data = {item["key"]: tree[item["path"]][0].decode() for item in items}
    configmap = {
        "apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
        "metadata": {"name": cm_name, "namespace": namespace,
                     "annotations": {"saw.redhat.com/tool-gate-sha256": digest}},
        "data": data,
    }
    return configmap, {"name": cm_name, "defaultMode": 0o444, "items": items}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("namespace", "owner", "subject", "workspace", "sandbox"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--output", choices=("configmap", "volume-source"), default="configmap")
    args = vars(parser.parse_args())
    output = args.pop("output")
    try:
        cm, source = projection(**args)
    except (ValueError, shared.InstallerError) as exc:
        parser.exit(2, str(exc) + "\n")
    json.dump(cm if output == "configmap" else source, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
