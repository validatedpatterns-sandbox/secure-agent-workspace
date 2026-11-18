"""Kubernetes delivery of the shared VM inline harness format."""
import base64
import json
import re
from pathlib import Path

import yaml

from .core import shared


def read_bundles(raw, index):
    bundles = shared.parse_harness_files(raw)
    if bundles and not isinstance(index.get("bundles"), dict):
        raise shared.InstallerError("inline harness requires the Helm digest index")
    shared.check_harness_index(bundles, index)
    return bundles


def bundle_tree(bundle):
    return {rel: (base64.b64decode(data, validate=True), False) for rel, data in bundle.files.items()}


def binding_for(sandbox, bundles):
    if not sandbox.harness_ref:
        return None
    if sandbox.harness_ref.get("image"):
        raise shared.InstallerError("OCI harness verification is unavailable in the Kubernetes runtime")
    bundle = shared.pinned_bundle(sandbox, bundles)
    if bundle.name != sandbox.harness_ref["name"] or bundle.agent != sandbox.agent:
        raise shared.InstallerError("harness identity or agent mismatch")
    return {"name": bundle.name, "digest": bundle.digest}


def configure(command, driver, bundle, workspace, sandbox, catalog):
    """Add only the approved RO tree and retain the existing signed tool gate."""
    info = shared.describe_harness_tree(bundle_tree(bundle), inline=True)
    attached = {p.type for p in workspace.providers if p.enabled and p.name in sandbox.providers}
    shared.check_harness_governance(workspace, sandbox, info, catalog, attached)
    config = shared.openclaw_harness_config(info)
    ids = shared.harness_plugin_ids(info)
    if any(not re.fullmatch(r"[a-zA-Z0-9_-]+", name) or name == "saw-tool-gate" for name in ids):
        raise shared.InstallerError("invalid or reserved harness plugin ID")
    policy = yaml.safe_load((Path(shared.__file__).parent / "tool-actions.yaml").read_text())
    tools = {r["tool"] for r in policy["rules"] if r["action"] in ("allow", "approval")}
    discovery = {"tool_search", "tool_call"}
    mcp_tools = sorted(t for t in tools if t in discovery or t.partition("__")[0] in info["mcpServers"])
    spec = {"trustEnv": shared.MCP_TRUST_ENV, "tools": mcp_tools, "digest": bundle.digest, "paths": config.get("plugins.load.paths", []),
            "skills": config.get("skills.load.extraDirs", []), "plugins": ids,
            "servers": shared.harness_mcp_servers(info)}
    mounts = driver["containers"]["agent"]["volume_mounts"]
    mounts.append({"name": "saw-gate", "mount_path": shared.HARNESS_MOUNT, "read_only": True,
                   "sub_path": "harness-" + bundle.digest.removeprefix("sha256:")})
    # The bundle's skill and writer agree on /sandbox/briefing. Retain that subtree with its workspace.
    mounts.append({"name": "saw-workspace", "mount_path": "/sandbox/briefing",
                   "read_only": False, "sub_path": "briefing"})
    start = Path(__file__).with_name("harness_preflight.js").read_text()
    start = start.replace("HARNESS_SPEC", json.dumps(spec, ensure_ascii=True))
    anchor = "const target = process.env.OPENCLAW_CONFIG_PATH;"
    command[2] = command[2].replace(anchor, start + "\n" + anchor)
    enable = "\n".join(shared.enable_harness_plugin(name) for name in ids)
    command[2] = command[2].replace("exec openclaw gateway run", enable + "\nexec openclaw gateway run")
