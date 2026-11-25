"""Compile the same Helm-rendered personal-assistant BOM as the VM."""
import base64
from pathlib import Path

import pytest

from saw_kubernetes import compile_profile_files, ContractError
from saw_kubernetes.core import shared
from saw_kubernetes.harness import read_bundles, tool_rules
from saw_kubernetes.prepare_gate import publish_harness

from .profile_fixtures import ROOT, briefing_inputs


def test_briefing_plan_and_volume(tmp_path):
    files, cfg = briefing_inputs()
    plan = compile_profile_files(files, cfg)
    ws, = plan["workspaces"]
    sb, = ws["sandboxes"]
    spec = sb["spec"]
    assert {p["type"]:p["credentialRef"] for p in ws["providers"]} == {
        "gmail":{"secret":"gmail","key":"access_token"},
        "slack":{"secret":"slack","key":"bot_token"},
        "nvidia":{"secret":"inference","key":"api_key"}}
    mount, = [m for m in spec["template"]["driver_config"]["kubernetes"]["containers"]["agent"]["volume_mounts"]
              if m["mount_path"]=="/sandbox/harness"]
    assert mount["read_only"] and mount["name"]=="saw-gate"
    bom=tmp_path/"bom"; gate=tmp_path/"gate"; bom.mkdir(); gate.mkdir()
    for k,v in files.items(): (bom/k).write_text(v)
    pin="sha256:"+mount["sub_path"].removeprefix("harness-")
    for _ in range(2): publish_harness(gate,bom,"daily-briefing",pin)
    path=gate/mount["sub_path"]/"mcp/slack-reader.mjs"
    assert path.read_bytes()==(ROOT/"harness-bundles/daily-briefing/mcp/slack-reader.mjs").read_bytes()
    path.chmod(0o600); path.write_text("tampered")
    with pytest.raises(ValueError): publish_harness(gate,bom,"daily-briefing",pin)


@pytest.mark.parametrize("fault", ["missing","edited","no-approval","missing-provider","no-index"])
def test_untrusted_briefing_is_rejected(fault):
    files,cfg=briefing_inputs()
    ks=sorted(k for k in files if k.startswith("harness__") and not k.endswith("__map"))
    if fault=="missing": del files[ks[0]]
    if fault=="edited": files[ks[0]]=base64.b64encode(b"tampered").decode()
    if fault=="no-index": del files["harness-index.yaml"]
    if fault=="no-approval": del cfg["bindings"]["personal-assistant/assistant"]["toolGate"]["harness"]
    if fault=="missing-provider": cfg["credentialBindings"]=[b for b in cfg["credentialBindings"] if b["type"]!="gmail"]
    with pytest.raises(ContractError): compile_profile_files(files,cfg)


def local_audit(cfg):
    """The default (no auditReceipts): the gate logs locally instead of waiting for receipts."""
    gate = cfg["bindings"]["personal-assistant/assistant"]["toolGate"]
    del gate["receiptKey"]
    gate["localAudit"] = True
    return gate


def test_briefing_runs_with_the_local_audit_gate():
    files, cfg = briefing_inputs()
    local_audit(cfg)
    spec, = [sb["spec"] for sb in compile_profile_files(files, cfg)["workspaces"][0]["sandboxes"]]
    mounts = spec["template"]["driver_config"]["kubernetes"]["containers"]["agent"]["volume_mounts"]
    audit, = [m for m in mounts if m["mount_path"] == "/sandbox/.saw/audit"]
    # The same log/ subtree the governance extension admits, on the sandbox's own volume.
    assert audit == {"name": "saw-audit", "mount_path": "/sandbox/.saw/audit", "read_only": False, "sub_path": "log"}
    assert [m for m in mounts if m["mount_path"] == "/sandbox/harness"]
    command = spec["command"][2]
    # The plugin is loaded and checked, and the gate creates its own log file.
    assert "entries:{'saw-tool-gate':{enabled:true}}" in command and "saw-plugins.json" in command
    assert "O_CREAT" in command and "permits non-append writes" not in command
    # The plugin carries no writer key, so it appends to the local file.
    identity = shared.tool_gate_identity("fixture", cfg["ownerSubject"], "personal-assistant", "assistant")
    bundle = read_bundles(*shared.split_bom_files(files)[1:])["daily-briefing"]
    tree, _, digest, _ = shared.tool_gate_bundle(Path(shared.__file__).parent, identity, None, tool_rules(bundle))
    assert b"__SAW_AUDIT_KEY__" in tree["plugin/index.js"][0] and digest in command


@pytest.mark.parametrize("bad", [False, "yes"])
def test_local_audit_is_true_and_never_beside_a_receipt_key(bad):
    files, cfg = briefing_inputs()
    gate = local_audit(cfg)
    gate["localAudit"] = bad
    with pytest.raises(ContractError, match="localAudit"):
        compile_profile_files(files, cfg)
    files, cfg = briefing_inputs()
    cfg["bindings"]["personal-assistant/assistant"]["toolGate"]["localAudit"] = True
    with pytest.raises(ContractError, match="localAudit"):
        compile_profile_files(files, cfg)
