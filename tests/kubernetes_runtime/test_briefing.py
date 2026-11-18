"""Compile the same Helm-rendered personal-assistant BOM as the VM."""
import base64
from pathlib import Path

import pytest

from saw_kubernetes import compile_profile_files, ContractError
from saw_kubernetes.core import shared
from saw_kubernetes.harness import read_bundles
from saw_kubernetes.prepare_gate import publish_harness

from .profile_fixtures import ROOT, briefing_inputs


def test_briefing_plan_and_volume(tmp_path):
    files, cfg = briefing_inputs()
    plan = compile_profile_files(files, cfg)
    ws, = plan["workspaces"]
    sb, = ws["sandboxes"]
    spec = sb["spec"]
    assert {p["type"]:p["credentials"] for p in ws["providers"]} == {
        "gmail":{"GMAIL_ACCESS_TOKEN":"saw-cred.gmail.access_token"},
        "slack":{"SLACK_BOT_TOKEN":"saw-cred.slack.bot_token"},
        "nvidia":{"NVIDIA_API_KEY":"saw-cred.inference.api_key"}}
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
    if fault=="missing-provider": cfg["proxyBindings"]=[b for b in cfg["proxyBindings"] if b["type"]!="gmail"]
    with pytest.raises(ContractError): compile_profile_files(files,cfg)
