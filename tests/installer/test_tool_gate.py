"""The tool-action gate is installed into agent sandboxes only."""

import base64
import json
import shutil
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "charts" / "openshell-saw" / "files" / "installer"


def tool_gate_installs(fake_env):
    """Payloads of the node writer each agent sandbox receives."""
    found = []
    for call in fake_env.openshell_calls():
        if call[:2] != ["sandbox", "exec"]:
            continue
        script = next((arg for arg in call if isinstance(arg, str) and "SAW_TOOL_GATE_B64" in arg), None)
        if script is None:
            continue
        encoded = script.split('SAW_TOOL_GATE_B64 = "', 1)[1].split('"', 1)[0]
        payload = json.loads(base64.b64decode(encoded))
        name = call[call.index("-n") + 1]
        found.append((name, payload))
    return found


def test_agent_sandboxes_get_the_gate_with_the_signed_in_user(
        ab, fake_env, config, shipped_profile_files, secrets_dir):
    profiles = ab.parse_profiles(shipped_profile_files)
    creds = ab.resolve_credentials(profiles, secrets_dir)
    config = {**config, "ownerSubject": "subject-alice"}
    ab.ProfileApplier(ab.Shell(), config, creds).apply(profiles)
    installs = tool_gate_installs(fake_env)
    assert sorted(name for name, _payload in installs) == ["cuda-sandbox", "notebook"]
    notebook = next(payload for name, payload in installs if name == "notebook")
    assert notebook["enable"] is True
    identity = json.loads(notebook["files"]["/sandbox/.saw/identity.json"])
    assert identity == {
        "username": "saw-test",
        "subject": "subject-alice",
        "sandbox": "notebook",
        "workspace": "default",
    }
    assert "before_tool_call" in notebook["files"]["/sandbox/.openclaw/extensions/saw-tool-gate/index.js"]
    cuda = next(payload for name, payload in installs if name == "cuda-sandbox")
    assert json.loads(cuda["files"]["/sandbox/.saw/identity.json"])["workspace"] == "cuda-dev"
    assert "toolbox" not in [name for name, _payload in installs]


def test_a_generic_sandbox_does_not_get_the_tool_gate(ab, fake_env, config):
    provider = ab.Provider(name="nvidia", type="nvidia", model="nvidia/nemotron-3-super-120b-a12b")
    workspace = ab.Workspace(name="default", providers=[provider], sandboxes=[
        ab.Sandbox(name="toolbox", type="generic", image="base", providers=["nvidia"]),
        ab.Sandbox(name="notebook", type="openclaw", image="base", providers=["nvidia"]),
    ])
    profile = ab.Profile(name="data-science", workspaces=[workspace])
    creds = {"default": {"nvidia": "nvapi-TEST-KEY-123"}}
    ab.ProfileApplier(ab.Shell(), config, creds).apply([profile])
    assert [name for name, _payload in tool_gate_installs(fake_env)] == ["notebook"]


def test_tool_gate_decisions():
    node = shutil.which("node")
    assert node, "node is required to test the tool-action gate"
    result = subprocess.run(
        [node, "--test", str(GATE / "tool-gate.test.mjs")],
        cwd=GATE, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_shipped_tool_actions_yaml_parses_in_node():
    """The policy file is valid YAML, and the gate's own parser accepts it."""
    node = shutil.which("node")
    assert node, "node is required to test the tool-action gate"
    policy = GATE / "tool-actions.yaml"
    doc = yaml.safe_load(policy.read_text())
    assert doc["version"] == 1 and doc["defaultAction"] == "allow"
    assert [rule["id"] for rule in doc["rules"]] == [
        "exec-consequential", "message-send", "saw-denied-tool"]
    script = r"""
import { parsePolicy } from "./tool-gate.mjs";
import { readFileSync } from "node:fs";
const policy = parsePolicy(readFileSync(process.argv[1], "utf8"));
process.stdout.write(JSON.stringify(policy.rules.map((rule) => rule.id)));
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script, str(policy)],
        cwd=GATE, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == ["exec-consequential", "message-send", "saw-denied-tool"]


def test_before_tool_call_writes_the_audit_log(tmp_path):
    """The hook path writes allow, approval, and the resolution to the audit file."""
    node = shutil.which("node")
    assert node, "node is required to test the tool-action gate"
    audit = tmp_path / "tool-actions.jsonl"
    script = r"""
import { evaluateToolCall } from "./tool-gate.mjs";
import { readFileSync } from "node:fs";
const policyText = readFileSync(process.argv[1], "utf8");
const auditFile = process.argv[2];
const identity = {
  username: "alice", subject: "subject-alice", sandbox: "notebook", workspace: "default",
};
const allowed = evaluateToolCall({
  policyText, identity, toolName: "exec", params: { command: "git status" },
  sessionKey: "task-1", now: "2026-10-05T00:00:00Z", auditFile,
});
if (allowed.hook !== undefined) throw new Error("git status should execute");
const held = evaluateToolCall({
  policyText, identity, toolName: "exec", params: { command: "git push origin" },
  sessionKey: "task-1", now: "2026-10-05T00:01:00Z", auditFile,
});
if (!held.hook || !held.hook.requireApproval) throw new Error("git push should wait for approval");
if (held.hook.block) throw new Error("approval must not run the tool");
held.hook.requireApproval.onResolution("timeout");
"""
    result = subprocess.run(
        [node, "--input-type=module", "-e", script, str(GATE / "tool-actions.yaml"), str(audit)],
        cwd=GATE, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    lines = [json.loads(line) for line in audit.read_text().splitlines()]
    assert [line["decision"] for line in lines] == ["allow", "approval_required", "rejected"]
    for line in lines:
        assert line["user"] == {"username": "alice", "subject": "subject-alice"}
        assert line["task"]["id"] == "task-1"
        assert line["sandbox"] == "notebook" and line["workspace"] == "default"
        assert line["tool"] == "exec" and line["rule"]
        assert line["argsDigest"].startswith("sha256:")
        assert line["summary"] and line["time"]
    assert lines[2]["approval"]["resolution"] == "timeout"
