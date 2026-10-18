"""The tool gate is filled by the host and mounted into agent sandboxes."""
from conftest import TEST_PROXY

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from conftest import harness_files

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "charts" / "openshell-saw" / "files" / "installer"


def applier_for(ab, config, creds, **changes):
    harness = {"bundles": ab.parse_harness_files(harness_files())}
    return ab.ProfileApplier(ab.Shell(), {**config, **changes}, creds, harness=harness)


def test_agent_gate_files_come_from_read_only_volume(
        ab, fake_env, config, shipped_profile_files, secrets_dir):
    profiles = ab.parse_profiles(shipped_profile_files)
    creds = ab.resolve_credentials(profiles, secrets_dir, TEST_PROXY)
    applier = applier_for(ab, config, creds)
    applier.apply(profiles)
    state = fake_env.openshell_state()["sandboxes"]
    assert applier.verify(profiles) == []
    assert applier_for(ab, config, creds).verify(profiles) == []
    policy = (GATE / "tool-actions.yaml").read_bytes()
    policy_hash = "sha256:" + hashlib.sha256(policy).hexdigest()
    for ws, name in (("default", "notebook"), ("cuda-dev", "cuda-sandbox")):
        gate = ab.sandbox_volume_name(ab.GATE_VOLUME_PREFIX, ws, name)
        audit = ab.sandbox_volume_name(ab.AUDIT_VOLUME_PREFIX, ws, name)
        mounts = state[f"{ws}/{name}"]["driverConfig"]["podman"]["mounts"]
        actual_mounts = {m["target"]: (m["source"], m["read_only"]) for m in mounts}
        assert actual_mounts[ab.GATE_MOUNT] == (gate, True)
        assert actual_mounts[ab.AUDIT_MOUNT] == (audit, False)
        root = fake_env.state / "volumes" / gate
        assert (root / "tool-actions.yaml").read_bytes() == policy
        assert json.loads((root / "identity.json").read_text()) == {
            "username": "alice", "subject": "subject-alice", "sandbox": name, "workspace": ws}
        assert policy_hash in (root / "plugin/index.js").read_text()
        assert (root / "plugin/tool-gate.mjs").read_bytes() == (GATE / "tool-gate.mjs").read_bytes()
        assert (fake_env.state / "volumes" / audit / "tool-actions.jsonl").is_file()
        assert (fake_env.state / "volumes" / audit).stat().st_mode & 0o222 == 0
        cfg = state[f"{ws}/{name}"]["openclawConfig"]
        assert ab.GATE_MOUNT + "/plugin" in cfg["plugins.load.paths"]
        assert cfg["plugins.entries.saw-tool-gate"]["enabled"]
    assert not any("SAW_TOOL_GATE_B64" in " ".join(call) for call in fake_env.openshell_calls())
    assert any(call["args"][1:3] == ["chattr", "+a"] for call in fake_env.other_calls("sudo"))


def test_generic_sandbox_has_no_gate(ab, fake_env, config):
    provider = ab.Provider(name="nvidia", type="nvidia", model="nvidia/nemotron-3-super-120b-a12b")
    workspace = ab.Workspace(name="default", providers=[provider], sandboxes=[
        ab.Sandbox(name="toolbox", type="generic", image="base", providers=["nvidia"]),
        ab.Sandbox(name="notebook", type="openclaw", image="base", providers=["nvidia"]),
    ])
    profile = ab.Profile(name="data-science", workspaces=[workspace])
    creds = {"default": {"nvidia": "saw-cred.inference.api_key"}}
    applier_for(ab, config, creds).apply([profile])
    assert "driverConfig" not in fake_env.openshell_state()["sandboxes"]["default/toolbox"]
    assert len(fake_env.openshell_state()["sandboxes"]["default/notebook"]["driverConfig"]["podman"]["mounts"]) == 2


@pytest.mark.parametrize("change", [
    {"dashboard": {"owner": ""}}, {"ownerSubject": ""},
])
def test_missing_owner_or_subject_fails_apply(ab, fake_env, config, change):
    provider = ab.Provider(name="nvidia", type="nvidia", model="nvidia/test")
    sandbox = ab.Sandbox(name="notebook", type="openclaw", image="base", providers=["nvidia"])
    profile = ab.Profile(name="demo", workspaces=[ab.Workspace(
        name="default", providers=[provider], sandboxes=[sandbox])])
    with pytest.raises(ab.InstallerError, match="dashboard.owner|ownerSubject"):
        applier_for(ab, config, {"default": {"nvidia": "saw-cred.inference.api_key"}}, **change).apply([profile])
    assert "default/notebook" not in fake_env.openshell_state()["sandboxes"]


def test_harness_paths_and_restrictive_plugin_allow_keep_the_gate(
        ab, fake_env, config, shipped_profile_files, secrets_dir):
    profiles = ab.parse_profiles(shipped_profile_files)
    creds = ab.resolve_credentials(profiles, secrets_dir, TEST_PROXY)
    applier_for(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    cfg = state["sandboxes"]["default/notebook"]["openclawConfig"]
    cfg["plugins.allow"] = ["memory-core"]
    fake_env.set_openshell_state(state)
    second = applier_for(ab, config, creds)
    second.apply(profiles)
    cfg = fake_env.openshell_state()["sandboxes"]["default/notebook"]["openclawConfig"]
    assert cfg["plugins.load.paths"] == ["/sandbox/harness", "/sandbox/harness/plugins",
                                         ab.GATE_MOUNT + "/plugin"]
    assert cfg["plugins.allow"] == ["memory-core", "saw-tool-gate"]
    assert second.verify(profiles) == []


def test_missing_gate_mount_recreates_the_agent_sandbox(
        ab, fake_env, config, shipped_profile_files, secrets_dir):
    profiles = ab.parse_profiles(shipped_profile_files)
    creds = ab.resolve_credentials(profiles, secrets_dir, TEST_PROXY)
    applier_for(ab, config, creds).apply(profiles)
    state = fake_env.openshell_state()
    mounts = state["sandboxes"]["default/notebook"]["driverConfig"]["podman"]["mounts"]
    state["sandboxes"]["default/notebook"]["driverConfig"]["podman"]["mounts"] = [
        m for m in mounts if m["target"] != ab.GATE_MOUNT]
    fake_env.set_openshell_state(state)
    second = applier_for(ab, config, creds)
    second.apply(profiles)
    deletes = [c for c in fake_env.openshell_calls() if c[:3] == ["sandbox", "delete", "notebook"]]
    assert deletes
    assert second.verify(profiles) == []


def test_tool_gate_decisions():
    node = shutil.which("node")
    assert node, "node is required to test the tool-action gate"
    result = subprocess.run([node, "--test", str(GATE / "tool-gate.test.mjs")],
                            cwd=GATE, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_shipped_tool_actions_yaml_parses_in_node():
    node = shutil.which("node")
    assert node, "node is required to test the tool-action gate"
    policy = GATE / "tool-actions.yaml"
    doc = yaml.safe_load(policy.read_text())
    assert doc["version"] == 1 and doc["defaultAction"] == "deny"
    assert [rule["tool"] for rule in doc["rules"] if rule["action"] == "allow"] == [
        "exec", "exec", "exec", "exec", "read", "memory_search", "memory_get",
        "session_status", "sessions_list", "sessions_history"]
    script = r"""
import { parsePolicy } from "./tool-gate.mjs";
import { readFileSync } from "node:fs";
process.stdout.write(String(parsePolicy(readFileSync(process.argv[1], "utf8")).rules.length));
"""
    result = subprocess.run([node, "--input-type=module", "-e", script, str(policy)],
                            cwd=GATE, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert int(result.stdout) == len(doc["rules"])


def test_before_tool_call_writes_hash_and_rule(tmp_path):
    node = shutil.which("node")
    assert node, "node is required to test the tool-action gate"
    audit = tmp_path / "tool-actions.jsonl"
    script = r"""
import { evaluateToolCall } from "./tool-gate.mjs";
import { readFileSync } from "node:fs";
const policyText = readFileSync(process.argv[1], "utf8");
const identity = {username: "alice", subject: "subject-alice", sandbox: "notebook", workspace: "default"};
const common = {policyText, identity, sessionKey: "task-1", auditFile: process.argv[2]};
const allowed = evaluateToolCall({...common, toolName: "read", params: {path: "/tmp/x"}});
if (allowed.hook !== undefined) throw new Error("read should execute");
const held = evaluateToolCall({...common, toolName: "exec", params: {command: "rm -rf /tmp/x"}});
if (!held.hook?.requireApproval) throw new Error("rm should require approval");
held.hook.requireApproval.onResolution("timeout");
"""
    result = subprocess.run([node, "--input-type=module", "-e", script,
                             str(GATE / "tool-actions.yaml"), str(audit)],
                            cwd=GATE, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    lines = [json.loads(line) for line in audit.read_text().splitlines()]
    assert [line["decision"] for line in lines] == ["allow", "approval_required", "rejected"]
    policy_hash = "sha256:" + hashlib.sha256((GATE / "tool-actions.yaml").read_bytes()).hexdigest()
    for line in lines:
        assert line["user"] == {"username": "alice", "subject": "subject-alice"}
        assert line["task"]["id"] == "task-1"
        assert line["policyHash"] == policy_hash and line["rule"]
        assert line["argsDigest"].startswith("sha256:")
        assert json.dumps(line, separators=(",", ":")) in result.stderr
