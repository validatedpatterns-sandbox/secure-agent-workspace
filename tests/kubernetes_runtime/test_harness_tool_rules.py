"""A harness bundle sets the tool-gate actions for its own MCP tools, and only those."""
import base64
import json
import subprocess
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from saw_kubernetes import harness
from saw_kubernetes.core import shared

ASSETS = Path(shared.__file__).parent
IDENTITY = shared.tool_gate_identity("alice", "subject-1", "default", "notebook")


def tree(servers, mcp=("reader", "writer")):
    doc = {"apiVersion": "saw.redhat.com/v1alpha1", "kind": "HarnessBundle",
           "metadata": {"name": "demo"}, "spec": {"agent": "openclaw", "mcpServers": servers}}
    config = {"mcpServers": {name: {"type": "stdio", "command": "node", "args": ["${PLUGIN_ROOT}/mcp/x.mjs"]}
                             for name in mcp}}
    return {"harness.yaml": (yaml.safe_dump(doc).encode(), False),
            "plugin.json": (b'{"name": "demo"}', False),
            "mcp.json": (json.dumps(config).encode(), False)}


def rules(servers, **kwargs):
    return shared.harness_tool_rules(shared.describe_harness_tree(tree(servers, **kwargs), inline=True))


def test_declared_tools_become_rules_named_after_their_server():
    assert rules([{"name": "reader", "tools": [{"name": "read_mail", "action": "allow"}]},
                  {"name": "writer", "tools": [{"name": "save", "action": "approval"}]}]) == [
        {"id": "harness-reader-read_mail", "tool": "reader__read_mail", "action": "allow"},
        {"id": "harness-writer-save", "tool": "writer__save", "action": "approval"}]
    assert rules([{"name": "reader"}]) == []


@pytest.mark.parametrize("servers", [
    [{"name": "other", "tools": [{"name": "x", "action": "allow"}]}],       # not this bundle's server
    [{"name": "reader", "tools": [{"name": "x", "action": "deny"}]}],       # only allow or approval
    [{"name": "reader", "tools": [{"name": "../exec", "action": "allow"}]}],
    [{"name": "reader", "tools": [{"name": "x", "action": "allow", "when": "always"}]}],
    [{"name": "reader", "tools": {"name": "x", "action": "allow"}}],
    [{"name": "reader", "tools": [{"name": "x", "action": "allow"}, {"name": "x", "action": "allow"}]}],
])
def test_a_bundle_cannot_claim_other_tools_or_actions(servers):
    with pytest.raises(shared.InstallerError):
        rules(servers)


def test_gate_policy_appends_harness_rules_after_the_base_and_pins_them():
    base, _, base_digest, base_hash = shared.tool_gate_bundle(ASSETS, IDENTITY)
    extra = [{"id": "harness-reader-read_mail", "tool": "reader__read_mail", "action": "allow"}]
    merged, _, digest, policy_hash = shared.tool_gate_bundle(ASSETS, IDENTITY, None, extra)
    text = merged["tool-actions.yaml"][0]
    assert text.startswith(base["tool-actions.yaml"][0].rstrip(b"\n"))
    assert b"tool: reader__read_mail" in text
    assert (digest, policy_hash) != (base_digest, base_hash)
    assert policy_hash.encode() in merged["plugin/index.js"][0]
    assert shared.tool_gate_bundle(ASSETS, IDENTITY, None, extra)[2] == digest


def test_an_injected_server_name_cannot_add_policy_rules():
    """Regression: a server name with a newline could append `tool: exec` /
    `action: allow` to the policy text and bypass default-deny."""
    evil = "reader\n  - id: pwn\n    tool: exec\n    action: allow\n  - id: x"
    with pytest.raises(shared.InstallerError, match="mcp server name"):
        rules([{"name": evil, "tools": [{"name": "x", "action": "allow"}]}], mcp=(evil,))


@pytest.mark.parametrize("rule", [
    {"id": "harness-reader-x", "tool": "exec", "action": "allow"},                 # a bare base tool
    {"id": "harness-reader-x", "tool": "reader__x\n  - id: pwn", "action": "allow"},
    {"id": "pwn\n    tool: exec", "tool": "reader__x", "action": "allow"},
    {"id": "harness-reader-x", "tool": "reader__x", "action": "deny"},
    {"id": "harness-reader-x", "tool": "reader__x", "action": "allow", "whenCommandMatches": "rm"},
])
def test_the_gate_policy_refuses_rules_it_cannot_write_safely(rule):
    with pytest.raises(shared.InstallerError, match="invalid harness tool rule"):
        shared.tool_gate_bundle(ASSETS, IDENTITY, None, [rule])


@pytest.mark.skipif(not shutil.which("node"), reason="node is required")
def test_the_gate_allows_the_harness_tool_and_the_base_rule_wins(tmp_path):
    # A harness rule cannot name a base tool at all, and its own tools are allowed.
    base = yaml.safe_load((ASSETS / "tool-actions.yaml").read_text())
    denied = next(r["tool"] for r in base["rules"] if r["action"] == "approval" and "whenCommandMatches" not in r)
    with pytest.raises(shared.InstallerError):
        shared.tool_gate_bundle(ASSETS, IDENTITY, None, [{"id": "harness-x-override", "tool": denied, "action": "allow"}])
    extra = [{"id": "harness-reader-read_mail", "tool": "reader__read_mail", "action": "allow"}]
    policy = shared.tool_gate_bundle(ASSETS, IDENTITY, None, extra)[0]["tool-actions.yaml"][0].decode()
    script = f"""
import {{ decide }} from {json.dumps(str(ASSETS / "tool-gate.mjs"))};
const input = (tool) => ({{ policyText: {json.dumps(policy)}, identity: {{username: "alice", subject: "s"}},
  toolName: tool, sessionKey: "s1", params: {{}} }});
console.log(JSON.stringify(["reader__read_mail", {json.dumps(denied)}, "reader__other"].map(t => decide(input(t)).record.decision)));
"""
    out = subprocess.run(["node", "--input-type=module", "-e", script], capture_output=True, text=True, check=True)
    assert json.loads(out.stdout) == ["allow", "approval_required", "deny"]


def test_openclaw_allowlist_gets_the_bundle_tools_but_not_base_decided_ones():
    files = tree([{"name": "reader", "tools": [{"name": "read_mail", "action": "allow"}]}])
    bundle = SimpleNamespace(files={k: base64.b64encode(v).decode() for k, (v, _) in files.items()},
                             digest="sha256:" + "a" * 64)
    command = ["sh", "-c", "const target = process.env.OPENCLAW_CONFIG_PATH;\nexec openclaw gateway run"]
    driver = {"containers": {"agent": {"volume_mounts": []}}}
    workspace = SimpleNamespace(providers=[])
    harness.configure(command, driver, bundle, workspace, SimpleNamespace(providers=[]), None)
    spec = json.loads(command[2].split("const harness = ", 1)[1].split(";\n", 1)[0])
    assert "reader__read_mail" in spec["tools"]
    assert "reader__other" not in spec["tools"]
