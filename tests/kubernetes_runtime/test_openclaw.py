import json
import pytest

from saw_kubernetes.compiler import ContractError, compile_profile
from saw_kubernetes.reconcile import Reconciler
from .test_runtime import FakeGateway, mutate, sandbox, source


def agent(source, kind="openai", model="gpt-4.1-mini-2025-04-14"):
    from saw_kubernetes.core import shared
    protocol = "openai" if kind == "custom-inference" else shared.PROVIDER_PROTOCOLS[kind]
    endpoint = ("https://models.example.test/v1" if kind == "custom-inference" else
                shared.NATIVE_BASE_URLS.get(kind) or shared.PROTOCOL_NATIVE_BASE_URLS[protocol])
    if kind == "custom-inference":
        source[1]["customInferenceURL"] = endpoint
    source[1]["proxyBindings"] = [{"type":kind, "secret":"inference", "key":"api_key", "refresh":False}]
    mutate(source, "providers.yaml", lambda d: d["spec"]["providers"].append(
        {"name": kind, "type": kind, "credentialSecret": "inference"}))
    sandbox(source, lambda s: s.update(type="openclaw", providers=[kind], inference={
        "providerRef": kind, "protocol": protocol, "baseUrl": endpoint, "model": model}))


@pytest.mark.parametrize("kind,model", [
    ("openai", "gpt-4.1-mini"), ("anthropic", "claude-sonnet-4-6"),
    ("nvidia", "nvidia/nemotron-3.5-lightning-30b-a3b"), ("custom-inference", "org/model"),
])
def test_mutable_model_compiles_and_startup_accepts_published_selection(source, kind, model):
    import base64
    import shutil
    import subprocess
    agent(source, kind, model)
    binding = source[1]["bindings"]["default/toolbox"]
    key = base64.b64encode(bytes.fromhex("302a300506032b6570032100") + bytes(range(32))).decode()
    binding["toolGate"] = {"ownerLogin":"alice", "receiptKey":key, "modelSelector":True,
        "trusted":{"claimName":"saw-gate-test","uid":"gate-uid","readOnly":True},
        "audit":{"claimName":"saw-audit-test","uid":"audit-uid","readOnly":False}}
    command = compile_profile(*source)["workspaces"][0]["sandboxes"][0]["spec"]["command"]
    assert command[-1] == "model-from-gate"
    # Execute the actual startup selection, including the provider's model syntax.
    selection = command[2][command[2].index("const selection"):command[2].index("const config")]
    if not shutil.which("node"):
        pytest.skip("node is required to execute the compiled startup validation")
    for value, valid in [(model, True), ("$(id)", False), ("../escape", False)]:
        js = "const fs={readFileSync:()=>" + json.dumps(json.dumps({"generation":1,"model":value})) + "};\n"
        result = subprocess.run(["node", "-e", js + selection + "console.log(model);"], capture_output=True, text=True)
        assert (result.returncode == 0) == valid, result.stderr
        if valid:
            assert result.stdout.strip() == model


def test_openclaw_pinned_proxy_contract(source):
    agent(source)
    ws = compile_profile(*source)["workspaces"][0]
    assert ws["providers"][0]["credentials"] == {"OPENAI_API_KEY": "saw-cred.inference.api_key"}
    command = ws["sandboxes"][0]["spec"]["command"]
    assert command[-1] == "gpt-4.1-mini-2025-04-14"
    assert "saw-cred" not in json.dumps(command)
    assert "loopback" in command[2]


@pytest.mark.parametrize("change", ["absent", "alternative-url", "shell", "unknown-input"])
def test_openclaw_rejects_unapproved_bindings(source, change):
    agent(source)
    if change == "absent":
        source[1].pop("proxyBindings")
    else:
        update = {"alternative-url": {"baseUrl": "https://example.com/v1"},
                  "shell": {"model": "$(id)"}, "unknown-input": {"model": {"secretKeyRef": {"name":"private","key":"key"}}}}
        sandbox(source, lambda sb: sb["inference"].update(update[change]))
    with pytest.raises(ContractError):
        compile_profile(*source)


def test_redacted_provider_refuses_changed_revision(source, tmp_path):
    agent(source)
    plan = compile_profile(*source)
    ws = plan["workspaces"][0]
    provider = ws["providers"][0]
    gateway = FakeGateway()
    core = Reconciler(gateway, tmp_path / "ledger", lambda plan: None)
    real_call = gateway.call
    def call(method, body):
        result = real_call(method, body)
        if method == "CreateProvider":
            obj = result["provider"]
            obj["metadata"]["resource_version"] = "1"
            obj["credentials"]["OPENAI_API_KEY"] = "REDACTED"
        return result
    gateway.call = call
    state = {}
    assert not core._apply_provider(ws, provider, plan, state, 1, [])
    assert core._apply_provider(ws, provider, plan, state, 1, [])
    gateway.providers[(ws["name"], "openai")]["metadata"]["resource_version"] = "2"
    with pytest.raises(ContractError, match="revision"):
        core._apply_provider(ws, provider, plan, state, 1, [])


def test_retirement_checks_recorded_id_before_mutations(source, tmp_path):
    import uuid
    source[1]["retiredSandboxes"] = {"agent/old": str(uuid.uuid4())}
    plan = compile_profile(*source)
    gateway = FakeGateway()
    core = Reconciler(gateway, tmp_path / "ledger", lambda plan: None)
    with pytest.raises(ContractError, match="recorded identity"):
        core.reconcile(plan, generation=1)
    assert not gateway.sandboxes


def test_browser_policy_is_bound_to_one_owner_and_exact_https_origin(source):
    agent(source)
    binding = next(iter(source[1]["bindings"].values()))
    binding["browser"] = {"origin":"https://agent.apps.example.com","ownerLogin":"alice"}
    ws = compile_profile(*source)["workspaces"][0]
    command = ws["sandboxes"][0]["spec"]["command"][2]
    assert 'allowUsers:["alice"]' in command
    assert 'allowedOrigins:["https://agent.apps.example.com"]' in command
    assert command.index("config.gateway.trustedProxies") < command.index("fs.writeFileSync")
    binding["browser"]["origin"] = "https://*.example.com"
    with pytest.raises(ContractError):
        compile_profile(*source)


def test_tool_gate_uses_shared_identity_policy_and_exact_mounts(source):
    from saw_kubernetes.gate import projection
    agent(source)
    binding = source[1]["bindings"]["default/toolbox"]
    binding["toolGate"] = {
        "ownerLogin": "alice",
        "trusted": {"claimName": "saw-gate-test", "uid": "gate-uid", "readOnly": True},
        "audit": {"claimName": "saw-audit-test", "uid": "audit-uid", "readOnly": False},
    }
    plan = compile_profile(*source)
    spec = plan["workspaces"][0]["sandboxes"][0]["spec"]
    cm, _ = projection(source[1]["namespace"], "alice", source[1]["ownerSubject"], "default", "toolbox")
    assert cm["metadata"]["annotations"]["saw.redhat.com/tool-gate-sha256"] in spec["command"][2]
    mounts = spec["template"]["driver_config"]["kubernetes"]["containers"]["agent"]["volume_mounts"]
    assert [(m["mount_path"], m["read_only"]) for m in mounts[1:]] == [
        ("/sandbox/.saw/trusted", True), ("/sandbox/.saw/audit", False)]
    binding["toolGate"]["trusted"]["readOnly"] = False
    with pytest.raises(ContractError, match="mount mode"):
        compile_profile(*source)


def test_writer_key_binds_the_compiled_extension_and_tool_selection(source):
    import base64
    from pathlib import Path
    from saw_kubernetes.core import shared

    agent(source)
    binding = source[1]["bindings"]["default/toolbox"]
    # SubjectPublicKeyInfo prefix for Ed25519 followed by 32 fixture bytes.
    key = base64.b64encode(bytes.fromhex("302a300506032b6570032100") + bytes(range(32))).decode()
    binding["toolGate"] = {"ownerLogin":"alice", "receiptKey":key,
        "trusted":{"claimName":"saw-gate-test","uid":"gate-uid","readOnly":True},
        "audit":{"claimName":"saw-audit-inbox","uid":"queue-uid","readOnly":False}}
    plan = compile_profile(*source)
    spec = plan["workspaces"][0]["sandboxes"][0]["spec"]
    identity = shared.tool_gate_identity("alice", source[1]["ownerSubject"], "default", "toolbox")
    tree, _, digest, _ = shared.tool_gate_bundle(Path(shared.__file__).parent, identity, key)
    assert key.encode() in tree["plugin/index.js"][0]
    assert digest in spec["command"][2] and "allow:['read','write','exec']" in spec["command"][2]
    binding["toolGate"]["receiptKey"] = "invalid"
    with pytest.raises(ContractError, match="Ed25519"):
        compile_profile(*source)


@pytest.mark.parametrize("kind",["openclaw","nemoclaw"])
def test_openai_model_uses_shared_bom_resolution(source,kind):
    agent(source)
    ref={"secretKeyRef":{"name":"inference","key":"custom_model"},"default":"gpt-4.1-mini"}
    def configure(sb):
        sb["type"]=kind
        sb["inference"]["model"]=ref
    sandbox(source,configure)
    def model():
        return compile_profile(*source)["workspaces"][0]["sandboxes"][0]["spec"]["command"][-1]
    assert model()=="gpt-4.1-mini"
    source[1]["modelInputs"]={"inference.custom_model":"gpt-4.1"}
    assert model()=="gpt-4.1"
