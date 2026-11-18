"""All inference providers share BOM resolution and the VM's proxy profiles."""
import json
import shutil
import subprocess

import pytest

from saw_kubernetes import ContractError, compile_profile
from saw_kubernetes import provider as governed
from .test_openclaw import agent
from .test_runtime import source, sandbox


CASES = [
    ("openai", "gpt-4.1-mini", "https://api.openai.com/v1", "openai-completions", "OPENAI_API_KEY"),
    ("anthropic", "claude-sonnet-4-6", "https://api.anthropic.com", "anthropic-messages", "ANTHROPIC_API_KEY"),
    ("nvidia", "nvidia/nemotron-3.5-lightning-30b-a3b", "https://integrate.api.nvidia.com/v1", "openai-completions", "NVIDIA_API_KEY"),
]


@pytest.mark.parametrize("kind,model,url,api,env", CASES)
@pytest.mark.parametrize("native", [True, False])
def test_provider_compiles_native_protocol_and_placeholder_config(source, kind, model, url, api, env, native):
    agent(source, kind, model)
    if native:
        sandbox(source, lambda s: s["inference"].pop("baseUrl"))
    workspace = compile_profile(*source)["workspaces"][0]
    assert workspace["providers"][0]["credentials"] == {env:"saw-cred.inference.api_key"}
    command = workspace["sandboxes"][0]["spec"]["command"]
    assert "@SAW_" not in command[2]
    if not shutil.which("node"):
        pytest.skip("node is required to execute the compiled OpenClaw configuration")
    javascript = command[2].split("<<'JS'\n", 1)[1].split("\nJS\n", 1)[0]
    # Execute the generated startup without writing /sandbox or starting an agent.
    runner = """
const vm = require('node:vm');
let written;
vm.runInNewContext(process.argv[1], {
  require: name => name === 'node:fs' ? {
    writeFileSync: (path, data) => { written = data; }, renameSync: () => {}
  } : require(name),
  process: {argv: ['node','-',process.argv[2]], env:{OPENCLAW_CONFIG_PATH:'/fixture/config'}}
});
console.log(written);
"""
    result = subprocess.run(["node", "-e", runner, javascript, model], capture_output=True, text=True, check=True)
    batch = json.loads(result.stdout)
    config = {operation["path"]: operation["value"] for operation in batch}
    assert set(config) == {"gateway", "models", "agents", "tools", "plugins", "skills", "channels", "mcp"}
    assert all(set(operation) == {"path", "value"} for operation in batch)
    # Whole managed subtrees replace previous settings; the stock writer owns
    # metadata/backup publication and unrelated user configuration remains.
    assert 'openclaw config set --batch-file "$OPENCLAW_CONFIG_PATH.saw-managed"' in command[2]
    actual = config["models"]["providers"]["saw-" + kind]
    assert actual == {"baseUrl":url,"api":api,"apiKey":"${"+env+"}","models":[{"id":model,"name":model}]}
    assert config["agents"]["defaults"]["model"]["primary"] == "saw-"+kind+"/"+model
    assert config["tools"] == {"deny":["*"]}
    assert config["plugins"] == {"allow":[], "load":{"paths":[]}, "entries":{}}
    assert config["skills"] == {"load":{"extraDirs":[]}}
    assert config["channels"] == {} and config["mcp"] == {"servers":{}}


@pytest.mark.parametrize("kind,model,url,api,env", CASES)
def test_provider_uses_shipped_host_and_credential_policy(source, kind, model, url, api, env):
    agent(source, kind, model)
    credentials = compile_profile(*source)["workspaces"][0]["providers"][0]["credentials"]
    slot, hosts = governed.requirements(kind)
    assert slot["env_vars"] == [env]
    policy = {"markerPrefix":"saw-cred", "profiles":{kind:hosts}, "allowHosts":hosts,
              "bindings":[{"providers":[kind],"secret":"inference","key":"api_key"}]}
    assert governed.check_policy(kind, credentials, policy)
    assert not governed.check_policy(kind, credentials, {**policy,"allowHosts":[]})
    assert not governed.check_policy(kind, {env:"saw-cred.foreign.api_key"}, policy)
    sandbox(source, lambda s: s["inference"].update(baseUrl="https://foreign.example/v1"))
    with pytest.raises(ContractError):
        compile_profile(*source)


def test_anthropic_cannot_silently_use_openai_protocol(source):
    agent(source, "anthropic", "claude-sonnet-4-6")
    sandbox(source, lambda s: s["inference"].update(protocol="openai"))
    with pytest.raises(ContractError):
        compile_profile(*source)
