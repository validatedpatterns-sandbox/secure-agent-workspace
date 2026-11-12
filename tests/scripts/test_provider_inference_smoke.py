"""Exercise the live probe's wire contracts with local, credential-free fixtures."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(not shutil.which("node"), reason="node required")
@pytest.mark.parametrize("kind", ["openai", "anthropic", "nvidia"])
@pytest.mark.parametrize("failure", ["none", "http", "wrong-reply", "network"])
def test_live_probe_wire_contract_and_sanitized_output(kind, failure):
    prelude = """
const kind = process.argv[1];
globalThis.fetch = async (url, options) => {
  const body = JSON.parse(options.body);
  const host = {openai:'api.openai.com',anthropic:'api.anthropic.com',nvidia:'integrate.api.nvidia.com'}[kind];
  if (new URL(url).hostname !== host || options.redirect !== 'error') throw Error('invalid destination');
  const key = kind === 'anthropic' ? options.headers['x-api-key'] : options.headers.authorization;
  if (!key?.includes('fixture-placeholder')) throw Error('missing placeholder');
  if (kind === 'anthropic' && options.headers['anthropic-version'] !== '2023-06-01') throw Error('missing version');
  if (body[kind === 'openai' ? 'max_completion_tokens' : 'max_tokens'] !== 128) throw Error('missing bound');
  if (process.env.FIXTURE_FAILURE === 'network') throw Error('DO-NOT-PRINT-PRIVATE-ERROR');
  const reply = process.env.FIXTURE_FAILURE === 'wrong-reply' ? 'unexpected' : body.messages[0].content.split(': ').pop();
  return {ok:process.env.FIXTURE_FAILURE !== 'http',status:process.env.FIXTURE_FAILURE === 'http' ? 401 : 200,
          json:async()=>kind === 'anthropic' ? {content:[{type:'text',text:reply}]} : {choices:[{message:{content:reply}}]}};
};
"""
    # Keep production declaration names independent from fixture variables.
    prelude = prelude.replace("const kind =", "const fixtureKind =").replace("[kind]", "[fixtureKind]").replace("kind ===", "fixtureKind ===")
    environment = {**os.environ, "FIXTURE_FAILURE":failure,
                   "OPENAI_API_KEY":"fixture-placeholder", "ANTHROPIC_API_KEY":"fixture-placeholder",
                   "NVIDIA_API_KEY":"fixture-placeholder"}
    result = subprocess.run(["node", "--input-type=module", "-e", prelude + (ROOT/"tests/provider-inference-smoke.mjs").read_text(),
                             kind, "fixture-model"], env=environment, capture_output=True, text=True)
    assert (result.returncode == 0) == (failure == "none"), result.stderr
    assert "fixture-placeholder" not in result.stdout + result.stderr
    assert "DO-NOT-PRINT-PRIVATE-ERROR" not in result.stdout + result.stderr
    if failure == "none":
        assert '"nonceMatched":true' in result.stdout
