// Run against a stock OpenClaw binary. No provider requests or real credentials.
// All config, backups and state live in one temporary directory and are removed.
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, writeFileSync, renameSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';

const directory = mkdtempSync(join(tmpdir(), 'saw-config-publication-'));
const target = join(directory, 'openclaw.json');
const batch = join(directory, 'managed.json');
const executable = process.env.SAW_TEST_OPENCLAW || 'openclaw';
const env = {
  PATH: process.env.PATH, HOME: directory, OPENCLAW_HOME: directory,
  OPENCLAW_STATE_DIR: directory, OPENCLAW_CONFIG_PATH: target,
  XDG_CONFIG_HOME: directory, TMPDIR: directory,
  OPENAI_API_KEY: 'synthetic-config-test-only'
};
function cli(...args) {
  const result = spawnSync(executable, args, {env, encoding:'utf8', timeout:120000});
  assert.equal(result.status, 0, `stock CLI failed at ${args.slice(0, 2).join(' ')} (${result.status}): ${(result.stderr || '').slice(-1200)}`);
  return result.stdout.trim();
}
function configuration(model, stale = false) {
  const provider = {baseUrl:'https://api.openai.com/v1', api:'openai-completions',
    apiKey:'${OPENAI_API_KEY}', models:[{id:model, name:model}]};
  return {
    gateway:{mode:'local', bind:'loopback', port:19001},
    models:{providers:{'saw-openai':provider, ...(stale ? {'saw-stale':provider} : {})}},
    agents:{defaults:{model:{primary:'saw-openai/' + model}, workspace:join(directory, 'workspace')}},
    tools:stale ? {allow:['read']} : {deny:['*']},
    plugins:{allow:[], load:{paths:[]}, entries:{}}, skills:{load:{extraDirs:[]}},
    channels:{}, mcp:{servers:{}}
  };
}
function publish(value) {
  writeFileSync(batch, JSON.stringify(Object.entries(value).map(([path, value]) => ({path, value}))), {mode:0o600});
  cli('config', 'set', '--batch-file', batch);
}
try {
  publish(configuration('gpt-4.1-mini', true));
  // A second native write establishes a backup and observed baseline.
  cli('config', 'set', 'gateway.port', '19002', '--strict-json');
  assert.equal(JSON.parse(cli('config', 'get', 'agents.defaults.model.primary', '--json')), 'saw-openai/gpt-4.1-mini');
  assert.ok(JSON.parse(readFileSync(target)).meta);
  cli('plugins', 'list', '--json');

  // Reproduce the old integration failure: atomically replacing the entire
  // config without stock metadata causes recovery of the previous choice.
  writeFileSync(target + '.replacement', JSON.stringify(configuration('gpt-4.1')), {mode:0o600});
  renameSync(target + '.replacement', target);
  cli('plugins', 'list', '--json');
  const afterReplacement = JSON.parse(cli('config', 'get', 'agents.defaults.model.primary', '--json'));
  assert.ok(['saw-openai/gpt-4.1-mini', 'saw-openai/gpt-4.1'].includes(afterReplacement));
  const legacyReplacementRestored = afterReplacement === 'saw-openai/gpt-4.1-mini';
  if (process.argv.includes('--expect-restore')) assert.ok(legacyReplacementRestored);

  publish(configuration('gpt-4.1-mini', true));
  publish(configuration('gpt-4.1'));
  assert.equal(JSON.parse(cli('config', 'get', 'agents.defaults.model.primary', '--json')), 'saw-openai/gpt-4.1');
  const current = JSON.parse(readFileSync(target));
  assert.ok(current.meta);
  assert.deepEqual(Object.keys(current.models.providers), ['saw-openai']);
  assert.deepEqual(current.models.providers['saw-openai'].models.map(m => m.id), ['gpt-4.1']);
  assert.equal(current.models.providers['saw-openai'].apiKey, '${OPENAI_API_KEY}');
  assert.deepEqual(current.tools, {deny:['*']});
  console.log(JSON.stringify({legacyReplacementRestored, nativePublicationRetainedExactModel:true,
    metadataPreserved:true, credentialReferencePreserved:true, staleManagedFieldsRemoved:true, providerRequests:0}));
} finally {
  rmSync(directory, {recursive:true, force:true});
}
