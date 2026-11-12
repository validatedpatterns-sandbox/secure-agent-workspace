set -eu
umask 077
export HOME=/sandbox/workspace OPENCLAW_HOME=/sandbox/workspace
export OPENCLAW_CONFIG_PATH=/sandbox/workspace/.openclaw/openclaw.json
export TMPDIR=/sandbox/workspace/.openclaw/state SQLITE_TMPDIR=/sandbox/workspace/.openclaw/state
mkdir -p "$TMPDIR"
# Only the stock gateway's injected placeholder is visible here. Keep its
# environment reference in the config so the supervisor can rotate it.
node - "$1" <<'JS'
const fs = require('node:fs');
const crypto = require('node:crypto');
const model = process.argv[2];
const config = {
  gateway: {mode: 'local', bind: 'loopback', port: 18789,
            auth: {mode: 'token', token: crypto.randomBytes(32).toString('hex')}},
  models: {providers: {@SAW_PROVIDER_KEY@: {baseUrl: @SAW_BASE_URL@,
    @SAW_TIMEOUT@api: '@SAW_API@', apiKey: '${@SAW_KEY_ENV@}',
    models: [{id: model, name: model}]}}},
  agents: {defaults: {model: {primary: '@SAW_PROVIDER_ID@/' + model},
    workspace: '/sandbox/workspace/project'}},
  tools: {deny: ['*']}
};
@SAW_BROWSER_CONFIG@
const target = process.env.OPENCLAW_CONFIG_PATH;
// Remove previously managed harness/gate capabilities when absent from this
// approved startup. Do this after the preflights, never before their checks.
for (const [path, empty] of Object.entries({
  plugins:{allow:[], load:{paths:[]}, entries:{}}, skills:{load:{extraDirs:[]}},
  channels:{}, mcp:{servers:{}}
})) config[path] ??= empty;
// Publish complete managed subtrees with the stock writer. Replacing the config
// directly loses its metadata and triggers restoration of the previous backup.
const batch = target + '.saw-managed';
const tmp = batch + '.' + crypto.randomUUID();
fs.writeFileSync(tmp, JSON.stringify(Object.entries(config).map(([path, value]) => ({path, value}))),
                 {flag: 'wx', mode: 0o600});
fs.renameSync(tmp, batch);
JS
openclaw config set --batch-file "$OPENCLAW_CONFIG_PATH.saw-managed"
rm -f "$OPENCLAW_CONFIG_PATH.saw-managed"
exec openclaw gateway run --bind loopback --port 18789
