// Uses treeFiles and mountOptions from the tool-gate preflight in the same startup command.
const harness = HARNESS_SPEC;
const harnessRoot = '/sandbox/harness';
if (!mountOptions(harnessRoot).includes('ro')) throw Error('harness must have a read-only mount');
const harnessHash = crypto.createHash('sha256');
for (const path of treeFiles(harnessRoot).sort()) {
  const hash = crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex');
  harnessHash.update(path.slice(harnessRoot.length + 1) + '\0' + hash + '\n');
}
if ('sha256:' + harnessHash.digest('hex') !== harness.digest) throw Error('harness digest mismatch');
config.plugins.load.paths.push(...harness.paths);
config.plugins.allow.push(...harness.plugins);
if (harness.skills.length) config.skills = {load: {extraDirs: harness.skills}};
for (const entry of Object.values(harness.servers)) {
  if (!entry.command) continue;
  for (const name of harness.trustEnv)
    if (process.env[name]) entry.env[name] = '${' + name + '}';
}
config.tools.allow.push(...harness.tools);
config.channels = {...config.channels, slack: {enabled: false}};
config.mcp = {servers: harness.servers};
