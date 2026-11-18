// The controller substitutes the digest computed by the shared VM builder.
const root = '/sandbox/.saw/trusted';
const audit = '/sandbox/.saw/audit/tool-actions.jsonl';
const {O_APPEND, O_WRONLY, O_NOFOLLOW} = fs.constants;
function treeFiles(dir) {
  return fs.readdirSync(dir, {withFileTypes: true}).flatMap(entry => {
    const path = dir + '/' + entry.name;
    if (entry.isDirectory()) return treeFiles(path);
    if (!entry.isFile()) throw new Error('unexpected entry in trusted gate');
    return [path];
  });
}
function mountOptions(path) {
  const entry = fs.readFileSync('/proc/self/mountinfo', 'utf8').split('\n')
    .map(line => line.split(' ')).find(columns => columns[4] === path);
  if (!entry) throw new Error('missing dedicated mount at ' + path);
  return entry[5].split(',');
}
if (!mountOptions(root).includes('ro') || !mountOptions('/sandbox/.saw/audit').includes('rw'))
  throw new Error('incorrect tool gate or audit mount mode');
const digest = crypto.createHash('sha256');
for (const path of treeFiles(root).sort()) {
  const hash = crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex');
  digest.update(path.slice(root.length + 1) + '\0' + hash + '\n');
}
if ('sha256:' + digest.digest('hex') !== '@SAW_GATE_DIGEST@')
  throw new Error('tool gate does not match approved owner and policy');
if (!fs.lstatSync(audit).isFile()) throw new Error('audit trail must be a regular file');
fs.closeSync(fs.openSync(audit, O_WRONLY | O_APPEND | O_NOFOLLOW));
try {
  // No write and no truncation. A Linux append-only inode refuses this open.
  fs.closeSync(fs.openSync(audit, O_WRONLY | O_NOFOLLOW));
} catch (error) {
  if (error.code !== 'EPERM') throw error;
  config.plugins = {allow: ['saw-tool-gate'], load: {paths: [root + '/plugin']},
                    entries: {'saw-tool-gate': {enabled: true}}};
}
if (!config.plugins) throw new Error('audit trail permits non-append writes');
