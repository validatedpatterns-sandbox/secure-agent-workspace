import fs from 'node:fs';
import https from 'node:https';
import {createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';

const db = new DatabaseSync('/history/audit.db');
db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
  CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS records(seq INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, body TEXT NOT NULL,
    received TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`);
const getKey = db.prepare("SELECT value FROM metadata WHERE key='signing-key'");
if (!getKey.get()) {
  const key = generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'});
  db.prepare("INSERT OR IGNORE INTO metadata VALUES ('signing-key',?)").run(key);
}
const signer = createPrivateKey(getKey.get().value);
const identity = JSON.parse(process.env.IDENTITY);
const pub = createPublicKey(signer).export({type:'spki',format:'der'}).toString('base64');
console.log('receipt-public-key=' + pub);
const insert = db.prepare('INSERT OR IGNORE INTO records(id, body) VALUES (?, ?)');
const lookup = db.prepare('SELECT body FROM records WHERE id=?');
const tls = () => ({cert:fs.readFileSync('/tls/tls.crt'), key:fs.readFileSync('/tls/tls.key')});
const server = https.createServer(tls(), async (req,res) => {
  const reply = (status,text='') => {res.writeHead(status);res.end(text);};
  if (req.method === 'GET' && req.url === '/v1/receipt-key') return reply(200, pub);
  const match = /^\/v1\/records\/([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/.exec(req.url);
  if (!match || req.method !== 'POST') return reply(404);
  try {
    const parts = []; let size=0;
    for await (const part of req) {
      size += part.length;
      if (size > 16384) return reply(413);
      parts.push(part);
    }
    const body = Buffer.concat(parts).toString('utf8');
    let record;
    try {record=JSON.parse(body);} catch {return reply(400);}
    if (record?.user?.subject !== identity.subject || record?.user?.username !== identity.username ||
        record.workspace !== identity.workspace || record.sandbox !== identity.sandbox ||
        !['allow','deny','approval_required','approved','rejected'].includes(record.decision) ||
        !/^sha256:[0-9a-f]{64}$/.test(record.argsDigest)) return reply(422);
    const id = match[1];
    // Each insert is an autocommit SQLite transaction with synchronous=FULL.
    insert.run(id,body);
    if (lookup.get(id).body !== body) return reply(409);
    const hash = createHash('sha256').update(body).digest('hex');
    reply(201,sign(null, Buffer.from('saw-audit-v1:'+id+':'+hash), signer).toString('base64'));
  } catch { if (!res.headersSent) reply(503); }
});
server.requestTimeout=10000;
server.listen(8443,'0.0.0.0');

// OpenShift rotates the projected certificate while the history claim stays mounted.
setInterval(() => {
  try {server.setSecureContext(tls());} catch {console.error("cannot reload serving certificate");}
}, 60000).unref();
