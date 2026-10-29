// Shared by the daily-briefing MCP servers: a minimal MCP server over stdio
// (newline-delimited JSON-RPC, no dependencies), and the briefing store in
// /sandbox/briefing: per-source state for the day, and <day>/items.jsonl
// with every message collected that day.
import { appendFileSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { rootCertificates } from "node:tls";

export const ROOT = process.env.BRIEFING_DIR || "/sandbox/briefing";
const TEXT_LIMIT = 500;
const MAX_PAGES = 200;

export function today() {
  const now = new Date();
  const start = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  return { day: now.toLocaleDateString("sv-SE"), startSec: Math.floor(start.getTime() / 1000) };
}

export function loadState(source, day, empty) {
  try {
    const state = JSON.parse(readFileSync(join(ROOT, `state-${source}.json`), "utf8"));
    if (state.day === day) return state;
  } catch {}
  return { day, ...empty };
}

export function saveState(source, state) {
  mkdirSync(ROOT, { recursive: true });
  const file = join(ROOT, `state-${source}.json`);
  writeFileSync(`${file}.tmp`, JSON.stringify(state, null, 2));
  renameSync(`${file}.tmp`, file);
}

export function appendItems(day, items) {
  const dir = join(ROOT, day);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, "items.jsonl");
  appendFileSync(file, items.map((i) => JSON.stringify(i) + "\n").join(""));
  return file;
}

export function clip(text) {
  const t = String(text || "").replace(/\s+/g, " ").trim();
  return t.length > TEXT_LIMIT ? t.slice(0, TEXT_LIMIT) + "…" : t;
}

// Keep test and live page sizes small when needed, while never exceeding the
// provider API's maximum page size.
export function pageSize(max) {
  const n = Number(process.env.BRIEFING_PAGE_SIZE);
  return Number.isInteger(n) && n > 0 ? Math.min(n, max) : max;
}

// Follow a provider cursor until the complete list has arrived. A malformed
// pagination response is an error: callers must not advance their saved
// position after only a partial read.
export async function drain(fetchPage) {
  const used = new Set();
  let cursor = "";
  for (let page = 0; page < MAX_PAGES; page++) {
    const next = await fetchPage(cursor);
    if (!next) return;
    if (used.has(next)) throw new Error("pagination cursor repeated");
    used.add(next);
    cursor = next;
  }
  throw new Error(`more than ${MAX_PAGES} pages; position not advanced`);
}

// The sandbox's egress proxy re-signs TLS with OpenShell's CA. The server
// trusts it itself, from the file OpenShell mounts in every sandbox, rather
// than relying on NODE_EXTRA_CA_CERTS reaching it through OpenClaw (found
// live on 2026.9.2: SELF_SIGNED_CERT_IN_CHAIN even with it in mcp.json).
export const PROXY_CA = "/run/openshell-supervisor-ca/material/ca.crt";
let trusted;
function trustedRoots() {
  if (trusted === undefined) {
    trusted = null;     // no proxy CA (outside a sandbox): Node's roots only
    for (const file of [process.env.BRIEFING_PROXY_CA, process.env.NODE_EXTRA_CA_CERTS, PROXY_CA]) {
      if (!file) continue;
      try {
        trusted = [...rootCertificates, readFileSync(file, "utf8")];
        break;
      } catch {}
    }
  }
  return trusted;
}

// GET with the placeholder token; the sandbox proxy puts the real one in.
export function getJson(url, token) {
  const u = new URL(url);
  const lib = u.protocol === "http:" ? http : https;
  const ca = u.protocol === "https:" ? trustedRoots() : null;
  return new Promise((resolve, reject) => {
    const req = lib.get(u, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      timeout: 20000,
      ...(ca ? { ca } : {}),
    }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        let body;
        try { body = JSON.parse(data); } catch { body = {}; }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`HTTP ${res.statusCode} ${body.error?.message || body.error || ""}`.trim()));
        } else {
          resolve(body);
        }
      });
    });
    req.on("timeout", () => req.destroy(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })));
    // serve() reports err.cause.code first: keep codes such as
    // SELF_SIGNED_CERT_IN_CHAIN or ECONNREFUSED visible.
    req.on("error", (err) => reject(Object.assign(new Error(err.message), { cause: err })));
  });
}

// tools: [{name, description, inputSchema, run: async (args) => result}]
export function serve(name, tools) {
  const out = (msg) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...msg }) + "\n");
  createInterface({ input: process.stdin }).on("line", async (line) => {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    if (msg.id === undefined) return;               // notifications need no answer
    if (msg.method === "initialize") {
      out({ id: msg.id, result: {
        protocolVersion: msg.params?.protocolVersion || "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name, version: "0.1.0" },
      } });
    } else if (msg.method === "tools/list") {
      out({ id: msg.id, result: { tools: tools.map(({ run, ...t }) => t) } });
    } else if (msg.method === "tools/call") {
      const tool = tools.find((t) => t.name === msg.params?.name);
      if (!tool) return out({ id: msg.id, error: { code: -32602, message: `unknown tool ${msg.params?.name}` } });
      try {
        const result = await tool.run(msg.params?.arguments || {});
        out({ id: msg.id, result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] } });
      } catch (err) {
        // A proxy denial shows up here (EACCES, HTTP 403): report it as is.
        const text = `error: ${err?.cause?.code || err?.message || err}`;
        out({ id: msg.id, result: { isError: true, content: [{ type: "text", text }] } });
      }
    } else if (msg.method === "ping") {
      out({ id: msg.id, result: {} });
    } else {
      out({ id: msg.id, error: { code: -32601, message: `method not found: ${msg.method}` } });
    }
  });
}
