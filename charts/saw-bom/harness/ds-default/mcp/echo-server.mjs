// Sample MCP server over stdio (newline-delimited JSON-RPC), no dependencies.
// Tool: mcp_echo. It shows how a harness bundle ships an MCP server in
// mcp.json; replace it with real servers (stdio, or streamable-http with a
// url the sandbox's governance profile allows).
import { createInterface } from "node:readline";

const TOOLS = [{
  name: "mcp_echo",
  description: "Echo a message back (SAW harness MCP sample).",
  inputSchema: {
    type: "object",
    properties: { message: { type: "string" } },
    required: ["message"],
  },
}];

function reply(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}

function fail(id, code, message) {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n");
}

createInterface({ input: process.stdin }).on("line", (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.id === undefined) return;               // notifications need no answer
  if (msg.method === "initialize") {
    reply(msg.id, {
      protocolVersion: msg.params?.protocolVersion || "2025-06-18",
      capabilities: { tools: {} },
      serverInfo: { name: "saw-mcp-echo", version: "0.1.0" },
    });
  } else if (msg.method === "tools/list") {
    reply(msg.id, { tools: TOOLS });
  } else if (msg.method === "tools/call") {
    const text = `saw-mcp-echo: ${msg.params?.arguments?.message ?? ""}`;
    reply(msg.id, { content: [{ type: "text", text }] });
  } else if (msg.method === "ping") {
    reply(msg.id, {});
  } else {
    fail(msg.id, -32601, `method not found: ${msg.method}`);
  }
});
