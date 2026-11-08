import fs from "node:fs";
import {createHash, createPublicKey, randomUUID, verify} from "node:crypto";
// OpenClaw before_tool_call hook. Consequential tools come from
// tool-actions.yaml. This file does not list MCP servers or probe them.
import {
  AUDIT_PATH,
  IDENTITY_PATH,
  POLICY_PATH,
  TASK_PATH,
  evaluateToolCall,
  readJson,
  readText,
} from "./tool-gate.mjs";

// Replaced with the SHA-256 of the exact policy bytes when the host fills
// the read-only gate volume. No writable node_modules link is needed.
const EXPECTED_POLICY_HASH = "__SAW_POLICY_HASH__";

// The public key is compiled into the read-only plugin by the SAW bundle builder.
function submitAuditRecord(publicKey, record) {
  const directory = "/sandbox/.saw/audit";
  const id = randomUUID();
  const body = JSON.stringify(record);
  const fd = fs.openSync(directory + "/" + id + ".tmp", "wx", 0o600);
  try { fs.writeFileSync(fd, body); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(directory + "/" + id + ".tmp", directory + "/" + id + ".req");
  const directoryFd = fs.openSync(directory, fs.constants.O_DIRECTORY | fs.constants.O_RDONLY);
  try { fs.fsyncSync(directoryFd); } finally { fs.closeSync(directoryFd); }
  const hash = createHash("sha256").update(body).digest("hex");
  const challenge = Buffer.from("saw-audit-v1:" + id + ":" + hash);
  const key = createPublicKey({key:Buffer.from(publicKey, "base64"), format:"der", type:"spki"});
  const pause = new Int32Array(new SharedArrayBuffer(4));
  const receipt = directory + "/" + id + ".ack";
  const deadline = performance.now() + 5000;
  while (performance.now() < deadline) {
    let fd;
    try {
      fd = fs.openSync(receipt, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | fs.constants.O_NOFOLLOW);
      if (!fs.fstatSync(fd).isFile()) throw new Error("invalid audit receipt");
      const bytes = Buffer.alloc(89);
      const size = fs.readSync(fd, bytes, 0, bytes.length, 0);
      if (size !== 88 || !verify(null, challenge, key, Buffer.from(bytes.toString("ascii",0,size),"base64")))
        throw new Error("untrusted audit receipt");
      fs.unlinkSync(receipt);
      return;
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    } finally { if (fd !== undefined) fs.closeSync(fd); }
    Atomics.wait(pause,0,0,50);
  }
  throw new Error("audit writer did not acknowledge");
}

const receiptKey = "__SAW_AUDIT_KEY__";

export function handleBeforeToolCall(event, ctx) {
  const taskFile = readJson(TASK_PATH);
  const result = evaluateToolCall({
    policyText: readText(POLICY_PATH),
    expectedPolicyHash: EXPECTED_POLICY_HASH,
    identity: readJson(IDENTITY_PATH),
    taskTitle: taskFile && typeof taskFile.title === "string" ? taskFile.title : "",
    toolName: event && event.toolName,
    params: event && event.params,
    sessionKey: (ctx && ctx.sessionKey) || (event && event.sessionKey) || "",
    sessionId: (ctx && ctx.sessionId) || (event && event.sessionId) || "",
    auditFile: AUDIT_PATH,
    // OpenClaw catches callback exceptions and then permits the tool. End this
    // executor synchronously before it can act on an unacknowledged approval.
    unacknowledgedApproval: receiptKey.startsWith("MCowBQYDK2VwAyEA") ? () => process.exit(75) : undefined,
    appendRecord: receiptKey.startsWith("MCowBQYDK2VwAyEA") ? record => submitAuditRecord(receiptKey, record) : undefined,
  });
  return result.hook;
}

export default {
  id: "saw-tool-gate",
  name: "SAW tool gate",
  description: "Audit every tool call with the signed-in user and current task, and require approval before consequential tools run.",
  register(api) {
    api.on("before_tool_call", (event, ctx) => handleBeforeToolCall(event, ctx));
  },
};
