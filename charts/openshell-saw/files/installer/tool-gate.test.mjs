import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  appendAudit,
  decide,
  evaluateToolCall,
  hookResult,
  parseIdentity,
  parsePolicy,
  resolutionRecord,
} from "./tool-gate.mjs";
import toolGatePlugin from "./tool-gate-plugin.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const policyText = readFileSync(path.join(here, "../../../governance-policy/tool-actions.yaml"), "utf8");
const identity = {
  username: "alice",
  subject: "subject-alice",
  sandbox: "notebook",
  workspace: "default",
};

test("the mounted plugin loads and registers its hook without a writable SDK link", () => {
  const events = [];
  toolGatePlugin.register({ on: (name, handler) => events.push([name, handler]) });
  assert.equal(toolGatePlugin.id, "saw-tool-gate");
  assert.equal(events.length, 1);
  assert.equal(events[0][0], "before_tool_call");
  assert.equal(typeof events[0][1], "function");
});

function call(overrides = {}) {
  return decide({
    policyText,
    identity,
    toolName: "exec",
    params: { command: "git status" },
    sessionKey: "session-1",
    now: "2026-10-05T00:00:00Z",
    ...overrides,
  });
}

test("the consequential set is the policy file, not the gate source", () => {
  const source = readFileSync(path.join(here, "tool-gate.mjs"), "utf8");
  assert.equal(source.includes("git push"), false);
  assert.equal(source.includes("saw-denied-tool"), false);
  const policy = parsePolicy(policyText);
  assert.deepEqual(policy.rules.map((rule) => rule.id), [
    "exec-consequential", "exec-git-status", "exec-git-diff", "exec-git-log", "exec-git-show",
    "exec-briefing-cron-list", "exec-briefing-cron-change", "tool-search", "tool-call",
    "slack-new-messages", "slack-channels", "gmail-new-messages", "briefing-save",
    "read", "memory-search", "memory-get", "session-status", "sessions-list", "sessions-history",
    "message-send", "saw-denied-tool",
  ]);
  assert.equal(policy.defaultAction, "deny");
  const installerCopy = readFileSync(path.join(here, "tool-actions.yaml"), "utf8");
  assert.equal(installerCopy, policyText);
});

test("an ordinary tool call is allowed and audited with the user and task", () => {
  const decided = call({ taskTitle: "fix egress" });
  assert.equal(decided.effect.kind, "allow");
  assert.equal(decided.record.decision, "allow");
  assert.equal(decided.record.rule, "exec-git-status");
  assert.deepEqual(decided.record.user, { username: "alice", subject: "subject-alice" });
  assert.deepEqual(decided.record.task, { id: "session-1", title: "fix egress" });
  assert.equal(decided.record.sandbox, "notebook");
  assert.equal(decided.record.workspace, "default");
  assert.equal(hookResult(decided, () => {}), undefined);
});

test("a consequential exec does not execute until approval", () => {
  for (const command of ["git push origin main", "gh pr merge 1", "rm -rf /tmp/x", "kubectl delete pod x", "oc delete pod x"]) {
    const decided = call({ params: { command } });
    assert.equal(decided.effect.kind, "approval", command);
    assert.equal(decided.record.decision, "approval_required");
    assert.equal(decided.record.rule, "exec-consequential");
    assert.equal(decided.record.user.username, "alice");
    assert.equal(decided.record.task.id, "session-1");
    const hook = hookResult(decided, () => {});
    assert.equal(hook.block, undefined);
    assert.equal(hook.requireApproval.pluginId, "saw-tool-gate");
    assert.ok(hook.requireApproval.allowedDecisions.includes("deny"));
  }
  assert.equal(call({ params: { command: "echo rm foo" } }).effect.kind, "deny");
});

test("a denied tool does not execute", () => {
  const decided = call({ toolName: "saw-denied-tool", params: {} });
  assert.equal(decided.effect.kind, "deny");
  assert.equal(decided.record.decision, "deny");
  assert.equal(decided.record.rule, "saw-denied-tool");
  assert.deepEqual(decided.record.user, { username: "alice", subject: "subject-alice" });
  assert.equal(decided.record.task.id, "session-1");
  const hook = hookResult(decided, () => {});
  assert.equal(hook.block, true);
  assert.equal(hook.requireApproval, undefined);
});

test("message sends require approval", () => {
  const decided = call({ toolName: "message", params: { action: "send" } });
  assert.equal(decided.effect.kind, "approval");
  assert.equal(decided.record.rule, "message-send");
});

test("briefing discovery and exact read/write targets have named allows", () => {
  for (const toolName of ["tool_search", "tool_call", "slack-reader__new_messages",
    "slack-reader__channels", "gmail-reader__new_messages", "briefing-writer__save_briefing"]) {
    const result = call({ toolName, params: {} });
    assert.equal(result.effect.kind, "allow", toolName);
    assert.notEqual(result.record.rule, "default", toolName);
  }
  // Runtime evidence verifies OpenClaw re-enters the hook for the target;
  // that second decision still denies every target without a named allow.
  for (const toolName of ["write", "slack-reader__post_message", "gmail-reader__send_message",
    "briefing-writer__write_file", "tool_search_code", "unknown-tool"]) {
    const result = call({ toolName, params: {} });
    assert.equal(result.effect.kind, "deny", toolName);
    assert.equal(result.record.rule, "default", toolName);
  }
});

test("briefing cron inspection is allowed but schedule changes require approval", () => {
  assert.equal(call({ params: { command: "openclaw cron list --json" } }).record.rule,
    "exec-briefing-cron-list");
  for (const command of [
    "openclaw cron add --name daily-briefing --every 5m --session isolated --message 'Update my daily briefing.'",
    "openclaw cron rm job-id",
  ]) {
    const result = call({ params: { command } });
    assert.equal(result.effect.kind, "approval", command);
    assert.equal(result.record.rule, "exec-briefing-cron-change", command);
  }
  for (const command of ["openclaw cron run job-id", "openclaw cron listx", "openclaw cron rm-all"]) {
    assert.equal(call({ params: { command } }).effect.kind, "deny", command);
  }
  for (const command of [
    "openclaw cron add --name daily-briefing; rm -rf /",
    "openclaw cron list --json && rm -rf /",
    "sh -c 'openclaw cron add --name daily-briefing'",
  ]) {
    const result = call({ params: { command } });
    assert.equal(result.effect.kind, "deny", command);
    assert.equal(result.record.rule, "exec-opaque", command);
  }
});

test("a call with no current task is blocked and still names the user", () => {
  const decided = call({ sessionKey: "", sessionId: "" });
  assert.equal(decided.effect.kind, "deny");
  assert.equal(decided.record.decision, "deny");
  assert.equal(decided.record.rule, "no-task");
  assert.deepEqual(decided.record.task, { id: null, title: null });
  assert.equal(decided.record.user.username, "alice");
  assert.equal(hookResult(decided, () => {}).block, true);
});

test("a missing or invalid policy fails closed", () => {
  for (const policyText of ["", "version: 1\ndefaultAction: allow\nrules:\n  - id: x\n    tool: exec\n    action: maybe\n"]) {
    const decided = call({ policyText });
    assert.equal(decided.record.decision, "deny");
    assert.equal(decided.record.rule, "policy-invalid");
    assert.equal(decided.record.user.username, "alice");
    assert.equal(decided.record.task.id, null);
    assert.equal(hookResult(decided, () => {}).block, true);
  }
});

test("a call with no recorded user does not execute", () => {
  const decided = call({ identity: null });
  assert.equal(decided.record.rule, "identity-missing");
  assert.equal(decided.effect.kind, "deny");
  assert.deepEqual(decided.record.user, { username: "", subject: "" });
});

test("approval resolution is recorded with the same user and task", () => {
  const decided = call({ params: { command: "git push" } });
  const approved = resolutionRecord(decided.record, "allow-once", "2026-10-05T00:01:00Z");
  assert.equal(approved.decision, "approved");
  assert.deepEqual(approved.user, decided.record.user);
  assert.deepEqual(approved.task, decided.record.task);
  assert.equal(approved.approval.mode, "openclaw-requireApproval");
  for (const resolution of ["deny", "timeout", "cancelled", "allow-always"]) {
    const record = resolutionRecord(decided.record, resolution);
    assert.equal(record.decision, resolution === "allow-always" ? "approved" : "rejected");
    assert.equal(record.user.subject, "subject-alice");
    assert.equal(record.task.id, "session-1");
  }
});

function assertAuditShape(record) {
  assert.equal(typeof record.time, "string");
  assert.match(record.time, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(typeof record.user.username, "string");
  assert.equal(typeof record.user.subject, "string");
  assert.ok(Object.prototype.hasOwnProperty.call(record.task, "id"));
  assert.equal(typeof record.sandbox, "string");
  assert.equal(typeof record.workspace, "string");
  assert.equal(typeof record.tool, "string");
  assert.equal(typeof record.rule, "string");
  assert.ok(record.policyHash === null || /^sha256:[0-9a-f]{64}$/.test(record.policyHash));
  assert.match(record.argsDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(typeof record.summary, "string");
  assert.ok(["allow", "deny", "approval_required", "approved", "rejected"].includes(record.decision));
}

function auditFile() {
  const dir = path.join(mkdtempSync(path.join(tmpdir(), "saw-tool-gate-")), "audit");
  mkdirSync(dir);
  return path.join(dir, "tool-actions.jsonl");
}

function readAudit(file) {
  return readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

test("username and subject are both attached when the subject is set", () => {
  const decided = call();
  assert.deepEqual(decided.record.user, { username: "alice", subject: "subject-alice" });
  assertAuditShape(decided.record);
});

test("sessionKey and sessionId each map to task.id", () => {
  assert.equal(call({ sessionKey: "key-1", sessionId: "" }).record.task.id, "key-1");
  const bySession = call({ sessionKey: "", sessionId: "sess-9" });
  assert.equal(bySession.record.task.id, "sess-9");
  assert.equal(bySession.record.task.title, "sess-9");
  assert.equal(bySession.record.decision, "allow");
});

test("a missing session id blocks the call and is logged with a null task", () => {
  const file = auditFile();
  const result = evaluateToolCall({
    policyText,
    identity,
    toolName: "exec",
    params: { command: "git status" },
    sessionKey: "",
    sessionId: "",
    now: "2026-10-05T00:00:00Z",
    auditFile: file,
  });
  assert.equal(result.hook.block, true);
  assert.equal(result.record.decision, "deny");
  assert.deepEqual(result.record.task, { id: null, title: null });
  assert.equal(result.record.user.username, "alice");
  const [line] = readAudit(file);
  assert.equal(line.decision, "deny");
  assert.equal(line.task.id, null);
  assertAuditShape(line);
});

test("git status is allowed and git push or rm -rf require approval", () => {
  const status = call({ params: { command: "git status" } });
  assert.equal(status.record.decision, "allow");
  assert.equal(status.record.rule, "exec-git-status");
  assert.equal(hookResult(status, () => {}), undefined);

  for (const command of ["git push", "rm -rf /tmp/probe"]) {
    const decided = call({ params: { command } });
    const hook = hookResult(decided, () => {});
    assert.equal(decided.record.decision, "approval_required", command);
    assert.equal(hook.block, undefined, command);
    assert.equal(typeof hook.requireApproval.title, "string");
    assert.equal(hook.requireApproval.onResolution === undefined, false);
  }
});

test("read is explicitly allowed; an unknown tool is denied", () => {
  const decided = call({ toolName: "read", params: { path: "/sandbox/notes.txt" } });
  assert.equal(decided.effect.kind, "allow");
  assert.equal(decided.record.decision, "allow");
  assert.equal(decided.record.rule, "read");
  assert.equal(decided.record.tool, "read");
  assertAuditShape(decided.record);
  assert.equal(call({ toolName: "unknown" }).record.rule, "default");
  assert.equal(call({ toolName: "write" }).effect.kind, "deny");
});

test("a missing or invalid policy file is denied and written to the audit log", () => {
  for (const policyText of [null, "", "version: [\n", "not: yaml: :"]) {
    const file = auditFile();
    const result = evaluateToolCall({
      policyText,
      identity,
      toolName: "exec",
      params: { command: "git status" },
      sessionKey: "session-1",
      now: "2026-10-05T00:00:00Z",
      auditFile: file,
    });
    assert.equal(result.hook.block, true);
    assert.equal(result.record.decision, "deny");
    assert.equal(result.record.rule, "policy-invalid");
    const [line] = readAudit(file);
    assert.equal(line.decision, "deny");
    assert.equal(line.rule, "policy-invalid");
    assertAuditShape(line);
  }
});

test("a missing or corrupted identity file blocks execution", () => {
  assert.equal(parseIdentity(""), null);
  assert.equal(parseIdentity("{not json"), null);
  assert.equal(parseIdentity("[]"), null);
  for (const identityText of [undefined, "", "{not json", "[]"]) {
    const file = auditFile();
    const result = evaluateToolCall({
      policyText,
      identityText,
      toolName: "exec",
      params: { command: "git status" },
      sessionKey: "session-1",
      now: "2026-10-05T00:00:00Z",
      auditFile: file,
    });
    assert.equal(result.hook.block, true);
    assert.equal(result.record.decision, "deny");
    assert.equal(result.record.rule, "identity-missing");
    assert.deepEqual(result.record.user, { username: "", subject: "" });
    assert.equal(readAudit(file)[0].decision, "deny");
  }
});

test("approval, rejection, cancel, and timeout are logged and do not execute", () => {
  const file = auditFile();
  const result = evaluateToolCall({
    policyText,
    identity,
    toolName: "exec",
    params: { command: "git push origin main" },
    sessionKey: "session-1",
    now: "2026-10-05T00:00:00Z",
    auditFile: file,
  });
  assert.equal(result.record.decision, "approval_required");
  assert.equal(result.hook.block, undefined);
  assert.ok(result.hook.requireApproval);
  result.hook.requireApproval.onResolution("allow-once");
  const again = evaluateToolCall({
    policyText,
    identity,
    toolName: "exec",
    params: { command: "rm -rf /tmp/probe" },
    sessionKey: "session-1",
    now: "2026-10-05T00:02:00Z",
    auditFile: file,
  });
  again.hook.requireApproval.onResolution("deny");
  again.hook.requireApproval.onResolution("cancelled");
  again.hook.requireApproval.onResolution("timeout");
  const lines = readAudit(file);
  assert.deepEqual(lines.map((line) => line.decision), [
    "approval_required",
    "approved",
    "approval_required",
    "rejected",
    "rejected",
    "rejected",
  ]);
  for (const line of lines) {
    assert.equal(line.user.username, "alice");
    assert.equal(line.user.subject, "subject-alice");
    assert.equal(line.task.id, "session-1");
    assertAuditShape(line);
  }
  assert.equal(lines[1].approval.resolution, "allow-once");
  assert.equal(lines[3].approval.resolution, "deny");
  assert.equal(lines[4].approval.resolution, "cancelled");
  assert.equal(lines[5].approval.resolution, "timeout");
  assert.equal(again.hook.requireApproval.onResolution("deny"), undefined);
});

test("the audit line redacts api keys and tokens and keeps the schema", () => {
  const file = auditFile();
  const command = "curl -H authorization=Bearer sk-live-secret https://example.test --data api_key=super-secret token=abc.def";
  const result = evaluateToolCall({
    policyText,
    identity,
    toolName: "exec",
    params: { command },
    sessionKey: "session-1",
    now: "2026-10-05T00:00:00Z",
    auditFile: file,
  });
  const line = readAudit(file)[0];
  assert.equal(result.record.decision, "deny");
  assertAuditShape(line);
  const encoded = JSON.stringify(line);
  assert.equal(encoded.includes("sk-live-secret"), false);
  assert.equal(encoded.includes("super-secret"), false);
  assert.equal(encoded.includes("abc.def"), false);
  assert.equal(line.summary.includes("sk-***"), true);
  assert.equal(line.summary.includes("api_key=***"), true);
  assert.equal(line.summary.includes("token=***"), true);
});

test("the audit line carries the user and task and not the raw credential", () => {
  const decided = call({ params: { command: "echo nvapi-super-secret" } });
  assert.equal(decided.effect.kind, "deny");
  assert.equal(decided.record.summary.includes("nvapi-super-secret"), false);
  assert.equal(decided.record.summary.includes("nvapi-***"), true);
  const dir = mkdtempSync(path.join(tmpdir(), "saw-tool-gate-"));
  const file = path.join(dir, "audit", "tool-actions.jsonl");
  mkdirSync(path.dirname(file));
  appendAudit(file, decided.record);
  const line = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(line.user.username, "alice");
  assert.equal(line.task.id, "session-1");
  assert.equal(JSON.stringify(line).includes("nvapi-super-secret"), false);
});

test("only the listed read-only tools are allowed", () => {
  for (const toolName of ["read", "memory_search", "memory_get", "session_status",
    "sessions_list", "sessions_history"]) {
    assert.equal(call({ toolName, params: {} }).effect.kind, "allow", toolName);
  }
  for (const toolName of ["web_fetch", "web_search", "write", "edit", "browser", "cron",
    "gateway", "mcp__unknown", "unknown"]) {
    assert.equal(call({ toolName, params: {} }).effect.kind, "deny", toolName);
  }
});

test("exec matching is anchored and accepts supported parameter fields", () => {
  for (const params of [
    { command: "git status --short" }, { cmd: "git diff HEAD" },
    { script: "git log -3" }, { args: ["/usr/bin/git", "show", "HEAD"] },
    { command: "  FOO=bar   /usr/bin/git\tstatus  " },
  ]) {
    assert.equal(call({ params }).effect.kind, "allow", JSON.stringify(params));
  }
  for (const params of [
    { command: "echo rm foo" }, { command: "git statusful" },
    { command: "git push; git status" }, { command: "curl https://example.test" },
  ]) {
    assert.equal(call({ params }).effect.kind, "deny", JSON.stringify(params));
  }
  for (const params of [{ command: "/bin/rm -rf /tmp" }, { command: "rm\t-rf /tmp" }]) {
    assert.equal(call({ params }).effect.kind, "approval", JSON.stringify(params));
  }
});

test("unreadable and opaque exec calls fail closed before policy matching", () => {
  for (const params of [{}, { command: "  " }, { args: [] }]) {
    assert.equal(call({ params }).record.rule, "exec-unreadable");
  }
  for (const command of ["sh -c 'git push'", "bash -c 'git status'", "git status; rm -rf /",
    "git status && rm -rf /", "git status | cat", "git status\nrm -rf /",
    "env git status", "sudo git status", "node -e 'process.exit()'",
    "git diff --output=/tmp/written", "GIT_EXTERNAL_DIFF=/tmp/evil git diff",
    "PATH=/tmp/evil git status"]) {
    assert.equal(call({ params: { command } }).record.rule, "exec-opaque", command);
  }
  assert.equal(call({ params: { command: "git status", script: "rm -rf /" } }).record.rule,
    "exec-opaque");
});

test("incomplete identity and policy hash mismatch deny with audit fields", () => {
  for (const identity of [{}, { username: "" }, { username: "alice", subject: "" }]) {
    const decided = call({ identity });
    assert.equal(decided.record.rule, "identity-missing");
    assertAuditShape(decided.record);
  }
  const changed = call({ expectedPolicyHash: "sha256:" + "0".repeat(64) });
  assert.equal(changed.record.rule, "policy-hash");
  assert.equal(changed.effect.kind, "deny");
  assertAuditShape(changed.record);
  assert.notEqual(changed.record.policyHash, "sha256:" + "0".repeat(64));
});

test("an unavailable audit file blocks an otherwise allowed call", () => {
  const missing = path.join(mkdtempSync(path.join(tmpdir(), "saw-tool-gate-")), "missing", "log");
  const result = evaluateToolCall({ policyText, identity, toolName: "read", params: {},
    sessionKey: "session-1", auditFile: missing });
  assert.equal(result.record.decision, "deny");
  assert.equal(result.record.rule, "audit-unwritable");
  assert.equal(result.hook.block, true);
});
