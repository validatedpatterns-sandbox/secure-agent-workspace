import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
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

const here = path.dirname(fileURLToPath(import.meta.url));
const policyText = readFileSync(path.join(here, "../../../governance-policy/tool-actions.yaml"), "utf8");
const identity = {
  username: "alice",
  subject: "subject-alice",
  sandbox: "notebook",
  workspace: "default",
};

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
    "exec-consequential",
    "message-send",
    "saw-denied-tool",
  ]);
  assert.equal(policy.defaultAction, "allow");
  const installerCopy = readFileSync(path.join(here, "tool-actions.yaml"), "utf8");
  assert.equal(installerCopy, policyText);
});

test("an ordinary tool call is allowed and audited with the user and task", () => {
  const decided = call({ taskTitle: "fix egress" });
  assert.equal(decided.effect.kind, "allow");
  assert.equal(decided.record.decision, "allow");
  assert.equal(decided.record.rule, "default");
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
  assert.equal(call({ params: { command: "echo rm" } }).effect.kind, "allow");
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
  assert.match(record.argsDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(typeof record.summary, "string");
  assert.ok(["allow", "deny", "approval_required", "approved", "rejected"].includes(record.decision));
}

function auditFile() {
  return path.join(mkdtempSync(path.join(tmpdir(), "saw-tool-gate-")), "audit", "tool-actions.jsonl");
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
  assert.equal(status.record.rule, "default");
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

test("an unknown tool uses defaultAction allow and is still audited", () => {
  const decided = call({ toolName: "read", params: { path: "/sandbox/notes.txt" } });
  assert.equal(decided.effect.kind, "allow");
  assert.equal(decided.record.decision, "allow");
  assert.equal(decided.record.rule, "default");
  assert.equal(decided.record.tool, "read");
  assertAuditShape(decided.record);
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
  assert.equal(result.record.decision, "allow");
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
  assert.equal(decided.effect.kind, "allow");
  assert.equal(decided.record.summary.includes("nvapi-super-secret"), false);
  assert.equal(decided.record.summary.includes("nvapi-***"), true);
  const dir = mkdtempSync(path.join(tmpdir(), "saw-tool-gate-"));
  const file = path.join(dir, "audit", "tool-actions.jsonl");
  appendAudit(file, decided.record);
  const line = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(line.user.username, "alice");
  assert.equal(line.task.id, "session-1");
  assert.equal(JSON.stringify(line).includes("nvapi-super-secret"), false);
});
