// Decision engine for the SAW tool-action gate. The OpenClaw plugin is a
// thin wrapper around this module so the policy can be tested without
// OpenClaw. Tool names live in tool-actions.yaml, not in this file.
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const POLICY_PATH = "/sandbox/.saw/trusted/tool-actions.yaml";
export const IDENTITY_PATH = "/sandbox/.saw/trusted/identity.json";
export const TASK_PATH = "/sandbox/.saw/current-task.json";
export const AUDIT_PATH = "/sandbox/.saw/audit/tool-actions.jsonl";

const ACTIONS = new Set(["allow", "deny", "approval"]);

function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === "#") return line.slice(0, i);
  }
  return line;
}

function parseScalar(raw) {
  const text = raw.trim();
  if (text.length >= 2 && ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'")))) {
    return text.slice(1, -1);
  }
  if (/^-?\d+$/.test(text)) return Number(text);
  return text;
}

function field(body) {
  const match = body.match(/^([A-Za-z][A-Za-z0-9]*):\s*(.*)$/);
  if (!match) throw new Error(`invalid policy line: ${body}`);
  return [match[1], match[2]];
}

export function parsePolicy(text) {
  if (typeof text !== "string" || !text.trim()) throw new Error("tool-action policy is empty");
  let version = null;
  let defaultAction = null;
  let sawRules = false;
  const rules = [];
  let current = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = stripComment(raw);
    if (!line.trim()) continue;
    const indent = line.match(/^ */)[0].length;
    if (indent !== line.length - line.trimStart().length) throw new Error("policy indentation must be spaces");
    const body = line.trim();
    if (indent === 0) {
      current = null;
      const [key, value] = field(body);
      if (key === "version") version = parseScalar(value);
      else if (key === "defaultAction") defaultAction = parseScalar(value);
      else if (key === "rules") {
        if (value !== "") throw new Error("rules must be a list");
        sawRules = true;
      } else throw new Error(`unknown policy field ${key}`);
      continue;
    }
    if (!sawRules) throw new Error("nested content before rules");
    if (indent === 6 && body.startsWith("- ")) {
      if (!current || !Array.isArray(current.whenCommandMatches)) {
        throw new Error("command match outside whenCommandMatches");
      }
      current.whenCommandMatches.push(String(parseScalar(body.slice(2))));
      continue;
    }
    if (indent === 2 && body.startsWith("- ")) {
      const [key, value] = field(body.slice(2).trim());
      current = { [key]: parseScalar(value) };
      rules.push(current);
      continue;
    }
    if (indent === 4) {
      if (!current) throw new Error("rule field outside a rule");
      const [key, value] = field(body);
      if (key === "whenCommandMatches") {
        if (value !== "") throw new Error("whenCommandMatches must be a list");
        current.whenCommandMatches = [];
      } else current[key] = parseScalar(value);
      continue;
    }
    throw new Error(`unsupported indentation ${indent}`);
  }
  if (version !== 1) throw new Error("tool-action policy version must be 1");
  if (!ACTIONS.has(defaultAction)) throw new Error("defaultAction must be allow, deny, or approval");
  const ids = new Set();
  for (const rule of rules) {
    if (typeof rule.id !== "string" || !rule.id) throw new Error("every rule needs an id");
    if (ids.has(rule.id)) throw new Error(`duplicate rule id ${rule.id}`);
    ids.add(rule.id);
    if (typeof rule.tool !== "string" || !rule.tool) throw new Error(`rule ${rule.id} needs a tool`);
    if (!ACTIONS.has(rule.action)) throw new Error(`rule ${rule.id} has an unknown action`);
    if (rule.whenCommandMatches !== undefined) {
      if (!Array.isArray(rule.whenCommandMatches) || rule.whenCommandMatches.length === 0) {
        throw new Error(`rule ${rule.id} has an empty whenCommandMatches`);
      }
      if (rule.whenCommandMatches.some((item) => typeof item !== "string" || item === "")) {
        throw new Error(`rule ${rule.id} has an empty command match`);
      }
    }
  }
  return { version, defaultAction, rules };
}

function redactString(value) {
  return value
    .replace(/nvapi-[A-Za-z0-9_-]+/g, "nvapi-***")
    .replace(/\bsk-[A-Za-z0-9_-]+/g, "sk-***")
    .replace(/(api[_-]?key|token|secret|password|authorization)\s*[:=]\s*\S+/gi, "$1=***");
}

function redact(value) {
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = redact(value[key]);
    return out;
  }
  return value;
}

export function commandText(params) {
  if (!params || typeof params !== "object") return "";
  const texts = ["command", "cmd", "script", "args"].map((key) => {
    const value = params[key];
    if (Array.isArray(value)) return value.every((part) => typeof part === "string") ? value.join(" ") : "\n";
    if (value === undefined || value === null) return "";
    return typeof value === "string" ? value : "\n";
  }).filter((value) => value.trim());
  // Distinct representations must not let a harmless field conceal a second
  // command. The newline makes the combined input opaque below.
  return [...new Set(texts)].join("\n");
}

function normalizedExec(command) {
  if (!command.trim()) return { error: "exec-unreadable" };
  if (/[;&|`\n\r<>]|\$\(|\$\{/.test(command)) return { error: "exec-opaque" };
  const words = command.trim().split(/\s+/);
  const assignments = [];
  while (words.length && /^[A-Za-z_][A-Za-z0-9_]*=\S*$/.test(words[0])) assignments.push(words.shift());
  if (!words.length) return { error: "exec-unreadable" };
  words[0] = path.posix.basename(words[0]).toLowerCase();
  // These assignments can change the executable or make an inspection call
  // invoke Git helpers. Other inert leading assignments are normalized away.
  if (assignments.some((item) => /^(?:GIT_|LD_|PATH=|NODE_OPTIONS=)/i.test(item))) {
    return { error: "exec-opaque" };
  }
  const wrappers = new Set(["sh", "bash", "dash", "zsh", "ksh", "busybox", "env", "xargs",
    "eval", "sudo", "command", "nice", "nohup", "time"]);
  if (wrappers.has(words[0]) || (["python", "python3", "perl", "ruby", "node"].includes(words[0])
      && words.slice(1).some((part) => part === "-c" || part === "-e"))) {
    return { error: "exec-opaque" };
  }
  if (words[0] === "git" && ["diff", "log", "show"].includes(words[1]) &&
      words.slice(2).some((part) => /^--(?:output|ext-diff|textconv)(?:=|$)/.test(part) || part === "-o")) {
    return { error: "exec-opaque" };
  }
  return { command: words.join(" ") };
}

function digest(params) {
  const encoded = JSON.stringify(redact(params && typeof params === "object" ? params : {}));
  return `sha256:${createHash("sha256").update(encoded).digest("hex")}`;
}

function summaryOf(tool, params) {
  const command = redactString(commandText(params)).replace(/\s+/g, " ").trim();
  const text = command ? `${tool} ${command}` : tool || "";
  return text.slice(0, 120);
}

function userOf(identity) {
  return {
    subject: identity && typeof identity.subject === "string" ? identity.subject : "",
    username: identity && typeof identity.username === "string" ? identity.username : "",
  };
}

function baseRecord(input, extras) {
  const identity = input.identity;
  return {
    time: input.now || new Date().toISOString(),
    user: userOf(identity),
    task: extras.task,
    sandbox: identity && typeof identity.sandbox === "string" ? identity.sandbox : "",
    workspace: identity && typeof identity.workspace === "string" ? identity.workspace : "",
    tool: typeof input.toolName === "string" ? input.toolName : "",
    rule: extras.rule,
    policyHash: extras.policyHash,
    argsDigest: digest(input.params),
    summary: summaryOf(typeof input.toolName === "string" ? input.toolName : "", input.params),
    decision: extras.decision,
  };
}

function effectFor(action, tool, ruleId) {
  if (action === "allow") return { kind: "allow" };
  if (action === "deny") {
    const why = ruleId === "default"
      ? `Tool ${tool} is denied by the default action`
      : `Tool ${tool} is denied by rule ${ruleId}`;
    return { kind: "deny", blockReason: why };
  }
  return {
    kind: "approval",
    approval: {
      title: `Approve ${tool}`,
      description: `Tool ${tool} matches ${ruleId} and needs approval before it runs.`,
      severity: "warning",
      timeoutMs: 120000,
      allowedDecisions: ["allow-once", "deny"],
    },
  };
}

function decisionName(action) {
  if (action === "approval") return "approval_required";
  return action;
}

function blocked(input, rule, reason, task = { id: null, title: null }) {
  return {
    record: baseRecord(input, {
      task,
      rule,
      policyHash: input.policyHash ?? null,
      decision: "deny",
    }),
    effect: { kind: "deny", blockReason: reason },
  };
}

function ruleMatches(rule, tool, command) {
  if (rule.tool !== tool) return false;
  if (!rule.whenCommandMatches) return true;
  return rule.whenCommandMatches.some((needle) => {
    const normalized = needle.toLowerCase().replace(/\s+/g, " ").trim();
    return command === normalized || command.startsWith(`${normalized} `);
  });
}

export function decide(input) {
  const tool = typeof input.toolName === "string" ? input.toolName : "";
  const policyHash = typeof input.policyText === "string"
    ? `sha256:${createHash("sha256").update(input.policyText, "utf8").digest("hex")}` : null;
  input = { ...input, policyHash };
  if (policyHash && input.expectedPolicyHash && policyHash !== input.expectedPolicyHash) {
    return blocked(input, "policy-hash", "Tool call blocked: tool-action policy hash changed");
  }
  let policy;
  try {
    policy = parsePolicy(input.policyText);
  } catch {
    return blocked(input, "policy-invalid", "Tool call blocked: tool-action policy is missing or invalid");
  }
  if (!input.identity || typeof input.identity !== "object" ||
      typeof input.identity.username !== "string" || !input.identity.username.trim() ||
      typeof input.identity.subject !== "string" || !input.identity.subject.trim()) {
    return blocked(input, "identity-missing", "Tool call blocked: signed-in user is not recorded");
  }
  if (!tool) return blocked(input, "no-tool", "Tool call blocked: the tool name is missing");
  const session = (typeof input.sessionKey === "string" && input.sessionKey)
    || (typeof input.sessionId === "string" && input.sessionId)
    || "";
  if (!session) return blocked(input, "no-task", "Tool call blocked: no current task");
  const title = typeof input.taskTitle === "string" && input.taskTitle ? input.taskTitle : session;
  const task = { id: session, title };
  const rawCommand = commandText(input.params);
  const exec = tool === "exec" ? normalizedExec(rawCommand) : null;
  if (exec?.error) return blocked(input, exec.error, `Tool call blocked: ${exec.error}`, task);
  const command = exec ? exec.command : rawCommand;
  const rule = policy.rules.find((item) => ruleMatches(item, tool, command));
  const action = rule ? rule.action : policy.defaultAction;
  const ruleId = rule ? rule.id : "default";
  return {
    record: baseRecord(input, { task, rule: ruleId, policyHash, decision: decisionName(action) }),
    effect: effectFor(action, tool, ruleId),
  };
}

export function resolutionDecision(value) {
  if (value === "allow-once" || value === "allow-always") return "approved";
  return "rejected";
}

export function resolutionRecord(record, resolution, now) {
  return {
    ...record,
    time: now || new Date().toISOString(),
    decision: resolutionDecision(resolution),
    approval: { mode: "openclaw-requireApproval", resolution: String(resolution) },
  };
}

// undefined lets the tool run. deny blocks it. approval pauses it until the
// signed-in user answers; timeout and cancel are rejected by resolutionDecision.
export function hookResult(decided, onResolution) {
  if (decided.effect.kind === "allow") return undefined;
  if (decided.effect.kind === "deny") {
    return { block: true, blockReason: decided.effect.blockReason };
  }
  return {
    requireApproval: {
      ...decided.effect.approval,
      pluginId: "saw-tool-gate",
      onResolution,
    },
  };
}

export function appendAudit(file, record) {
  const line = `${JSON.stringify(record)}\n`;
  fs.appendFileSync(file, line);
  process.stderr.write(line);
}

export function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

export function readText(file) {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return null;
  }
}

export function parseIdentity(text) {
  if (typeof text !== "string" || !text.trim()) return null;
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    return value;
  } catch {
    return null;
  }
}

// The before_tool_call hook without the OpenClaw import. A thrown audit write
// blocks the call. onResolution appends a second line and does not execute.
export function evaluateToolCall(input) {
  const identity = input.identityText !== undefined ? parseIdentity(input.identityText) : input.identity;
  const decided = decide({
    policyText: input.policyText,
    expectedPolicyHash: input.expectedPolicyHash,
    identity,
    taskTitle: input.taskTitle,
    toolName: input.toolName,
    params: input.params,
    sessionKey: input.sessionKey,
    sessionId: input.sessionId,
    now: input.now,
  });
  const append = input.appendRecord || (input.auditFile && (record => appendAudit(input.auditFile, record)));
  if (append) {
    try {
      append(decided.record);
    } catch {
      const record = { ...decided.record, rule: "audit-unwritable", decision: "deny" };
      process.stderr.write(`${JSON.stringify(record)}\n`);
      return {
        record,
        hook: { block: true, blockReason: "Tool call blocked: the audit trail could not be written" },
      };
    }
  }
  const hook = hookResult(decided, (resolution) => {
    if (!append) return;
    try {
      append(resolutionRecord(decided.record, resolution));
    } catch {
      const record = { ...resolutionRecord(decided.record, resolution), auditWriteFailed: true };
      process.stderr.write(`${JSON.stringify(record)}\n`);
      if (record.decision === "approved" && input.unacknowledgedApproval) {
        input.unacknowledgedApproval();
      }
    }
  });
  return { record: decided.record, hook };
}
