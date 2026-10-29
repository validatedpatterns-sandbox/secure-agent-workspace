// MCP server (stdio): new Slack messages for the daily briefing, read-only.
// SLACK_BOT_TOKEN holds an OpenShell placeholder; the `slack` provider
// profile lets the sandbox proxy put the real token in for slack.com only.
import { appendItems, clip, drain, getJson, loadState, pageSize, saveState, serve, today } from "./briefing-lib.mjs";

const API = process.env.SLACK_API_URL || "https://slack.com/api";

async function call(method, params) {
  const token = process.env.SLACK_BOT_TOKEN || process.env.SLACK_TOKEN;
  if (!token) throw new Error("SLACK_BOT_TOKEN is not set: the sandbox has no slack provider");
  const url = new URL(`${API}/${method}`);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));
  const body = await getJson(url, token);
  if (!body.ok) throw new Error(`${method}: ${body.error || "not ok"}`);
  return body;
}

async function channels() {
  const found = [];
  await drain(async (cursor) => {
    const body = await call("conversations.list", {
      types: "public_channel,private_channel", exclude_archived: true, limit: pageSize(200),
      ...(cursor ? { cursor } : {}),
    });
    found.push(...(body.channels || []).filter((c) => c.is_member));
    const next = body.response_metadata?.next_cursor || "";
    if (body.has_more && !next) throw new Error("conversations.list: has_more without a cursor");
    return next;
  });
  return found;
}

async function history(ch, oldest) {
  const messages = [];
  await drain(async (cursor) => {
    const body = await call("conversations.history", {
      channel: ch.id, oldest, limit: pageSize(200), ...(cursor ? { cursor } : {}),
    });
    messages.push(...(body.messages || []));
    const next = body.response_metadata?.next_cursor || "";
    if (body.has_more && !next) throw new Error("conversations.history: has_more without a cursor");
    return next;
  });
  return messages;
}

async function newMessages() {
  const { day, startSec } = today();
  const state = loadState("slack", day, { channels: {}, users: {} });
  const userName = async (id) => {
    if (!id) return "unknown";
    if (!state.users[id]) {
      try {
        const u = (await call("users.info", { user: id })).user || {};
        state.users[id] = u.profile?.display_name || u.real_name || u.name || id;
      } catch { state.users[id] = id; }
    }
    return state.users[id];
  };
  const items = [];
  const list = await channels();
  const failures = [];
  let file = null;
  for (const ch of list) {
    const oldest = state.channels[ch.id] || String(startSec);
    let messages;
    try {
      messages = await history(ch, oldest);
    } catch (err) {
      failures.push(`#${ch.name}: ${err?.cause?.code || err.message}`);
      continue;
    }
    messages.sort((a, b) => Number(a.ts) - Number(b.ts));
    const chItems = [];
    for (const m of messages) {
      if (m.subtype && m.subtype !== "bot_message") continue;
      chItems.push({
        source: "slack", channel: `#${ch.name}`, from: await userName(m.user || m.bot_id),
        time: new Date(Number(m.ts) * 1000).toISOString(), text: clip(m.text),
        replies: m.reply_count || 0,
      });
    }
    if (chItems.length) file = appendItems(day, chItems);
    items.push(...chItems);
    state.channels[ch.id] = messages.reduce((a, m) => (Number(m.ts) > Number(a) ? m.ts : a), oldest);
    saveState("slack", state);
  }
  if (failures.length) {
    throw new Error(`conversations.history failed; position kept for: ${failures.join("; ")}`);
  }
  saveState("slack", state);
  return {
    day, channels: list.map((c) => `#${c.name}`), new: items.length,
    items: items.slice(-50), more: Math.max(0, items.length - 50), file,
  };
}

serve("slack-reader", [
  {
    name: "new_messages",
    description: "Slack messages posted today since the last call, in the channels the app is a member of (read-only). Also appends them to /sandbox/briefing/<day>/items.jsonl.",
    inputSchema: { type: "object", properties: {} },
    run: newMessages,
  },
  {
    name: "channels",
    description: "The Slack channels the app can read (it is a member of).",
    inputSchema: { type: "object", properties: {} },
    run: async () => (await channels()).map((c) => ({ id: c.id, name: `#${c.name}` })),
  },
]);
