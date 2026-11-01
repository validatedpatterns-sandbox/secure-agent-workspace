// MCP server (stdio): new Slack messages for the daily briefing, read-only.
// SLACK_BOT_TOKEN holds an OpenShell placeholder; the `slack` provider
// profile lets the sandbox proxy put the real token in for slack.com only.
import { appendItems, clip, drain, getJson, loadState, LockBusy, pageSize, saveState, serve, today, withLock } from "./briefing-lib.mjs";

const API = process.env.SLACK_API_URL || "https://slack.com/api";

function lookbackDays() {
  const days = Number(process.env.BRIEFING_THREAD_LOOKBACK_DAYS);
  return Number.isInteger(days) && days >= 1 && days <= 30 ? days : 7;
}

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

async function replies(ch, threadTs, oldest) {
  const messages = [];
  await drain(async (cursor) => {
    const body = await call("conversations.replies", {
      channel: ch.id, ts: threadTs, oldest, limit: pageSize(200), ...(cursor ? { cursor } : {}),
    });
    messages.push(...(body.messages || []));
    const next = body.response_metadata?.next_cursor || "";
    if (body.has_more && !next) throw new Error("conversations.replies: has_more without a cursor");
    return next;
  });
  return messages.filter((m) => m.ts !== threadTs && Number(m.ts) > Number(oldest) &&
    (!m.subtype || m.subtype === "bot_message" || m.subtype === "thread_broadcast"));
}

async function collect() {
  const { day, startSec } = today();
  const state = loadState("slack", day, { channels: {}, threads: {}, users: {} });
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
  const slackItem = async (ch, m) => ({
    source: "slack", id: `slack:${ch.id}:${m.ts}`, channel: `#${ch.name}`,
    from: await userName(m.user || m.bot_id),
    time: new Date(Number(m.ts) * 1000).toISOString(), text: clip(m.text),
  });
  const items = [];
  const list = await channels();
  const failures = [];
  let file = null;
  const lookback = String(startSec - lookbackDays() * 86400);
  for (const ch of list) {
    const oldest = state.channels[ch.id] || String(startSec);
    let messages;
    try {
      messages = await history(ch, lookback);
    } catch (err) {
      failures.push(`#${ch.name}: ${err?.cause?.code || err.message}`);
      continue;
    }
    messages.sort((a, b) => Number(a.ts) - Number(b.ts));
    const chItems = [];
    for (const m of messages) {
      if (Number(m.ts) <= Number(oldest)) continue;
      if (m.subtype && m.subtype !== "bot_message") continue;
      chItems.push({ ...await slackItem(ch, m), replies: m.reply_count || 0 });
    }
    state.threads[ch.id] ||= {};
    for (const parent of messages) {
      if (parent.thread_ts !== parent.ts || !(parent.reply_count > 0)) continue;
      const position = state.threads[ch.id][parent.ts] || String(startSec);
      if (parent.latest_reply && Number(parent.latest_reply) <= Number(position)) continue;
      try {
        const threadReplies = await replies(ch, parent.ts, position);
        for (const m of threadReplies) {
          chItems.push({ ...await slackItem(ch, m), in_thread: clip(parent.text, 200) });
        }
        state.threads[ch.id][parent.ts] = threadReplies.reduce(
          (latest, m) => Number(m.ts) > Number(latest) ? m.ts : latest, position);
      } catch (err) {
        failures.push(`#${ch.name} thread ${parent.ts}: ${err?.cause?.code || err.message}`);
      }
    }
    chItems.sort((a, b) => a.time.localeCompare(b.time));
    if (chItems.length) {
      const appended = await appendItems(day, chItems);
      items.push(...appended.added);
      if (appended.added.length) file = appended.file;
    }
    state.channels[ch.id] = messages.reduce((a, m) => (Number(m.ts) > Number(a) ? m.ts : a), oldest);
    saveState("slack", state);
  }
  if (failures.length) {
    throw new Error(`Slack read failed; position kept for: ${failures.join("; ")}`);
  }
  saveState("slack", state);
  return {
    day, channels: list.map((c) => `#${c.name}`), new: items.length,
    items: items.slice(-50), more: Math.max(0, items.length - 50), file,
  };
}

async function newMessages() {
  try {
    return await withLock("slack", collect);
  } catch (err) {
    if (err instanceof LockBusy && err.lockName === "slack") {
      return { day: today().day, busy: true, new: 0, items: [], more: 0, file: null,
        note: "another update is collecting Slack messages now; they are saved to items.jsonl" };
    }
    throw err;
  }
}

serve("slack-reader", [
  {
    name: "new_messages",
    description: "Slack messages posted today since the last call in the channels the app is a member of, including today's replies in threads started in the last 7 days (read-only). Also appends them to /sandbox/briefing/<day>/items.jsonl.",
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
