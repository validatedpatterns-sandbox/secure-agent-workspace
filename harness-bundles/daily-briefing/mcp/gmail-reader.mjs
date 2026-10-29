// MCP server (stdio): new Gmail messages for the daily briefing, read-only.
// GMAIL_ACCESS_TOKEN holds an OpenShell placeholder; the `gmail` provider
// profile lets the namespace credential proxy mint and inject the real token
// for gmail.googleapis.com only. Refresh material never reaches this process.
import { appendItems, clip, drain, getJson, loadState, pageSize, saveState, serve, today } from "./briefing-lib.mjs";

const API = process.env.GMAIL_API_URL || "https://gmail.googleapis.com/gmail/v1/users/me";

function token() {
  const t = process.env.GMAIL_ACCESS_TOKEN;
  if (!t) throw new Error("GMAIL_ACCESS_TOKEN is not set: the sandbox has no gmail provider");
  return t;
}

async function newMessages() {
  const { day, startSec } = today();
  const state = loadState("gmail", day, { seen: [] });
  const seen = new Set(state.seen);
  const ids = new Set();
  await drain(async (pageToken) => {
    const url = new URL(`${API}/messages`);
    url.searchParams.set("maxResults", String(pageSize(500)));
    url.searchParams.set("q", `after:${startSec}`);
    if (pageToken) url.searchParams.set("pageToken", pageToken);
    const list = await getJson(url, token());
    for (const { id } of list.messages || []) {
      if (id) ids.add(id);
    }
    return list.nextPageToken || "";
  });
  const items = [];
  try {
    for (const id of ids) {
    if (seen.has(id)) continue;
    const m = await getJson(`${API}/messages/${id}?format=metadata` +
      "&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date", token());
    const header = (n) => (m.payload?.headers || []).find((h) => h.name.toLowerCase() === n)?.value || "";
    items.push({
      source: "gmail", from: header("from"), subject: clip(header("subject")),
      time: new Date(Number(m.internalDate || 0)).toISOString(), snippet: clip(m.snippet),
      unread: (m.labelIds || []).includes("UNREAD"),
    });
    seen.add(id);
    }
  } catch (err) {
    if (items.length) appendItems(day, items);
    state.seen = [...seen];
    saveState("gmail", state);
    throw err;
  }
  items.sort((a, b) => a.time.localeCompare(b.time));
  const file = items.length ? appendItems(day, items) : null;
  state.seen = [...seen];
  saveState("gmail", state);
  return { day, new: items.length, items: items.slice(-50), more: Math.max(0, items.length - 50), file };
}

serve("gmail-reader", [
  {
    name: "new_messages",
    description: "Gmail messages received today since the last call: sender, subject, snippet, unread (read-only). Also appends them to /sandbox/briefing/<day>/items.jsonl.",
    inputSchema: { type: "object", properties: {} },
    run: newMessages,
  },
]);
