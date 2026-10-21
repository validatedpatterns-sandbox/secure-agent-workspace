// MCP server (stdio): new Gmail messages for the daily briefing, read-only.
// GMAIL_ACCESS_TOKEN holds an OpenShell placeholder; the `gmail` provider
// profile lets the sandbox proxy put the real, gateway-refreshed token in
// for gmail.googleapis.com only.
import { appendItems, clip, getJson, loadState, saveState, serve, today } from "./briefing-lib.mjs";

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
  const list = await getJson(`${API}/messages?maxResults=50&q=${encodeURIComponent(`after:${startSec}`)}`, token());
  const items = [];
  for (const { id } of list.messages || []) {
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
  items.sort((a, b) => a.time.localeCompare(b.time));
  const file = items.length ? appendItems(day, items) : null;
  state.seen = [...seen];
  saveState("gmail", state);
  return { day, new: items.length, items, file };
}

serve("gmail-reader", [
  {
    name: "new_messages",
    description: "Gmail messages received today since the last call: sender, subject, snippet, unread (read-only). Also appends them to /sandbox/briefing/<day>/items.jsonl.",
    inputSchema: { type: "object", properties: {} },
    run: newMessages,
  },
]);
