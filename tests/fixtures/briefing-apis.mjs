import { readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
const day = Math.floor(new Date(new Date().setHours(0, 0, 0, 0)).getTime() / 1000);
const gmailCount = Number(process.env.FAKE_GMAIL_COUNT || 1);
const slackCount = Number(process.env.FAKE_SLACK_COUNT || 1);
const channelPages = Number(process.env.FAKE_CHANNEL_PAGES || 1);
const slackThreads = () => process.env.FAKE_SLACK_THREADS
  ? JSON.parse(readFileSync(process.env.FAKE_SLACK_THREADS, "utf8")) : [];
const failSpec = process.env.FAKE_FAIL_ONCE || "";
const failed = new Set();
const requests = [];
const reply = (res, body, status = 200) => {
  const send = () => {
    res.writeHead(status, {"content-type": "application/json"});
    res.end(JSON.stringify(body));
  };
  const delay = Number(process.env.FAKE_DELAY_MS || 0);
  if (delay > 0) setTimeout(send, delay);
  else send();
};
const record = (url) => {
  requests.push({path: url.pathname, query: Object.fromEntries(url.searchParams)});
  if (process.env.FAKE_REQUEST_LOG) writeFileSync(process.env.FAKE_REQUEST_LOG, JSON.stringify(requests));
};
const pageNumber = (cursor) => cursor ? Number(cursor) : 0;
const nextCursor = (page, end, count) => {
  if (process.env.FAKE_REPEAT_CURSOR) return "repeat";
  return end < count ? String(page + 1) : "";
};
const failOnce = (path, page, res) => {
  const key = `${path}:${page}`;
  if (failSpec === key && !failed.has(key)) {
    failed.add(key);
    reply(res, {ok: false, error: "server_error"}, 500);
    return true;
  }
  return false;
};
const handler = (req, res) => {
  const url = new URL(req.url, "http://x");
  record(url);
  const expected = url.pathname.startsWith("/slack") ? "slack-ph" : "gmail-ph";
  if (req.headers.authorization !== `Bearer ${expected}`)
    return reply(res, {ok: false, error: "invalid_auth"}, 401);
  if (url.pathname === "/slack/conversations.list") {
    const all = channelPages > 1
      ? [{id: "C0", name: "random", is_member: false}, {id: "C1", name: "eng", is_member: true}]
      : [{id: "C1", name: "eng", is_member: true}, {id: "C2", name: "random", is_member: false}];
    const page = pageNumber(url.searchParams.get("cursor"));
    const limit = Number(url.searchParams.get("limit") || all.length);
    const start = page * limit, end = Math.min(start + limit, all.length);
    if (failOnce(url.pathname, page + 1, res)) return;
    const next = nextCursor(page, end, all.length);
    const body = {ok: true, channels: all.slice(start, end)};
    if (next) { body.has_more = true; body.response_metadata = {next_cursor: next}; }
    else if (process.env.FAKE_HAS_MORE_NO_CURSOR) body.has_more = true;
    return reply(res, body);
  }
  if (url.pathname === "/slack/conversations.history") {
    const oldest = Number(url.searchParams.get("oldest"));
    const generated = Array.from({length: slackCount}, (_, i) => ({
      ts: String(day + 60 + i), user: "U1",
      text: i === 0 ? "Can you review the PR today?" : `Slack message ${i + 1}`,
    }));
    const threaded = slackThreads().flatMap((thread) => [
      {...thread, thread_ts: thread.ts, reply_count: thread.replies.length,
        latest_reply: thread.replies.reduce((latest, m) => Number(m.ts) > Number(latest) ? m.ts : latest, "0")},
      ...thread.replies.filter((m) => m.subtype === "thread_broadcast")
        .map((m) => ({...m, thread_ts: thread.ts})),
    ]);
    const all = [...generated, ...threaded].sort((a, b) => Number(b.ts) - Number(a.ts));
    const page = pageNumber(url.searchParams.get("cursor"));
    const limit = Number(url.searchParams.get("limit") || all.length);
    const filtered = all.filter((m) => Number(m.ts) > oldest);
    const start = page * limit, end = Math.min(start + limit, filtered.length);
    if (failOnce(url.pathname, page + 1, res)) return;
    const next = nextCursor(page, end, filtered.length);
    const body = {ok: true, messages: filtered.slice(start, end)};
    if (next) { body.has_more = true; body.response_metadata = {next_cursor: next}; }
    else if (process.env.FAKE_HAS_MORE_NO_CURSOR) body.has_more = true;
    return reply(res, body);
  }
  if (url.pathname === "/slack/conversations.replies") {
    const thread = slackThreads().find((t) => t.ts === url.searchParams.get("ts"));
    if (!thread) return reply(res, {ok: false, error: "thread_not_found"});
    const oldest = Number(url.searchParams.get("oldest"));
    const all = [thread, ...thread.replies.filter((m) => Number(m.ts) > oldest)
      .sort((a, b) => Number(a.ts) - Number(b.ts))];
    const page = pageNumber(url.searchParams.get("cursor"));
    const limit = Number(url.searchParams.get("limit") || all.length);
    const start = page * limit, end = Math.min(start + limit, all.length);
    if (failOnce(url.pathname, page + 1, res)) return;
    const next = nextCursor(page, end, all.length);
    const body = {ok: true, messages: all.slice(start, end)};
    if (next) { body.has_more = true; body.response_metadata = {next_cursor: next}; }
    else if (process.env.FAKE_HAS_MORE_NO_CURSOR) body.has_more = true;
    return reply(res, body);
  }
  if (url.pathname === "/slack/users.info") return reply(res, {ok: true, user: {real_name: "Dana"}});
  if (url.pathname === "/gmail/messages") {
    const all = Array.from({length: gmailCount}, (_, i) => ({id: `m${i + 1}`}));
    const page = pageNumber(url.searchParams.get("pageToken"));
    const limit = Number(url.searchParams.get("maxResults") || all.length);
    const start = page * limit, end = Math.min(start + limit, all.length);
    if (failOnce(url.pathname, page + 1, res)) return;
    const next = nextCursor(page, end, all.length);
    const body = {messages: all.slice(start, end)};
    if (next) body.nextPageToken = next;
    return reply(res, body);
  }
  if (url.pathname.startsWith("/gmail/messages/")) {
    const id = url.pathname.split("/").pop();
    const index = Number(id.slice(1)) - 1;
    return reply(res, {id, internalDate: String((day * 1000) + 5000 + (index * 1000)),
      snippet: `Message ${index + 1}`, labelIds: ["UNREAD"],
      payload: {headers: [{name: "From", value: "cfo@example.com"},
        {name: "Subject", value: index === 0 ? "Q3" : `Mail ${index + 1}`}]}});
  }
  res.writeHead(404); res.end();
};
// FAKE_TLS_DIR: serve HTTPS with that directory's self-signed cert (the
// stand-in for the sandbox egress proxy, which re-signs TLS with its own CA).
const tls = process.env.FAKE_TLS_DIR;
(tls ? https.createServer({ key: readFileSync(`${tls}/key.pem`), cert: readFileSync(`${tls}/cert.pem`) }, handler)
     : http.createServer(handler))
  .listen(0, "127.0.0.1", function () { console.log(this.address().port); });
