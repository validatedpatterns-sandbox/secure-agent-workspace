# Personal assistant

The `personal-assistant` profile creates a NemoClaw sandbox with the
`daily-briefing` harness enabled. It reads Slack and Gmail and saves a briefing
under `/sandbox/briefing/<YYYY-MM-DD>/briefing.md`.

Deploy with README **Option A: Validated Pattern**, pinning an image built from
this branch's `credential-proxy/` sources. Create a Keycloak account, then sign
in to Developer Hub as that user and choose **personal-assistant**. Supply:

- An NVIDIA inference key for the selected model.
- A static Slack bot token; invite the bot to the channels it should read and
  grant its read scopes (`channels:read`, `channels:history`, `users:read`).
- A Google OAuth client ID, client secret, and refresh token with the
  `https://www.googleapis.com/auth/gmail.readonly` scope. Obtain offline access
  for the Gmail account through the OAuth consent flow for that client.

A Google OAuth client in **Testing** gives Gmail refresh tokens a seven-day
lifetime. Use an **In production** client (internal where appropriate) for a
longer deployment. See [Google's expiration documentation](https://developers.google.com/identity/protocols/oauth2#expiration).
Slack rotating refresh tokens are unsupported; use a static bot token.

Create the Slack app as an **internal (custom) app** in the workspace that owns
the bot, and do not distribute it. Since [2025-05-29](https://docs.slack.dev/changelog/2025/05/29/rate-limit-changes-for-non-marketplace-apps), newly created apps that are not distributed through the Marketplace are limited to one `conversations.history` request per minute with at most 15 messages per page; internal apps retain the higher request allowance. The readers page through every available Gmail message and Slack channel/history page since the last saved position.

The provider Secrets stay in Vault and the namespace credential proxy. The
VM gets metadata and markers. Gmail access tokens are minted in the proxy,
cached only in memory, and refreshed five minutes before expiry. The token URL
comes only from the shipped profile, preventing tenant-controlled redirects
of refresh material. A transient network, timeout, 429, or 5xx failure during
early refresh keeps serving the cached token until it really expires and retries
after 60 seconds; authorization failures drop it immediately and return a
sanitized 502. Updating the Vault material through ESO drops the cache.

Once installation reports `apply: Done`, ask **Set up my daily briefing.**
The agent checks for an existing job, asks approval for `openclaw cron add`,
then schedules one isolated run every five minutes and updates the briefing
immediately. The command includes `--no-deliver`: updates are saved locally,
without requiring a chat delivery channel. A second setup request keeps the
existing job. Scheduled updates
need no approval; stopping the schedule requires approval. The local
`save_briefing` tool writes only today's briefing. Slack posts, sending email,
and generic writes remain subject to the default-deny tool policy.
Each update rebuilds from today's saved messages, even when the readers report
zero new messages, so a summary interrupted after collection can recover.

Verify that the proxy Deployment is Ready, `gmail-meta` and `slack-meta` hold
only `provider`, and `make test-credential-isolation` passes. After the first
Gmail read the proxy log should contain `event=oauth-refresh binding=gmail
status=ok` without any token or material. Restart the proxy and read again;
it should mint another token. Leave the briefing running for more than 70
minutes to exercise renewal. A wrong refresh token should yield a sanitized
502 and `error=invalid_grant` while Slack, inference, and readiness still work.
Restore the correct Vault entry and wait for ESO sync to recover.

See [credential isolation](credential-isolation.md) for rotation and operator
procedures, and [the bundle](../harness-bundles/daily-briefing/skills/daily-briefing/SKILL.md)
for the agent's update instructions.
