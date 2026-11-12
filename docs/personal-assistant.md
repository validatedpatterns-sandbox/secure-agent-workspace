# Personal assistant

The `personal-assistant` profile creates a NemoClaw sandbox with the
`daily-briefing` harness enabled. It reads Slack and Gmail and saves a briefing
under `/sandbox/briefing/<YYYY-MM-DD>/briefing.md`.

Deploy with README [Option A: Validated Pattern](../README.md#option-a-validated-pattern-automated-gitops).
The chart defaults to the published, digest-pinned credential proxy image;
override it only for a mirror or custom build (see [container images](container-images.md)).
Create the portal user's Keycloak account before signing in:

```bash
make keycloak-add-user KC_USER=dana
make keycloak-password KC_USER=dana
```

Retrieve the password using the reported Secret location or supported clipboard
helper. Keep passwords and keys out of terminal output and recordings. Do not
add Dana to `overrides/saw-users.yaml` when using the portal: that would create
a GitOps workspace instead. Sign in to Developer Hub as Dana, then choose
**Create** → **Create or update my agent workspace** → **personal-assistant**.
Supply:

- An NVIDIA inference key for the selected model.
- A static Slack bot token; invite the bot to the channels it should read and
  grant its read scopes (`channels:read`, `channels:history`, `users:read`).
  Reading private channels also needs `groups:read` and `groups:history`.
- A Google OAuth client ID, client secret, and refresh token with the
  `https://www.googleapis.com/auth/gmail.readonly` scope. Obtain offline access
  for the Gmail account through the OAuth consent flow for that client.

A Google OAuth client in **Testing** gives Gmail refresh tokens a seven-day
lifetime. Use an **In production** client (internal where appropriate) for a
longer deployment. See [Google's expiration documentation](https://developers.google.com/identity/protocols/oauth2#expiration).
Slack rotating refresh tokens are unsupported; use a static bot token.

Create the Slack app as an **internal (custom) app** in the workspace that owns
the bot, and do not distribute it. Since [2025-05-29](https://docs.slack.dev/changelog/2025/05/29/rate-limit-changes-for-non-marketplace-apps), newly created apps that are not distributed through the Marketplace are limited to one `conversations.history` request per minute with at most 15 messages per page; internal apps retain the higher request allowance. The Gmail reader pages through every available message since today's start.

Each Slack update reads top-level messages from today and the previous seven
days, then fetches threads with new replies. It collects replies posted today
when their first message is at most seven days old; replies to older threads
are not collected. Set `BRIEFING_THREAD_LOOKBACK_DAYS` to an integer from 1
to 30 to change the window (default 7). Each update makes at least one
`conversations.history` request per member channel, with another page for
every 200 top-level messages in the window, plus one or more
`conversations.replies` requests per thread with new replies. This request
rate requires an internal Slack app rather than a non-Marketplace distributed
app with the one-request-per-minute limit.

In proxy mode the provider Secrets stay in Vault and the namespace credential proxy. The
VM gets metadata and markers. Gmail access tokens are minted in the proxy,
cached only in memory, and refreshed five minutes before expiry. The token URL
comes only from the shipped profile, preventing tenant-controlled redirects
of refresh material. A transient network, timeout, 429, or 5xx failure during
early refresh keeps serving the cached token until it really expires and retries
after 60 seconds; authorization failures drop it immediately and return a
sanitized 502. Updating the Vault material through ESO drops the cache.

In direct mode (`credentialProxy.enabled: false`) the VM mounts full provider
Secrets. The gateway configures and rotates Gmail OAuth credentials itself;
Slack remains a static bot token. Check:

```bash
openshell provider refresh status gmail --workspace personal-assistant
```

The token URL host must stay in `egress.allow`. A token-only Gmail Secret is
accepted with a warning and needs manual renewal. Mode switches preserve
`/sandbox/briefing`; see [switching modes](credential-isolation.md#switching-modes)
for the restart, cleanup and mandatory key-rotation sequence.

## Open and verify the assistant

Follow the portal pipeline through `register`, `argo-cd-apps`, `vm`,
`vm-running`, and `sandboxes`. Follow the VM installer separately:

```bash
make saw-logs OPENSHELL_SAW_NAME=dana
```

Wait for `apply: Done`, then open **Catalog** → **saw-dana** →
**assistant UI (personal-assistant)** and sign in as Dana. For CLI checks:

```bash
export OPENSHELL_SAW_NAME=dana
make saw-configure
# If the token expired or browser sign-in did not finish:
# openshell gateway login dana
openshell gateway list
openshell --gateway dana provider list --workspace personal-assistant
openshell --gateway dana sandbox list --workspace personal-assistant
```

Expected: providers `nvidia`, `slack`, and `gmail`, and sandbox `assistant`.
Add sample Slack messages and email, then ask the assistant to summarize
today's messages in a channel the bot has joined and today's unread email.
The daily-briefing readers collect today's messages; use fresh sample data.
Check a second user's sign-in to Dana's UI returns HTTP 403.

In default proxy mode, verify Gmail refresh through the proxy log after a
read; `openshell provider refresh status` describes gateway-managed refresh
in direct mode, not the proxy's token cache. Slack uses a static token and
has no refresh-expiry check.

## Check governance refusals and policy changes

The Slack and Gmail profiles permit only their listed GET requests. Ask the
assistant to send a Slack message: it must not post. A refusal may occur at
the agent tool gate before a network request is made. Read
`/sandbox/.saw/audit/tool-actions.jsonl` for tool decisions; the gateway logs
interceptor decisions for control-plane operations such as provider creation.
The interceptor pod does not receive every Slack or Gmail HTTP request.
See [tool actions](governance-interceptor.md#tool-actions) and
[credential proxy request logs](credential-isolation.md#how-a-request-is-handled).

To demonstrate rejection of an unapproved provider, first check that `notion`
is absent from this gateway's catalog:

```bash
openshell --gateway dana provider list-profiles --workspace personal-assistant
# Only when notion is absent; use a placeholder, never a real credential:
NOTION_API_KEY=demo-placeholder openshell --gateway dana provider create \
  --name notion --type notion --workspace personal-assistant --credential NOTION_API_KEY
```

Expected: the gateway rejects the unknown provider type. If an administrator
has already approved `notion`, this is no longer a refusal test.

Granting a new integration requires a reviewed policy change: publish its
GET-only profile and allow its exact endpoint through the VM's egress policy.
Follow [adding a provider profile](governance-interceptor.md#adding-a-new-provider-profile).
After the change merges into the branch Argo CD watches, wait for sync and
confirm the profile appears with `provider list-profiles` before retrying.
APF deployments also require a newly signed bundle (see [APF](apf.md)).
Approval of a profile alone does not configure an integration: provision the
real credential outside the VM, its proxy binding and metadata, and attach
the provider to the sandbox through its SAW-BOM profile. Follow
[credential isolation](credential-isolation.md#typed-provider-config-135) and
[harness bundles](harness-bundles.md#servers-that-need-an-api-key).
Successful creation with a placeholder demonstrates catalog approval only;
it does not prove working Notion access.

## Schedule the daily briefing

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
Scheduled and manual updates can overlap safely. Each reader takes a
per-source lock and refreshes it during long collections; saved items are
deduplicated by ID. Stale-lock recovery checks the lock's identity before
removing it. A second update may report `busy: true` while another process
collects from the same source; it should continue using the saved items.

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
