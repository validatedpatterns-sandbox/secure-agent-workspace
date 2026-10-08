# Personal assistant: a daily Slack and Gmail briefing

The `personal-assistant` SAW-BOM profile gives a user one workspace,
`personal-assistant`, with a NemoClaw sandbox, `assistant`, that keeps a
daily briefing of their Slack and Gmail messages. Its providers are NVIDIA
(inference), Slack and Gmail; it has no web search. Asked to, the agent
updates the briefing every 5 minutes with whatever arrived since the last
update. For the whole demo, from install to the briefing, see
[the personal assistant demo](personal-assistant-demo.md).

What makes it safe to hand an agent the user's Slack and mail:

| Layer | What it does |
|---|---|
| Providers `slack`, `gmail` | Read-only profiles (`charts/governance-policy/profiles`): GET only, on the listed Slack and Gmail API paths, from `node` or `curl` only. |
| Credential refresh | The gateway holds the OAuth client secret and refresh token, and refreshes the access token before it expires (OpenShell `provider refresh`, `oauth2-refresh-token`). Slack's rotated refresh tokens are kept. |
| Placeholders | The sandbox sees `SLACK_BOT_TOKEN` and `GMAIL_ACCESS_TOKEN` as placeholders. The egress proxy puts the current token in only on requests to the profile's endpoints. |
| Harness bundle `daily-briefing` | The skill and two MCP servers (`slack-reader`, `gmail-reader`) are mounted read-only at `/sandbox/harness`. Each server declares the profile that governs it, and the installer refuses the bundle unless the gateway serves that profile and the sandbox has the provider. |

## The bundle

`harness-bundles/daily-briefing` (CI publishes it as an image) and the same
tree inline in `charts/saw-bom/harness/daily-briefing`, which the profile
uses (`harnessRef: {name: daily-briefing}`):

```
harness.yaml                    governance: slack-reader -> slack, gmail-reader -> gmail
plugin.json, mcp.json           Agent Plugins bundle: OpenClaw loads skills/ and mcp.json
skills/daily-briefing/SKILL.md  update, schedule (cron tool, every 5 min), show
mcp/slack-reader.mjs            tool new_messages: today's messages since the last call
mcp/gmail-reader.mjs            tool new_messages: today's mail since the last call
mcp/briefing-lib.mjs            stdio MCP loop and the store in /sandbox/briefing
```

The servers keep their state and the day's messages in
`/sandbox/briefing/` (`state-slack.json`, `state-gmail.json`,
`<day>/items.jsonl`); the agent writes `<day>/briefing.md`.

Harness bundles are mounted when a sandbox is created, and `nemoclaw onboard`
cannot add a mount on podman. For a NemoClaw sandbox with a `harnessRef` the
installer creates the sandbox itself, from the NemoClaw image with the
bundle mounted, and configures OpenClaw in it, as it does after onboarding.
A NemoClaw sandbox created earlier by `nemoclaw onboard` is created again once
(its `/sandbox` is not kept).

## Slack app (token rotation)

1. Create an app at <https://api.slack.com/apps>. Bot token scopes:
   `channels:read`, `channels:history`, `groups:read`, `groups:history`,
   `users:read`.
2. *OAuth & Permissions*: turn on **token rotation**, and install the app
   with the OAuth flow (`oauth.v2.access`). The response has an access token
   (`xoxe.xoxb-…`, 12 hours) and a refresh token (`xoxe-1-…`).
3. Invite the app to the channels the briefing should read
   (`/invite @<app>`).

The Secret `slack` needs `client_id`, `client_secret`, and `refresh_token`.
Without token rotation, a plain bot token in `bot_token` is used as is, with
no refresh.

## Google OAuth (Gmail, read-only)

1. In a Google Cloud project, enable the Gmail API and create an OAuth
   client (type *Desktop app* or *Web application*).
2. Get a refresh token for the scope
   `https://www.googleapis.com/auth/gmail.readonly` (for example with the
   OAuth 2.0 Playground, using your own client: settings, then *Use your own
   OAuth credentials*). Ask for offline access, so a refresh token is issued.

The Secret `gmail` needs `client_id`, `client_secret`, and `refresh_token`.
Access tokens last an hour; the gateway refreshes them 5 minutes before they
expire.

## Turn it on for a user

`overrides/saw-users.yaml`:

```yaml
users:
  - name: carol
    profiles:
      - personal-assistant
```

saw-users sees from the profile catalog that the sandbox needs its bundle
(`harnessRequired`) and sets `harnessEnabled` and `allowDriverConfig` for the
user. It also syncs the `slack` and `gmail` Secrets from Vault and mounts
them on the VM.

Load the keys into Vault: uncomment the `slack` and `gmail` entries in your
`values-secret` file (see `values-secret.yaml.template`) and run
`./pattern.sh make load-secrets`. They go to `secret/data/hub/slack` and
`secret/data/hub/gmail` (or under the user's `vaultPrefix`). In the
Developer Hub portal, the `personal-assistant` profile asks for the same
fields and stores them under the user's own Vault path.

Check on the VM, as the installer's identity:

```
openshell provider refresh status gmail --workspace personal-assistant
openshell provider refresh status slack --workspace personal-assistant
```

## Demo

In the assistant's OpenClaw UI (route `<user>-personal-assistant-assistant-ui`) or TUI:

1. "Set up my daily briefing." The agent adds the `daily-briefing` cron job
   (every 5 minutes, isolated session), runs one update, and shows
   `briefing.md`.
2. Post in a channel the app is in, or send yourself an email; within 5
   minutes the briefing has it.
3. "Print the Slack token." The agent only has a placeholder.
4. Ask it to post to Slack, or to call another API: the profiles are
   read-only and list only Slack and Gmail. The sandbox log shows the denial
   (`openshell logs assistant --workspace personal-assistant --source sandbox`).

## Limits

- The NemoClaw image's OpenClaw (2026.7.1) is older than the one the bundle
  format was checked with (2026.9.x). Check after the first apply that
  OpenClaw lists the `slack-reader__*` and `gmail-reader__*` tools and the
  `daily-briefing` skill. The schedule uses the agent's `cron` tool; if that
  OpenClaw has none, schedule the update from the OpenClaw UI's cron page.
- Running processes keep their environment: a provider attached to a running
  sandbox reaches OpenClaw after its gateway restarts, which the installer
  does when the sandbox's providers change.
- A refresh failure that needs the user (a revoked grant) shows as
  `reauthorize` in `provider refresh status`. Put a new refresh token in
  Vault; the installer configures it on its next run.
