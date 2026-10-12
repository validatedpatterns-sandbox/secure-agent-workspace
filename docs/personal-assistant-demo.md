# Demo: a personal assistant with a daily Slack and Gmail briefing

End to end, from an empty cluster to an agent that keeps a daily briefing of
one user's Slack and Gmail:

1. Install the pattern.
2. Create a Keycloak user, `dana`.
3. As dana, create a workspace in Red Hat Developer Hub with the
   `personal-assistant` profile.
4. In the assistant's UI, set up the briefing and watch it update.

What dana gets: one workspace, `personal-assistant`, with one NemoClaw
sandbox, `assistant`. The `daily-briefing` harness bundle is mounted in it:
a skill and two MCP servers, `slack-reader` and `gmail-reader`. Its
providers are NVIDIA (inference), Slack and Gmail, all read-only, and the
agent only ever sees placeholders for their tokens. How each layer works is
in [daily-briefing.md](daily-briefing.md).

## Before the demo

You need:

- An OpenShift cluster where you are `cluster-admin`, with `oc`, `jq` and
  `python3` on your machine.
- An NVIDIA API key (<https://build.nvidia.com>).
- A Slack app and a Google OAuth client. They take the longest, so set
  them up first: [Slack app](daily-briefing.md#slack-app-token-rotation) and
  [Google OAuth](daily-briefing.md#google-oauth-gmail-read-only). For each
  you end up with a client ID, a client secret and a refresh token. A plain
  Slack bot token (`xoxb-…`) or a Gmail access token works too, but is
  not refreshed (a Gmail access token lasts an hour).
- In Slack: invite the app to a channel you will post in during the demo
  (`/invite @<app>`).

The keys are typed into the portal in step 3; nothing goes into Git.

## 1. Install the pattern

The pattern path of the README (Option A), from this branch:

```bash
oc login --server=https://api.<cluster>:6443 -u <admin>
make ssh-key-generate        # SSH keys, and ~/values-secret.yaml from the template
make images-mirror          # the golden VM image (openshell-gateway), into the internal registry (~5 min)
export TARGET_BRANCH=feat/demo TARGET_ORIGIN=origin   # the branch must be pushed to origin
./pattern.sh make install
```

`./pattern.sh make install` installs the operators, Vault, External
Secrets, Keycloak, OpenShift Virtualization, Red Hat Developer Hub with the
self-service portal, and the governance interceptor. Wait until every Argo
CD application is `Synced` and `Healthy`:

```bash
oc get applications.argoproj.io -A
```

Developer Hub's URL:

```bash
echo "https://$(oc get route backstage-developer-hub -n rhdh -o jsonpath='{.spec.host}')"
```

`overrides/saw-users.yaml` also declares a Git workspace for `alice`
(profile `data-science`). It is not part of this demo. Its VM waits for the
NVIDIA and Brave keys from `~/values-secret.yaml`; put them there before
the install (see the README, step 4), or remove the entry from
`overrides/saw-users.yaml` and push before installing.

## 2. Create dana in Keycloak

Developer Hub does not create Keycloak accounts. An administrator does:

```bash
make keycloak-add-user KC_USER=dana
```

This keeps dana's generated password in the Secret
`openshell-keycloak-users` in `saw-keycloak`; it is not printed. Read it with:

```bash
oc -n saw-keycloak extract secret/openshell-keycloak-users --keys=dana --to=-
```

(`make keycloak-password KC_USER=dana` says which Secret holds it.)

dana is a plain user (role `openshell-user`). Do not use `alice` or `bob`
for this step: they are built-in test users, and alice already has a
workspace from `overrides/saw-users.yaml`.

Developer Hub imports Keycloak users every 2 minutes. Wait that long before
dana signs in, or she sees no actions.

## 3. Create the workspace in Developer Hub

Use a **private browser window**, so you are not signed in as someone else
already (Developer Hub and the workspace UIs share one Keycloak sign-in).

1. Open Developer Hub and sign in as `dana`.
2. **Create** → **Create or update my agent workspace**.
3. Profile: **personal-assistant** ("Personal assistant: NemoClaw agent with
   NVIDIA inference and a daily Slack and Gmail briefing").
4. Fill in the keys:
   - **inference: API key**: the NVIDIA API key.
   - **slack**: client ID, client secret and refresh token, or only the
     access token (`bot_token`).
   - **gmail**: client ID, client secret and refresh token, or only the
     access token.

   The form requires only the NVIDIA key. Fill in Slack and Gmail too: if a
   provider has neither the full refresh material nor a token, the installer
   stops with "Secret 'slack' needs refresh material … or a 'bot_token'
   token".
5. **Review**, then **Create**.

The run page shows each step. Expect about 15 minutes on a cluster that has
the golden image cached: submit, the pipeline that stores the keys in Vault
(under dana's own path), Argo CD creating `saw-dana`, the VM starting, and
the installer setting up OpenShell, the providers and the sandbox.

Follow it from a terminal if you like:

```bash
oc get vm,dv -n saw-dana
oc get events -n saw-dana --sort-by=.lastTimestamp | tail
```

When the run reaches **Workspace status report**, the workspace is `Ready`.
In Developer Hub's **Catalog**, `saw-dana` has the links, including
**assistant UI (personal-assistant)**.

## 4. The briefing

Open the assistant UI, in the same private window:
`https://dana-personal-assistant-assistant-ui.<apps domain>`. It signs in
through Keycloak and admits only dana.

Then, in the OpenClaw chat:

1. **"Set up my daily briefing."** The agent adds a `daily-briefing` cron
   job (every 5 minutes), runs one update, and shows today's
   `briefing.md`.
2. Post a message in the Slack channel the app is in, and send yourself an
   email. Within 5 minutes, ask **"Show my briefing."**: both are there.
3. **"Print the Slack token."** The agent only has a placeholder; the real
   token is added by the gateway's proxy, and only on requests to Slack's
   API.
4. **"Post 'hello' to the channel."** or **"Send an email."** The providers
   are read-only (GET only, on the listed Slack and Gmail paths), so the
   request is denied. Show the denial in the sandbox log (step 5 below).

## Checks and troubleshooting

| What you see | Why | What to do |
|---|---|---|
| The run fails at "Submit the request" with HTTP 500 | Developer Hub cannot verify the Kubernetes API's certificate | `oc logs -n rhdh deploy/backstage-developer-hub -c saw-ca-bundle` should list `added: Kubernetes API CA` |
| "Start the VM" takes long, the VM shows `Starting` | the VM waits until its provider Secrets exist (External Secrets creates them from Vault) | `oc get events -n saw-dana \| grep FailedMount` |
| 403 on the assistant UI after signing in | signed in as someone other than dana | use a private window, sign in as dana |
| "Invalid parameter: redirect_uri" | the UI's redirect URI is not registered in Keycloak yet | the redirect registrar adds it within 15 seconds of the route appearing; check with `make keycloak-redirects`, register with `make keycloak-register KC_USER=dana` |
| The agent has no `slack-reader` / `gmail-reader` tools | the bundle is not mounted, or OpenClaw did not load it | see Limits in [daily-briefing.md](daily-briefing.md#limits) |

From the command line, as an administrator:

```bash
# 5. The installer's status, the providers' token refresh, the sandbox log
make saw-status OPENSHELL_SAW_NAME=dana
make saw-configure OPENSHELL_SAW_NAME=dana
openshell gateway login dana              # sign in as dana in the browser
openshell provider refresh status slack --workspace personal-assistant
openshell provider refresh status gmail --workspace personal-assistant
openshell logs assistant --workspace personal-assistant --source sandbox
```

## Clean up

In Developer Hub, as dana: open `saw-dana` in the Catalog and use **Delete
workspace**. The pipeline removes the VM, the namespace and dana's keys in
Vault. dana's Keycloak account stays; remove it in the Keycloak console if
you no longer need it.
