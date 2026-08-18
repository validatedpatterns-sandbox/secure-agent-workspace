# Two-VM OpenClaw and Gmail-read POC

This runbook reproduces the verified OpenShift Virtualization deployment with
two VMs and two independent OpenShell gateways:

```text
Operator workstation
  |
  | oc port-forward (local 28789 -> service 18789)
  v
Agent VM: saw-agent
  OpenShell Gateway A
    `- OpenClaw sandbox
         |- inference.local -> OpenAI (credential resolved by Gateway A)
         `- gog -> internal Service :18080
                    |
                    | random inter-VM bearer
                    v
Integration VM: saw-integrations
  OpenShell Gateway B
    `- Gmail-read proxy sandbox
         `- gmail.googleapis.com
              (OAuth access token resolved by Gateway B)
```

The gateways do not federate. Each manages only the sandboxes on its own VM.
The VMs communicate over ordinary TCP through a namespace-internal OpenShift
Service. The agent never receives the Google OAuth credential, and the
integration VM never receives the OpenAI credential.

This milestone includes Gmail reads only. Gmail writes, Keycloak, an OAuth
front door, and external Routes are intentionally out of scope.

## Verified versions and images

The POC was verified with:

- OpenShell Gateway, supervisor, and CLI `0.0.106` on both VMs.
- Gmail proxy source branch `feat/openshell-two-vm-proxy` at commit `8998cf9`.
- Custom `gog` source commit `91d4451`, included by the OpenClaw image.
- OpenClaw CSB source commit `e278c7f`.
- Linux amd64 Gmail proxy image:
  `quay.io/sallyom/forge-gmail-read-proxy@sha256:dfb6ba5c61745c564035ea49b4e95ed2b21132b49c279c046e8e15e5e9b00f20`
- Linux amd64 OpenClaw image:
  `quay.io/sallyom/openclaw-openshell@sha256:fcd2a6b618293a4fc62c158cc2e7113e93d8d592addc5470ad75e586116cf592`

Use architecture-specific digests rather than mutable tags. The image build
system is intentionally outside this runbook.

## Prerequisites

Start from the `secure-agent-workspace` checkout. The Gmail deployment script
also expects `forge-proxy-gateways` in the adjacent directory:

```text
secure-agent-workspace/
forge-proxy-gateways/
```

You need:

- An OpenShift cluster with OpenShift Virtualization.
- Permission to create namespaces, VMs, DataVolumes, Services, Jobs, Secrets,
  and NetworkPolicies.
- Permission to clone the golden-image DataSource across namespaces.
- `oc`, `helm`, `virtctl`, `jq`, and `gog` on the workstation.
- A Google Desktop OAuth client authorized for the account being tested.
- An OpenAI API key in the local `OPENAI_API_KEY` environment variable.

The commands below use a shared example namespace instead of a personal one.
Change it once here if your team uses another namespace:

```bash
export NS=secure-agent-workspace-poc
export DATA_SOURCE_NAMESPACE=openshell-agents
export DATA_SOURCE=openshell-gateway
export VIRTCTL=virtctl
export SSH_KEY_PATH="$HOME/.generated-ssh-keys/sandbox-ssh"
export LOCAL_UI_PORT=28789

export GMAIL_READ_IMAGE='quay.io/sallyom/forge-gmail-read-proxy@sha256:dfb6ba5c61745c564035ea49b4e95ed2b21132b49c279c046e8e15e5e9b00f20'
export OPENCLAW_IMAGE='quay.io/sallyom/openclaw-openshell@sha256:fcd2a6b618293a4fc62c158cc2e7113e93d8d592addc5470ad75e586116cf592'
```

Confirm the cluster and permissions before creating anything:

```bash
oc whoami
oc auth can-i create namespaces
oc auth can-i create virtualmachines.kubevirt.io -n "$NS"
oc auth can-i create networkpolicies.networking.k8s.io -n "$NS"
oc auth can-i create datavolumes.cdi.kubevirt.io -n "$NS"
oc auth can-i create datavolumes/source -n "$DATA_SOURCE_NAMESPACE"
oc get datasource "$DATA_SOURCE" -n "$DATA_SOURCE_NAMESPACE"
```

## 1. Create the two gateway VMs

Generate the SSH key if it does not already exist, then install the two Helm
releases:

```bash
make generate-keys

NS="$NS" \
DATA_SOURCE="$DATA_SOURCE" \
DATA_SOURCE_NAMESPACE="$DATA_SOURCE_NAMESPACE" \
SSH_KEY_PATH="$SSH_KEY_PATH" \
scripts/deploy-two-vm-poc.sh

oc -n "$NS" wait \
  --for=condition=complete \
  job/saw-agent-setup job/saw-integrations-setup \
  --timeout=30m

oc -n "$NS" get vm,vmi,service
```

Expected result:

- `saw-agent` and `saw-integrations` VMs are running and ready.
- Each VM has its own OpenShell Gateway, supervisor, and CLI.
- `saw-agent-gateway` and `saw-integrations-gateway` are internal Services.
- No external Route or LoadBalancer exists.

## 2. Bootstrap the Gmail-read boundary on Gateway B

Deploy the Gmail proxy sandbox:

```bash
NS="$NS" \
VIRTCTL="$VIRTCTL" \
SSH_KEY_PATH="$SSH_KEY_PATH" \
GMAIL_READ_IMAGE="$GMAIL_READ_IMAGE" \
scripts/deploy-gmail-read-proxy.sh
```

This script:

1. Generates a random inter-VM bearer on `saw-agent`. The raw value stays in a
   mode-0600 file on that VM and is never stored in Kubernetes or copied to
   Gateway B.
2. Gives the Gmail proxy only the SHA-256 verifier for that bearer.
3. Creates the `gmail-read` provider on Gateway B with a temporary invalid
   credential so the sandbox can be bootstrapped before OAuth is configured.
4. Creates the `gmail-read` sandbox from the pinned image and attaches the
   provider using an OpenShell resolver placeholder.
5. Starts the proxy forward on Gateway B port 18080.
6. Applies `gmail-read-networkpolicy.yaml`, allowing Agent VM traffic to port
   18080 while leaving Gmail write paths denied by the application fence.
7. Verifies that an unauthenticated request returns 401 and a write path
   returns 403.

The script intentionally refuses to overwrite an existing sandbox.

## 3. Install the real Gmail-read credential on Gateway B

Authorize the intended Google account locally with only Gmail read scope. The
OAuth client JSON contains a secret, so restrict its permissions first:

```bash
export GMAIL_ACCOUNT='teammate@example.com'
export GMAIL_OAUTH_CLIENT_JSON="$HOME/.creds/google-oauth-client.json"

chmod 600 "$GMAIL_OAUTH_CLIENT_JSON"
gog auth credentials "$GMAIL_OAUTH_CLIENT_JSON"
gog auth add "$GMAIL_ACCOUNT" \
  --services gmail \
  --gmail-scope readonly \
  --readonly \
  --force-consent
gog auth list --check --json
```

The selected account should report `valid: true`, service `gmail`, and scope
`https://www.googleapis.com/auth/gmail.readonly`.

Export the refresh token only into a temporary mode-0700 directory, stream the
three OAuth inputs through SSH stdin into Gateway B, and remove the export. No
secret appears in a command argument or terminal output:

```bash
OAUTH_TMP="$(mktemp -d /tmp/saw-gmail-oauth.XXXXXX)"
TOKEN_FILE="$OAUTH_TMP/token.json"
gog auth tokens export "$GMAIL_ACCOUNT" --out "$TOKEN_FILE" >/dev/null

jq -r -s '
  .[0] as $client |
  .[1] as $token |
  [
    ($client.installed // $client.web).client_id,
    ($client.installed // $client.web).client_secret,
    $token.refresh_token
  ] | .[]
' "$GMAIL_OAUTH_CLIENT_JSON" "$TOKEN_FILE" |
  "$VIRTCTL" -n "$NS" ssh cloud-user@vm/saw-integrations \
    --identity-file="$SSH_KEY_PATH" \
    --command='set -eu
      export PATH="$HOME/.local/bin:$PATH"
      IFS= read -r GMAIL_CLIENT_ID
      IFS= read -r GMAIL_CLIENT_SECRET
      IFS= read -r GMAIL_REFRESH_TOKEN
      export GMAIL_CLIENT_SECRET GMAIL_REFRESH_TOKEN
      openshell provider refresh configure \
        --credential-key GMAIL_ACCESS_TOKEN \
        --strategy oauth2-refresh-token \
        --material "client_id=${GMAIL_CLIENT_ID}" \
        --secret-material-env client_secret=GMAIL_CLIENT_SECRET \
        --secret-material-env refresh_token=GMAIL_REFRESH_TOKEN \
        gmail-read
      unset GMAIL_CLIENT_ID GMAIL_CLIENT_SECRET GMAIL_REFRESH_TOKEN
      openshell provider refresh rotate \
        --credential-key GMAIL_ACCESS_TOKEN gmail-read
      openshell provider refresh status gmail-read'

rm -f "$TOKEN_FILE"
rmdir "$OAUTH_TMP"
unset OAUTH_TMP TOKEN_FILE
```

Do not continue until the refresh status is `refreshed` with no last error.

The sandbox was created while the provider held the bootstrap credential.
Replace only that disposable sandbox so the new process receives the real
provider binding; the provider and refresh configuration remain in Gateway B:

```bash
"$VIRTCTL" -n "$NS" ssh cloud-user@vm/saw-integrations \
  --identity-file="$SSH_KEY_PATH" \
  --command='export PATH="$HOME/.local/bin:$PATH"; openshell sandbox delete gmail-read'

until ! "$VIRTCTL" -n "$NS" ssh cloud-user@vm/saw-integrations \
  --identity-file="$SSH_KEY_PATH" \
  --command='export PATH="$HOME/.local/bin:$PATH"; openshell sandbox get gmail-read' \
  >/dev/null 2>&1; do
  sleep 2
done

NS="$NS" \
VIRTCTL="$VIRTCTL" \
SSH_KEY_PATH="$SSH_KEY_PATH" \
GMAIL_READ_IMAGE="$GMAIL_READ_IMAGE" \
scripts/deploy-gmail-read-proxy.sh
```

## 4. Deploy OpenClaw on Gateway A

```bash
NS="$NS" \
VIRTCTL="$VIRTCTL" \
SSH_KEY_PATH="$SSH_KEY_PATH" \
OPENCLAW_IMAGE="$OPENCLAW_IMAGE" \
scripts/deploy-openclaw-sandbox.sh
```

The script creates the `gmail-read-proxy` transport provider on Gateway A. It
contains only the random inter-VM bearer. The OpenClaw sandbox receives a
resolver placeholder and these non-secret settings:

```text
GOG_GMAIL_BASE_URL=http://saw-integrations-gateway.<namespace>.svc.cluster.local:18080/
GOG_READONLY=1
```

It also creates the persistent `openclaw-csb-data` volume, generates a
mode-0600 Control UI token on the Agent VM, starts OpenClaw, and forwards Agent
VM port 18789 to the sandbox.

## 5. Install the OpenAI inference credential on Gateway A

The following streams the existing local `OPENAI_API_KEY` through SSH stdin.
It does not print the key or place it in a command argument:

```bash
test -n "${OPENAI_API_KEY:-}"

printf '%s\n' "$OPENAI_API_KEY" |
  "$VIRTCTL" -n "$NS" ssh cloud-user@vm/saw-agent \
    --identity-file="$SSH_KEY_PATH" \
    --command='set -eu
      export PATH="$HOME/.local/bin:$PATH"
      IFS= read -r OPENAI_API_KEY
      export OPENAI_API_KEY
      openshell provider create \
        --name openai-inference \
        --type openai \
        --credential OPENAI_API_KEY
      unset OPENAI_API_KEY
      openshell inference set \
        --provider openai-inference \
        --model gpt-5.6-sol
      openshell inference get'
```

If `openai-inference` already exists, inspect it with
`openshell provider get openai-inference` instead of recreating it.

Verify inference from inside the OpenClaw sandbox:

```bash
"$VIRTCTL" -n "$NS" ssh cloud-user@vm/saw-agent \
  --identity-file="$SSH_KEY_PATH" \
  --command='export PATH="$HOME/.local/bin:$PATH"
    openshell sandbox exec -n openclaw-csb --no-tty -- \
      curl -fsS --max-time 60 \
      https://inference.local/v1/chat/completions \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer unused" \
      --data-binary '\''{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"Reply exactly: OK"}],"max_completion_tokens":32}'\'''
```

Expected result: a successful response containing `OK`.

## 6. Verify Gmail end to end

Run a real Gmail read from the OpenClaw sandbox while discarding all message
output:

```bash
"$VIRTCTL" -n "$NS" ssh cloud-user@vm/saw-agent \
  --identity-file="$SSH_KEY_PATH" \
  --command="export PATH=\"\$HOME/.local/bin:\$PATH\"
    openshell sandbox exec -n openclaw-csb --no-tty -- /bin/sh -lc '
      GOG_ACCOUNT=\"$GMAIL_ACCOUNT\" \
      gog gmail search \"is:unread\" --max 1 --json >/dev/null && \
      echo gmail-read-end-to-end-ok
    '"
```

Expected result: `gmail-read-end-to-end-ok`.

`gog` may note that it received a direct access token. That is expected: `gog`
does not hold the refresh token; Gateway B rotates the provider credential and
resolves the current access token at egress.

## 7. Open the OpenClaw Control UI

Keep this port-forward running in one terminal. Local port 28789 avoids a
collision with a local OpenClaw instance on 18789:

```bash
oc -n "$NS" port-forward service/saw-agent-gateway \
  "$LOCAL_UI_PORT":18789
```

On macOS, copy the Control UI token without displaying it:

```bash
"$VIRTCTL" -n "$NS" ssh cloud-user@vm/saw-agent \
  --identity-file="$SSH_KEY_PATH" \
  --command='cat /home/cloud-user/.config/secure-agent-workspace/openclaw-gateway-token' |
  tr -d '\r\n' |
  pbcopy
```

Open this URL, paste the token after `=`, and press Enter:

```text
http://localhost:28789/#token=
```

The token is in the URL fragment, which is handled browser-side rather than
sent as part of the HTTP request. Use the platform clipboard command instead
of `pbcopy` on non-macOS workstations.

## Security boundaries

| Secret | Stored by | Available to |
|---|---|---|
| OpenAI API key | Gateway A provider store | `inference.local` route only |
| Google client secret and refresh token | Gateway B provider store | OAuth refresh mechanism only |
| Google access token | Gateway B provider store | Gmail proxy egress placeholder only |
| Random inter-VM bearer | Gateway A provider store and mode-0600 VM file | `gog` requests to Gateway B only |
| OpenClaw UI token | Mode-0600 file on Agent VM | Operator accessing the forwarded UI |

Never put these values in Helm values, Kubernetes manifests, Git, shell
arguments, or this document.

The applied integrations NetworkPolicy permits Agent VM traffic only to Gmail
proxy port 18080. Port 22 remains available inside the cluster network for
KubeVirt SSH tunneling and still requires the VM SSH key. Gmail writes remain
blocked by the proxy's method and path allowlists.

## Known limitations

- OpenShell forwards are background CLI processes. Restart them after a VM or
  gateway reboot; a later milestone should manage them declaratively or with
  systemd.
- The broader Agent egress policy in `deploy/two-vm/networkpolicy.yaml` is not
  applied because it would block inference until the AI Gateway destination is
  explicitly allowlisted.
- The bootstrap flow temporarily creates the Gmail provider with an invalid
  token, then replaces the sandbox after OAuth configuration.
- Keycloak and an OAuth front door remain future work.

## Troubleshooting

- `401` from Google after configuring OAuth: confirm
  `openshell provider refresh status gmail-read` reports `refreshed`, then
  replace the Gmail sandbox so it receives the updated provider binding.
- Unexpected proxy behavior: confirm the deployment uses the exact tested
  amd64 digest listed in this runbook.
- Control UI does not load: verify both `openshell forward list` on Gateway A
  and the local `oc port-forward` process.
- `address already in use` locally: change `LOCAL_UI_PORT`; keep the remote
  side mapped to 18789.
