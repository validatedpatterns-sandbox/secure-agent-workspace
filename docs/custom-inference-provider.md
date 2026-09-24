# Using a Custom vLLM / OpenAI-Compatible Inference Endpoint

This guide explains how to configure the Secure Agent Workspace (SAW) to use a self-hosted vLLM model or any OpenAI-compatible inference endpoint instead of a cloud provider.

## Overview

By default SAW connects agents to cloud inference APIs (NVIDIA NIM, Gemini, Anthropic, etc.). You can point it at any OpenAI-compatible endpoint — for example, a [vLLM](https://github.com/vllm-project/vllm) or [Ollama](https://ollama.com) server running inside your OpenShift cluster.

## Prerequisites

- SAW installed on an OpenShift cluster (see [README](../README.md))
- An OpenAI-compatible inference server accessible via an OpenShift Route
- The cluster domain (e.g. `apps.cluster-abc.example.com`)

## Step 1: Get an OpenAI-Compatible Endpoint

You need an HTTP endpoint that implements the [OpenAI chat completions API](https://platform.openai.com/docs/api-reference/chat). Any of the following work:

- **[vLLM](https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html)** — high-throughput serving, GPU recommended
- **[Ollama](https://ollama.com)** — easy to run on CPU; exposes `/v1` for OpenAI compatibility
- **[RHOAI Model Serving](https://docs.redhat.com/en/documentation/red_hat_openshift_ai_self-managed)** — if you have Red Hat OpenShift AI installed, use a KServe InferenceService with a vLLM ServingRuntime
- **Any other OpenAI-compatible server** — as long as it exposes `/v1/chat/completions`

The endpoint must be reachable as an OpenShift Route (HTTPS). Note the Route **hostname** (e.g. `my-model.apps.cluster-abc.example.com`) — you will need it in Steps 2 and 3.

## Step 2: Set the Inference Secret

Add the `url` field to your local `~/values-secret.yaml` under the `inference` block:

```yaml
- name: inference
  fields:
  - name: provider
    value: custom          # tells the BOM to use the custom/openai profile
  - name: model
    value: tinyllama:latest  # must match the model name served by your endpoint
  - name: api_key
    value: "<endpoint-api-key>" # use a dummy value only if your server has auth disabled
  - name: url
    value: "https://<your-vllm-route>/v1"
```

> **Note:** Setting `provider: custom` automatically creates the compatible provider in `vllm`. NVIDIA providers and sandboxes requiring them are skipped before image pulls or readiness polling. Workspace records and independent providers such as Brave may still be created. Sandboxes in `vllm` connect to your endpoint through the OpenShell governance proxy.

The custom profile requires an explicit `provider: custom`. A cloud provider
such as `openai`, `build`, or `gemini`, or an unset provider type, skips that
profile and its dependent sandbox. Only an eligible custom provider is checked
for a nonempty endpoint and model. Cloud secrets may omit `url` entirely.

## Step 3: Set the Governance Profile Host

The governance interceptor enforces egress from sandboxes. You must declare the allowed endpoint host before installing.

The repository ships `customEndpointHost: ""`, which renders no custom profile.
Set `overrides/governance-policy.yaml` in your deployment branch (keep the reusable
default empty):

```yaml
customEndpointHost: "<your-vllm-route-hostname>"
# Example:
# customEndpointHost: "vllm-tinyllama-vllm-test.apps.cluster-abc.example.com"
```

Commit and push this file:

```bash
git add overrides/governance-policy.yaml
git commit -m "chore: set vLLM endpoint for <cluster-name>"
git push
```

## Step 4: Install

```bash
export TARGET_REVISION='<your-branch>'   # e.g. main
./pattern.sh make install
```

The installation:
1. Pushes secrets to Vault (including the `url` field)
2. Deploys the governance-policy chart with the `openai.yaml` profile containing your endpoint
3. Runs the BOM setup job which creates:
   - A `vllm` workspace on the gateway
   - An `openai`-type provider with `base_url` pointing to your endpoint
   - A `notebook` sandbox using the `openai` provider

## Step 5: Verify

After logging in and configuring the gateway on your workstation (or from the
configured gateway VM), check:

```bash
# List provider profiles — should show your endpoint
openshell provider list-profiles | grep openai

# List providers in the vllm workspace
openshell provider list --workspace vllm

# Check sandbox is Ready
openshell sandbox list --workspace vllm
openshell sandbox get notebook --workspace vllm
```

The list should include `notebook` with phase `Ready`.

**If `openshell sandbox list` reports `No sandboxes found` after a successful
login:** the command without `--workspace` lists the default workspace. The
custom inference notebook lives in `vllm`, so use `--workspace vllm` when listing,
inspecting, or executing commands in it. An empty default workspace is expected
when its NVIDIA-dependent notebook was skipped for the custom provider; it does
not mean authentication or notebook provisioning failed.

Test inference from inside the sandbox:

```bash
openshell sandbox exec -n notebook --workspace vllm --no-tty --timeout 150 \
  --env 'INFERENCE_URL=https://<your-vllm-route>/v1/chat/completions' -- sh -c '
  curl -sS --fail-with-body --connect-timeout 10 --max-time 120 \
    "$INFERENCE_URL" -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${OPENAI_API_KEY:?managed credential missing}" \
    -d "{\"model\":\"tinyllama:latest\",\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}],\"max_tokens\":20}"
  '
```

A successful response looks like:
```json
{
  "choices": [{"message": {"role": "assistant", "content": "Hello! ..."}}],
  "model": "tinyllama:latest"
}
```

> **Note:** The first inference request may take 1–2 minutes on CPU while the model loads. Subsequent requests are fast.

This curl check verifies sandbox egress and inference, not the OpenClaw agent.
For an agent turn using its configured model and gateway, run:

```bash
openshell sandbox exec -n notebook --workspace vllm --no-tty --timeout 150 -- \
  env OPENCLAW_HOME=/sandbox OPENCLAW_NIX_MODE=0 \
  openclaw agent --agent main --session-id custom-provider-validation \
  --message "Say hello briefly." --timeout 120 --json
```

Require an actual assistant response and confirm the intended model/endpoint
in the result or server-side request records. A successful health check alone
does not establish this. For authenticated-endpoint validation, use a test server
that enforces its key: the managed-credential request must succeed, while the
same curl request with `Authorization: Bearer intentionally-wrong` must fail
with 401/403. Do not print the injected environment value or real key.

Authenticated custom inference and the OpenClaw turn still require live rollout
validation of the review fixes. Earlier keyless TinyLlama curl success does not
cover those checks. The NVIDIA `inference.local` path has been tested separately;
Gemini live inference has not.

## How It Works

```
values-secret.yaml (url field)
  → Vault → ESO → inference K8s Secret
    → setup-bom-profiles.sh → PROV_OPENAI_URL in bom.env
      → apply_bom.py → openshell provider create \
          --type openai \
          --config base_url=<url>
        → Sandbox created with _provider_openai network policy
          → Sandbox egress to <vllm-host>:443 allowed for node + curl
```

The governance profile allows `/usr/local/bin/node` and `/usr/bin/curl` to reach
the configured endpoint. It declares `OPENAI_API_KEY` as a bearer credential and
requires TLS termination so OpenShell can resolve its endpoint-bound placeholder
before forwarding HTTP. OpenClaw receives that placeholder through
`CUSTOM_API_KEY`, never the real Vault key. Setup fails if a direct custom endpoint
has no managed placeholder; `proxy-managed` remains exclusive to the
`https://inference.local/v1` routing path. TLS verification remains enabled.

On repeat setup, provider creation failures fail provisioning. A duplicate name
is accepted only after checking the provider's workspace and type and successfully
reconciling the desired credential and endpoint. A cloud provider with an
unexpected existing custom endpoint is rejected for inspection instead of silently
reused. Dependent sandboxes are not onboarded after provider provisioning fails.
Older custom providers using the generic `API_KEY` credential are migrated to
`OPENAI_API_KEY` during that reconciliation.

## Switching Back to a Cloud Provider

Change `~/values-secret.yaml`:

```yaml
- name: inference
  fields:
  - name: provider
    value: build            # NVIDIA NIM
  - name: model
    value: nvidia/nemotron-3-super-120b-a12b
  - name: api_key
    path: ~/.nvapi-key
  - name: url
    value: ""               # empty = no custom endpoint
```

And clear the governance override:

```yaml
# overrides/governance-policy.yaml
customEndpointHost: ""
```

Then reinstall.

## Known Limitations

- **Profile selection**: workspace directories are still processed. Disabled or incompatible providers and sandboxes requiring any of them are skipped consistently during deployment and verification. Independent compatible providers remain enabled. Selection of entire workspaces remains future work.

- The `vllm` provider accepts `inference.provider=custom` through its `nemoclawProvider: custom` alias. Its `urlSecretKey: url` and `modelSecretKey: model` fields read the endpoint and model from the inference secret. Set `model` to the exact name served by the endpoint; the setup fails if that required secret field is missing.

## Compatibility and deployment checks

Existing cloud-provider Vault records do not need `url`: missing or empty URLs
become an empty string in the inference Secret. `provider`, `model`, and `api_key`
remain required fields. Custom inference requires a nonempty URL and model.
No manual provider creation is needed. URLs and models in `bom.env` are shell-quoted.

Check each layer separately on the gateway VM:

```bash
systemctl --user status openshell-gateway.service --no-pager
systemctl --user show openshell-gateway.service -p ExecStartPre -p NRestarts
openshell sandbox get notebook --workspace vllm
openshell sandbox provider list notebook --workspace vllm
# OpenClaw readiness does not prove successful inference
openshell sandbox exec -n notebook --workspace vllm -- curl -sf http://127.0.0.1:18789/health
# Dashboard and authentication proxy, when enabled
systemctl --user is-active openshell-dashboard.service openshell-dashboard-proxy.service
curl -f http://127.0.0.1:8090/api/v1/healthz
curl -f http://127.0.0.1:8080/ping
```

Then run the chat-completion request in the verification section and confirm a
valid response. Open the web UI route and complete OIDC login separately.

## Troubleshooting and upgrades

- If sandbox requests hang after CONNECT/TLS while the same route works from
  the VM, check Docker MTU. OpenShift VM uplinks can use 1400 while Docker defaults
  to 1500, causing the proxy's upstream TLS handshake to stall. Docker setup runs
  `configure-docker-mtu.sh` before gateway startup: it derives the uplink MTU,
  creates new `openshell-docker` networks with that MTU, and reconciles the existing
  bridge and attached container interfaces. Existing Docker network options are
  immutable, so IPv4 TCP MSS rules in both directions, scoped to that bridge/uplink,
  also limit segment sizes for future containers on older networks. New-container
  large-request/response validation on an old network remains a rollout check.
  No network deletion, policy bypass, or TLS
  verification disablement is needed. This helper applies to Docker, not Podman.
- After updating scripts on an existing VM, run
  `sudo /usr/local/bin/openshell-configure-docker-mtu` to reconcile immediately.
  The root `openshell-docker-mtu.service` applies settings after Docker starts
  and before the gateway user manager starts; it also restarts with Docker.
  Setup removes the obsolete `zz-docker-mtu.conf` user-service hook so network
  configuration runs directly in the system manager without relying on `sudo`
  during user-service startup.
  Retry with a new connection; existing stalled requests should be cancelled.
- The cache hook uses `zz-prepopulate-cache.conf` to run after `route-san.conf`,
  which resets `ExecStartPre`. Upgrades remove the old `prepopulate-cache.conf`.
  Certificate generation and cache preparation must both succeed.
- Dashboard setup replaces its two managed unit entries, including baked-in
  symlinks or read-only files, with VM-user-owned files. It does not recursively
  change home-directory ownership. Enabled dashboard installation, restart, or
  120-second readiness failures now fail the setup Job.
- Intentional provider/sandbox skips appear as `SKIP`. Actual creation failures
  or readiness timeouts fail setup and stop OpenClaw onboarding for that sandbox.
- Keep-alive services include workspace and sandbox names. Setup starts and checks
  the replacement before disabling an existing legacy service with only the
  sandbox name. Replacement failure preserves the legacy service and fails setup.
- Uninstall watching defaults to 600 seconds; override with
  `./pattern.sh make uninstall UNINSTALL_TIMEOUT_SECONDS=900`. This bounds the
  playbook/watcher phase, not the entire Make target. Process cleanup adds at most
  five seconds for TERM and two seconds for reaping after KILL; an unreaped process
  is reported without blocking indefinitely. Pre/post-cleanup have separate waits:
  VMI, HyperConverged, and Namespace deletion each allow 120 seconds, and Argo app
  deletion allows 60 seconds per app. Kubernetes requests are individually bounded.
  Failures return nonzero and stop subsequent cleanup. Normal uninstall retains
  Namespace and HyperConverged finalizers, keeps CNV controllers available until
  HyperConverged deletion finishes, and does not run `clean-stale-operators`.
  Inspect the named resource's conditions, remaining dependents, and controller
  logs before retrying; do not remove finalizers or webhooks merely to force it away.
