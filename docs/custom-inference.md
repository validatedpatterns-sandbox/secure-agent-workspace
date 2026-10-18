# Custom inference endpoint (vLLM, Ollama, any OpenAI-compatible server)

A SAW can use a model server of your own instead of a cloud provider.
OpenShell 0.1.x removed managed inference routing (`openshell inference`,
`https://inference.local`), so the agent calls the endpoint itself:

- The installer creates an `openai` provider with the endpoint's base URL
  (`--config OPENAI_BASE_URL=<url>`) and a nonsecret marker, and attaches it to the sandbox.
- OpenClaw is onboarded against the endpoint's own URL, with the placeholder
  marker the sandbox holds in `OPENAI_API_KEY`. The per-namespace credential
  proxy replaces the marker with the real key only on a bound HTTPS host.
  The key never enters the VM.
- So the provider's **profile must name the endpoint's host**. The shipped
  `openai` profile allows `api.openai.com` only; see Requirements.

## Configure

1. Use the `custom-inference` SAW-BOM profile instead of `data-science`
   (saw-bom values, e.g. `overrides/saw-bom.yaml`):

   ```yaml
   profiles:
     - custom-inference
   ```

2. Put the endpoint in the `inference` Secret (in `~/values-secret-secure-agent-workspace.yaml`,
   which the pattern reads before `~/values-secret.yaml`; see `values-secret.yaml.template`).
   With the quickstart, one command does steps 1 and 2:

   ```bash
   make saw-create OPENSHELL_SAW_NAME=<name> PROFILES=custom-inference \
     PROVIDER=openai MODEL=<served model> ENDPOINT_URL=https://<host>/v1 API_KEY=<key>
   ```

   The Secret's keys:

   | Key | Value |
   |---|---|
   | `provider` | `openai` (OpenShell's provider type for any OpenAI-compatible API) |
   | `model` | the model name the server serves, e.g. `meta-llama/Llama-3.1-8B-Instruct` |
   | `url` | the OpenAI-compatible base URL, ending in `/v1` |
   | `api_key` | the server's key, held only in the namespace proxy Secret |

3. Restart the VM (`make saw-restart`) so the installer applies it.

## Requirements

- The **credential proxy** must reach the URL, not your laptop. Use an HTTPS
  Route host on port 443 for a keyed endpoint whose certificate chains to the
  proxy image's system trust roots; `localhost` is refused.
- If that host is outside the cluster, add it to `egress.extraAllow` in the
  `openshell-saw` values (see [Egress from the VM](deployment-guide.md#egress-from-the-vm))
  **before** upgrading a sandbox that already runs. The firewall turns on at
  the next sync and cannot read the URL from Vault, so inference to that host
  times out. A `*.svc` address needs a narrow `networkPolicy.extraEgress`
  rule selecting the endpoint's namespace, pods, and TCP port; it needs no
  EgressFirewall hostname entry. An `http://` or `https://`
  golden-image URL is allowed on its own; that does not cover the inference host.
- `url` must be `https://host[:443][/path]` without credentials, query or
  fragment. A keyed HTTP URL exposes the marker to the endpoint and is
  unsupported; the installer warns about it. Other HTTPS ports are refused.
- The `openai` provider profile must name the endpoint's host. With
  governance on, the gateway uses only the governance catalog: set the
  `host`/`port` of the endpoint in `charts/governance-policy/profiles/openai.yaml`
  to your server's (keep `binaries`: OpenClaw runs under `node`). The
  provider's `OPENAI_BASE_URL` alone is not enough: OpenShell never sends
  the marker to a host the profile does not name. The credential proxy also
  binds the Secret key to that host.
- `inferenceTimeout` is still accepted but no longer used: there is no
  gateway router to time out.

## Limitations

- Not yet verified end to end on OpenShell 0.1.x; the installer does not
  yet generate a per-endpoint profile.
- NemoClaw sandboxes onboard their own provider settings; the profile only
  ships an OpenClaw sandbox.
