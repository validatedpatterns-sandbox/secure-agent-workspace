# Custom inference endpoint (vLLM, Ollama, any OpenAI-compatible server)

A SAW can use a model server of your own instead of a cloud provider.
OpenShell 0.1.x removed managed inference routing (`openshell inference`,
`https://inference.local`), so the agent calls the endpoint itself:

- The installer creates an `openai` provider with the endpoint's base URL
  (`--config OPENAI_BASE_URL=<url>`) and the key (passed via the
  environment), and attaches it to the sandbox.
- OpenClaw is onboarded against the endpoint's own URL, with the placeholder
  key the sandbox holds in `OPENAI_API_KEY`. The sandbox proxy replaces the
  placeholder with the real key only on requests to an endpoint of the
  provider's profile, from a binary the profile lists. The key never enters
  the sandbox.
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
   make openshell-saw-create OPENSHELL_SAW_NAME=<name> PROFILES=custom-inference \
     PROVIDER=openai MODEL=<served model> ENDPOINT_URL=https://<host>/v1 API_KEY=<key>
   ```

   The Secret's keys:

   | Key | Value |
   |---|---|
   | `provider` | `openai` (OpenShell's provider type for any OpenAI-compatible API) |
   | `model` | the model name the server serves, e.g. `meta-llama/Llama-3.1-8B-Instruct` |
   | `url` | the OpenAI-compatible base URL, ending in `/v1` |
   | `api_key` | the server's key; any non-empty value if it needs none |

3. Restart the VM (`make openshell-saw-restart`) so the installer applies it.

## Requirements

- The **gateway VM** must reach the URL, not your laptop: use a cluster Service
  (`http://vllm.<ns>.svc:8000/v1`) or Route host. `localhost` is refused.
- If that host is outside the cluster, add it to `egress.extraAllow` in the
  `openshell-saw` values (see [Egress from the VM](deployment-guide.md#egress-from-the-vm))
  **before** upgrading a sandbox that already runs. The firewall turns on at
  the next sync and cannot read the URL from Vault, so inference to that host
  times out. A `*.svc` address needs no entry. An `http://` or `https://`
  golden-image URL is allowed on its own; that does not cover the inference host.
- `url` must be `http(s)://host[:port][/path]` without credentials, query or
  fragment. The installer rejects anything else without logging the value.
- The `openai` provider profile must name the endpoint's host. With
  governance on, the gateway uses only the governance catalog: set the
  `host`/`port` of the endpoint in `charts/governance-policy/profiles/openai.yaml`
  to your server's (keep `binaries`: OpenClaw runs under `node`). The
  provider's `OPENAI_BASE_URL` alone is not enough: OpenShell never sends
  the key to a host the profile does not name.
- `inferenceTimeout` is still accepted but no longer used: there is no
  gateway router to time out.

## Limitations

- Not yet verified end to end on OpenShell 0.1.x; the installer does not
  yet generate a per-endpoint profile.
- NemoClaw sandboxes onboard their own provider settings; the profile only
  ships an OpenClaw sandbox.
