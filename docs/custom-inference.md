# Custom inference endpoint (vLLM, Ollama, NIM, any OpenAI-compatible server)

A SAW can use a model server of your own instead of a cloud provider.
OpenShell 0.1.x removed managed inference routing (`openshell inference`,
`https://inference.local`), so the agent calls the endpoint itself:

- The endpoint, the model and the key are the `inference` Secret (`url`,
  `model`, `api_key`). The `custom-inference` SAW-BOM profile reads them
  through the sandbox's `inference:` block; the installer validates the URL
  and onboards OpenClaw against it.
- The key never enters the sandbox: the sandbox holds a placeholder, and
  the gateway's proxy replaces it only on requests to a host the provider's
  **profile** names, from a binary the profile lists. So the endpoint's host
  must be in a provider profile; with governance on (the default) that
  catalog is the governance interceptor's.
- The pattern ships no profile for a host it cannot know. **You add one**,
  as a plain OpenShell profile file under `overrides/governance-profiles/`,
  and the `governance-extra-profiles` application serves it next to the
  shipped profiles. OpenShell recommends exactly this (one profile per
  credential) over reusing the `openai` profile for another host.

## Configure

1. **The profile.** Edit `overrides/governance-profiles/custom-inference.yaml`
   (shipped as an example) so `endpoints` names your server, and make sure
   the file is listed in `overrides/governance-profiles/kustomization.yaml`:

   ```yaml
   id: custom-inference
   ...
   endpoints:
     - host: vllm.models.svc        # the host of the url below
       port: 8000                   # its port (443 for https without one)
       protocol: rest
       enforcement: enforce
       access: read-write
   ```

   Several hosts that share one key (a Service and its Route) go in one
   profile; a second server with its own key is a second file with its own
   `id`, used by a provider with that `type`.

2. **Egress.** A host outside the cluster must be allowed by the VM
   firewall: `egress.extraAllow` under `defaults.openshellSaw` (or one
   user's `values`) in `overrides/saw-users.yaml`. An in-cluster Service
   (`*.svc`) needs a `networkPolicy.extraEgress` rule instead
   ([Egress from the VM](deployment-guide.md#egress-from-the-vm)).

3. **The profile selection.** The workspace uses `profiles: [custom-inference]`
   (a user entry in `overrides/saw-users.yaml`, the portal, or
   `make saw-create ... PROFILES=custom-inference`).

4. **The Secret** (`~/values-secret-secure-agent-workspace.yaml`, then
   `./pattern.sh make load-secrets`; the quickstart's `make saw-create
   PROVIDER=custom-inference MODEL=... ENDPOINT_URL=... API_KEY=...` writes
   the same keys):

   | Key | Value |
   |---|---|
   | `url` | the OpenAI-compatible base URL, ending in `/v1` |
   | `model` | the model name the server serves |
   | `api_key` | the server's key; any non-empty value if it needs none |
   | `provider` | optional: `custom-inference` (the installer refuses a key labelled for another service); leave it out of a Secret shared with other profiles |

5. Commit and push steps 1-3, wait for Argo CD, then restart the VM
   (`make saw-restart`) so the installer applies the Secret.

### Changing the endpoint

Change `url` in the Secret and `host`/`port` in the profile file (and
`extraAllow`), push, restart the VM. The sandbox is not recreated: the
endpoint is agent configuration (`inference:`), not sandbox environment, so
`/sandbox` is untouched; OpenClaw is onboarded again against the new URL.

## How the pieces fit

| Where | What | Changed by |
|---|---|---|
| `overrides/governance-profiles/<id>.yaml` | which host(s) the key may reach | git |
| `inference` Secret in Vault | `url`, `model`, `api_key` | `load-secrets` / the portal |
| `charts/saw-bom/profiles/custom-inference` | provider `type: custom-inference`; sandbox `inference:` reading the Secret | shipped |

The installer sees `custom-inference` as a type it neither has built in
nor ships, looks it up in the gateway's live catalog, and takes the
credential variable (`CUSTOM_INFERENCE_API_KEY`) from the served profile.
If the profile is not there yet (the extra-profiles app has not synced,
or the file is not listed), the apply fails before creating anything, with
a message naming this directory. The sandbox's `inference.protocol` is
stated (`openai`): the installer cannot infer it for a profile of your own.

## Requirements

- The **gateway VM** must reach the URL, not your laptop: a cluster Service
  (`http://vllm.<ns>.svc:8000/v1`) or a Route/host the firewall allows.
  `localhost` is refused.
- `url` must be `http(s)://host[:port][/path]` without credentials, query or
  fragment. The installer rejects anything else without logging the value.
- `inferenceTimeout` on a provider is no longer used: there is no gateway
  router to time out. Use the sandbox's `inference.timeoutSeconds`.

## Limitations

- One custom endpoint per deployment is the shipped shape; a second server
  is a second profile file and a provider of that type (and, for the shipped
  `custom-inference` BOM profile, a copy of it with that type).
- With governance **off** the gateway reads only the profiles the installer
  ships; extra profiles are not delivered to the VM. Keep governance on for
  custom endpoints.
- NemoClaw sandboxes onboard their own provider settings; the profile only
  ships an OpenClaw sandbox.
