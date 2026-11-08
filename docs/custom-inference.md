# Custom inference endpoint (vLLM, Ollama, NIM, any OpenAI-compatible server)

A SAW can use a model server of your own instead of a cloud provider.
OpenShell 0.1.x removed managed inference routing (`openshell inference`,
`https://inference.local`), so the agent calls the endpoint itself:

- The endpoint, the model and the key are the `inference` Secret (`url`,
  `model`, `api_key`). The `custom-inference` SAW-BOM profile reads them
  through the sandbox's `inference:` block; the installer validates the URL
  and onboards OpenClaw against it.
- The key never enters the VM or sandbox. The namespace credential proxy
  replaces a marker only for the host of `url` in the credential Secret.
  Keyed endpoints require HTTPS on port 443 with a publicly trusted
  certificate. The gateway's governance profile separately permits the
  sandbox binary to reach that host.
- The pattern publishes an example profile under
  `overrides/governance-profiles/custom-inference.yaml`. Set its endpoint
  to your approved host; `governance-extra-profiles` serves it next to the
  shipped profiles. Publishing it alone grants no VM egress or credential
  destination. Use one profile per credential rather than reusing the
  `openai` profile for another host.

This configures an agent to call an existing server; it does not deploy a
model on the cluster. A tested hosted-API example uses `https://integrate.api.nvidia.com/v1` with model
`nvidia/nemotron-3.5-lightning-30b-a3b` and an API key referenced from
`~/.nvidia-api-key`; inference runs on NVIDIA's servers.

## Configure

1. **The profile.** Edit the existing
   `overrides/governance-profiles/custom-inference.yaml` and set `endpoints`
   to your server. Its file is already listed in the active
   `configMapGenerator` in `overrides/governance-profiles/kustomization.yaml`;
   no copy or uncomment step is needed:

   ```yaml
   id: custom-inference
   ...
   endpoints:
     - host: models.example.com    # the host of the url below
       port: 443                   # keyed HTTPS only
       protocol: rest
       enforcement: enforce
       access: read-write
   ```

   The proxy binds a deployment-owned provider only to the Secret's `url`
   host, even if its governance profile lists more hosts. A second server
   with its own key is a second file with its own
   `id`, used by a provider with that `type` **and that name**: the
   governance interceptor matches a sandbox's providers by profile id, so a
   governed provider is always named after its type (the installer refuses
   anything else).

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
   | `api_key` | the server's key, mounted only by the namespace proxy; for keyless HTTP use `API_KEY=''` in quickstart |
   | `provider` | optional: `custom-inference` (the installer refuses a key labelled for another service); leave it out of a Secret shared with other profiles |

   The VM mounts `inference-meta`, containing every non-credential field
   selected by the profile catalog (including `url`, `model`, and optional
   `provider`), with no `api_key`. A deployment-owned keyed provider's
   `inference.baseUrl` must reference `{secretKeyRef: {name: inference, key: url}}`
   so the installer and proxy use the same host.

5. **Deploy and wait.** Run `./pattern.sh make load-secrets`, then
   `make keycloak-add-users` to create any missing accounts from the local
   user file. Commit and push steps 1-3 to the branch Argo CD watches.
   Wait for `governance-extra-profiles`, `saw-<user>`, `saw-<user>-bom`, and
   `saw-<user>-secrets` to be Synced/Healthy. A new VM applies its inputs on
   boot; restart only an existing VM with
   `make saw-restart OPENSHELL_SAW_NAME=<user>`. Follow
   `make saw-logs OPENSHELL_SAW_NAME=<user>` until `apply: Done`.
   Argo CD health is not proof that the in-VM installer finished.

   The [README walkthrough](../README.md#custom-inference-provider) shows
   the full command sequence and shared Secret example.

### Open the notebook chat

A GitOps entry does not automatically appear in the RHDH workspace catalog
or create a Tekton run. The shipped custom-inference notebook also has no
UI Route enabled. Use the documented CLI tunnel after `apply: Done`:

```bash
make saw-configure OPENSHELL_SAW_NAME=erin SAW_NS=saw-erin
make openclaw-gui OPENSHELL_SAW_NAME=erin SAW_NS=saw-erin \
  WORKSPACE=default SANDBOX_NAME=notebook GUI_PORT=28789
```

Replace `erin` and `saw-erin` with your user and namespace. Sign in as the
workspace owner when prompted; `make keycloak-password KC_USER=erin`
copies Erin's password using an available clipboard tool. Keep the GUI
command running while using the browser.

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

- The **credential proxy** must reach keyed HTTPS endpoints; the **VM**
  must reach keyless HTTP endpoints such as `http://vllm.<ns>.svc:8000/v1`.
  `localhost` is refused.
- `url` must be `http(s)://host[:port][/path]` without credentials, query or
  fragment. The installer rejects anything else without logging the value.
- A keyed HTTPS endpoint must use port 443 and a publicly trusted
  certificate. Other HTTPS ports are refused. HTTP bypasses credential
  injection and sends only a marker, so use it only for a keyless server.
  Custom keyed ports and in-cluster service-CA trust are follow-up work.
- `inferenceTimeout` on a provider is no longer used: there is no gateway
  router to time out. Use the sandbox's `inference.timeoutSeconds`.

### Keycloak compatibility

Keycloak releases enforcing [Admin REST audience checks](https://www.keycloak.org/docs/26.8.2/upgrading/#admin-rest-api-now-enforces-an-audience-check)
require both the Admin API audience and the built-in `kc-admin-api` scope
on service-account tokens. SAW's updated bootstrap assigns it as a default
scope to the owner resolver, redirect registrar, and the RHDH client when
its catalog-reader service account is enabled. Older realms without that
scope retain their existing behavior.

Deploy that bootstrap update before creating new workspaces on these
Keycloak releases. Roles alone are insufficient: HTTP 401 with
`Expected audience not available in the token` indicates this compatibility
issue, rather than missing custom-inference settings or a user login.
The fix was tested with Red Hat build of Keycloak `26.6.9.redhat-00002`.

## Limitations

- One custom endpoint per deployment is the shipped shape; a second server
  is a second profile file and a provider of that type (and, for the shipped
  `custom-inference` BOM profile, a copy of it with that type).
- With governance **off** the gateway reads only the profiles the installer
  ships; extra profiles are not delivered to the VM. Keep governance on for
  custom endpoints.
- NemoClaw sandboxes onboard their own provider settings; the profile only
  ships an OpenClaw sandbox.
