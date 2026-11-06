# Provider qualification

The same SAW-BOM, governance profiles and namespace credential proxy apply to
VM and container deployments. The Kubernetes adapter supports a selected
OpenAI, Anthropic or NVIDIA provider; it also supports an explicitly approved
OpenAI-compatible custom endpoint. Anthropic uses `anthropic-messages`, not an
OpenAI compatibility endpoint. No OpenShell driver or agent image change is
required.

## Inputs

Use the [container installation](container-installation.md) procedure, including
site approval, digest-pinned images, RHDH enrollment and Vault/ESO provisioning.
For each provider, select it in the approved BOM; do not put a key in the BOM,
intent, application Pod, gateway or controller ledger.

| Provider type | Native endpoint | Protocol | Placeholder environment variable |
|---|---|---|---|
| `openai` | `https://api.openai.com/v1` | `openai` | `OPENAI_API_KEY` |
| `anthropic` | `https://api.anthropic.com` | `anthropic` | `ANTHROPIC_API_KEY` |
| `nvidia` | `https://integrate.api.nvidia.com/v1` | `openai` | `NVIDIA_API_KEY` |

Example BOM documents for an Anthropic qualification profile:

```yaml
apiVersion: saw.redhat.com/v1alpha1
kind: Providers
spec:
  providers:
    - name: anthropic
      type: anthropic
      credentialSecret: inference
      credentialSecretKey: api_key
---
apiVersion: saw.redhat.com/v1alpha1
kind: Sandboxes
spec:
  sandboxes:
    - name: notebook
      type: openclaw
      image: <approved-stock-openclaw-image>@sha256:<digest>
      providers: [anthropic]
      inference:
        providerRef: anthropic
        protocol: anthropic
        model: claude-sonnet-4-6
      ui:
        route: true
```

These are the provider/sandbox documents within a normal profile, not new
Kubernetes CRDs. Keep its Workspace document and normal catalog/site approval.
Use equivalent provider/model choices for OpenAI and NVIDIA. The controller
checks the native endpoint against the shipped governance profile and the
enrolled proxy policy. A public model selector is not a credential reference.
Simultaneously registering additional `inference.models` choices is still
rejected by the container compiler; qualify one selected provider per sandbox.

## Checks

First run the offline contracts:

```sh
make test-installer TEST_PATHS=tests/kubernetes_runtime
```

Node is required to execute the generated OpenClaw configuration. The Rust
compiler/governance test requires Cargo and cached `serde_json`; CI fetches this
dependency and makes the test mandatory. An offline skip is not a Rust pass.

For live qualification, use a disposable registration and the ordinary owner
login. Capture the Git revision, component image digests, cluster version,
registration identity, actual gateway driver, workload Pod UID and PVC UIDs.
Verify the stock Kubernetes driver created the workload; running inside a
KubeVirt VM on OpenShift does not qualify the Kubernetes driver.

With the owner's stock OpenShell CLI configured for that gateway:

```sh
GATEWAY=<configured-gateway-name>
WORKSPACE=default
SANDBOX=notebook
PROVIDER=openai
MODEL=gpt-4.1-mini-2025-04-14
openshell --gateway "$GATEWAY" sandbox exec -n "$SANDBOX" \
  --workspace "$WORKSPACE" --no-tty -- \
  node --input-type=module -e "$(cat tests/provider-inference-smoke.mjs)" \
  "$PROVIDER" "$MODEL"
```

Expected: `httpStatus: 200`, `nonceMatched: true`, exit 0. The script makes one
request from the sandbox, through its normal proxy path, to the provider's fixed
official endpoint. It prints no key, headers, provider error body or model reply.
Repeat with the selected Anthropic and NVIDIA models in their own registered
sandboxes. Do not substitute a direct request from the bastion for this check.
Use `openshell sandbox exec` for this probe: administrative `oc exec` into the
application container does not establish the OpenShell execution session or its
provider placeholder environment, so it does not test the owner's inference path.
Before a model-update test, run the same probe with the proposed model ID and
credential binding. Visibility in the provider's model catalog does not establish
that an inference request will succeed. Record a rejected model separately from
controller convergence and storage persistence.

Then exercise RHDH/OpenClaw:

1. **Create:** select **Container** and the approved profile. Wait for the
   matching registration/intent to become Ready. Open the owner-only chat link
   and request a unique token. Record the selected model and returned token.
2. **Update:** change the public model input through the normal update flow.
   Verify a fresh workload, the new model, successful chat and unchanged PVCs.
   Inspect the provider/model in the resulting chat transcript as well as the
   API probe. A stock agent's automatic configuration migration can change a
   model after startup; a correct public selector or direct API reply alone is
   insufficient.
3. **Restart:** use the normal stop/start intent. Verify chat and a workspace
   canary survive; check a fresh Pod UID and unchanged PVC UIDs.
4. **Isolation:** verify an unknown credential marker and an unapproved
   destination are denied, and another owner's browser login cannot open chat.
   Keep keys confined to the trusted credential-proxy namespace.
5. **Delete:** delete through RHDH. Verify foreground compute cleanup and the
   documented retained workspace/audit data disposition.

Keep a browser session open across a relay OIDC-token expiry. Check a new chat
connection and reconnection of an existing WebSocket separately, without
automatically resubmitting tool approvals or other non-idempotent operations.
Record any connection gap even if the relay subsequently recovers.

Record provider-by-provider results in the
[support matrix](provider-driver-support-matrix.md). Configuration tests,
authenticated API inference and browser lifecycle are separate evidence.

## VM regression alongside containers

Use a separate disposable **VM** registration with the same approved profile and
provider/model inputs. Repeat both sandboxes' API, owner-browser, shared tool-gate
and credential/owner-denial checks. Resolve the workspace from the stock agent
configuration; do not assume the container path. The tested stock VM images used
`/sandbox/.openclaw/workspace`.

After the RHDH model update completes, use the documented targeted VM restart:

```sh
KUBECONFIG=<cluster-kubeconfig> make saw-restart \
  DEPLOYMENT_MODE=vm OPENSHELL_SAW_NAME=<registration-name> \
  SAW_NS=<workspace-namespace>
```

Wait for the new VM instance and that instance's installer/BOM completion, not
stale completion markers from before the restart. Require the same VM/root-PVC
UIDs, a new VMI UID, unchanged workspace canaries and original audit records,
and the selected model in fresh API and browser-chat transcripts. Check that
temporary administrator files and trust entries have been removed.

Delete through RHDH and verify removal of the workspace Applications, namespace,
VM/root PVC, registry entry and registration-scoped Vault keys. Both chat routes
must become unavailable. VM audit lives on the root disk and is deleted with it;
container audit-history retention is a different backend contract. Snapshot
unrelated workspaces before and after to detect unintended Pod/image, VMI or PVC
replacement. A new workspace on an existing SAW platform does not qualify a new
platform installation.

## Interrupted provider creation

Before `CreateProvider`, the controller fsyncs a pending provider digest and
the original intent generation to its ledger PVC. The plan contains public
credential-routing markers, never provider keys. If the response is lost, it
reissues the same payload and deterministic request ID under the same installer
principal. The pinned stock gateway replays its durable mutation receipt only
while the resource identity/version still match. Only that receipt authorizes
recording the credential revision; a redacted `GetProvider` is insufficient.

Changed provider inputs, replaced resources, lost/expired gateway receipts or a
lost local ledger fail closed and require explicit recovery. Do not repair these
by copying a current version into the ledger or disabling ownership checks.
