# SAW TP provider and driver support matrix

**Updated:** 2026-11-06. Historical VM live results: 2026-10-21.

Keep implementation, offline contracts and live qualification separate. The
Kubernetes integration now compiles native OpenAI, Anthropic and NVIDIA
providers, uses the shared governance/credential policy, and reconciles them
through the stock gateway. This does not by itself qualify a live provider.

## Validation matrix

| Provider | Historical VM model | Podman live (2026-10-21) | Kubernetes offline contracts | Kubernetes live qualification |
|---|---|---|---|---|
| OpenAI | `gpt-6-luna` | Historical pass; see scope below | Passed: native protocol/config, marker/host policy, mutable selection | Sandbox API inference, owner chat and audited tool decisions passed on both data-science slots. Standalone model update, stop/start and explicit restart preserved workspace/audit data. RHDH browser create/update/stop/start/delete/recreate passed. Fresh static GitOps and RHDH installations passed inference, owner chat and audited tool decisions on both slots; fresh-connection recovery across relay-token renewal passed; OpenAI VM regression also passed (scope below) |
| Anthropic | `claude-sonnet-4-6` | Historical pass; see scope below | Passed: native Messages protocol/config, marker/host policy, mutable selection | Not qualified |
| NVIDIA | `nvidia/nemotron-3.5-lightning-30b-a3b` | Historical pass; see scope below | Passed: OpenAI protocol/config, marker/host policy, slash-qualified model selection | Not qualified |

Offline cases use synthetic credentials and Node execution of the actual
compiled OpenClaw configuration. Provider recovery tests cover a lost create
response, process restart and a later intent generation; drift, replacement,
changed markers and missing receipts fail closed. The Rust admission contract
test consumes the actual Helm/compiler harness output (3 volumes/5 mounts,
also with 16 extra data volumes) and rejects altered aliases. CI requires that
Rust test to execute, rather than silently treating a missing toolchain as a pass.

## Historical VM results

The 2026-10-21 results covered authenticated inference from a sandbox through
the in-VM OpenShell sandbox proxy, before namespace credential isolation. Each
API returned **HTTP 200** with a response matching the test prompt. These results
do not qualify the current namespace-proxy path or candidate installation.

OpenClaw chat also returned responses from all three providers. NVIDIA passed
with both an explicit model selection and the configured notebook default.

The historical backend was Podman inside KubeVirt VMs on OpenShift. This does
not validate the OpenShell Kubernetes driver. Environment identities and raw
live evidence belong in the separate qualification record, not this matrix.

## Candidate VM regression

A fresh RHDH VM registration passed OpenAI API inference and owner browser chat
on both data-science sandboxes, with `gpt-4.1-2025-04-14` confirmed in response
transcripts. Shared tool policy passed allowed reads, policy denial, owner
rejection and owner approval; actual file effects and six append-only audit
records per sandbox were verified. Anonymous/foreign-owner access and credential
marker/destination denials passed. Temporary installer administrator credentials
were removed and the gateway trust bundle restored. RHDH model update followed
by the documented targeted VM restart passed
`gpt-4.1-mini-2025-04-14` inference on both sandboxes, with the same VM/root PVC,
a fresh VM instance, and unchanged original workspace files and audit hashes.
Both owner browser chats also passed after the restart. RHDH deletion removed
the four workspace Applications, VM namespace/root PVC, registry entry and
registration-scoped Vault keys; both retired chat routes became unavailable.
Unlike container audit history, VM audit records live on the root disk and are
deleted with it. Pre-existing workspaces retained their Pod/image, VM-instance
and PVC identities. This is a workspace regression on an installed platform,
not a fresh platform-install qualification.

## Remaining work

Use [provider qualification](provider-driver-qualification.md) to reproduce the
completed OpenAI checks and qualify additional providers/profiles. Keep immutable
image/Git revisions and actual workload identities in the separate evidence
record; the completed OpenAI lifecycle is not outstanding work.
Anthropic and NVIDIA require separate native-provider runs with real credentials
before their live cells can pass. Do not infer their results from OpenAI success.

The current OpenAI result uses the official remote API through the Kubernetes
credential proxy. The CUDA-named sandbox does not imply local GPU inference.
The stock gateway also passed committed-provider-response recovery with a fresh
temporary administrator identity; the same provider ID/version was recovered
and the disposable provider and temporary credentials were removed afterward.
These checks do not replace RHDH lifecycle or final clean-install qualification.

Current qualification also exposed failures that remain distinct from the
initial inference pass:

- An earlier model update reached Ready and preserved storage, but stock
  OpenClaw restored/migrated the notebook's model configuration. The integration
  now publishes managed configuration through the native batch command and uses
  an explicit managed provider ID. Fresh standalone and RHDH sandboxes passed
  actual API inference and owner chat with matching requested/response models;
  both RHDH browser UIs also passed. A standalone model update then passed actual
  API inference and owner chat on both replacement application Pods, with the
  selected model reflected in provider response transcripts. Workspace canaries,
  tool effects and original audit records survived unchanged. A subsequent
  standalone stop/start and explicit restart passed the same persistence,
  inference and chat checks. The post-restart controller observation found no
  remaining temporary administrator sessions or private credential directories.
  RHDH browser model update also passed with fresh application Pods, unchanged
  workspace PVCs and the selected model confirmed by both provider transcripts
  and a new browser-chat response. RHDH browser stop passed with no application
  Pods, unavailable chat routes and retained workspace/audit claims. RHDH browser
  start then passed actual inference and owner chat on both fresh application
  Pods, with the original workspace files, tool effects and audit records intact.
  Standalone deletion retained its two audit-history claims and left other
  workspace namespaces unchanged. RHDH browser deletion removed the runtime
  and registration while retaining both audit-history claims. Recreating the
  workspace through RHDH produced a fresh registration and passed actual API
  inference, owner browser chat and six expected audit events on each slot.
- A RHDH tool run reached its decisions, but the stock CLI closed an exec relay
  before reporting the verification command's exit status. Independent read-only
  checks confirmed that slot's expected file effects and audit records. The
  combined test remains failed. A separate test with new fixtures after the
  RHDH model update passed both slots, including stock-exec verification and six
  expected audit records per slot. This does not resolve the earlier
  intermittent transport failure or justify retrying mutating commands.
- The stock CLI's browser-forward process briefly closes its listener when
  its OIDC token expires. Both relays passed new HTTP requests and fresh
  authenticated WebSocket handshakes initiated within measured natural renewal
  gaps, without request replay. This qualifies sampled new-connection recovery;
  survival or automatic reconnection of an already-open WebSocket is not
  established, and uninterrupted chat is not guaranteed.
- Initial deployment of the shared transport exposed a Python import collision
  with the adjacent OIDC helper. Isolated mode fixes that startup failure, with
  a subprocess regression reproducing the old failure. GitOps recovery and
  subsequent inference/chat passed. Separate fresh static GitOps and RHDH
  installations of the final integration revision then passed actual inference,
  owner chat and audited tool decisions on both data-science slots. They needed
  no manual workload repair or operator retry. The static identity bootstrap
  and one relay-binding Job per installation required automatic retries; these
  are not zero-retry installation results.
- VM regression exposed parent Application sync oscillation: Argo adds
  PreDelete hook-state finalizers and the parent repeatedly removed them. Both
  portal and static projector parents now preserve only those two exact entries
  during comparison and sync. Automatic GitOps convergence passed without
  changing workload revisions, and existing workspace identities were unchanged.
- An identity-service upgrade rejected the existing service-account admin API
  tokens and blocked RHDH enrollment. The shared bootstrap now assigns the
  supported built-in Admin API scope; live reads recovered for all three
  service clients with unchanged roles. Bootstrap runs during Sync to avoid
  waiting for the identity-dependent ApplicationSet's health. The portal also
  preserves the prior workspace projection on lookup failure. The subsequent
  fresh OpenAI registrations above passed;
  that does not qualify other providers or a fresh platform installation.

Credential-marker and destination denials passed in isolated live checks.
Separate direct-connect probes from both application Pods timed out to two
currently resolved OpenAI IPv4 addresses on TCP/443, while mediated inference
succeeded before and after; the stock deny-all network policies remained in
place. This bounds the network result to the tested destinations and transport.
An authenticated second owner was denied access to the first owner's notebook
in the browser, with the proxy confirming the rejected identity. Broader
profile/provider coverage remains unqualified; the completed OpenAI lifecycle
and final fresh-workspace replays are described above.
Keep detailed failures and immutable revision evidence in the separate
qualification record.

The container compiler currently selects one inference provider per sandbox;
additional simultaneous `inference.models` chat choices remain unsupported and
fail closed. Kata/confidential runtime qualification is outside this matrix.

## Scope

The historical live scope was inference in existing workspaces after credential
and model updates. It did not qualify clean installation, restart recovery,
tools, or memory embeddings. The current container evidence includes
installation, browser lifecycle, persistence and denial checks described above.
Candidate VM regression passed within the OpenAI/data-science scope. A fresh
platform installation, established-WebSocket continuity and other providers
remain unqualified. Offline tests and image builds do not satisfy those live
criteria.
