# Architecture Alignment Analysis

## NVIDIA Secure Agent Workspace Reference Design vs. This Implementation

This document maps the [NVIDIA Secure Agent Workspace OpenShift Virtualization Reference Implementation](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/openshift-virtualization-reference-implementation.html) and its [Security and Governance Model](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html) to this repository's actual implementation. It identifies what is implemented, what is partially implemented, and what gaps remain.

## Summary

| Area | Reference Design | This Implementation | Status |
|---|---|---|---|
| VM-per-user isolation | One persistent VM per user | One KubeVirt VM per sandbox, cloned from bootc golden image | Implemented |
| OIDC / SSO | Trusted access broker with SSO | Red Hat Build of Keycloak with OIDC, PKCE, device code flow | Implemented |
| GitOps control plane | ArgoCD for policy and config | Red Hat Validated Patterns with ArgoCD | Implemented |
| Network boundary controls | NetworkPolicy, EgressFirewall, EgressIP | Namespaced default-deny NetworkPolicy for pod ingress and egress, plus EgressFirewall with an explicit hostname allowlist in Git. No EgressIP | Partial |
| Agent runtime | OpenShell or equivalent runtime sandbox | OpenShell Gateway + OpenClaw/NemoClaw agents | Implemented |
| Secret management | Credential mediation outside the agent process; external placement for guest-compromise threats | HashiCorp Vault + External Secrets Operator; default proxy mode keeps provider keys outside the VM; optional direct mode mounts full Secrets in the guest | Proxy mode: Implemented. Direct mode: Partial (agent-process isolation only) |
| Policy distribution | Signed policy bundles via NFS | Signed APF bundle (Ed25519, monotonic `policy_revision`), served in-cluster as the optional `apf` governance engine; no NFS transport | Partial |
| OCSF-compatible audit | Lifecycle events, broker sessions, tool events | Governance decisions are logged (interceptor audit log; APF JSONL audit trail); no unified OCSF pipeline | Partial |
| Operator kill switch | Stop VM, remove route, revoke SSO, rotate policy | VM lifecycle via OpenShift API; SSO revocation via Keycloak | Implemented |
| Image governance | Only approved images deployed | Bootc golden image via BuildConfig; the installer bundle and BOM components are signature-checked (cosign + per-pull podman policy, `signing.mode: warn` by default); no admission control on the VM image | Partial |

## Detailed Alignment

### 1. VM-per-User Isolation

**Reference:** "One VM per user, no shared agent process space."

**Implementation:** Each `make saw-create` or ArgoCD-deployed sandbox creates a dedicated `VirtualMachine` resource cloned from the golden image DataSource. The VM runs Fedora 44 with the OpenShell gateway, a container-based agent sandbox, and per-user cloud-init configuration. VMs are isolated at the KubeVirt/QEMU level.

**Alignment:** Full. The fundamental invariant of single-tenant workspaces is preserved.

### 2. Identity and Access (OIDC / SSO)

**Reference:** "SSO-backed, short-lived, auditable user sessions into the workspace."

**Implementation:**
- Red Hat Build of Keycloak deployed via the RHBK operator
- OIDC with PKCE (S256) and device code flow for CLI authentication
- Realm roles (`openshell-user`, `openshell-admin`) for authorization
- Gateway validates OIDC tokens directly (signature, expiry, issuer, audience, roles)
- Auth proxy on the dashboard route validates `preferred_username == owner`
- Token lifetime configurable (default 900s)

**Alignment:** Full. The implementation provides SSO integration, short-lived tokens, and per-user access enforcement at both the gateway (gRPC) and dashboard (HTTP) layers.

### 3. GitOps Control Plane

**Reference:** "Git serves as the source of truth for policy intent; GitOps reconciles platform desired state."

**Implementation:**
- Red Hat Validated Patterns framework with ArgoCD
- `values-prod.yaml` defines operators, subscriptions, and applications
- Charts in `charts/` are ArgoCD-managed applications
- `overrides/` provides per-deployment value customization
- Multi-source config with clustergroup chart version `0.9.*`

**Alignment:** Full for infrastructure and application deployment. The GitOps model manages operators, Keycloak, secrets, and sandbox configuration declaratively.

### 4. Network Boundary Controls

**Reference:** "Default-deny egress posture with enterprise-defined allowlists" using NetworkPolicy, EgressFirewall, EgressIP.

**Implementation:**
- TLS passthrough on the gateway route preserves gRPC/HTTP2
- Auth proxy restricts dashboard access to the sandbox owner
- Each sandbox namespace gets an OpenShift `EgressFirewall` named `default`. The VM uses masquerade, so traffic leaving the guest is traffic leaving that pod. Undeclared internet hosts are denied. The allowlist is `egress.allow` plus `egress.extraAllow` in [`charts/openshell-saw/values.yaml`](../charts/openshell-saw/values.yaml), and the Keycloak route host from the OIDC issuer. See [Deployment guide](deployment-guide.md#egress-from-the-vm).
- With NetworkPolicy enabled, a sandbox namespace keeps default-deny, a narrow VM allow policy, CDI importer access, and (when cleanup is enabled) exact API egress for the pre-delete cleanup hook. Proxy mode also adds `saw-credential-proxy`. Its temporary CA-hook policy allows API access while initializing the proxy CA and is removed after success. The CA hook runs as an Argo Sync / Helm `pre-install,pre-upgrade` hook; Argo applies the firewall first to avoid an upgrade deadlock. The VM may reach DNS, the selected governance engine, the internal registry, the Keycloak issuer Route through ingress, and outside TCP ports permitted by the EgressFirewall. Pod and Service CIDRs, exact API endpoint IPs, and link-local CIDRs are excluded from the outside rule. GitOps stages the policy off per user until an administrator checks live topology and in-cluster destinations. CI checks profile host and port parity with rendered firewall and policy rules.

**Residual risk:** NetworkPolicy and EgressFirewall cannot filter by Route host. Cluster Routes on TCP 443 remain reachable behind their own authentication. A fixed source address still needs EgressIP; an optional AdminNetworkPolicy could add a cluster-level guardrail.

### 5. Agent Runtime

**Reference:** "OpenShell or equivalent runtime sandboxing."

**Implementation:**
- The golden image is built with `virt-customize`; the in-VM BOM installer installs the OpenShell gateway and CLI at boot (OpenShell `0.1.2-rhaiv.6`)
- OpenClaw, Hermes, and Deep Agents Code agents supported
- Agents run inside container sandboxes managed by the OpenShell gateway
- Inference routed through user-configured provider endpoints

**Alignment:** Largely implemented. Phase II runtime enforcement is configured through the governance layer. A governance service — the OpenShell interceptor by default (policy served unsigned from ConfigMaps), or NVIDIA APF (policy served from an Ed25519-signed bundle) — injects a per-sandbox policy with filesystem (landlock), process and network rules. Per-tool approval is the OpenClaw `saw-tool-gate` hook fed by `charts/governance-policy/tool-actions.yaml`: a consequential tool does not run until the configured approval path allows it, and each call is audited with the signed-in user and the current task. In proxy mode (the default), provider credentials are injected at request time by the per-namespace credential proxy; the VM holds nonsecret markers and the sandbox uses placeholders, so the real keys never enter the VM ([Credential isolation](credential-isolation.md)). A unified, cluster-wide OCSF audit pipeline is still absent. See [Governance interceptor](governance-interceptor.md) and [APF governance](apf.md).

### 6. Secret Management

The [Security and Governance Model](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html#phase-ii-agent-runtime-controls)
states the Phase II requirement as attributes, independent of product:

> They form a stacked model: in-sandbox containment (reference implementation NVIDIA OpenShell — open-source) and a separate credential / authorization proxy. The requirement is the attributes below, not a specific product.

> Credential proxy and isolation. A trusted mediator outside the agent process authorizes requests and injects provider credentials. Record whether raw credentials enter a supervisor, guest or external service; agent-process isolation does not imply guest-root isolation. Validate provider scope, token lifetime, audit and revocation. Where controls must survive guest compromise, place them outside that guest with an independently enforced request path.

The control-surface table describes credential mediation as:

> Credential mediation and provider authorization; external placement where required by the guest-compromise threat model

Table 7 distinguishes an unprivileged exploit inside the agent process:

> Sandbox process and syscall scoping; credential proxy still holds secrets

from root inside the workspace:

> Only additional controls whose enforcement and administration remain outside the compromised guest.
> Policy signatures authenticate artifacts but do not prevent bypass of a compromised in-guest enforcer; treat exposed credentials accordingly.

The application-session and token-revocation guidance adds:

> Treat credentials accessible during guest compromise as exposed; external proxy placement reduces that exposure only when its trust and request paths remain intact.

**Implementation:** HashiCorp Vault backs the provider Secrets, synced by
External Secrets Operator. SSH access is managed through Vault too, and
`values-secret.yaml.template` defines the schema. Credential custody depends
on `credentialProxy.enabled`:

| Reference attribute | Proxy mode (default) | Direct mode (`credentialProxy.enabled: false`) |
|---|---|---|
| Mediator outside the agent process injects credentials | The OpenShell supervisor swaps the sandbox placeholder for a marker; the namespace proxy swaps that marker for the key at its bound HTTPS host | The OpenShell supervisor injects the real key |
| Where raw credentials enter ("supervisor, guest or external service") | External service: the namespace proxy pod. The VM, gateway and supervisor hold markers; provider keys and Gmail OAuth material stay outside the guest | Guest: VM input disk, gateway store, supervisor and NemoClaw credentials file; Gmail refresh material is handled by the gateway |
| Agent-process compromise (Table 7) | Provider keys stay outside the agent process and VM | Provider keys stay outside the agent process |
| Root in the guest (Table 7) | Provider keys cannot be read from VM storage. VM root can still use bound keys through markers while it controls the VM; protection depends on the external proxy and request path remaining trusted | Keys are exposed. Revoke/rotate them; moving to proxy mode requires rotation plus a `credentialProxy.keyGeneration` bump |
| Provider scope | Bindings restrict each marker to its profile hosts (or custom HTTPS URL host) on port 443 | OpenShell provider policy endpoints |
| Token lifetime | Gmail access tokens minted and cached in the proxy, capped at 1 hour and refreshed 5 minutes early | Gmail access tokens minted through the gateway's provider refresh |
| Audit | Proxy log per request: method, host, redacted path, binding and status; no unified OCSF pipeline (§8) | Gateway logs; no unified OCSF pipeline |
| Revocation and rotation | Rotate in Vault; the proxy rereads projected keys per request and invalidates cached Gmail tokens when material changes. No VM restart; allow for ESO and volume projection delay | Rotate in Vault; restart the VM and apply, or apply after projected inputs update when `vm.liveInputs` is enabled |

**Alignment:** Proxy mode implements external provider-key custody for the
guest-compromise threat model. This does not prevent VM root from making
requests with a bound marker or make a compromised gateway trustworthy.
Direct mode provides agent-process isolation only: guest root can read the
keys, so it is partial alignment and unsuitable when credential controls
must survive guest compromise. Both modes retain hardened admin mTLS.
Scope, token lifetime, audit and revocation must be evaluated separately;
a unified OCSF audit pipeline remains a gap. See
[Credential isolation](credential-isolation.md) for the request path,
migration and rotation procedures.

### 7. Policy Distribution

**Reference:** "Signed policy bundles are mounted or fetched read-only by the workspace." GitOps publishes policy-release metadata; an in-VM agent validates signatures and applies policy via the OpenShell API.

**Implementation:** Implemented as the optional `apf` governance engine (NVIDIA Agent Policy Fabric). `make apf-bundle` signs the policy in `charts/governance-policy` into a bundle: each file is hashed, the manifest is signed with Ed25519, and a monotonic `policy_revision` guards against rollback. The bundle is served in-cluster (as a ConfigMap, not over NFS); APF refuses any policy change that does not arrive through a signed bundle and stamps provenance (`apf.nvidia.com/*`) on every sandbox. The default engine remains the OpenShell interceptor, which serves the same `charts/governance-policy` files from ConfigMaps without signing. See [APF governance](apf.md).

**Remaining gap:** The transport is in-cluster (ConfigMap), not the reference design's read-only NFS mount with an in-VM policy agent, and APF's anti-rollback counter is not yet durable across pod restarts (see [APF governance — Rollback](apf.md#rollback)). After a new bundle, a gateway refreshes its provider catalog when its VM restarts, and each sandbox keeps the policy it was created with until it is recreated.

### 8. Audit

**Reference:** "OCSF-compatible audit path captures workspace lifecycle events, broker sessions, policy-release activity and runtime/tool events."

**Implementation:** Partial. Tool-call decisions (allow, deny, approval required, approved, rejected) are appended to `/sandbox/.saw/audit/tool-actions.jsonl` on the sandbox volume, each with the signed-in user and the current task; the governance interceptor logs its allow/deny decisions and APF writes a JSONL audit trail. OpenShift's built-in audit logging captures API-server events and Keycloak logs authentication events, all separate. What is missing is a unified, OCSF-compatible pipeline that normalizes and forwards these.

**Gap:** Adding structured audit logging would require:
1. Forwarding OpenShift audit logs, Keycloak events, and OpenShell gateway logs to a central collector
2. Normalizing events to the OCSF schema
3. Optionally integrating with OpenShift's cluster logging operator

### 9. Operator Kill Switch

**Reference:** "Revoke SSO, stop VM, remove route, rotate policy, or rebake image."

**Implementation:**
- Stop VM: `helm uninstall <sandbox>` or `virtctl stop <vm>`
- Revoke SSO: Remove user from Keycloak or delete the sandbox's OIDC token
- Remove route: Managed by helm; deleted with the sandbox release
- Rebake image: `make gateway-build` rebuilds the bootc image

**Alignment:** Full. All kill switch capabilities are available through standard OpenShift and helm operations.

### 10. Image Governance

**Reference:** "Only approved VM images can be deployed."

**Implementation:**
- Bootc golden image built via OpenShift BuildConfig from a known Fedora 44 base
- OpenShell RPMs downloaded from GitHub releases (pinned version)
- CDI imports the image into a DataSource that sandboxes clone from

**Partial:** The image build pipeline is reproducible and version-pinned. The guest checks each BOM component signature before install (`signing.mode: warn` by default; `enforce` stops before replacing binaries). The golden image includes cosign for the installer bundle. The OpenShell publisher key is not in the image, and there is still no admission controller that rejects an unapproved VM image.

## Phase Mapping

| Reference Design Phase | This Implementation |
|---|---|
| **Phase I: Perimeter-based enforcement** | Largely implemented — VM isolation, OIDC, image governance, secret management, GitOps, operator controls |
| **Phase II: Runtime-based enforcement** | Largely implemented — signed APF policy bundles, per-tool approval with user/task audit (`tool-actions.yaml`, `saw-tool-gate`), per-namespace credential proxying (default proxy mode; direct mode provides agent-process isolation only), and per-tool/endpoint, filesystem and process enforcement through the governance layer; remaining: a unified OCSF audit pipeline, NFS policy transport, and a durable anti-rollback counter |

## Recommendations for Closing Gaps

1. **Network guardrails:** The sandbox namespace now has default-deny NetworkPolicy and an external hostname EgressFirewall. Consider EgressIP if a fixed source address is required, and an AdminNetworkPolicy for a cluster-wide boundary independent of namespaced policy edits.
2. **Image admission:** The guest already checks component signatures and can verify an installer bundle with cosign. What is still missing is an admission controller (e.g., Kyverno) that rejects an unapproved golden image, and the publisher public key in `/etc/saw/trust`.
3. **Audit pipeline:** Deploy OpenShift's cluster logging operator with OCSF-compatible log normalization.
4. **Policy bundles (Phase II):** Implemented via APF — signed Ed25519 bundles, see [APF governance](apf.md). Remaining: a durable anti-rollback counter and, if the reference design's read-only NFS transport is required, an in-VM policy agent.
