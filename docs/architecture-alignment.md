# Architecture Alignment Analysis

## NVIDIA Secure Agent Workspace Reference Design vs. This Implementation

This document maps the [NVIDIA Secure Agent Workspace OpenShift Virtualization Reference Implementation](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/openshift-virtualization-reference-implementation.html) to this repository's actual implementation. It identifies what is implemented, what is partially implemented, and what gaps remain.

## Summary

| Area | Reference Design | This Implementation | Status |
|---|---|---|---|
| VM-per-user isolation | One persistent VM per user | One KubeVirt VM per sandbox, cloned from bootc golden image | Implemented |
| OIDC / SSO | Trusted access broker with SSO | Red Hat Build of Keycloak with OIDC, PKCE, device code flow | Implemented |
| GitOps control plane | ArgoCD for policy and config | Red Hat Validated Patterns with ArgoCD | Implemented |
| Network boundary controls | NetworkPolicy, EgressFirewall, EgressIP | TLS passthrough route + auth proxy; NetworkPolicy not yet configured | Partial |
| Agent runtime | OpenShell or equivalent runtime sandbox | OpenShell Gateway + OpenClaw/NemoClaw agents | Implemented |
| Secret management | Credential proxy / external secret boundary | HashiCorp Vault + External Secrets Operator | Implemented |
| Policy distribution | Signed policy bundles via NFS | Not implemented (Phase II feature) | Gap |
| OCSF-compatible audit | Lifecycle events, broker sessions, tool events | Not implemented | Gap |
| Operator kill switch | Stop VM, remove route, revoke SSO, rotate policy | VM lifecycle via OpenShift API; SSO revocation via Keycloak | Implemented |
| Image governance | Only approved images deployed | Bootc golden image built via BuildConfig; no signing/attestation | Partial |

## Detailed Alignment

### 1. VM-per-User Isolation

**Reference:** "One VM per user, no shared agent process space."

**Implementation:** Each `make sandbox-create` or ArgoCD-deployed sandbox creates a dedicated `VirtualMachine` resource cloned from the golden image DataSource. The VM runs Fedora 44 with the OpenShell gateway, a container-based agent sandbox, and per-user cloud-init configuration. VMs are isolated at the KubeVirt/QEMU level.

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
- No NetworkPolicy or EgressFirewall resources are deployed by default

**Gap:** The reference design calls for default-deny egress with explicit allowlists. This implementation does not configure network policies. Adding `NetworkPolicy` resources to restrict VM egress to approved inference endpoints and enterprise systems would close this gap.

### 5. Agent Runtime

**Reference:** "OpenShell or equivalent runtime sandboxing."

**Implementation:**
- OpenShell v0.0.89 gateway and CLI installed in the bootc image
- OpenClaw, Hermes, and Deep Agents Code agents supported
- Agents run inside container sandboxes managed by the OpenShell gateway
- Inference routed through user-configured provider endpoints

**Alignment:** Full for Phase I. The reference design's Phase II runtime sandboxing (per-tool enforcement, credential proxying, filesystem scoping) is an OpenShell-internal capability not configured by this deployment.

### 6. Secret Management

**Reference:** "Secrets should live behind a credential proxy or external secret boundary."

**Implementation:**
- HashiCorp Vault as the backing store
- External Secrets Operator syncs secrets from Vault into k8s Secrets
- ExternalSecret resources for each inference provider (anthropic, gemini, openai, nvidia, openrouter, vertex) and search providers (tavily, brave-search)
- SSH private/public keys managed through Vault
- `values-secret.yaml.template` defines the secret schema
- The setup Job mounts provider secrets and injects API keys at runtime

**Alignment:** Full. API keys and SSH keys flow through Vault and ESO, keeping credentials out of Git, helm values, and ArgoCD state.

### 7. Policy Distribution

**Reference:** "Signed policy bundles are mounted or fetched read-only by the workspace." GitOps publishes policy-release metadata; an in-VM agent validates signatures and applies policy via the OpenShell API.

**Implementation:** Not implemented. No policy bundle signing, NFS-based distribution, or in-VM policy agent exists in this deployment.

**Gap:** This is the reference design's Phase II capability. The current deployment relies on Phase I perimeter controls (VM isolation, OIDC, network). Implementing policy distribution would require:
1. A policy bundle build/sign pipeline
2. NFS or ConfigMap-based distribution to VMs
3. An in-VM agent that watches for policy updates and applies them via `openshell policy set`

### 8. Audit

**Reference:** "OCSF-compatible audit path captures workspace lifecycle events, broker sessions, policy-release activity and runtime/tool events."

**Implementation:** Not implemented. OpenShift's built-in audit logging captures API server events, and Keycloak logs authentication events, but there is no unified OCSF-compatible audit pipeline.

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
- Rebake image: `make build-gateway-image` rebuilds the bootc image

**Alignment:** Full. All kill switch capabilities are available through standard OpenShift and helm operations.

### 10. Image Governance

**Reference:** "Only approved VM images can be deployed."

**Implementation:**
- Bootc golden image built via OpenShift BuildConfig from a known Fedora 44 base
- OpenShell RPMs downloaded from GitHub releases (pinned version)
- CDI imports the image into a DataSource that sandboxes clone from

**Partial:** The image build pipeline is reproducible and version-pinned, but there is no image signing, attestation, or admission control to prevent unapproved images from being used.

## Phase Mapping

| Reference Design Phase | This Implementation |
|---|---|
| **Phase I: Perimeter-based enforcement** | Largely implemented — VM isolation, OIDC, image governance, secret management, GitOps, operator controls |
| **Phase II: Runtime-based enforcement** | Not yet implemented — policy bundles, credential proxying, per-tool enforcement, runtime reporting |

## Recommendations for Closing Gaps

1. **NetworkPolicy:** Add default-deny egress policies to sandbox namespaces with allowlists for inference provider endpoints and enterprise systems.
2. **Image signing:** Integrate Sigstore/cosign into the BuildConfig pipeline and add an admission controller (e.g., Kyverno) to enforce signed images.
3. **Audit pipeline:** Deploy OpenShift's cluster logging operator with OCSF-compatible log normalization.
4. **Policy bundles (Phase II):** Implement when OpenShell's policy API stabilizes — requires NFS storage, a signing pipeline, and an in-VM policy agent.
