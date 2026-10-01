# Secure Agent Workspace — End-to-End Deployment Guide

## Overview

The Secure Agent Workspace (SAW) deploys a per-user AI agent sandbox running inside a KubeVirt virtual machine on OpenShift. The deployment is fully GitOps-driven via Red Hat Validated Patterns and ArgoCD.

Each sandbox provides an OpenShell gateway with OIDC authentication, governance policy enforcement, and a web-based agent interface — all managed declaratively from Git.

## Architecture

```text
                         +-----------------------+
                         |  OpenShift Cluster     |
                         |                        |
   User (CLI/Browser)    |  +------------------+  |
         |               |  | Keycloak (OIDC)  |  |
         | OIDC login    |  +--------+---------+  |
         v               |           |             |
   +-----+------+        |  +--------v---------+  |
   | TLS Route  +------->|  | KubeVirt VM      |  |
   | (passthru) |        |  |  openshell-saw   |  |
   +------------+        |  |                  |  |
                         |  |  Gateway :17670  |  |
                         |  |  Dashboard :8080 |  |
                         |  |  Agent :18789    |  |
                         |  |  Docker sandboxes|  |
                         |  +--------+---------+  |
                         |           |             |
                         |  +--------v---------+  |
                         |  | Governance        |  |
                         |  | Interceptor :18081|  |
                         |  +------------------+  |
                         |                        |
                         |  +------------------+  |
                         |  | Vault + ESO      |  |
                         |  | (secrets)        |  |
                         |  +------------------+  |
                         +-----------------------+
```

## ArgoCD Applications

All applications are defined in `values-prod.yaml` and deployed by the Validated Patterns framework. ArgoCD syncs them automatically — dependencies are resolved at runtime via init containers and wait loops, not explicit ordering.

| Application | Namespace | Purpose |
| --- | --- | --- |
| `openshift-cnv` | `openshift-cnv` | KubeVirt operator for VM lifecycle |
| `vault` | `vault` | HashiCorp Vault for secret storage |
| `openshift-external-secrets` | `external-secrets` | External Secrets Operator |
| `saw-users` | `openshell-agents` | One namespace and three apps per user, from `overrides/saw-users.yaml` |
| `openshell-keycloak` | `saw-keycloak` | Keycloak OIDC provider + realm |
| `governance-policy` | `openshell-agents` | Policy ConfigMaps (profiles + sandbox policy) |
| `governance-interceptor` | `openshell-agents` | gRPC interceptor deployment; with `global.governance.engine: apf`, the APF inputs and an Argo CD app for the APF chart ([apf.md](apf.md)) |

**Operator Subscriptions:** OpenShift Virtualization, RHBK (Keycloak), External Secrets Operator, RHDH, OpenShift AI.

## Deployment Phases

### Phase 1: Golden VM Image

The `openshell-gateway-image` BuildConfig creates a Fedora 44 qcow2 image with:

- Docker CE (podman removed), Node.js, Python3, cloud-init, openssh, qemu-guest-agent
- `cloud-user` with sudo access and Docker group membership
- Systemd user service for the OpenShell gateway (`openshell-gateway.service`)
- First-boot setup service (`openshell-gateway-setup.service`) that starts Docker, enables the gateway, and configures mTLS certs

The image is pushed to an internal ImageStream (`openshell-gateway:latest`) and used as a DataSource for cloning VM disks.

Build trigger: `make build-gateway-docker` (Docker variant) or `make build-gateway-podman` (Podman variant), or automatically via ArgoCD.

### Phase 2: Keycloak + OIDC

RHBK operator deploys Keycloak. A `KeycloakRealmImport` creates the `openshell` realm with:

- **Clients:**
  - `openshell-cli` — public client, PKCE with S256, device code flow, 24h token lifetime
  - `openshell-dashboard` — public client, PKCE, redirect URIs registered dynamically per sandbox
- **Users:** developer, admin, alice, bob (test accounts)
- **Roles:** `openshell-user`, `openshell-admin`
- **Token mappers:** realm roles in access tokens, audience mapper so dashboard tokens are accepted by the gateway

### Phase 3: Secrets

ExternalSecret CRs pull from Vault:

| Secret | Vault Path | Content |
| --- | --- | --- |
| `openshell-aap-ssh` | `<prefix>/ssh` | SSH private key + public key |
| `openshell-ssh-pubkey` | `<prefix>/ssh` | SSH public key (for cloud-init) |
| `inference` | `<prefix>/inference` | Provider type, model, API key |
| `web-search` | `<prefix>/web-search` | Brave provider and API key |

`<prefix>` is `secret/data/hub` unless a user sets `vaultPrefix`. One shared hub key then serves every workspace. To give one person their own keys, put them in Vault at `secret/data/hub/saw-<user>/...` and set that user's `vaultPrefix` to `secret/data/hub/saw-<user>`. The `saw-users` chart reads the prefix; it does not create Vault entries. See the commented example in `values-secret.yaml.template`.

### Phase 4: Governance Policy

The `governance-policy` chart creates two ConfigMaps from files in the chart:

- `governance-interceptor-policy` — sandbox filesystem/process policy from `policy.yaml`
- `governance-interceptor-profiles` — all `profiles/*.yaml` auto-discovered via Helm glob

The `governance-interceptor` chart deploys the interceptor pod, which mounts both ConfigMaps and serves them over gRPC. See [governance-interceptor.md](governance-interceptor.md) for the full enforcement flow.

### Phase 5: VM Boot + In-guest installer

The VM boots from a clone of the golden image. Nothing logs in over SSH to install it. See [Versioned BOM installer](versioned-bom-installer.md).

#### Cloud-init

Cloud-init runs once and writes the static files: the mount script, the `saw-install` and `saw-apply` units, first-boot copies of `gateway.env` and `gateway.toml`, and (only when `vm.liveInputs` is true) the reconcile units. SSH keys are not in this Secret. KubeVirt `accessCredentials` writes `cloud-user`'s `authorized_keys` from the `<name>-ssh-pubkey` Secret.

#### Prepare Job

The chart's prepare Job stays on the cluster. It bootstraps the golden image DataSource and registers the dashboard redirect URI in Keycloak. It does not install binaries or apply profiles.

#### Guest

`saw-install` pulls each BOM component by digest and starts the gateway. `saw-apply` reads the mounted profiles and provider Secrets and creates workspaces, providers, and sandboxes, and attaches each sandbox's providers (OpenShell 0.1.x has no inference routes: agents call their provider's own endpoint). The default signature mode is `warn`. The default prune mode is `report` (log `would delete`, delete nothing). Inputs are iso9660 disks unless `vm.liveInputs` is true, in which case virtiofs updates them without a restart.

## Upgrading from the single-user layout

Before the `saw-users` chart, `values-prod.yaml` defined Alice's SAW directly:
the `saw-alice` namespace and the `openshell-saw`, `saw-bom` and
`pattern-secrets` applications (VM `openshell-saw`). Upgrading an existing
install does not remove them: the pattern's top-level application syncs
without pruning, so the old applications keep running next to the new
`saw-alice*` ones and both manage the same ExternalSecrets and ConfigMap in
`saw-alice`.

Remove the old applications **without cascading**. Every pattern application
carries the `resources-finalizer.argocd.argoproj.io/foreground` finalizer, so
a plain `oc delete application` would also delete the ExternalSecrets and the
`saw-bom-profiles` ConfigMap that the new applications now use.

```bash
ARGO_NS=vp-gitops   # the pattern's Argo CD namespace (global.vpArgoNamespace)
for app in openshell-saw saw-bom pattern-secrets; do
  oc -n "$ARGO_NS" patch application "$app" --type json \
    -p '[{"op":"remove","path":"/metadata/finalizers"}]'
  oc -n "$ARGO_NS" delete application "$app"
done
# The old VM and its disk are no longer managed; delete them.
oc -n saw-alice delete vm openshell-saw
oc -n saw-alice delete datavolume openshell-saw-root --ignore-not-found
```

The `saw-alice*` applications keep the shared objects in place (they self-heal
anything removed). Alice's new VM is `alice` in `saw-alice`: use
`OPENSHELL_SAW_NAME=alice`. Sandboxes and files inside the
old VM are not migrated; the new VM recreates the profile's workspaces and
sandboxes.

## Network Architecture

### Routes

| Route | Target Port | TLS | Purpose |
| --- | --- | --- | --- |
| `<name>-gateway` | 17670 | Passthrough | gRPC gateway (CLI + API) |
| `<name>-dashboard` | 18789 | Passthrough | Openclaw agent web UI |
| `<name>-webui` | 8080 | Edge | OpenShell Dashboard (via oauth2-proxy) |

### Internal Connectivity

| From | To | Protocol | Purpose |
| --- | --- | --- | --- |
| Gateway (VM) | Governance interceptor (pod) | gRPC over HTTP | Policy enforcement |
| Gateway (VM) | Keycloak (pod) | HTTPS | OIDC token validation |
| In-guest installer | mounted ConfigMaps and Secrets | virtiofs or iso9660 | Install binaries and apply profiles |
| Dashboard (VM) | Gateway (VM) | gRPC over TLS | Agent operations |

### Authentication Flows

- **CLI:** `openshell gateway login` triggers OIDC device code flow via Keycloak. Token is cached locally and sent as a bearer token on gRPC calls.
- **Dashboard:** OAuth2 proxy handles browser-based OIDC login, proxies authenticated requests to the dashboard backend, which connects to the gateway.
- **In-guest installer:** its own mTLS client certificate, `CN=saw-installer` and `OU=openshell-admin`, registered as the `saw-installer` gateway entry. Users still use OIDC.

## Operator Quick Reference

### Prerequisites

```bash
make check-prereqs          # Verify operators and CLI tools
```

### Initial Setup

```bash
make generate-keys           # Create SSH keypair
make ssh-secret              # Create Kubernetes secrets from keys
make build-gateway-docker    # Build Docker golden VM image (or: make copy-images)
make keycloak                # Deploy Keycloak (if not via ArgoCD)
```

### Sandbox Lifecycle

```bash
# Create
make openshell-saw-create OPENSHELL_SAW_NAME=my-saw

# Access — NemoClaw sandbox
OPENSHELL_SAW_NAME=my-saw SANDBOX_NAME=cuda-sandbox make nemoclaw-tui
OPENSHELL_SAW_NAME=my-saw SANDBOX_NAME=cuda-sandbox GUI_PORT=18789 make nemoclaw-gui

# Access — OpenClaw sandbox
OPENSHELL_SAW_NAME=my-saw SANDBOX_NAME=notebook make openclaw-tui
OPENSHELL_SAW_NAME=my-saw SANDBOX_NAME=notebook GUI_PORT=18790 make openclaw-gui

# SSH into a sandbox
make openshell-saw-ssh OPENSHELL_SAW_NAME=my-saw
make login OPENSHELL_SAW_NAME=my-saw

# Monitor
make openshell-saw-list
make openshell-saw-logs OPENSHELL_SAW_NAME=my-saw
make status

# Delete
make openshell-saw-delete OPENSHELL_SAW_NAME=my-saw
make delete-all              # Remove everything
```

### Governance

```bash
make governance-demo OPENSHELL_SAW_NAME=my-saw
make governance-list-profiles OPENSHELL_SAW_NAME=my-saw
make governance-add-profile OPENSHELL_SAW_NAME=my-saw PROFILE_NAME=github
make governance-remove-profile OPENSHELL_SAW_NAME=my-saw PROFILE_NAME=github
make governance-create-profile OPENSHELL_SAW_NAME=my-saw \
  PROFILE_NAME=jira PROFILE_FILE=/path/to/jira.yaml
```

### Testing

```bash
make test                    # Headless E2E test
```
