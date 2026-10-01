# Secure Agent Workspace

Deploy isolated, per-user AI agent sandboxes on OpenShift Virtualization with OIDC authentication and policy-controlled access.

## Table of Contents

- [Secure Agent Workspace](#secure-agent-workspace)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Detailed description](#detailed-description)
    - [Architecture diagrams](#architecture-diagrams)
      - [Reference Architecture](#reference-architecture)
      - [GitOps Policy Model](#gitops-policy-model)
      - [Storage Layout](#storage-layout)
      - [Implementation Overview](#implementation-overview)
  - [Requirements](#requirements)
    - [Minimum hardware requirements](#minimum-hardware-requirements)
    - [Minimum software requirements](#minimum-software-requirements)
    - [Required user permissions](#required-user-permissions)
  - [Deploy](#deploy)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
      - [Option A: Validated Pattern (automated, GitOps)](#option-a-validated-pattern-automated-gitops)
      - [Option B: Quickstart (manual, step-by-step)](#option-b-quickstart-manual-step-by-step)
      - [Supported inference providers](#supported-inference-providers)
      - [Custom inference provider](#custom-inference-provider)
      - [Governance with APF (optional)](#governance-with-apf-optional)
    - [Validating the deployment](#validating-the-deployment)
    - [Delete](#delete)
  - [Repository structure](#repository-structure)
  - [References](#references)
  - [Technical details](#technical-details)
    - [Security model](#security-model)
    - [Keycloak test users](#keycloak-test-users)
    - [Namespace modes](#namespace-modes)
    - [OIDC issuer resolution](#oidc-issuer-resolution)
  - [Tags](#tags)

## Overview

Secure Agent Workspace provisions dedicated KubeVirt virtual machines for each user, running NVIDIA OpenShell with NemoClaw/OpenClaw AI agents. Each sandbox is isolated at the VM level, authenticated via OIDC, and connected to the user's chosen inference provider. The platform supports both a GitOps-driven Validated Pattern deployment and a manual quickstart flow.

## Detailed description

Organizations adopting AI coding and knowledge agents need strong isolation guarantees: each user's agent must run in its own boundary, with auditable access to enterprise systems, controlled network egress, and centralized identity management. Traditional container-based isolation is insufficient when agents can execute arbitrary code and tool calls.

This quickstart implements NVIDIA's [Secure Agent Workspace reference architecture](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/openshift-virtualization-reference-implementation.html) on Red Hat OpenShift. Each user gets a dedicated Fedora 44 VM running the OpenShell gateway and an AI agent (OpenClaw, Hermes, or Deep Agents Code). The VM provides process-level and network-level isolation. OIDC authentication (via Red Hat Build of Keycloak) ensures only the sandbox owner can access their workspace. Secrets for inference providers flow through HashiCorp Vault and the External Secrets Operator, keeping API keys out of Git and helm values.

The system supports multiple inference providers (Gemini, Anthropic, OpenAI, NVIDIA Build, OpenRouter, Ollama, or custom endpoints) and optional web search integration (Tavily, Brave). A bootc-based golden image pipeline pre-bakes all packages into a container image that CDI imports directly, enabling fast VM provisioning without cloud-init package installation.

For a self-hosted OpenAI-compatible endpoint (vLLM, Ollama, ...), see [Custom inference provider](#custom-inference-provider).

### Architecture diagrams

The following diagrams are from the [NVIDIA Secure Agent Workspace OpenShift Virtualization Reference Implementation](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/openshift-virtualization-reference-implementation.html).

#### Reference Architecture

![OpenShift Virtualization Reference Implementation](docs/images/openshift-reference-shape.png)

#### GitOps Policy Model

![GitOps Policy Model — End-to-End Policy Flow](docs/images/gitops-policy-model.png)

#### Storage Layout

![NFS storage layout for policy bundles and workspace persistence](docs/images/nfs-storage-layout.png)

#### Implementation Overview

```
                     OpenShift Cluster
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  Operators (deployed by Validated Pattern or manually):  │
│  ┌──────────────────┐  ┌──────────────────┐              │
│  │ OpenShift        │  │ Red Hat Build    │              │
│  │ Virtualization   │  │ of Keycloak      │              │
│  └──────────────────┘  └──────────────────┘              │
│                                                          │
│  Infrastructure (ArgoCD-managed):                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────────┐  │
│  │ Vault    │ │ ESO      │ │ Keycloak (OIDC provider) │  │
│  └──────────┘ └──────────┘ └──────────────────────────┘  │
│       │                              │                   │
│       │ secrets sync                 │ JWKS validation   │
│       ▼                              ▼                   │
│  ┌──────────────────────────────────────────┐            │
│  │ Golden Image (bootc)                     │            │
│  │ Fedora 44 + OpenShell + podman + nodejs  │            │
│  │ Built via BuildConfig → CDI DataSource   │            │
│  └─────────────────┬────────────────────────┘            │
│                    │ clone per user                      │
│       ┌────────────┼────────────┐                        │
│       ▼            ▼            ▼                        │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐                     │
│  │ alice   │ │ bob     │ │ carol   │  Per-user VMs       │
│  │ sandbox │ │ sandbox │ │ sandbox │  with gateway +     │
│  │  VM     │ │  VM     │ │  VM     │  agent + routes     │
│  └─────────┘ └─────────┘ └─────────┘                     │
│       │            │            │                        │
│       └────────────┼────────────┘                        │
│                    │                                     │
│  Routes:  TLS passthrough (gRPC) + edge (dashboard)      │
└──────────────────────────────────────────────────────────┘
        │
        ▼
   User (openshell CLI / browser)
```

| Component | Technology | Purpose |
|---|---|---|
| VM isolation | OpenShift Virtualization (KubeVirt) | One VM per user with process and network isolation |
| Identity | Red Hat Build of Keycloak (RHBK) | OIDC authentication, user management, SSO |
| Agent runtime | NVIDIA OpenShell + OpenClaw/NemoClaw | AI coding and knowledge agents inside sandbox |
| Gateway | OpenShell Gateway (gRPC over TLS) | Sandbox lifecycle, SSH proxy, inference routing |
| Golden image | Bootc (Fedora 44) + CDI | Pre-baked VM image for fast provisioning |
| Secrets | HashiCorp Vault + External Secrets Operator | API keys for inference providers, SSH keys |
| GitOps | ArgoCD (Validated Patterns) | Declarative cluster configuration |
| Access control | Dashboard token + OIDC gateway validation | Per-user access via application-level tokens |

## Requirements

### Minimum hardware requirements

| Resource | Per sandbox VM | Cluster overhead |
|---|---|---|
| CPU | 4 cores | 8 cores (operators, Keycloak, Vault) |
| Memory | 8 GiB | 16 GiB |
| Storage | 40 GiB (VM disk) | 50 GiB (golden image, registry) |

### Minimum software requirements

| Software | Version |
|---|---|
| Red Hat OpenShift | 4.22+ |
| OpenShift Virtualization operator | stable channel |
| Red Hat Build of Keycloak operator | stable-v26 channel |
| Helm CLI | 3.x |
| oc CLI | matching cluster version |
| openshell CLI | [latest release](https://github.com/NVIDIA/OpenShell/releases) |

### Required user permissions

**Cluster admin** is required for the initial deployment (operator installation, namespace creation). After setup, end users interact only via the `openshell` CLI and their OIDC credentials — no OpenShift access needed.

## Deploy

### Prerequisites

1. An OpenShift 4.22+ cluster with the required operators installed (see Requirements)
2. `oc` CLI logged in with cluster-admin
3. `helm` 3.x installed
4. An API key for at least one inference provider (Gemini, Anthropic, OpenAI, NVIDIA, OpenRouter)
5. The `openshell` CLI installed ([releases](https://github.com/NVIDIA/OpenShell/releases))

Verify prerequisites:

```bash
make check-prereqs
```

### Installation

Two deployment paths are available:

#### Option A: Validated Pattern (automated, GitOps)

Deploys everything — operators, Vault, ESO, Keycloak, secrets, and a default sandbox — via ArgoCD.

```bash
# 1. Clone the repository
git clone https://github.com/validatedpatterns-sandbox/secure-agent-workspace.git
cd secure-agent-workspace

# 2. Log in to OpenShift with cluster-admin
oc login --server=https://api.<cluster>:6443 -u <user>

# 3. Generate SSH keys (used for on-demand SSH into the gateway VM)
make generate-keys

# 4. Configure secrets
cp values-secret.yaml.template ~/values-secret.yaml
# The default profile needs an NVIDIA key and a Brave Search key:
#   ~/.nvidia-api-key and ~/.brave-api-key (one line each, chmod 600)

# 5. Copy pre-built images to the cluster (~5 min)
# Mirrors images from quay.io/rh-ai-quickstart to the internal registry.
# No build needed — images are pre-built by maintainers.
make copy-images

# 6. Deploy the pattern (runs inside the VP utility container)
# NOTE: The deploying branch must exist on the remote (origin).
# pattern.sh forwards TARGET_BRANCH and TARGET_ORIGIN (not TARGET_REVISION).
#   export TARGET_BRANCH=main TARGET_ORIGIN=origin
./pattern.sh make install

# 7. Authenticate and configure the CLI
make login                    # Opens browser → login with alice / alice
export OPENSHELL_SAW_NAME=alice          # VM alice in namespace saw-alice
make openshell-saw-configure-gateway
openshell gateway login $OPENSHELL_SAW_NAME   # Authenticate CLI with gateway

# 8. Verify
# The first command lists the default workspace; the second lists cuda-dev.
openshell sandbox list
openshell sandbox list --workspace cuda-dev
```

Add or remove one `users:` entry in `overrides/saw-users.yaml` and push; Argo CD creates or removes `saw-<name>`.
Each user's virtual machine is named after them, in namespace `saw-<name>` (Alice's machine is `alice` in `saw-alice`, not `openshell-saw`), the same layout as `make openshell-saw-create OPENSHELL_SAW_NAME=alice`.
Set `OPENSHELL_SAW_NAME` to the user name; `SAW_NS` defaults to `saw-<name>`.
Removing an entry deletes that user's Argo apps and leaves the VM running.
To delete the namespace and the VM as well, first set `pruneOnRemove: true` on that user's entry and push, then remove the entry and push.
Upgrading an install that still has the `openshell-saw` VM: see [Upgrading from the single-user layout](docs/deployment-guide.md#upgrading-from-the-single-user-layout).

#### Option B: Quickstart (manual, step-by-step)

Install operators from OperatorHub first, then deploy components manually. RHBK must be installed in the `saw-keycloak` namespace (set `KEYCLOAK_NS` to use another one, e.g. `KEYCLOAK_NS=keycloak` for a Keycloak your cluster already has). Each sandbox gets its own namespace, `saw-<name>`.

```bash
# 1. Clone the repository
git clone https://github.com/validatedpatterns-sandbox/secure-agent-workspace.git
cd secure-agent-workspace

# 2. Log in to OpenShift with cluster-admin
oc login --server=https://api.<cluster>:6443 -u <user>

# 3. Verify prerequisites
make check-prereqs

# 4. Generate SSH keys
make generate-keys

# 5. Copy pre-built images to the cluster
make copy-images

# 6. Deploy Keycloak (if one is already running in KEYCLOAK_NS, it is used;
#    you are asked before the OpenShell realm is imported into it)
make keycloak

# 7. Verify Keycloak (realm, openshell-cli client, roles)
make keycloak-check
make keycloak-issuer

# 8. Deploy governance interceptor
helm upgrade --install governance-policy charts/governance-policy \
  --namespace openshell-agents
helm upgrade --install governance-interceptor charts/governance-interceptor \
  --namespace openshell-agents

# 9. Authenticate
make login                    # Opens browser → login with alice / alice
make whoami                   # Verify identity

# 10. Create a sandbox (deploys into namespace saw-alice)
export OPENSHELL_SAW_NAME=alice
make openshell-saw-create \
  PROVIDER=build \
  MODEL=nvidia/nemotron-3-super-120b-a12b \
  API_KEY=<your-api-key>

# 11. Follow the in-VM installer (in another terminal)
make openshell-saw-logs

# 12. Check status
make openshell-saw-list
make status

# 13. Wait for the installer to finish
make openshell-saw-status
# Wait for "install" and "apply" to show "phase": "Done"

# 14. Configure the openshell CLI
make openshell-saw-configure-gateway

# 15. Authenticate CLI with the gateway
openshell gateway login $OPENSHELL_SAW_NAME
# Log in as alice / alice in the browser

# 16. Verify sandboxes
# sandbox list without --workspace only shows workspace "default"
openshell sandbox list
openshell sandbox list --workspace cuda-dev

# 17. Launch TUI (pick one)
SANDBOX_NAME=cuda-sandbox \
WORKSPACE=cuda-dev \
make nemoclaw-tui # NemoClaw
SANDBOX_NAME=notebook \
make openclaw-tui # OpenClaw

# 18. Launch GUI (pick one)
SANDBOX_NAME=cuda-sandbox \
WORKSPACE=cuda-dev \
GUI_PORT=18789 \
make nemoclaw-gui # NemoClaw
SANDBOX_NAME=notebook \
GUI_PORT=18790 \
make openclaw-gui # OpenClaw
```

> **Token expiry:** The OIDC access token lasts 10 hours. If it expires, run `make login` to re-authenticate, then `make openshell-saw-configure-gateway` to copy the fresh token. Alternatively, run `openshell gateway login` directly to re-authenticate with the gateway.

You can set `OPENSHELL_SAW_NAME` once via `export` and all `openshell-saw-*` targets will use it automatically. The sandbox namespace defaults to `saw-$OPENSHELL_SAW_NAME`; set `SAW_NS` if it differs (the pattern's default sandbox is `alice` in `saw-alice`).

> **Sandbox name limit:** `OPENSHELL_SAW_NAME` must be **19 characters or fewer**. OpenShell rejects longer names with "name exceeds maximum length". The Helm chart and `make openshell-saw-create` will both fail fast with a clear error if this limit is exceeded.

#### Supported inference providers

| Provider | Key | Example model |
|---|---|---|
| Google Gemini | `gemini` | `gemini-2.5-flash` |
| Anthropic | `anthropic` | `claude-sonnet-4-6` |
| OpenAI | `openai` | `gpt-4o` |
| NVIDIA Build | `build` | `meta/llama-3.3-70b-instruct` |
| OpenRouter | `openrouter` | `anthropic/claude-sonnet-4-6` |
| Ollama (local) | `ollama` | `llama3` |
| Custom OpenAI-compatible endpoint (vLLM, Ollama, ...) | `openai` + `ENDPOINT_URL` | the model the server serves; see [Custom inference provider](#custom-inference-provider) |

#### Custom inference provider

Use a model server of your own (vLLM, Ollama, or any OpenAI-compatible API) instead of a cloud provider. The installer creates an `openai` provider with the endpoint's base URL and onboards OpenClaw against that URL. OpenShell 0.1.x has no inference routing: the agent sends a placeholder key, and the sandbox proxy puts in the real one only for the hosts the provider profile names, so the profile must name your endpoint's host (see [docs/custom-inference.md](docs/custom-inference.md)).

Select the `custom-inference` SAW-BOM profile and give the endpoint's URL, model and key.

**Option A (Validated Pattern)** — in `~/values-secret-secure-agent-workspace.yaml`, use the commented custom example of the `inference` secret (`provider: openai`, `model`, `url`, `api_key`), and select the profile in `charts/saw-bom/values.yaml` (committed to the branch the pattern deploys):

```yaml
profiles:
  - custom-inference
```

**Option B (Quickstart)** — one command:

```bash
make openshell-saw-create OPENSHELL_SAW_NAME=alice PROFILES=custom-inference \
  PROVIDER=openai MODEL=<served model> \
  ENDPOINT_URL=http://vllm.<namespace>.svc:8000/v1 \
  API_KEY=<key>          # any non-empty value if the server needs no key
```

Notes:

- The **gateway VM** calls the URL, not your laptop: use a cluster Service or Route host. `localhost` is refused.
- With governance on, the `openai` provider type must be in the governance catalog (`charts/governance-policy/profiles/openai.yaml`, shipped with the chart).
- Self-hosted models can be slow; the profile sets a 300-second inference timeout.

Details: [docs/custom-inference.md](docs/custom-inference.md).

#### Governance with APF (optional)

Every SAW gateway calls a fail-closed governance service. By default that is the OpenShell governance interceptor. It can instead be NVIDIA **Agent Policy Fabric (APF)**, which serves the same policy (`charts/governance-policy`) as an Ed25519-signed bundle, stamps provenance on every sandbox, refuses runtime policy changes and writes an audit trail. Details: [docs/apf.md](docs/apf.md).

**1. Get access to APF (once).** APF's Helm chart and images are private on `ghcr.io/mkhaas/apf`.

- Ask the owner (@mkhaas) for read access to the chart **and to each image package**: `apf-policy-service`, `apf-policy-gateway` and `apf-compile`. On GHCR each image has its own access list, so access to one does not give the others.
- Create a GitHub token (classic) with the `read:packages` scope and save it:
  ```bash
  printf '%s' '<token>' > ~/.ghcr-token && chmod 600 ~/.ghcr-token
  ```
- Check that you can pull:
  ```bash
  docker login ghcr.io -u <github-user> --password-stdin < ~/.ghcr-token
  docker pull ghcr.io/mkhaas/apf/apf-policy-gateway:0.2.0
  ```

**2. Create your signing key and bundle.** This repository ships no key and no bundle. Each deployment makes its own, so no deployment trusts someone else's key.

```bash
python3 -m pip install cryptography        # if missing
make apf-keys      # seed -> ~/.apf-keys/apf.seed (never in git); public key -> charts/governance-interceptor/files/apf/apf.pub
make apf-bundle    # signs charts/governance-policy -> charts/governance-interceptor/files/apf/bundle.tar.gz
git add charts/governance-interceptor/files/apf
git commit -m "chore(governance): sign the APF policy bundle"
git push origin <branch the pattern deploys from>
```

Keep `~/.apf-keys/apf.seed` safe: only its holder can sign policy changes. `make apf-bundle-check` verifies the committed bundle.

**3. Add the secrets.** Add these two entries under `secrets:` in your values-secret file (`~/values-secret-secure-agent-workspace.yaml`, or `~/values-secret.yaml`):

```yaml
  # Pull the private APF chart (Argo CD) and images (cluster)
  - name: ghcr
    fields:
    - name: username
      value: <github-user>
    - name: token
      path: ~/.ghcr-token
  # The private half of the key from step 2
  - name: apf-signing
    fields:
    - name: seed
      path: ~/.apf-keys/apf.seed
```

Load them and check that the three ExternalSecrets become ready:

```bash
./pattern.sh make load-secrets          # reports one more secret per entry
oc get externalsecret ghcr-pull governance-apf-signing -n openshell-agents
oc get externalsecret governance-apf-chart-repo -n vp-gitops
```

They read `secret/hub/ghcr` and `secret/hub/apf-signing` in Vault and create the image pull secret, the signing key Secret, and the Argo CD repository Secret for the private chart, all outside the user namespaces.

**4. Switch the engine.** Either set it in git:

```yaml
# values-global.yaml
global:
  governance:
    engine: apf
```

or set it on the installed pattern without a commit:

```bash
oc patch pattern secure-agent-workspace -n patterns-operator --type merge \
  -p '{"spec":{"extraParameters":[{"name":"global.governance.engine","value":"apf"}]}}'
```

For a new install, pass the same override: `./pattern.sh make install EXTRA_HELM_OPTS="--set main.extraParameters[0].name=global.governance.engine --set main.extraParameters[0].value=apf"`.

Argo CD then removes the interceptor, creates the `governance-apf` app (the APF chart, still serving `governance-interceptor.openshell-agents.svc:18081`), and re-renders each user's gateway config with APF's bindings. Restart each user VM once so it boots with them:

```bash
oc get application governance-apf -n vp-gitops              # Synced / Healthy
oc get pod -n openshell-agents -l app.kubernetes.io/name=apf  # 2/2 Running
virtctl -n saw-<user> restart <user>
```

While APF is not running the gateways refuse write operations (fail closed). If the APF pod shows `ErrImagePull` with `denied`, your account lacks access to that image package (step 1).

**Quickstart (no Argo CD):** after steps 1 and 2, `GHCR_USER=<github-user> GHCR_TOKEN="$(cat ~/.ghcr-token)" make governance-apf`, then create SAWs with `make openshell-saw-create ... GOVERNANCE_ENGINE=apf`.

**Changing policy:** edit `charts/governance-policy`, run `make apf-bundle` (it bumps `policy_revision`), commit and push the new bundle. **Switching back:** set `engine: interceptor` (or remove the override), delete the `governance-apf` Application and restart the user VMs.

### Validating the deployment

```bash
# List sandboxes (default workspace, then cuda-dev)
openshell sandbox list
openshell sandbox list --workspace cuda-dev

# NemoClaw sandbox (TUI and GUI) — workspace cuda-dev
SANDBOX_NAME=cuda-sandbox \
WORKSPACE=cuda-dev \
make nemoclaw-tui
SANDBOX_NAME=cuda-sandbox \
WORKSPACE=cuda-dev \
GUI_PORT=18789 \
make nemoclaw-gui

# OpenClaw sandbox (TUI and GUI) — workspace default
SANDBOX_NAME=notebook \
make openclaw-tui
SANDBOX_NAME=notebook \
GUI_PORT=18790 \
make openclaw-gui

# Legacy aliases (default to nemoclaw)
make openshell-saw-tui
make openshell-saw-gui

# Or access the dashboard directly via the route
oc get route ${OPENSHELL_SAW_NAME}-dashboard -n ${SAW_NS:-saw-$OPENSHELL_SAW_NAME} -o jsonpath='https://{.spec.host}'

# Installer status, and a shell on the gateway VM for debugging
# (adds your SSH key to the VM on demand)
make openshell-saw-status
make openshell-saw-vm-ssh

# Installer and chart tests (no cluster needed; needs helm and
# python3 -m pip install -r tests/requirements.txt)
make test-installer

# Run offline template validation (43 checks)
./tests/test-oidc-templates.sh
```

### Delete

```bash
# Delete a single sandbox
make openshell-saw-delete

# Delete Keycloak + PostgreSQL
make delete-keycloak

# Delete all quickstart resources (keycloak, images, gateway image)
make delete-all

# Uninstall the validated pattern (experimental)
./pattern.sh make uninstall
```

## Repository structure

```
.
├── Makefile                          # Root Makefile (includes common + quickstart)
├── Makefile-common                   # Validated Pattern targets (install, load-secrets, etc.)
├── Makefile-quickstart               # Quickstart targets (build, keycloak, openshell-saw-create, etc.)
├── values-global.yaml                # Pattern config (name, ArgoCD, secret loader)
├── values-prod.yaml                  # ClusterGroup (operators, subscriptions, applications)
├── values-secret.yaml.template       # Secrets template (inference keys, SSH keys)
├── overrides/
│   └── saw-users.yaml                # One list entry per user
├── charts/                           # ArgoCD-managed Helm charts
│   ├── openshell-keycloak/           # Keycloak CR + KeycloakRealmImport (RHBK operator)
│   ├── openshell-saw/            # Per-user sandbox VM + gateway + agent
│   ├── pattern-secrets/              # ExternalSecrets for provider API keys + SSH
│   └── saw-users/                    # Turns the user list into namespaces and Argo apps
├── image-builder-charts/             # Build-time charts (imagestreams, bootc image)
│   └── helm/
│       ├── nemoclaw-imagestream/     # NemoClaw sandbox image BuildConfig
│       ├── nemoclaw-cli-imagestream/ # NemoClaw CLI image BuildConfig
│       └── openshell-gateway-image/  # Bootc gateway VM image + golden image
├── scripts/                          # Runtime utilities and automation
│   ├── e2e-test.sh                   # Headless E2E test
│   ├── openshell-saw-create.sh             # Sandbox provisioning logic
│   ├── openshell-saw-gui.sh                # Web UI port-forward
│   ├── openshell-saw-logout.sh             # Clear OIDC tokens from VMs
│   ├── generate-keys.sh              # SSH keypair generation
│   └── oidc-login.sh                 # Browser-based OIDC login
├── tests/                            # Test scripts
│   ├── test-bootc-e2e.sh             # Bootc pipeline E2E (28 checks)
│   ├── test-oidc-templates.sh        # Helm template validation (43 checks)
│   ├── test-access-control.sh        # Per-user access control E2E
│   └── test-multiuser-isolation.sh   # Namespace isolation E2E
├── cli/                              # Admin provisioning CLI (openshell-saw)
├── pattern.sh                        # VP utility container wrapper
└── ansible.cfg                       # VP ansible config
```

## References

- [NVIDIA Secure Agent Workspace Reference Design](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/)
- [OpenShift Virtualization Reference Implementation](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/openshift-virtualization-reference-implementation.html)
- [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)
- [NVIDIA NemoClaw](https://github.com/NVIDIA/NemoClaw)
- [Red Hat Validated Patterns](https://validatedpatterns.io/)
- [Red Hat Build of Keycloak](https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/)

## Technical details

### Security model

The system implements layered isolation:

1. **VM-level isolation** — Each user gets a dedicated KubeVirt VM (one VM per user, no shared agent process space)
2. **OIDC authentication** — Keycloak provides SSO with PKCE and device code flow support
3. **Per-user access control** — Auth proxy validates the OIDC token's `preferred_username` matches the sandbox owner
4. **TLS passthrough** — Gateway route preserves gRPC/HTTP2 end-to-end; the gateway validates OIDC tokens directly
5. **Secret management** — API keys flow through Vault + ESO; the user's SSH private key never touches the cluster in plaintext
6. **Governed gateways** — every gateway calls a fail-closed governance service: the OpenShell governance interceptor, or APF with a signed policy bundle ([docs/apf.md](docs/apf.md))

### Keycloak test users

| Username | Password | Roles |
|---|---|---|
| `developer` | `developer` | `openshell-user` |
| `admin` | `admin` | `openshell-user`, `openshell-admin` |
| `alice` | `alice` | `openshell-user`, `openshell-admin` |
| `bob` | `bob` | `openshell-user`, `openshell-admin` |

### Namespaces

| Namespace | Contents |
|---|---|
| `saw-<name>` (one per sandbox) | The gateway VM, its installer inputs and provider Secrets |
| `openshell-agents` | Golden VM image, image builds, governance interceptor |
| `keycloak` | Keycloak (RHBK) |

The gateway VM installs itself from a versioned Bill of Materials on every boot; see [docs/versioned-bom-installer.md](docs/versioned-bom-installer.md).

### OIDC issuer resolution

The sandbox chart resolves the OIDC issuer URL automatically:
- **Validated Pattern flow:** Computed from `global.clusterDomain` (injected by ArgoCD)
- **Quickstart flow:** Detected from the Keycloak route at `make openshell-saw-create` time
- **Manual override:** Set `oidc.issuerUrl` explicitly

## Tags

| Field | Value |
|---|---|
| **Title** | Secure Agent Workspace |
| **Description** | Deploy isolated, per-user AI agent sandboxes on OpenShift Virtualization |
| **Industry** | Cross-industry |
| **Product** | Red Hat OpenShift |
| **Use case** | AI agent sandboxing, secure coding environments |
| **Partner** | NVIDIA |
