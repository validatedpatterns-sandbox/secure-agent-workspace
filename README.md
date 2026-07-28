# OpenShell Sandbox Helm Charts

Six Helm charts for deploying per-user OpenShell + NemoClaw agent sandboxes on OpenShift Virtualization (KubeVirt).

## Architecture

```
                      openshell-agents (shared namespace)
┌─────────────────────────────┐  ┌─────────────────────────────┐
│  nemoclaw-imagestream       │  │  nemoclaw-cli-imagestream   │  Deploy once per cluster
│  ImageStream + BuildConfig  │  │  ImageStream + BuildConfig  │  Build sandbox + CLI images
│  Builds NemoClaw sandbox    │  │  Builds NemoClaw CLI        │
└──────────────┬──────────────┘  └──────────────┬──────────────┘
               │ image.sandbox override          │ CLI extracted at sandbox setup
               ▼                                 ▼
┌─────────────────────────────┐
│  openshell-keycloak         │  (Optional) Local OIDC provider
│  Keycloak Deployment +      │  for development/testing
│  Route + Realm ConfigMap    │  Test users: developer, admin, alice, bob
└──────────────┬──────────────┘
               │ JWKS validation
               ▼
┌─────────────────────────────┐
│  openshell-gateway-image    │  (Optional) Pre-baked gateway
│  ImageStream + BuildConfig  │  VM disk image for faster boot
│  virt-customize + qcow2     │
└──────────────┬──────────────┘
               │ containerDisk (alternative to snapshot)
               ▼
┌─────────────────────────────────────────────────────────────┐
│  openshell-gateway                                          │  Deploy once per cluster
│  (master VM + snapshot)                                     │  Fedora 44 + OpenShell gateway
│  DataVolume + cloud-init + golden image DataSource          │  Post-install hook creates snapshot
└──────────────────────────────┬──────────────────────────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         ▼                     ▼                     ▼
  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
  │ alice sandbox    │  │ bob sandbox      │  │ carol sandbox    │
  │ VM + Routes +    │  │ VM + Routes +    │  │ VM + Routes +    │
  │ oauth2-proxy +   │  │ oauth2-proxy +   │  │ oauth2-proxy +   │
  │ Job + SSH secret │  │ Job + SSH secret │  │ Job + SSH secret │
  └──────────────────┘  └──────────────────┘  └──────────────────┘
         ▲                                              ▲
   shared namespace (default)                 OR per-user namespaces
   openshell-agents                              saw-alice, saw-bob
```

Sandboxes can live in a **shared namespace** (default, scales to thousands of users) or in **per-user namespaces** (`saw-<username>`). Each sandbox has an optional **oauth2-proxy** that restricts access to the owning user by validating the OIDC token's `preferred_username`.

## Prerequisites

- OpenShift cluster with **OpenShift Virtualization** (KubeVirt/CDI) installed
- `helm` 3.x
- `oc` or `kubectl` logged in with cluster-admin
- `openshell` CLI installed ([releases](https://github.com/NVIDIA/OpenShell/releases))
- API key for your chosen inference provider (Gemini, Anthropic, OpenAI, NVIDIA, OpenRouter, or custom)
- SSH keypair (`~/.ssh/id_ed25519`)

## User Flow

```bash
# 1. Log in to OpenShift
oc login ...

# 2. Provision a sandbox (owner auto-detected from oc whoami)
make sandbox-create SANDBOX_NAME=my-sandbox PROVIDER=gemini MODEL=gemini-2.5-flash API_KEY=<key>

# 3. Configure the openshell CLI to point at the gateway
make openshell-configure-gateway SANDBOX_NAME=my-sandbox

# 4. Authenticate with Keycloak via the openshell CLI
openshell gateway login

# 5. Use your sandbox (already created during provisioning)
openshell sandbox list
```

Users interact only via the `openshell` CLI and their gateway URL. No knowledge of OpenShift or Kubernetes is required after step 1.

## Quick Start (snapshot mode)

The default flow creates a master gateway VM, snapshots it, then clones from the snapshot for each user. For a faster alternative using pre-built container disk images, see [Quick Start (containerDisk)](#quick-start-containerdisk) below.

```bash
# 1. Build the NemoClaw sandbox image (one-time)
make build

# 2. Build the NemoClaw CLI image (one-time)
make build-cli

# 3. (Optional) Deploy Keycloak for OIDC authentication
make keycloak

# 4. Deploy the gateway VM and snapshot it (~8-12 min)
make gateway OIDC_ISSUER=$(make keycloak-issuer)

# 5. Create a user sandbox
make sandbox-create SANDBOX_NAME=my-sandbox PROVIDER=gemini MODEL=gemini-2.5-flash API_KEY=<your-key>

# 6. Configure and use
make openshell-configure-gateway SANDBOX_NAME=my-sandbox
openshell gateway login
openshell sandbox list
```

See `make help` for all available targets.

## Quick Start (containerDisk)

An alternative to the snapshot flow that pre-bakes all OpenShell packages into a container disk image. Sandboxes boot directly from the image -- no master VM or snapshot required.

```bash
# Build images (once per cluster)
make build                    # NemoClaw sandbox image
make build-cli                # NemoClaw CLI image
make build-gateway-image      # Pre-baked gateway VM image (~15 min)

# Deploy gateway from pre-built image (no snapshot needed)
make gateway-from-image

# Create sandbox (boots directly from image)
make sandbox-create SANDBOX_NAME=my-sandbox PROVIDER=gemini MODEL=gemini-2.5-flash API_KEY=<key> SOURCE_MODE=containerDisk
```

## Per-User Access Control

Each sandbox is protected by an **oauth2-proxy** that validates the OIDC token's `preferred_username` matches the sandbox owner. When a user provisions a sandbox, their identity is auto-detected from `oc whoami` and the proxy is configured to only allow that user.

### How It Works

```
User (openshell CLI)
  │
  │ Authorization: Bearer <JWT>
  ▼
OpenShift Route (TLS edge)
  │
  ▼
oauth2-proxy (per-sandbox)
  │ Validates: preferred_username == owner
  │ If mismatch → 403
  ▼
OpenShell Gateway (in VM)
  │ Also validates OIDC token (role-based)
  ▼
Sandbox container
```

- **Access control is always on** when an owner is detected (auto from `oc whoami`)
- Admin can provision for another user: `make sandbox-create ... OWNER=alice`
- To disable: `--set accessControl.enabled=false` in the Helm install

### Sandbox Chart Values

| Key | Default | Description |
|-----|---------|-------------|
| `accessControl.enabled` | `false` | Enable oauth2-proxy per-user access control |
| `accessControl.owner` | `""` | Owner's `preferred_username` (from OIDC token) |
| `accessControl.image` | `quay.io/oauth2-proxy/oauth2-proxy:v7.7.1` | oauth2-proxy container image |
| `accessControl.cookieSecret` | `""` | Cookie encryption secret (auto-generated if empty) |

## Namespace Modes

Two namespace strategies are available, controlled by `NAMESPACE_MODE`:

| Mode | Description |
|------|-------------|
| `shared` (default) | All sandboxes in one namespace (`openshell-agents`). Scales to thousands of users. Access control enforced by oauth2-proxy. |
| `perUser` | Each user gets `saw-<username>` namespace. Provides Kubernetes-level resource isolation. |

```bash
# Shared namespace (default)
make sandbox-create SANDBOX_NAME=my-sandbox PROVIDER=gemini ...

# Per-user namespace
make sandbox-create SANDBOX_NAME=my-sandbox PROVIDER=gemini ... NAMESPACE_MODE=perUser
```

## openshell-saw CLI

An admin provisioning CLI for cluster-level operations. Users interact with their sandboxes via the upstream `openshell` CLI.

### Install

```bash
cd cli && pip install -e .
```

### Commands

| Command | Description |
|---------|-------------|
| `openshell-saw login` | Authenticate with OIDC (for provisioning) |
| `openshell-saw whoami` | Show current identity and token status |
| `openshell-saw sandbox create NAME -p PROVIDER -m MODEL -k KEY` | Provision a sandbox |
| `openshell-saw sandbox create NAME --owner USER ...` | Provision for another user |
| `openshell-saw sandbox list` | List sandboxes |
| `openshell-saw sandbox url NAME` | Show gateway and dashboard URLs |
| `openshell-saw sandbox ssh NAME` | SSH into a sandbox VM |
| `openshell-saw sandbox logs NAME` | Follow setup job logs |
| `openshell-saw sandbox delete NAME` | Delete a sandbox |
| `openshell-saw build gateway-image` | Build the pre-baked VM image |
| `openshell-saw status` | Show all OpenShell resources |

## OIDC Authentication

For environments that require user authentication:

```bash
# 1. Deploy Keycloak (local OIDC provider for testing)
make keycloak

# 2. Deploy gateway with OIDC enabled
make gateway OIDC_ISSUER=$(make keycloak-issuer)

# 3. Create a sandbox (owner auto-detected, access control enabled)
make sandbox-create SANDBOX_NAME=my-sandbox PROVIDER=gemini MODEL=gemini-2.5-flash API_KEY=<key>

# 4. Configure and login
make openshell-configure-gateway SANDBOX_NAME=my-sandbox
openshell gateway login

# 5. Check identity
make whoami
```

When using an external OIDC provider (Okta, Entra ID, corporate SSO), skip step 1 and pass the provider's issuer URL directly:

```bash
make gateway OIDC_ISSUER=https://sso.corp.example.com
```

See `docs/oidc-keycloak.md` for full details.

## Supported Inference Providers

| Provider key | Example model | Notes |
|-------------|---------------|-------|
| `gemini` | `gemini-2.5-flash` | Google Gemini API |
| `anthropic` | `claude-sonnet-4-6` | Anthropic API |
| `openai` | `gpt-4o` | OpenAI API |
| `build` | `meta/llama-3.3-70b-instruct` | NVIDIA Build / Endpoints |
| `openrouter` | `anthropic/claude-sonnet-4-6` | OpenRouter |
| `ollama` | `llama3` | Local Ollama (no API key needed) |
| `custom` | any | Custom endpoint (set `ENDPOINT_URL`) |

Vertex AI (legacy): use `GCP_SA_JSON` instead of `PROVIDER`/`API_KEY`:

```bash
make sandbox-create SANDBOX_NAME=my-sandbox GCP_SA_JSON=path/to/gcp-sa.json
```

## Network Policy

Sandboxes are network-restricted by default. You must allow outbound access to your LLM provider's API endpoint before the agent can make inference calls.

Configure network policy using the OpenShell terminal:

```bash
# SSH into the sandbox VM
make sandbox-ssh SANDBOX_NAME=my-sandbox

# Open the OpenShell terminal to manage policies
openshell term
```

Use `openshell policy` to allowlist endpoints. Common endpoints by provider:

| Provider | Endpoint to allow |
|----------|-------------------|
| Gemini | `generativelanguage.googleapis.com` |
| Anthropic | `api.anthropic.com` |
| OpenAI | `api.openai.com` |
| NVIDIA Build | `integrate.api.nvidia.com`, `build.nvidia.com` |
| OpenRouter | `openrouter.ai` |

## Chart 1: nemoclaw-imagestream (sandbox image builder)

Builds the NemoClaw sandbox image from the [NVIDIA/NemoClaw](https://github.com/NVIDIA/NemoClaw) repository using an OpenShift BuildConfig and stores it in an ImageStream.

### Install

```bash
helm install nemoclaw-imagestream ./charts/nemoclaw-imagestream \
  --namespace openshell-agents --create-namespace
```

Then start the build:

```bash
oc start-build nemoclaw-sandbox -n openshell-agents --follow
```

### Values

| Key | Default | Description |
|-----|---------|-------------|
| `namespace` | `openshell-agents` | Target namespace |
| `source.git.uri` | `https://github.com/NVIDIA/NemoClaw.git` | NemoClaw source repo |
| `source.git.ref` | `main` | Git branch or tag |
| `build.baseImage` | `ghcr.io/nvidia/nemoclaw/sandbox-base:latest` | Base image for NemoClaw build |
| `build.model` | `claude-sonnet-4-6` | Default model |
| `build.inferenceBaseUrl` | `https://inference.local/v1` | Inference endpoint |
| `build.inferenceApi` | `openai-completions` | Inference API type |
| `build.contextWindow` | `200000` | Model context window |
| `build.maxTokens` | `8192` | Max output tokens |
| `build.reasoning` | `false` | Enable reasoning mode |
| `build.toolDisclosure` | `progressive` | Tool disclosure mode |
| `build.agentTimeout` | `600` | Agent timeout (seconds) |
| `build.webSearchEnabled` | `0` | Enable web search |
| `output.imageStreamTag` | `nemoclaw-sandbox:latest` | ImageStream output tag |

### What it creates

- **ImageStream** — registry target for the built NemoClaw image
- **BuildConfig** — clones the NemoClaw repo and builds the Dockerfile with configured build args

## Chart 2: nemoclaw-cli-imagestream (CLI image builder)

Builds the NemoClaw CLI as a standalone container image. The CLI is extracted from this image during sandbox setup and installed on the gateway VM for `nemoclaw sandbox connect` and `nemoclaw sandbox dashboard-url` commands.

### Install

```bash
helm install nemoclaw-cli-imagestream ./charts/nemoclaw-cli-imagestream \
  --namespace openshell-agents --create-namespace
```

Then start the build:

```bash
oc start-build nemoclaw-cli -n openshell-agents --follow
```

### Values

| Key | Default | Description |
|-----|---------|-------------|
| `namespace` | `openshell-agents` | Target namespace |
| `source.git.uri` | `https://github.com/NVIDIA/NemoClaw.git` | NemoClaw source repo |
| `source.git.ref` | `main` | Git branch or tag |
| `build.nodeImage` | `node:22-trixie-slim` | Node.js base image for build and runtime |
| `output.imageStreamTag` | `nemoclaw-cli:latest` | ImageStream output tag |

### What it creates

- **ImageStream** — registry target for the built NemoClaw CLI image
- **BuildConfig** — multi-stage Docker build: installs dependencies, runs `npm run build:cli`, copies dist + agents + scripts into a slim runtime image

## Chart 3: openshell-gateway (master VM + snapshot)

Deploys a single Fedora 44 VM with OpenShell CLI + gateway pre-installed. A post-install hook waits for cloud-init to complete, then creates a `VirtualMachineSnapshot` for fast cloning.

### Install

```bash
helm install openshell-gateway ./charts/openshell-gateway \
  --namespace openshell-agents --create-namespace \
  --set sshPublicKey="$(cat ~/.ssh/id_ed25519.pub)" \
  --timeout 30m
```

### Values

| Key | Default | Description |
|-----|---------|-------------|
| `sshPublicKey` | `""` (required) | Operator's SSH public key |
| `namespace` | `openshell-agents` | Target namespace |
| `vm.cores` | `4` | VM CPU cores |
| `vm.memory` | `8Gi` | VM memory |
| `vm.diskSize` | `40Gi` | Root disk size |
| `openshell.version` | `0.0.89` | OpenShell RPM version |
| `openshell.fedoraRelease` | `44` | Fedora release for RPM suffix |
| `image.fedoraCloud` | Fedora 44 qcow2 URL | Cloud image download URL |
| `image.sandbox` | `image-registry...nemoclaw-sandbox:latest` | Sandbox container image |
| `image.supervisor` | `ghcr.io/nvidia/openshell/supervisor:latest` | Supervisor container image |
| `snapshot.enabled` | `true` | Create VirtualMachineSnapshot after cloud-init |
| `snapshot.timeout` | `900` | Seconds to wait for VMI Ready before snapshotting |
| `test.enabled` | `true` | Run cloud-init readiness test on install |
| `test.vmiTimeout` | `600` | Seconds to wait for VMI in test |
| `test.gatewayTimeout` | `300` | Seconds to wait for gateway port in test |

### What it creates

- **DataVolume** — downloads the Fedora 44 cloud image (one-time, ~5-10 min)
- **Secret** — cloud-init user-data (OpenShell RPM install + gateway systemd setup)
- **VirtualMachine** — the master gateway VM
- **Service** — ClusterIP exposing gateway (17670) and SSH (22)
- **VirtualMachineSnapshot** (post-install hook) — snapshot of the gateway VM for fast cloning

### Verify

```bash
# Check snapshot readiness
oc -n openshell-agents get virtualmachinesnapshots

# Stream test pod logs in real time
kubectl logs -f openshell-gateway-cloud-init-test -n openshell-agents

# Or run the built-in test (shows logs after completion)
helm test openshell-gateway -n openshell-agents --logs

# SSH in and check the gateway
virtctl -n openshell-agents ssh cloud-user@vm/openshell-gateway
openshell status
```

> **Host key changed after reinstall?** Each `helm install` creates a new VM with
> fresh SSH host keys. Clear the stale entry and reconnect:
>
> ```bash
> ssh-keygen -R "vm.openshell-gateway.openshell-agents"
> virtctl -n openshell-agents ssh cloud-user@vm/openshell-gateway
> ```

## Chart 4: openshell-sandbox (per-user)

Clones from the gateway snapshot and configures a NemoClaw agent sandbox for a single user. Each install creates a dedicated VM with its own inference provider configuration, OpenClaw agent, and optional per-user access control.

### Install

```bash
make sandbox-create SANDBOX_NAME=my-sandbox \
  PROVIDER=gemini MODEL=gemini-2.5-flash API_KEY=<your-key>
```

Or with Helm directly:

```bash
helm install my-sandbox ./charts/openshell-sandbox \
  --namespace openshell-agents \
  --set sandboxName=my-sandbox \
  --set sshPublicKey="$(cat ~/.ssh/id_ed25519.pub)" \
  --set inference.provider=gemini \
  --set inference.model=gemini-2.5-flash \
  --set inference.apiKey=<your-key> \
  --set accessControl.enabled=true \
  --set accessControl.owner=myusername \
  --set oidc.issuerUrl=https://keycloak.example.com/realms/openshell
```

### Values

| Key | Default | Description |
|-----|---------|-------------|
| `sandboxName` | `""` (required) | DNS-safe sandbox name |
| `sshPublicKey` | `""` (required) | User's SSH public key |
| `sourceMode` | `snapshot` | VM source: `snapshot` or `containerDisk` |
| `sourceSnapshot` | `snap-openshell-gateway` | VirtualMachineSnapshot to clone from |
| `sourceGoldenImage` | `openshell-gateway` | Golden image DataSource name |
| `sourceGoldenImageNamespace` | `""` | Namespace for golden image (cross-namespace) |
| `agent` | `openclaw` | Agent: `openclaw`, `hermes`, or `langchain-deepagents-code` |
| `inference.provider` | `""` | Provider key (see supported providers) |
| `inference.model` | `""` | Model ID |
| `inference.apiKey` | `""` | API key |
| `route.enabled` | `false` | Expose gateway via OpenShift Route |
| `route.dashboard` | `false` | Expose dashboard via OpenShift Route |
| `accessControl.enabled` | `false` | Enable oauth2-proxy per-user restriction |
| `accessControl.owner` | `""` | Owner's OIDC `preferred_username` |
| `accessControl.image` | `quay.io/oauth2-proxy/oauth2-proxy:v7.7.1` | oauth2-proxy image |
| `namespaceMode` | `shared` | `shared` or `perUser` |
| `oidc.token` | `""` | OIDC access token (optional) |
| `oidc.issuerUrl` | `""` | OIDC issuer URL |
| `oidc.clientId` | `openshell-cli` | OIDC client ID |

### What it creates

- **VirtualMachineClone** — clones from the gateway snapshot (~1-2 min)
- **Service** — ClusterIP for the cloned VM
- **Job** — configures sandbox, installs CLI, starts gateway
- **oauth2-proxy** (when `accessControl.enabled`) — Deployment + Service + ConfigMap + Secret
- **Routes** — gateway and dashboard (point to oauth2-proxy when access control is enabled)
- **ServiceAccount + RBAC** — namespace permissions for the Job

### Monitor setup progress

```bash
make sandbox-logs SANDBOX_NAME=my-sandbox
```

### Connect

```bash
# Configure and login via openshell CLI (recommended)
make openshell-configure-gateway SANDBOX_NAME=my-sandbox
openshell gateway login
openshell sandbox list

# Or use direct access (admin)
make tui SANDBOX_NAME=my-sandbox    # Terminal UI
make gui SANDBOX_NAME=my-sandbox    # Web UI
make sandbox-ssh SANDBOX_NAME=my-sandbox  # SSH debug
```

### Uninstall

```bash
make delete-sandbox SANDBOX_NAME=my-sandbox
# or: helm uninstall my-sandbox --namespace openshell-agents
```

## Chart 5: openshell-keycloak (OIDC provider)

Deploys a Keycloak server pre-configured as an OIDC provider for OpenShell. **Optional** — only needed for local testing. Production deployments should use an external OIDC provider (Okta, Entra ID, corporate SSO).

### Install

```bash
make keycloak
```

### Test Users

| Username | Password | Roles |
|----------|----------|-------|
| `developer` | `developer` | `openshell-user` |
| `admin` | `admin` | `openshell-user`, `openshell-admin` |
| `alice` | `alice` | `openshell-user`, `openshell-admin` |
| `bob` | `bob` | `openshell-user`, `openshell-admin` |

### Values

| Key | Default | Description |
|-----|---------|-------------|
| `keycloak.image` | `quay.io/keycloak/keycloak:26.2` | Keycloak container image |
| `keycloak.realm` | `openshell` | Realm name |
| `keycloak.registrationAllowed` | `true` | Allow self-registration |
| `keycloak.route.enabled` | `true` | Create OpenShift Route |
| `keycloak.clients.cli.clientId` | `openshell-cli` | OIDC client ID |
| `keycloak.externalIdp.enabled` | `false` | Federate to external IdP |

## Chart 6: openshell-gateway-image (pre-baked VM image)

Builds a pre-baked Fedora 44 VM image with all OpenShell packages pre-installed using `virt-customize`. The resulting container image wraps a qcow2 disk that can be used as a `containerDisk` volume source.

### Install

```bash
make build-gateway-image
```

## SSH Key Setup

The sandbox chart's setup Job needs SSH access to the cloned VM. Create the secret before installing sandboxes:

```bash
make ssh-secret
```

## Access Control E2E Test

Validates that oauth2-proxy per-user access control works — alice cannot access bob's gateway, and vice versa:

```bash
# Requires: oc logged in, Keycloak deployed with alice/bob test users
scripts/test-access-control.sh
```

The test provisions two sandboxes with access control in a shared namespace, then verifies cross-user access is blocked at the Route level. Pass `--skip-cleanup` to keep resources for debugging.

## Upgrading OpenShell version

1. Update `openshell.version` and `openshell.fedoraRelease` in `openshell-gateway/values.yaml`
2. Reinstall the gateway chart (this downloads new RPMs via cloud-init and creates a new snapshot)
3. New sandbox installs will clone the updated snapshot
