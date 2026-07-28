# Secure Agent Workspace

Helm charts for deploying per-user OpenShell + NemoClaw agent sandboxes on OpenShift Virtualization (KubeVirt) with OIDC authentication and per-user access control.

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
│  openshell-gateway-image    │  Build once per cluster
│  ImageStream + BuildConfig  │  Bootc image (Fedora 44 + OpenShell)
│  DataVolume + DataSource    │  CDI imports → golden image PVC
└──────────────┬──────────────┘
               │ sandboxes clone from golden image
         ┌─────┼─────────────────────┐
         ▼                     ▼                     ▼
  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
  │ alice sandbox    │  │ bob sandbox      │  │ carol sandbox    │
  │ VM + Routes +    │  │ VM + Routes +    │  │ VM + Routes +    │
  │ auth proxy +     │  │ auth proxy +     │  │ auth proxy +     │
  │ Job + SSH secret │  │ Job + SSH secret │  │ Job + SSH secret │
  └──────────────────┘  └──────────────────┘  └──────────────────┘
         ▲                                              ▲
   shared namespace (default)                 OR per-user namespaces
   openshell-agents                              saw-alice, saw-bob
```

Sandboxes can live in a **shared namespace** (default, scales to thousands of users) or in **per-user namespaces** (`saw-<username>`). Each sandbox has an **auth proxy** (dashboard only) that restricts access to the owning user by validating the OIDC token's `preferred_username`.

## Prerequisites

- OpenShift cluster with **OpenShift Virtualization** (KubeVirt/CDI) installed
- `helm` 3.x
- `oc` logged in with cluster-admin
- `openshell` CLI installed ([releases](https://github.com/NVIDIA/OpenShell/releases))
- API key for your chosen inference provider (Gemini, Anthropic, OpenAI, NVIDIA, OpenRouter, or custom)
- SSH keypair (`~/.ssh/id_ed25519`)

## User Flow

```bash
# 1. Log in to OpenShift
oc login ...

# 2. Authenticate with the OIDC provider (Keycloak or external SSO)
make login

# 3. Provision a sandbox (owner auto-detected from OIDC token)
make sandbox-create SANDBOX_NAME=my-sandbox PROVIDER=gemini MODEL=gemini-2.5-flash API_KEY=<key>
# Prompt: "Logged in as 'alice'. Press Enter to set owner to 'alice', or type a different owner:"

# 4. Configure the openshell CLI to point at the gateway
#    Option A: via make target (auto-detects route URL and OIDC issuer)
make openshell-configure-gateway SANDBOX_NAME=my-sandbox
#    Option B: manually with openshell gateway add
GATEWAY_URL=$(oc get route my-sandbox-gateway -n openshell-agents -o jsonpath='https://{.spec.host}')
openshell gateway add "$GATEWAY_URL" --name my-sandbox --gateway-insecure \
  --oidc-issuer https://<keycloak-host>/realms/openshell --oidc-client-id openshell-cli

# 5. Authenticate with the gateway via the openshell CLI
openshell gateway login

# 6. Use your sandbox (already created during provisioning)
openshell --gateway-insecure sandbox list
```

Users interact only via the `openshell` CLI and their gateway URL. No knowledge of OpenShift or Kubernetes is required after the initial setup.

> **Note:** The gateway VM uses a self-signed TLS certificate. Pass `--gateway-insecure` to `openshell` commands, or set `export OPENSHELL_GATEWAY_INSECURE=true` in your shell profile to skip certificate verification.

## Quick Start

Builds a bootc gateway image, then clones from it for each user sandbox.

```bash
# One-time cluster setup
make build                    # NemoClaw sandbox image
make build-cli                # NemoClaw CLI image
make build-gateway-image      # Bootc gateway VM image (~10 min)
make keycloak                 # OIDC provider (or use external SSO)

# Per-user
make login                    # Authenticate with OIDC
make sandbox-create SANDBOX_NAME=my-sandbox PROVIDER=gemini MODEL=gemini-2.5-flash API_KEY=<key>
make openshell-configure-gateway SANDBOX_NAME=my-sandbox
openshell gateway login
openshell --gateway-insecure sandbox list
```

See `make help` for all available targets.

## Per-User Access Control

Each sandbox is protected by an **auth proxy** (openresty/nginx+lua) that validates the OIDC token's `preferred_username` matches the sandbox owner. The owner is auto-detected from the OIDC token obtained via `make login`.

### How It Works

```
User (openshell CLI)                    User (browser)
  │                                       │
  │ Authorization: Bearer <JWT>           │ Authorization: Bearer <JWT>
  ▼                                       ▼
OpenShift Route (TLS passthrough)       OpenShift Route (TLS edge)
  │                                       │
  │ gRPC/HTTP2 preserved                  ▼
  │                                     Auth proxy (per-sandbox, openresty)
  │                                       │ Decodes JWT, checks: preferred_username == owner
  │                                       │ If mismatch → 403 Forbidden
  │                                       │ If no token → 401 Unauthorized
  ▼                                       ▼
OpenShell Gateway (in VM)               Dashboard (in VM)
  │ Validates OIDC token (signature, expiry, roles)
  ▼
Sandbox container
```

The gateway route uses TLS **passthrough** so that gRPC/HTTP2 is preserved end-to-end. The gateway validates OIDC tokens directly (signature, expiry, issuer, audience, roles). The dashboard route uses TLS **edge** termination with an auth proxy that additionally checks `preferred_username == owner` for per-user access control.

- Owner is auto-detected from `make login` OIDC token
- Admin can provision for another user: `make sandbox-create ... OWNER=alice`
- To disable access control: pass `--set accessControl.enabled=false` in the Helm install

### Access Control Values

| Key | Default | Description |
|-----|---------|-------------|
| `accessControl.enabled` | `false` | Enable per-user access control |
| `accessControl.owner` | `""` | Owner's `preferred_username` (from OIDC token) |
| `accessControl.image` | `docker.io/openresty/openresty:1.27.1.1-alpine` | Auth proxy container image |

## Namespace Modes

Two namespace strategies are available, controlled by `NAMESPACE_MODE`:

| Mode | Description |
|------|-------------|
| `shared` (default) | All sandboxes in one namespace (`openshell-agents`). Scales to thousands of users. Access control enforced by auth proxy. |
| `perUser` | Each user gets `saw-<username>` namespace. Provides Kubernetes-level resource isolation. |

```bash
# Shared namespace (default)
make sandbox-create SANDBOX_NAME=my-sandbox PROVIDER=gemini ...

# Per-user namespace
make sandbox-create SANDBOX_NAME=my-sandbox PROVIDER=gemini ... NAMESPACE_MODE=perUser
```

## OIDC Authentication

The system supports any OIDC-compliant provider. For local development, a Keycloak chart is included.

### With Keycloak (development)

```bash
make keycloak                 # Deploy Keycloak with test users
make login                    # Authenticate (opens browser)
make sandbox-create ...       # Owner auto-detected from token
```

### With external OIDC provider (production)

```bash
make login OIDC_ISSUER=https://sso.corp.example.com
make sandbox-create ...
```

No Keycloak deployment needed. The gateway validates tokens directly against the external provider's JWKS endpoint.

### Test Users (Keycloak)

| Username | Password | Roles |
|----------|----------|-------|
| `developer` | `developer` | `openshell-user` |
| `admin` | `admin` | `openshell-user`, `openshell-admin` |
| `alice` | `alice` | `openshell-user`, `openshell-admin` |
| `bob` | `bob` | `openshell-user`, `openshell-admin` |

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

## openshell-saw CLI

An admin provisioning CLI for cluster-level operations. Users interact with their sandboxes via the upstream `openshell` CLI.

```bash
# Install
cd cli && pip install -e .
```

| Command | Description |
|---------|-------------|
| `openshell-saw login` | Authenticate with OIDC (for provisioning) |
| `openshell-saw whoami` | Show current identity and token status |
| `openshell-saw sandbox create NAME --owner USER -p PROVIDER -m MODEL -k KEY` | Provision a sandbox |
| `openshell-saw sandbox list` | List sandboxes |
| `openshell-saw sandbox url NAME` | Show gateway and dashboard URLs |
| `openshell-saw sandbox ssh NAME` | SSH into a sandbox VM |
| `openshell-saw sandbox logs NAME` | Follow setup job logs |
| `openshell-saw sandbox delete NAME` | Delete a sandbox |
| `openshell-saw status` | Show all OpenShell resources |

## Charts

### openshell-sandbox (per-user)

Creates a dedicated VM with inference provider, OpenClaw agent, and per-user access control.

**Key values:**

| Key | Default | Description |
|-----|---------|-------------|
| `sandboxName` | `""` (required) | DNS-safe sandbox name |
| `sshPublicKey` | `""` (required) | User's SSH public key |
| `sourceGoldenImage` | `openshell-gateway` | Golden image DataSource name |
| `agent` | `openclaw` | Agent: `openclaw`, `hermes`, or `langchain-deepagents-code` |
| `inference.provider` | `""` | Provider key |
| `inference.model` | `""` | Model ID |
| `inference.apiKey` | `""` | API key |
| `accessControl.enabled` | `false` | Enable per-user restriction |
| `accessControl.owner` | `""` | Owner's OIDC `preferred_username` |
| `namespaceMode` | `shared` | `shared` or `perUser` |
| `route.enabled` | `false` | Expose gateway via OpenShift Route |
| `route.dashboard` | `false` | Expose dashboard via OpenShift Route |

**What it creates:** VirtualMachine (from golden image), Service, setup Job, auth proxy (Deployment + Service + ConfigMap), Routes, ServiceAccount + RBAC.

### openshell-gateway-image (bootc VM image)

Builds a bootc-based gateway VM image via OpenShift BuildConfig. CDI imports the image into a golden image PVC that sandboxes clone from.

```bash
make build-gateway-image
```

### openshell-keycloak (OIDC provider)

Optional Keycloak server for development. Production deployments should use an external OIDC provider.

```bash
make keycloak
```

### nemoclaw-imagestream / nemoclaw-cli-imagestream

Build the NemoClaw sandbox and CLI images from the [NVIDIA/NemoClaw](https://github.com/NVIDIA/NemoClaw) repo.

```bash
make build        # sandbox image
make build-cli    # CLI image
```

## E2E Tests

### Access control test

Validates per-user access control — alice cannot access bob's gateway, and vice versa:

```bash
scripts/test-access-control.sh
```

Runs 13 checks: provisions alice/bob sandboxes in a shared namespace, verifies auth proxy pods, Route configuration, and cross-user 403 blocking.

### Multi-user isolation test

Validates namespace-per-user isolation:

```bash
scripts/test-multiuser-isolation.sh
```

Runs 14 checks across separate `saw-alice` and `saw-bob` namespaces.

Pass `--skip-cleanup` to keep resources for debugging.

## Teardown

```bash
make delete-sandbox SANDBOX_NAME=my-sandbox   # Delete a sandbox
make delete-all                               # Delete gateway + keycloak + images
```
