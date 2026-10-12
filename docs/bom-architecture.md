# BOM-Driven Agent Configuration — Architecture

## End-to-End Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        GitOps (ArgoCD)                                  │
│                                                                         │
│  values-prod.yaml ──► saw-bom chart ──► ConfigMap (saw-bom-profiles)    │
│  overrides/saw-users.yaml ──► openshell-saw chart ──► VM per person     │
└─────────────────────────┬───────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Inputs on the VM: iso9660 disks, or virtiofs when vm.liveInputs is on  │
│                                                                         │
│  installer ConfigMap (BOM, apply_bom.py, gateway config)                │
│  saw-bom-profiles ConfigMap                                             │
│  provider Secrets (inference, web-search, ...)                          │
└─────────────────────────┬───────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│              apply_bom.py (runs on the gateway VM, no SSH)              │
│                                                                         │
│  saw-install (root)                                                     │
│  ├── Check component signatures (warn by default; enforce stops first) │
│  ├── Pull each digest, install the binary, start the gateway           │
│  └── Skip components that are already current                           │
│                                                                         │
│  saw-apply (root reads inputs, then cloud-user runs the plan)          │
│  ├── mTLS client cert CN=saw-installer, OU=openshell-admin              │
│  ├── Workspaces, providers, sandboxes (provider attached per sandbox)   │
│  ├── provider update when a Secret key changes                          │
│  ├── Ledger of created objects; report mode only logs deletions        │
│  └── Verify workspaces, providers, and sandboxes                        │
│                                                                         │
│  saw-reconcile, only when vm.liveInputs is true                        │
│  └── install+apply on a BOM change; apply only on profile or Secret    │
└─────────────────────────────────────────────────────────────────────────┘
```

Details, including signature custody and what still needs a VM restart, are
in [Versioned BOM installer](versioned-bom-installer.md).

## Component Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    OpenShift Cluster                                 │
│                                                                      │
│  ┌─────────────┐   ┌──────────────┐  ┌────────────────┐              │
│  │  Keycloak    │  │  Vault +     │  │  Governance    │              │
│  │  (OIDC/SSO)  │  │  ESO         │  │  Interceptor   │              │
│  │              │  │  (Secrets)   │  │  (Policy Sign) │              │
│  └──────┬───────┘  └──────┬───────┘  └───────┬────────┘              │
│         │                 │                  │                       │
│         ▼                 ▼                  ▼                       │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │              Gateway VM (KubeVirt / openshell-saw)             │  │
│  │                                                                │  │
│  │  ┌─────────────────────────────────────┐                       │  │
│  │  │  OpenShell Gateway (port 17670)     │                       │  │
│  │  │  ├── Provider management            │                       │  │
│  │  │  ├── Sandbox lifecycle              │                       │  │
│  │  │  ├── Inference routing              │                       │  │
│  │  │  ├── Governance policy enforcement  │                       │  │
│  │  │  └── Network proxy (per sandbox)    │                       │  │
│  │  └──────────┬──────────────────────────┘                       │  │
│  │             │                                                  │  │
│  │     ┌───────┴────────────────────────────────┐                 │  │
│  │     │           Docker Containers            │                 │  │
│  │     │                                        │                 │  │
│  │     │  ┌─────────────────────────────────┐   │                 │  │
│  │     │  │  cuda-sandbox (nemoclaw)        │   │                 │  │
│  │     │  │  Image: nemoclaw-sandbox:latest │   │                 │  │
│  │     │  │  Workspace: cuda-dev            │   │                 │  │
│  │     │  │  Provider: nvidia               │   │                 │  │
│  │     │  │  OpenClaw Gateway (:18789)      │   │                 │  │
│  │     │  │  ├── TUI: make nemoclaw-tui     │   │                 │  │
│  │     │  │  └── GUI: make nemoclaw-gui     │   │                 │  │
│  │     │  └─────────────────────────────────┘   │                 │  │
│  │     │                                        │                 │  │
│  │     │  ┌─────────────────────────────────┐   │                 │  │
│  │     │  │  notebook (openclaw)             │  │                 │  │
│  │     │  │  Image: aipcc openclaw:2026.9.6  │  │                 │  │
│  │     │  │  Workspace: default              │  │                 │  │
│  │     │  │  Provider: nvidia                │  │                 │  │
│  │     │  │  OpenClaw Gateway (:18789)       │  │                 │  │
│  │     │  │  ├── TUI: make openclaw-tui      │  │                 │  │
│  │     │  │  └── GUI: make openclaw-gui      │  │                 │  │
│  │     │  └─────────────────────────────────┘   │                 │  │
│  │     │                                        │                 │  │
│  │     │  ┌─────────────────────────────────┐   │                 │  │
│  │     │  │  toolbox (generic)              │   │                 │  │
│  │     │  │  Image: base                    │   │                 │  │
│  │     │  │  Workspace: cuda-dev            │   │                 │  │
│  │     │  │  Provider: nvidia               │   │                 │  │
│  │     │  └─────────────────────────────────┘   │                 │  │
│  │     └────────────────────────────────────────┘                 │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  Routes (OpenShift)                                            │  │
│  │  ├── openshell-saw-gateway  → VM:17670  (OpenShell API)        │  │
│  │  ├── openshell-saw-dashboard → VM:18789 (OpenClaw UI)          │  │
│  │  └── openshell-saw-webui    → VM:8080  (OAuth2 Proxy)          │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

The `openshell-saw-dashboard` Route maps to VM port 18789, the OpenClaw UI, which is not reachable on OpenShell 0.1.x (see [OpenClaw UI and the dashboard Route](deployment-guide.md#openclaw-ui-and-the-dashboard-route)). The `openshell-saw-webui` Route maps to VM port 8080, the oauth2-proxy in front of the OpenShell Dashboard.

## BOM Profile Structure

```
charts/saw-bom/profiles/
└── data-science/                    # Profile name
    ├── cuda-dev/                    # Workspace
    │   ├── workspace.yaml           # Workspace metadata + enabled flag
    │   ├── providers.yaml           # Provider definitions (nvidia)
    │   └── sandbox.yaml             # Sandbox definitions (nemoclaw, generic)
    └── default/                     # Workspace
        ├── workspace.yaml           # Uses existing 'default' workspace
        ├── providers.yaml           # Provider definitions (nvidia, brave)
        └── sandbox.yaml             # Sandbox definitions (openclaw)
```

## Sandbox Types

| Type | Image | Use Case | Gateway | Entrypoint |
|------|-------|----------|---------|------------|
| nemoclaw | nemoclaw-sandbox:latest | NemoClaw-managed agent with inference | OpenClaw via sandbox exec | NemoClaw supervisor |
| openclaw | quay.io/aipcc/base-images/agentic/openclaw:2026.9.6 | Standalone OpenClaw agent | OpenClaw via sandbox exec | CSB entrypoint (wrapped) |
| generic | base | Plain sandbox for tools/scripts | None | OpenShell supervisor |

## Inference (OpenShell 0.1.x: no inference routes)

```
User → OpenClaw TUI/GUI
         │
         ▼
  OpenClaw Gateway (inside sandbox, port 18789)
         │
         │ model: nvidia/nemotron-3-super-120b-a12b
         │ baseUrl: https://integrate.api.nvidia.com/v1 (the provider's own endpoint)
         │ key: the placeholder in NVIDIA_API_KEY
         │
         ▼
  OpenShell Network Proxy (10.200.0.1:3128)
         │
         │ Swaps in the real NVIDIA_API_KEY, only for the provider
         │ profile's endpoints and binaries (node, curl)
         │ Enforces governance network policy
         │
         ▼
  integrate.api.nvidia.com:443
```

## Security Boundaries

```
┌─────────────────────────────────────────────────┐
│ Governance Layer                                │
│ ├── Signed policy per sandbox                   │
│ ├── Network policies (endpoint allowlist)       │
│ ├── Filesystem policies (read-only / read-write)│
│ ├── Process policies (run_as_user: sandbox)     │
│ └── Landlock enforcement (best_effort)          │
├─────────────────────────────────────────────────┤
│ Credential Boundary                             │
│ ├── API keys in Vault / K8s secrets             │
│ ├── OpenShell provider stores credentials       │
│ ├── Proxy injects credentials at request time   │
│ └── No credentials inside sandbox containers    │
├─────────────────────────────────────────────────┤
│ Identity Boundary                               │
│ ├── OIDC via Keycloak (alice)                   │
│ ├── mTLS for internal gateway communication     │
│ ├── Gateway token for OpenClaw Control UI       │
│ └── Sandbox user (UID 65532) — non-root         │
└─────────────────────────────────────────────────┘
```

## Make Targets

| Target | Description | Example |
|--------|-------------|---------|
| `nemoclaw-tui` | NemoClaw sandbox TUI | `OPENSHELL_SAW_NAME=alice SANDBOX_NAME=cuda-sandbox make nemoclaw-tui` |
| `openclaw-tui` | OpenClaw sandbox TUI | `OPENSHELL_SAW_NAME=alice SANDBOX_NAME=notebook make openclaw-tui` |
| `nemoclaw-gui` | NemoClaw sandbox GUI | `... GUI_PORT=18789 make nemoclaw-gui` |
| `openclaw-gui` | OpenClaw sandbox GUI | `... GUI_PORT=18790 make openclaw-gui` |
| `openshell-saw-tui` | Alias for nemoclaw-tui | `make saw-tui` |
| `openshell-saw-gui` | Alias for nemoclaw-gui | `make saw-gui` |
