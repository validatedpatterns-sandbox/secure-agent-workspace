# Codex Sandbox Compute Architectures

Three approaches for running Codex sandboxes, compared across security,
performance, complexity, and dependencies.

## Architecture A: KubeVirt VM (current)

```
KubeVirt VirtualMachine (per user)
  └── Fedora VM (golden image)
        ├── Docker daemon
        ├── openshell-gateway (systemd)
        ├── openshell-supervisor (in sandbox container)
        ├── codex-openshell container (sandbox)
        │     └── codex app-server
        ├── port forward (systemd)
        └── setup Job provisions via SSH
```

**How it works:** The SAW controller runs `helm install` which creates a
KubeVirt VirtualMachine. A setup Job SSHes into the booted VM, upgrades
OpenShell, runs BOM provisioning (creates workspace, providers, sandbox),
starts the codex app-server, and configures port forwarding.

## Architecture B: Pod with DinD (proposed)

```
Pod (per user)
  ├── openshell-gateway container
  │     └── Docker driver → talks to DinD via shared socket
  ├── docker-in-docker container (privileged)
  │     └── sandbox container (codex-openshell)
  │           ├── openshell-supervisor
  │           └── codex app-server
  ├── oauth2-proxy sidecar
  │     └── :8089 → upstream app-server
  ├── init container (runs apply_bom.py)
  └── Shared volumes: Docker socket, TLS, config
```

**How it works:** Same as Architecture A but everything runs in a pod
instead of a VM. OpenShell's Docker driver manages sandbox containers
inside the DinD sidecar. The supervisor, network namespace isolation,
governance proxy, and credential injection all work unchanged because
the Docker driver is container-runtime-agnostic.

## Architecture C: OpenShell Kubernetes Driver (future)

```
openshell-gateway (shared or per-user pod)
  └── Kubernetes compute driver
        └── creates Agent Sandbox CRD objects

Agent Sandbox Controller (cluster-level)
  └── reconciles Sandbox CRDs into Pods

codex sandbox Pod (per session)
  ├── openshell-supervisor (ImageVolume sidecar)
  └── codex-openshell container
```

**How it works:** OpenShell's Kubernetes driver creates Sandbox CRDs.
An external controller (not part of OpenShell) reconciles them into
pods with the supervisor injected as a sidecar. No Docker daemon,
no VM. The supervisor enforces policy inside the pod's network namespace.

---

## Comparison

| Aspect | A: VM (current) | B: Pod + DinD | C: K8s Driver |
|--------|-----------------|---------------|---------------|
| **Status** | Production, tested | Proposed | Experimental |
| **Provisioning time** | ~5 min | ~1 min | ~30s |
| **Resources per session** | 4 CPU / 8GB | 0.5 CPU / 1GB | 0.3 CPU / 512MB |
| **Isolation** | VM kernel boundary | Pod + netns | Pod + netns |
| **OpenShell sandbox** | Full (Docker driver) | Full (Docker driver) | Full (K8s driver) |
| **L7 governance** | Yes (supervisor proxy) | Yes (supervisor proxy) | Yes (supervisor proxy) |
| **Credential injection** | Yes (proxy) | Yes (proxy) | Yes (proxy) |
| **Network policy** | OpenShell + VM firewall | OpenShell + NetworkPolicy | OpenShell + NetworkPolicy |
| **Privileged container** | No (Docker in VM) | **Yes** (DinD needs SYS_ADMIN) | No |
| **External dependencies** | KubeVirt/CNV operator | None (just pods) | Agent Sandbox CRD controller |
| **OpenShift SCC** | anyuid (setup Job) | **privileged** (DinD) | Standard |
| **Cluster operators** | KubeVirt, RHBK | RHBK only | RHBK, Agent Sandbox |
| **Helm chart** | openshell-saw (complex) | New chart (medium) | OpenShell upstream chart |
| **Setup mechanism** | SSH + setup Job | Init container + kubectl exec | Gateway API |
| **Golden image build** | Yes (bootc qcow2) | No | No |
| **Multi-session per user** | Each session = new VM | Each session = new pod | Each session = new pod |
| **Cost at 100 users** | 400 CPU / 800GB RAM | 50 CPU / 100GB RAM | 30 CPU / 50GB RAM |

## Security comparison

| Threat | A: VM | B: Pod + DinD | C: K8s Driver |
|--------|-------|---------------|---------------|
| Container escape | VM boundary stops it | DinD is privileged — escape = node access | Pod boundary (weaker than VM) |
| Cross-user access | VM isolation | Pod isolation + NetworkPolicy | Pod isolation + NetworkPolicy |
| Kernel exploit | Separate VM kernel | Shared host kernel | Shared host kernel |
| Network sniffing | VM NIC isolation | Pod netns (shared node) | Pod netns (shared node) |

## Recommendation

| Use case | Recommended |
|----------|-------------|
| Production, multi-tenant, untrusted users | **A (VM)** — strongest isolation |
| Internal team, trusted users, fast iteration | **B (Pod + DinD)** — good balance |
| Future, when Agent Sandbox CRD matures | **C (K8s Driver)** — lightest, no DinD |

## Implementation effort to add B or C

**Architecture B (Pod + DinD):**
- New Helm chart: Pod with gateway + DinD + proxy containers (~200 lines)
- Init container for BOM provisioning (adapt `apply_bom.py`)
- Controller: `helm install openshell-saw-pod` instead of `openshell-saw`
- SCC: grant `privileged` to the DinD service account
- Effort: ~2-3 days

**Architecture C (K8s Driver):**
- Install Agent Sandbox CRD + controller (external dep)
- Deploy OpenShell gateway with K8s compute driver config
- Controller: call OpenShell gateway API instead of helm
- Effort: ~1-2 days (but blocked on Agent Sandbox controller availability)

## What stays the same across all three

- CodexSession CRD + controller
- saw-codex-api REST service
- codex-saw TUI client
- OIDC authentication (Keycloak)
- Owner isolation (sub-based labels)
- Session limit enforcement
- codex-openshell container image
- Governance profiles (OpenAI, GitHub)
