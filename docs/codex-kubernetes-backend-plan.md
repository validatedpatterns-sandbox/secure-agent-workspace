# Implementation plan: native Kubernetes backend for Codex SAW

## 1. Scope and decisions

Extend the `codex-saw` branch with a native Kubernetes backend. One CodexSession
creates one dedicated OpenShell gateway pod and one Codex sandbox pod, replacing
the KubeVirt VM and its Docker runtime.

**Key simplifications over the original proposal:**

- Controller stays simple (kopf handlers for create/delete/stop/start, ~250 lines)
- One shared governance interceptor (same as VM approach)
- Provisioning uses the existing OIDC token-passing pattern (no service client)
- No custom `start-codex` entrypoint (current exec-based startup, add later)
- Upgrade path: delete VM session, create Kubernetes session
- Forwarding uses the existing `openshell forward service` as a sidecar container

VM remains the default. Both backends coexist. Codex only.

### Pinned versions

| Component | Version |
|-----------|---------|
| OpenShell gateway/supervisor | `v0.0.116` |
| Agent Sandbox controller | `v1.0.2` |
| Codex image | `quay.io/aipcc/base-images/agentic/codex:latest` |
| Codex-openshell derived image | Built on cluster |

## 2. Architecture

```
User (codex-saw TUI)
  → saw-codex-api (OIDC auth)
    → CodexSession CR (spec.runtime.backend: kubernetes)
      → Controller creates Helm release
        → Session namespace (saw-<name>-<uid>)
          ├── Gateway StatefulSet (1 replica)
          │     ├── openshell-gateway container
          │     ├── openshell-forward container (sidecar)
          │     └── gateway PVC (SQLite, keys)
          ├── Service + Route (port 8089)
          ├── Provisioning Job (BOM setup via OpenShell API)
          └── Sandbox CR (created by gateway via OpenShell API)
                → Agent Sandbox controller
                  → Agent pod (supervisor + codex) + workspace PVC

Shared (openshell-agents namespace):
  ├── Governance interceptor (existing, shared)
  ├── Keycloak
  ├── saw-codex-api + controller
  └── Agent Sandbox controller + CRD
```

### What changes from VM approach

| VM | Kubernetes |
|----|-----------|
| KubeVirt VirtualMachine | Gateway StatefulSet + agent pod |
| Docker inside VM | OpenShell K8s driver creates Sandbox CRs |
| Setup Job SSHes into VM | Provisioning Job calls OpenShell API |
| systemd codex-forward | Sidecar container in gateway pod |
| ~5 min provisioning | ~1 min provisioning |
| 4 CPU / 8GB per session | ~1 CPU / 1GB per session |

### What stays the same

- CodexSession CRD + controller
- saw-codex-api + TUI
- OIDC authentication + JWT WebSocket auth
- Governance interceptor (shared)
- codex-openshell container image
- BOM profiles (providers, sandbox config)
- `/sessions` and `/sessions/{name}/connect` API contract

## 3. CR changes

```yaml
apiVersion: saw.redhat.com/v1alpha1
kind: CodexSession
metadata:
  name: alice-code
spec:
  name: alice-code
  owner: "<keycloak-sub>"
  runtime:
    backend: kubernetes    # vm | kubernetes; omitted = vm
  desiredState: Running    # Running | Stopped
status:
  phase: Creating | Running | Stopped | Stopping | Deleting | Error
  backend: kubernetes
  namespace: saw-alice-code-a1b2
  message: "..."
```

Backend and owner are immutable after creation. Default backend is `vm`.

## 4. Controller changes

Current controller: `on_create`, `on_delete`, `check_status` timer (~198 lines).

Add:
- **Backend dispatch** — `on_create` checks `spec.runtime.backend`, calls either
  `_create_vm(...)` (existing helm install) or `_create_kubernetes(...)` (new chart)
- **`on_update`** — watches `spec.desiredState` changes, calls stop/start
- **Stop** — calls `openshell sandbox stop` via the gateway API (or patches Sandbox CR)
- **Start** — calls `openshell sandbox start`, waits for readiness
- **Status timer** — checks gateway pod + sandbox status, updates CR phase

No reconciliation engine, no generation tracking. Just handlers.

```python
@kopf.on.create("saw.redhat.com", "v1alpha1", "codexsessions")
def on_create(spec, meta, namespace, **_):
    backend = spec.get("runtime", {}).get("backend", "vm")
    if backend == "vm":
        _create_vm(spec, meta, namespace)
    elif backend == "kubernetes":
        _create_kubernetes(spec, meta, namespace)

@kopf.on.field("saw.redhat.com", "v1alpha1", "codexsessions",
               field="spec.desiredState")
def on_desired_state(old, new, spec, meta, namespace, **_):
    if new == "Stopped":
        _stop_session(spec, meta, namespace)
    elif new == "Running" and old == "Stopped":
        _start_session(spec, meta, namespace)
```

Estimated: ~350 lines total (up from 198).

## 5. New chart: `charts/openshell-saw-kubernetes`

Based on pinned upstream `v0.0.116` chart with integration additions.

### Templates

| Template | What |
|----------|------|
| `statefulset.yaml` | Gateway (1 replica) + forward sidecar |
| `service.yaml` | ClusterIP on 8089 (forward) + 17670 (gateway) |
| `route-codex.yaml` | TLS edge for WebSocket (port 8089) |
| `route-gateway.yaml` | TLS passthrough for gateway gRPC (17670) |
| `configmap-gateway.yaml` | `gateway.toml` with K8s driver, OIDC, governance |
| `pvc-gateway.yaml` | SQLite + keys persistence |
| `serviceaccount.yaml` | Gateway SA with sandbox/pod management RBAC |
| `role.yaml` + `rolebinding.yaml` | Namespace-scoped permissions |
| `job-provision.yaml` | Runs BOM provisioning via OpenShell API |
| `secret-tls.yaml` | Gateway TLS material |
| `networkpolicy.yaml` | Deny lateral access, allow gateway↔agent |

### Gateway config

```toml
[openshell.drivers.kubernetes]
default_image = "<codex-openshell-image>"
supervisor_image = "<pinned-supervisor>"
sandbox_namespace = "<session-namespace>"

[openshell.gateway.oidc]
issuer = "<keycloak-url>"
audience = "openshell-cli"

[[openshell.gateway.interceptors]]
name = "governance"
grpc_endpoint = "http://governance-interceptor.openshell-agents.svc:18081"
failure_policy = "fail_closed"
```

### Forward sidecar

```yaml
- name: codex-forward
  image: <gateway-image>
  command:
    - openshell
    - forward
    - service
    - codex
    - --target-port
    - "8089"
    - --local
    - "0.0.0.0:8089"
    - --gateway-endpoint
    - "https://localhost:17670"
    - --gateway-insecure
```

Restarts automatically via Kubernetes container restart policy.

## 6. Provisioning Job

Runs inside the session namespace. Uses the OpenShell API (not SSH/virtctl).

Reuses `apply_bom.py` profile parsing but with a Kubernetes adapter:

```python
# Instead of: guest_ssh("openshell sandbox create ...")
# Uses: openshell --gateway https://gateway-svc:17670 sandbox create ...
```

Steps:
1. Wait for gateway readiness (`/healthz`)
2. Authenticate to gateway (OIDC token from Secret)
3. Create workspace `default`, grant owner access
4. Create providers (openai, github) with governed profiles
5. Create sandbox `codex` from codex-openshell image
6. Wait for sandbox Ready
7. Configure Codex (auth.json, config.toml, ws-secret) via `openshell sandbox exec`
8. Start codex app-server via `openshell sandbox exec`
9. Verify readyz

No Docker, no virtctl, no systemd, no SSH.

## 7. Agent Sandbox controller

Install once, cluster-wide. Not per-session.

```bash
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v1.0.2/sandbox.yaml
```

Prerequisites check in `make codex-setup`:
```bash
oc get crd sandboxes.agents.x-k8s.io || echo "Install Agent Sandbox controller first"
```

## 8. API changes

Additive — no breaking changes:

| Endpoint | Change |
|----------|--------|
| `POST /sessions` | Accept optional `backend` field (default: vm) |
| `POST /sessions/{name}/stop` | New — sets `desiredState: Stopped` |
| `POST /sessions/{name}/start` | New — sets `desiredState: Running` |
| `GET /sessions` | Add `backend` and `state` to response |
| `GET /sessions/{name}/connect` | Return 503 if Stopped |

## 9. TUI changes

- Show `backend` column (vm/k8s)
- Show `state` (running/stopped/creating/deleting)
- Add `t` key for stop/start toggle
- Add backend selection in create dialog (default: vm)

## 10. Delivery sequence

### PR 1 — Qualify the stack (~1 week)

Build/pin OpenShell v0.0.116 images. Install Agent Sandbox controller on OpenShift.
Manually deploy one gateway + one Codex sandbox. Test: create, connect, inference,
git clone, stop, start, delete. **Gate: it works on OpenShift.**

### PR 2 — Backend dispatch + new chart (~2 weeks)

- CR schema: add `runtime.backend`, `desiredState`, status fields
- Controller: backend dispatch (vm/kubernetes), stop/start handlers
- New `openshell-saw-kubernetes` chart
- Provisioning Job (API-driven BOM)
- API: backend field on create, stop/start endpoints
- TUI: backend column, stop/start toggle

**Gate: create a Kubernetes session from TUI, connect, delete. VM sessions unaffected.**

### PR 3 — Polish + mixed-cluster testing (~1 week)

- NetworkPolicy
- Workspace PVC retention on delete
- Start/stop persistence
- VM + Kubernetes sessions coexisting
- Documentation + Makefile targets
- Acceptance matrix

## 11. Acceptance matrix

| Scenario | Expected |
|----------|----------|
| Create VM session (default) | Works as before |
| Create Kubernetes session | Gateway pod + agent pod in session namespace |
| Connect to Kubernetes session | JWT WebSocket auth, same as VM |
| Stop Kubernetes session | Agent pod terminated, gateway running, status: Stopped |
| Start stopped session | Same sandbox, same data, status: Running |
| Delete Kubernetes session | Finalizer cleans up namespace + resources |
| VM + Kubernetes concurrent | Independent, no interference |
| Governance enforced | Shared interceptor denies unauthorized endpoints |
| Non-owner access | Denied at API + gateway level |
| Session limit | Counts both VM and K8s sessions |
| Gateway pod restart | Reconnects to existing sandbox, data preserved |
| Agent pod crash | Gateway reports error, bounded recovery |
| Provisioning failure | Error status, no duplicate sandbox |

## 12. Estimated effort

| PR | Effort | New code |
|----|--------|----------|
| PR 1 (qualify) | 1 week | ~0 lines (manual testing) |
| PR 2 (implement) | 2 weeks | ~1500 lines |
| PR 3 (polish) | 1 week | ~500 lines |
| **Total** | **4 weeks** | **~2000 lines** |

Compare: the VM implementation was ~2700 lines across 34 commits.
