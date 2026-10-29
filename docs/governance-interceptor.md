# Governance Interceptor — Policy Enforcement Flow

## Overview

The governance interceptor enforces admin-controlled policies on AI agent sandboxes. It runs as a Kubernetes pod and intercepts gRPC calls from the OpenShell gateway to enforce which providers, sandbox configurations, and operations are allowed.

The architecture separates **policy data** from the **interceptor application**, allowing admins to add or remove provider profiles by simply dropping YAML files into a Git repository.

## Architecture

```
+-----------------------------+
|  Git Repository             |
|  charts/governance-policy/  |
|    profiles/github.yaml     |
|    profiles/nvidia.yaml     |
|    profiles/slack.yaml      |
|    policy.yaml              |
+----------+------------------+
           | git push
           v
+-----------------------------+
|  ArgoCD                     |
|  governance-policy app      |
+----------+------------------+
           | sync
           v
+-----------------------------+      +---------------------------------+
| ConfigMaps                  |      |  governance-interceptor pod     |
|  governance-interceptor-    | ---> |    mounts /config/policy/       |
|    policy (sandbox policy)  |      |    mounts /config/profiles/     |
|  governance-interceptor-    |      |    file watcher detects changes |
|    profiles (provider YAML) |      |    reloads policy in-place      |
+-----------------------------+      +----------+----------------------+
                                                |
                                                | gRPC: Describe / Evaluate
                                                | push propagation on reload
                                                v
                                     +----------------------------+
                                     |  OpenShell Gateway (VM)    |
                                     |    intercepts CreateSandbox|
                                     |    intercepts CreateProvider|
                                     |    intercepts UpdateConfig  |
                                     |    allow / deny + audit log |
                                     +----------------------------+
```

## Components

### governance-policy chart

Contains only policy data — no application code.

- `policy.yaml` — sandbox filesystem and process policy (landlock rules, read-only paths, run-as-user)
- `profiles/*.yaml` — provider profile definitions (one file per provider)
- `templates/configmap.yaml` — Helm template that auto-discovers all `profiles/*.yaml` via glob

The ConfigMap template uses `{{ .Files.Glob "profiles/*.yaml" }}` to include every profile file automatically. Adding a new provider is just dropping a YAML file — no `values.yaml` edit needed.

**Two ConfigMaps are created:**

| ConfigMap | Content | Mount path |
|---|---|---|
| `governance-interceptor-policy` | `policy.yaml` (sandbox policy) | `/config/policy/` |
| `governance-interceptor-profiles` | All `profiles/*.yaml` files | `/config/profiles/` |

### governance-interceptor chart

Contains the interceptor application deployment.

- Deployment pulls the interceptor container image
- Mounts both ConfigMaps as directory volumes (not subPath — enables kubelet auto-sync)
- Exposes a gRPC service on port 18081
- The interceptor connects back to the gateway endpoint for push propagation

### Provider profile format

Each profile is a YAML file named after the provider ID (filename = profile ID on the gateway).
Profiles use OpenShell's provider profile schema. Set `id` to the filename: the interceptor
overwrites it from the filename anyway, but OpenShell's own parser requires it, so the same
file also works with `openshell provider profile import -f <file>` (the SAW installer imports
`brave.yaml` this way when governance is off).

```yaml
id: github
display_name: GitHub
description: GitHub API and Git operations
category: source_control
endpoints:
  - host: api.github.com
    port: 443
    protocol: rest
    enforcement: enforce
    access: read-write
binaries: [/usr/bin/gh, /usr/local/bin/gh]
```

## gRPC Protocol

The interceptor implements the `GatewayInterceptor` gRPC service with three RPCs:

### Describe

Called by the gateway at startup and on refresh. Returns the interceptor's manifest — which RPCs it wants to intercept and what phases it operates in.

```
Gateway ---Describe---> Interceptor
       <---Manifest---
```

The manifest declares bindings:
- `CreateSandbox` — phases: `modify_operation`, `validate`
- `CreateProvider` — phase: `validate`
- `UpdateConfig` — phase: `validate`
- `SubmitPolicyAnalysis` — phase: `validate`

### Evaluate

Called on every intercepted gRPC request. The interceptor receives the operation payload and returns an allow/deny decision with optional patches.

```
User ---CreateProvider---> Gateway ---Evaluate---> Interceptor
                                  <---allow/deny--
     <---success/error---
```

For `CreateSandbox`, the interceptor operates in two phases:
1. **modify_operation** — injects signed sandbox policy (filesystem rules, landlock config, process constraints) as patches to the request
2. **validate** — verifies the sandbox configuration meets governance requirements

For `CreateProvider`, the interceptor checks if the provider type matches an approved profile. If the provider type is not in the loaded profiles, the request is denied.

### SnapshotProviderProfiles

Called by the gateway to fetch the current set of provider profiles from the interceptor. This is how the gateway's `provider list-profiles` command gets its data.

## Policy Propagation Flow

### Adding a new provider profile

1. Admin creates `charts/governance-policy/profiles/jira.yaml`
   and adds each exact external endpoint host to `charts/openshell-saw/values.yaml`
   `egress.allow` (or `egress.extraAllow` for a site-specific host). An in-cluster
   endpoint also needs `networkPolicy.extraEgress` for its namespace, pods, and
   port. CI checks shipped profile hosts and ports against the chart allowlist.
2. Admin commits and pushes to Git
3. ArgoCD detects the change and syncs the `governance-policy` application
4. The `governance-interceptor-profiles` ConfigMap is updated with the new key
5. Kubelet syncs the mounted ConfigMap volume into the interceptor pod (~60s)
6. The interceptor's file watcher detects the change and reloads policy in-place
7. The interceptor pushes the updated manifest to the gateway via the gateway endpoint
8. The gateway now enforces the new profile — no restart needed

Typical end-to-end propagation: **15–60 seconds**.

### Removing a provider profile

Same flow in reverse — delete the file, push, and the profile is removed from enforcement.

### How the gateway connects

The gateway VM is configured via `gateway.toml` (rendered by the openshell-saw chart's cloud-init):

```toml
[openshell]
version = 2              # OpenShell 0.1.x gateway.toml schema

[openshell.gateway]
compute_driver = "podman"
provider_profile_sources = [
  { type = "interceptor", name = "governance" },
]

[[openshell.gateway.interceptors]]
name           = "governance"
grpc_endpoint  = "http://governance-interceptor.<namespace>.svc.cluster.local:18081"
failure_policy = "fail_closed"
binding_policy = "allowlist"

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/CreateSandbox"
phases = ["modify_operation", "validate"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/CreateProvider"
phases = ["validate"]
```

The interceptor must be built from the same OpenShell release as the gateways (0.1.x negotiates `PeerMetadata`), and for 0.1.2 it carries a two-line patch for [NVIDIA/OpenShell#3929](https://github.com/NVIDIA/OpenShell/issues/3929): it keeps only the profile-signature annotation, because the gateway hashes profiles with more than one annotation non-deterministically and no sandbox with a provider becomes ready. See `image-builder-charts/helm/governance-interceptor-image/files/Dockerfile`.

The `binding_policy = "allowlist"` means only the explicitly listed RPCs are intercepted. The `failure_policy = "fail_closed"` means if the interceptor is unreachable, all intercepted operations are denied.

## Tool actions

The interceptor above does not see a tool call. OpenShell 0.1.2 only forwards allowlisted control-plane RPCs (`CreateSandbox`, `CreateProvider`, `UpdateConfig`, `SubmitPolicyAnalysis`), and its timeout is too short for a person to approve something. Agent tool calls run inside the sandbox.

`charts/governance-policy/tool-actions.yaml` is the tool policy (`allow`, `deny`, or `approval` per tool; `whenCommandMatches` narrows `exec`). The installer disk carries an identical copy. `saw-apply` fills a `saw-gate-*` podman volume on the host with this policy, the signed-in identity (`username` from `accessControl.owner`, `subject` from the resolved `ownerSubject`), and the plugin tree. Every OpenClaw and NemoClaw sandbox mounts it read-only at `/sandbox/.saw/trusted`. A generic toolbox sandbox gets no gate.

OpenClaw loads `saw-tool-gate` from `/sandbox/.saw/trusted/plugin` through `plugins.load.paths`. The installer appends it to a restrictive `plugins.allow`, enables it, and verifies that OpenClaw reports it loaded from the trusted mount. Each policy read is hashed against a SHA-256 constant embedded in the mounted plugin. A mismatch denies the call with rule `policy-hash`.

- The default action is `deny`. The explicit read-only allowlist covers `read`, memory reads, session inspection, and `exec` for `git status`, `git diff`, `git log`, and `git show`. `message`, `git push`, `gh pr merge`, `rm`, `kubectl delete`, and `oc delete` require approval. Unknown tools deny.
- The daily briefing allows exactly `slack-reader__new_messages`, `slack-reader__channels`, `gmail-reader__new_messages`, and `briefing-writer__save_briefing`. The writer saves only today's briefing; generic `write` stays denied. `exec` for `openclaw cron list` is allowed, while `openclaw cron add` and `openclaw cron rm` require approval. Scheduled updates use only the allowed readers and writer.
- `tool_search` and `tool_call` are allowed for discovery and dispatch. Live testing on OpenClaw 2026.9.2 (`3928bad`) with only these dispatcher rules produced separate `default`/`deny` audit records for `slack-reader__new_messages` and `gmail-reader__new_messages`. Every dispatched target therefore still needs its own rule. Recheck that behavior when upgrading OpenClaw; do not allow a dispatcher that bypasses target hooks.
- `exec` matches the command at its start after normalizing whitespace, leading assignments, and the executable basename. Empty commands deny as `exec-unreadable`; shell operators and opaque wrappers such as `sh -c` deny as `exec-opaque`.
- Every call appends one JSON line to `/sandbox/.saw/audit/tool-actions.jsonl`, a separate `saw-audit-*` volume. The directory is not writable by the sandbox user, and the log file is append-only (`chattr +a`). The same line goes to gateway stderr for `podman logs`. Each line includes the user, OpenClaw session task id, `policyHash`, rule, and decision. An optional `/sandbox/.saw/current-task.json` `title` is copied onto that record.
- `allow` runs the tool after the audit append succeeds.
- `deny` blocks it.
- `approval` pauses the tool (`requireApproval`) until the signed-in user approves in the session. Timeout and cancel are recorded as rejected and the tool does not run.
- A missing policy, either missing identity field, a missing session, or a failed audit append blocks the call. Missing owner or subject also fails the installer apply before the OpenClaw gateway starts.

The mounted plugin and policy are read-only to the agent. The installer recreates an existing agent sandbox missing its gate or audit mount; OpenShell deletes that sandbox's `/sandbox` volume during recreation, so preserve needed files before applying. The writable `openclaw.json` can still be changed between applies; the next apply checks the loaded plugin again. This is not a cluster OCSF pipeline.

The gate tests live in `charts/openshell-saw/files/installer/tool-gate.test.mjs`
and `tests/installer/test_tool_gate.py`. They run in `make test` and CI.
`make test-tool-gate` runs the Node unit tests alone. See the
[testing guide](testing.md) for required tools and CI coverage.

## Audit Trail

Every interceptor decision is logged by the gateway:

```
gateway interceptor evaluated
  interceptor=governance
  binding_id=govern-create-provider
  phase="validate"
  service=openshell.v1.OpenShell
  method=CreateProvider
  decision="allow"    # or "deny"
  patch_count=0
  log_annotations={}
```

## Operations

### List active profiles

```bash
make governance-profile-list OPENSHELL_SAW_NAME=alice
```

### Add a profile from a YAML file

```bash
make governance-profile-create OPENSHELL_SAW_NAME=alice \
  PROFILE_NAME=jira PROFILE_FILE=/path/to/jira.yaml
```

### Remove a profile

```bash
make governance-profile-remove OPENSHELL_SAW_NAME=alice \
  PROFILE_NAME=github
```

### Restore a previously removed profile

```bash
make governance-profile-add OPENSHELL_SAW_NAME=alice \
  PROFILE_NAME=github
```

### Run the full demo

```bash
make governance-demo OPENSHELL_SAW_NAME=alice
```

### Applying profile changes

`governance-add-profile`, `governance-remove-profile`, and `governance-create-profile` run `scripts/governance-profile.sh`, which edits `charts/governance-policy/profiles/`, commits, and runs `git push origin HEAD`, then waits for Argo CD to sync the `governance-policy` application. This is the GitOps (Option A) path.

On the quickstart path (Option B), governance-policy is installed with Helm, not Argo CD, so a push does not change the cluster. Edit the profiles under `charts/governance-policy/profiles/` and re-apply the chart:

```bash
helm upgrade --install governance-policy charts/governance-policy \
  --namespace openshell-agents
```

`make governance-profile-list` lists local profiles without a name. Set `OPENSHELL_SAW_NAME` to query that gateway.
