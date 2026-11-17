# OpenShell 0.1.6 release record

The CLI, gateway, supervisor and sandbox BOM uses `0.1.6-rhaiv.4`. The
interceptor pinned in `charts/governance-interceptor/values.yaml` supplies the
matching published OpenShell `v0.1.6` image, including the provider-annotation
workaround and driver-config guard.

Deployment may proceed. Existing SAW deployments using OpenShell older than
0.1.6 must deploy SAW fresh; see [Existing deployments](#existing-deployments).

## Published artifact

- Repository build: `fe19b46c29928e5d7bd6ad62440e591bb4907d3f` (#156).
- OpenShell source: `v0.1.6` at `ac7f615cd12d5cc49cb16eb1f5f10ffeb1e90f47`.
- [Publication run](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/actions/runs/43196073756): both native builds passed six admission tests each, followed by manifest merge and anonymous public-pull verification.
- Public image: `ghcr.io/validatedpatterns-sandbox/governance-interceptor@sha256:19f145ac163822bca6d406898975b5b770b75b196fa0bee0bc86b108fad213b3`.
- `linux/amd64`: `sha256:118827092bfa9074c1fd1a2ca9fa60d9711025a24e574414295f463213f6f5a4`.
- `linux/arm64`: `sha256:309f0381e45d47efdc4579d5ddb18312709896f2b75888c56c453bacafeb86f4`.

Anonymous checks on November 12, 2026 confirmed `v0.1.6` and
`sha-fe19b46c29928e5d7bd6ad62440e591bb4907d3f` resolve to this index. Publishing
remains main-only; PR builds do not push images or use registry credentials.

## Validation

- November 12 clean README Option A install on OpenShift 4.22.22 with this pin
  and no overrides: all 16 applications healthy. Inference, owner isolation,
  file-tool confinement, approval audit, credential cleanup, reapply and
  two-way NetworkPolicy (36/36) passed.
- Restart fixes are merged: credentials (#162), guest-initiated shutdown (#164),
  workspace preservation (#167) and recovery after a workload exits during
  startup (#168).
- Upgrade experiments retained all three baseline test files and gateway
  credentials, but some existing workloads kept an obsolete runtime boundary.
  In-place upgrades from pre-0.1.6 deployments are not supported.
- Fresh-user first boot and real inference passed in both workspaces on
  November 16. On November 17, the operator confirmed the post-restart check
  worked. Detailed results and the reduced acceptance scope are recorded in
  [#157](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/issues/157).

## Follow-ups

New findings are tracked separately without blocking deployment. The catalog
and host-triggered shutdown investigations in
[#161](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/issues/161)
remain deferred. The live NetworkPolicy probe timeout is tracked in
[#171](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/issues/171).

## Existing deployments

### Moving from OpenShell older than 0.1.6

Deploy SAW fresh using the current [README installation instructions](../README.md#installation).
Back up any workspace files and configuration you need before retiring the old
deployment. Do not reuse the old VMs or sandbox containers: their workload
boundaries can remain on the older runtime even after a VM restart. Existing
workspace files and gateway credentials are not automatically migrated into
the fresh deployment.

This replaces the pre-0.1.6 in-place recovery work tracked in
[#170](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/issues/170).

### Updating a deployment already on OpenShell 0.1.6

1. After Argo CD syncs, `make saw-restart-pending` lists the VMs waiting for a
   restart. VMs install the new BOM only at boot.
2. `make saw-restart-pending CONFIRM=yes` restarts each VM from inside the guest
   ([VM shutdown and restart](vm-shutdown.md)). Open agent sessions end.
3. For each VM, `make saw-status OPENSHELL_SAW_NAME=<name>` shows when boot
   install and apply finish.

## Installer and tool permissions

OpenClaw/NemoClaw apply requires `tools.fs.workspaceOnly` to read back as JSON
boolean `true`. A failed repair keeps the existing agent stopped. A durable
`confinement-stops.json` hold protects a host-stopped workload from deletion:
recover/start the existing sandbox in place, then reapply to verify confinement
and clear the hold. The record is normally `/var/lib/saw/user/confinement-stops.json`,
or `~/.local/state/openshell/confinement-stops.json` without a ledger. Do not
remove it to bypass recovery. A configured agent can resume without a usable
provider while retaining its model/credentials; unchanged reapply leaves it running.

In OpenClaw 2026.9.6, `automations` aliases `cron`. Only `list`, `status`, `get`,
`show` and `runs` need no approval; `add`, `edit`, `rm`, `enable`, `disable` and
`run` require it. Unsupported aliases, mixed read/write `scratch`, unknown
commands and shell wrappers remain denied. Every `agents set-identity` call
requires approval: its file/avatar inputs can reach outside the workspace and
it rewrites configuration, beyond filesystem-tool confinement. Denial,
cancellation or timeout prevents execution. See the [governance guide](governance-interceptor.md).
