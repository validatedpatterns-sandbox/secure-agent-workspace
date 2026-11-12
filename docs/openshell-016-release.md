# OpenShell 0.1.6 release follow-up

The CLI, gateway, supervisor and sandbox BOM uses `0.1.6-rhaiv.4`.
The governance interceptor must be built from NVIDIA/OpenShell `v0.1.6`,
using this repository's interceptor Dockerfile. Its provider-annotation
workaround and driver-config admission checks are required.

The agreed sequence is **merge PR #156, publish the upstream interceptor,
then merge a digest-pinning follow-up and complete clean-install validation**.
Publication and final deployment acceptance are follow-up work, rather than
prerequisites for merging #156. Track that work in
[the 0.1.6 release follow-up issue](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/issues/157).

**Deployment hold:** the follow-up now pins the verified public 0.1.6
interceptor. Clean-install acceptance on the fresh cluster is still required
before this follow-up is ready to merge and the hold can be removed. The
earlier 0.1.2 digest (`253b58d070d3ed341287fcbab44684d84a437fcb9f26be5834ebf554a40ec22f`)
and preliminary internal-registry build do not satisfy that acceptance.

## Published artifact

- Repository build: `fe19b46c29928e5d7bd6ad62440e591bb4907d3f`, the merge of #156.
- OpenShell source: `v0.1.6` at `ac7f615cd12d5cc49cb16eb1f5f10ffeb1e90f47`.
- [Upstream publication run](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/actions/runs/43196073756): both native architecture builds and the multi-platform merge/public-pull job passed. Each native build passed all six driver-config admission tests. The source includes the provider-annotation workaround.
- Anonymous verification on November 12, 2026: `v0.1.6` and `sha-fe19b46c29928e5d7bd6ad62440e591bb4907d3f` resolve to the same index.
- Public index: `sha256:19f145ac163822bca6d406898975b5b770b75b196fa0bee0bc86b108fad213b3`.
- `linux/amd64` manifest: `sha256:118827092bfa9074c1fd1a2ca9fa60d9711025a24e574414295f463213f6f5a4`.
- `linux/arm64` manifest: `sha256:309f0381e45d47efdc4579d5ddb18312709896f2b75888c56c453bacafeb86f4`.

## Clean-install checkpoint — November 12, 2026

The public image was tested from shipping source
`7d8c8440ac76381e277a56e05121c05317ef58aa`, using separate deployment inputs
`bd7ce216c1a436af51cab10422df571214e10f52` on OpenShift 4.22.22/amd64.
README Option A completed with no interceptor override: all sixteen
applications were Synced/Healthy, and the live interceptor used the public
index and amd64 child digest above. Cluster-specific users, endpoints and
credentials are excluded from the shipping PR. NetworkPolicy was enabled
from first boot; web search and GPU hardware were disabled. Topology was
verified from cluster network, Service and EndpointSlice objects;
`prereqs-check` was omitted at the operator's request.

Completed checks:

- Explicit OpenClaw and NemoClaw TUIs, both localhost GUIs and the default
  TUI/GUI entry points executed real model turns. Both owners reached their
  UIs; default and opt-in custom inference worked through the credential
  proxy. The first owner received HTTP 403 on the second owner's UI.
- All four installed OpenShell components and running binary/image references
  matched the mounted BOM. Three sandboxes each completed six real file-tool
  calls: workspace write/edit succeeded, while absolute, traversal and symlink
  escapes and an outside edit failed. Host readback confirmed untouched outside
  sentinels, absent escape files and strict boolean workspace confinement.
- Automation inspection ran without approval. A test cron mutation and an
  outside `agents set-identity --identity-file` command each prompted under
  their expected rules and were explicitly rejected. Audit records confirmed
  both decisions; the live cron API found only the three pre-existing built-in
  jobs per sandbox, and identity fields were unchanged.
- Both full guest credential scans passed; neither VM mounted full provider
  Secrets or retained gateway CA keys/admin credentials. Peer-required live
  NetworkPolicy checks passed **36/36**, covering both peer directions without
  skips. An interrupted earlier run was discarded and rerun completely.
- Both reapply operations passed. Temporary two-CA bundles returned to the
  one-CA client bundle, admin credentials/runtime directories were removed,
  and workspace files, passwords, policy, owner identity and confinement were
  preserved. This does not yet satisfy the separate reboot gate below.
- Local suite: **2097 passed, 3 skipped**; chart/rendered-shell lint, catalog
  freshness, OIDC templates (**50/50**) and offline NetworkPolicy (**4/4**)
  passed. Two local skips require Cargo (native admission tests passed in the
  publication jobs); the third requires an APF bundle. CI passed on this
  shipping source for Python 3.12 and 3.14.

**Reboot acceptance is blocked.** On the first test VM's normal
`make saw-restart`, Podman `5.8.1-1.fc44` could not open its SQLite state
catalog (`database disk image is malformed`). The gateway consequently never
listened, and boot install/apply failed. Read-only integrity checks found
ContainerState overflow-page/index errors. No kernel storage errors were
reported. The damaged catalog was preserved privately; no sandbox, volume or
database was deleted, and both original workspace sentinel files remained
intact. Retry services on that VM were stopped for diagnosis.

The second VM's catalog passed its pre-restart integrity check, and a consistent
private backup was taken before its own reboot test. Final reboot, repeated
file-tool/inference and post-restart peer-network checks remain outstanding.
A manual catalog recovery must not be counted as a passing clean reboot.

Upstream [Podman PR #29733](https://github.com/podman-container-tools/podman/pull/29733)
merged a change to use SQLite WAL on local filesystems on October 29. It
addresses another reported corruption signature; its relationship to this
failure is unproven. The official Fedora update available during diagnosis
was Podman 5.8.9, which predates that merge. No runtime package was changed.
Keep the deployment hold and PR #160 in draft until the runtime failure is
resolved and the complete clean-install/reboot gates pass.

## Publication and digest-pinning sequence

1. Merge #156 into upstream `main`. Its build-file changes trigger
   `build-governance-interceptor.yml`, which publishes only from `main`.
   PR builds must continue to use `push: false`. If publication needs a manual
   retry, an upstream publisher can dispatch the workflow on `main`.
2. Require passing native Rust admission tests, both architecture build jobs,
   the merged multi-platform image and its anonymous public-pull check.
   Record the repository build commit and exact NVIDIA/OpenShell source commit.
3. Verify public `ghcr.io/validatedpatterns-sandbox/governance-interceptor:v0.1.6`
   and `sha-<build-commit>` tags resolve to the same index, containing
   `linux/amd64` and `linux/arm64`. Record the index and architecture-specific
   manifest digests without registry credentials.
4. Open a follow-up PR pinning the verified public index digest in
   `charts/governance-interceptor/values.yaml`. Remove the preliminary internal
   interceptor override from the separate acceptance deployment inputs and
   require applicable CI on the follow-up's exact head.
5. Record cleanup of the task-owned preliminary deployment, preserve unrelated
   resources, and repeat a clean README Option A installation using the shipped
   default. Complete the README interactive/inference and live security checks,
   including credential isolation, peer checks, confinement, automation approval,
   reapply and VM restart. Record sanitized evidence and exact tested SHAs.
6. Merge the verified digest-pinning follow-up and complete its acceptance gates
   before treating the upgrade as validated for deployment. Remove the temporary
   deployment-hold notices from README, this guide, `docs/container-images.md`
   and the chart comments once acceptance passes, then close the tracking issue.

`make governance-interceptor-build-local` builds the same reviewed source for
preliminary tests in the cluster's internal registry. Record its output digest
and use it only on the separate deployment branch. This does not meet the
public upstream publication or final fresh-install acceptance requirements.

## Installer and tool permissions

For OpenClaw and NemoClaw, apply now fails unless setting
`tools.fs.workspaceOnly` succeeds and reads back as the JSON boolean `true`.
An existing agent with an invalid or unreadable setting is stopped before its
mounted tool policy changes. A failed repair leaves it stopped. A durable host-side
`confinement-stops.json` record prevents a host-stopped workload (`Completed`)
from being deleted as a broken sandbox on any later apply, including after an
installer or VM restart. Apply reports the hold until an operator recovers and
starts the existing sandbox in place; it does not recreate it. Keep the stop
record until apply verifies confinement and successfully resumes the agent.
The record lives beside the managed-resource ledger (normally
`/var/lib/saw/user/confinement-stops.json`), or in
`~/.local/state/openshell/` when no ledger is configured. Do not remove the
record to work around the hold: that would re-enable broken-sandbox deletion.
If no provider is usable, apply resumes an already configured agent with its
existing model and credentials after a successful repair; a fresh sandbox
remains unonboarded. Successful, unchanged reapply does not stop the agent merely to check confinement.

OpenClaw `automations` aliases `cron` in the pinned 2026.9.6 release. Both
allow only `list`, `status`, `get`, `show`, and `runs` without approval.
`add`, `edit`, `rm`, `enable`, `disable`, and `run` require approval. Unsupported
aliases (`create`, `remove`, `delete`), the mixed read/write `scratch` interface
and unknown commands stay denied. Shell wrappers, chaining, substitutions
and conflicting command representations remain denied. Command registration
was verified against the upstream release's
[`register.ts`](https://github.com/openclaw/openclaw/blob/v2026.9.6/src/cli/cron-cli/register.ts),
[`register.cron-add.ts`](https://github.com/openclaw/openclaw/blob/v2026.9.6/src/cli/cron-cli/register.cron-add.ts),
[`register.cron-simple.ts`](https://github.com/openclaw/openclaw/blob/v2026.9.6/src/cli/cron-cli/register.cron-simple.ts)
and [`register.cron-edit.ts`](https://github.com/openclaw/openclaw/blob/v2026.9.6/src/cli/cron-cli/register.cron-edit.ts).

`openclaw agents set-identity` requires approval for every invocation, including
ordinary name changes. In the pinned OpenClaw version, `--identity-file` can
read arbitrary paths and `--avatar` accepts HTTP(S) and data URIs; the command
also rewrites `openclaw.json`. Filesystem-tool workspace confinement does not
limit this CLI command. Cancelled, denied or timed-out approvals do not run it;
shell wrappers, chaining and substitutions remain denied.
