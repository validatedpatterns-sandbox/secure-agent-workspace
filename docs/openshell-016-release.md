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
