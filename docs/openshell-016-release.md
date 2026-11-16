# OpenShell 0.1.6 release record

The CLI, gateway, supervisor and sandbox BOM uses `0.1.6-rhaiv.4`. The
interceptor pin in #160 supplies the matching published OpenShell `v0.1.6`
image, including the provider-annotation workaround and driver-config guard.

**Deployment hold:** [#165](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/issues/165)
can discard workspace files and passwords during automatic recovery. Keep #160
on hold until its fix and the remaining acceptance below are recorded in
[#157](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/issues/157).
The credential fix [#162](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/pull/162)
and guest-shutdown fix [#164](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/pull/164)
are merged; they do not clear this preservation blocker.

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

## Validation checkpoint

The November 12 clean README Option A install on OpenShift 4.22.22/amd64 used
shipping source `7d8c8440ac76381e277a56e05121c05317ef58aa` and deployment inputs
`bd7ce216c1a436af51cab10422df571214e10f52`, with the public chart default and no
interceptor override. NetworkPolicy was enabled from first boot; web search
and GPU hardware were disabled. All sixteen applications became Synced/Healthy.

Initial real inference/UI and owner isolation, all three sandboxes' file-tool
confinement, approval/rejection audit, credential/admin cleanup and reapply
passed. Peer-required NetworkPolicy passed **36/36**. Initial local tests passed
**2097 with 3 skips**; native publication tests covered the two Rust skips, and
the other needs an APF bundle. These are historical results, not CI results for
the rebased PR head.

Follow-up guest shutdown and boot/reapply completed on both controls; all three
gateways answered inference.
C and D's notebook retained their original files/passwords/policy/identity.
D's CUDA sandbox was automatically replaced and lost its original sentinel
and password (#165); inference on its replacement is not preservation acceptance.
The final peer check and a fresh install of the corrected runtime were not run.
Detailed receipts and the unresolved original catalog/shutdown investigation
remain in [#161](https://github.com/validatedpatterns-sandbox/secure-agent-workspace/issues/161).

## Remaining rollout gate

1. Resolve #165 with workspace preservation or a recovery hold that retains the
   existing data; verify original files and passwords survive recovery.
2. Complete focused combined restart/reapply acceptance: current inputs, healthy
   consistent catalogs, real inference/tools, preserved identity/policy/confinement
   and healthy two-way peer isolation. Reuse completed initial security evidence;
   record any unperformed checks explicitly in #157.
3. Require CI on the final pin PR head and record the accepted source/evidence
   in #157 before merging or deploying. Clear deployment-hold notices in README,
   this guide, container-image docs and chart comments only after acceptance.

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
