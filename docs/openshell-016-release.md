# OpenShell 0.1.6 publication requirements

The CLI, gateway, supervisor and sandbox BOM uses `0.1.6-rhaiv.4`.
The governance interceptor must be built from NVIDIA/OpenShell `v0.1.6`,
using this repository's interceptor Dockerfile. Its provider-annotation
workaround and driver-config admission checks are required.

The existing chart digest (`253b58d070d3ed341287fcbab44684d84a437fcb9f26be5834ebf554a40ec22f`)
is the published **0.1.2** interceptor. It is retained only while the replacement
PR is a draft. It must be replaced before readiness; relabeling that digest as
0.1.6 does not satisfy the dependency.

An upstream publisher must run `build-governance-interceptor.yml` from an
approved upstream `main` commit containing the 0.1.6 build inputs. PR builds
must continue to use `push: false`. Required artifacts and evidence:

- Public `ghcr.io/validatedpatterns-sandbox/governance-interceptor:v0.1.6`
  and `sha-<build-commit>` tags, with the exact build commit and source commit.
- A multi-platform index with `linux/amd64` and `linux/arm64` manifests.
- Passing native Rust admission tests, both image build jobs and the merged
  image's anonymous public-pull validation.
- The index digest and architecture-specific manifest digests, obtained
  without registry credentials. Pin the verified index digest in
  `charts/governance-interceptor/values.yaml`, then remove the draft-only
  warning in this document and `docs/container-images.md`.
- Passing candidate CI and clean README Option A installation using that
  shipped default, including real inference and the complete live security
  and interactive acceptance checks.

`make governance-interceptor-build-local` builds the same reviewed source for
preliminary tests in the cluster's internal registry. Record its output digest
and use it only on the separate deployment branch. This does not meet the
public upstream publication or final fresh-install acceptance requirements.

## Installer and tool permissions

For OpenClaw and NemoClaw, apply now fails unless setting
`tools.fs.workspaceOnly` succeeds and reads back as the JSON boolean `true`.
An existing agent with an invalid or unreadable setting is stopped before its
mounted tool policy changes. A failed repair leaves it stopped. Successful,
unchanged reapply does not stop the agent merely to check confinement.

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
