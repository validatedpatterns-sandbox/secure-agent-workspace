# SAW implementation status: one versioned apply_bom.py

Current decision: Argo + ESO + a small guest service + the existing apply_bom.py.
The installer BOM selects component versions; release authors update the script
when deployment behavior changes. No custom controller, separate OpenShell adapter,
direct gRPC client, vendored API or fixed .116 compatibility gate.

Canonical source now lives in installer/apply_bom.py, with legacy parser tests
in installer/tests. The guest bundle consumes it directly. The legacy chart has
only a generated files/apply_bom.py packaging copy, checked for drift by the fast
gate; regenerate with tools/saw/sync_installer_chart.py after installer edits.

## Implemented

- Existing Argo blueprint resources: user/SAW namespaces, scoped ESO inputs,
  SAW-BOM profile references, shared saw-images imports and retained private clones.
- InstallerBOM schema/example and per-tenant installer ConfigMap with live virtiofs
  mount. Guest-enabled tenants must supply an installer BOM. Helm validation is
  generated from shared schema sources, not manually maintained duplicate schemas.
- Fixed private-stdin invocation of apply_bom.py. OpenShell versions and
  release-specific validation/verification live in that script, not the guest.
- apply_bom.py supports installer BOM validation and declared software-version
  checking. The existing --profiles-dir legacy deployment interface is preserved.
- Mounted workspace/provider-only profiles now use the CLI inside apply_bom.py:
  enrollment-owned workspace creation, exact membership reconciliation, scoped
  provider creation/credential updates, and read-only metadata verification.
  Retries, drift repair, ownership/type conflicts and credential isolation have
  offline CLI-contract tests. No separate OpenShell adapter was introduced.
- The generic process runner permits drift repair after a structured negative
  verification and kills CLI descendants on timeout before releasing its lock.
- Local gateway bootstrap now lives in apply_bom.py: staged per-VM TLS/JWT identity,
  enrollment/machine-id/DMI UUID binding, root-only client configuration, fixed
  systemd service startup and authenticated readiness checks. The service uses
  rootless Podman through cloud-user's user socket; its supervisor image follows InstallerBOM.
  The bundle includes/hash-checks that unit. CI installs Podman unit dependencies
  for Linux syntax verification; no controller image is built or published.
- Deterministic bundle pairs the selected BOM with the actual apply_bom.py and its
  SHA-256. The software BOM can change without rebuilding an API client.
- Scoped unit/security/Helm tests and source-bundle validation CI.

Removed the previous adapter entry point, control-plane/gRPC modules, vendored
protos/license copy, descriptor compiler, associated tests, gRPC dependencies and
fixed runtime lock. The old controller work remains removed. No published image
or cluster deployment was removed or modified.

## Not implemented or qualified

The mounted path requires a qualified image with preinstalled payloads, Podman and
the bundled systemd units; it now creates its own local gateway identity. The
gateway runs as cloud-user and refuses a rootful engine. The reconciler remains
root for protected inputs and service orchestration. Legacy state is not adopted.
External OIDC access and certificate renewal are not implemented.
It supports nvidia/openai/anthropic single-key
providers in new, explicitly owned workspaces. Existing unlabeled workspaces,
including built-in default, are not automatically adopted. See the exact
[guest prerequisites and boundaries](../guest/README.md#workspaceprovider-increment).

Profiles with enabled sandboxes are rejected before mutation with
`SandboxApplyNotImplemented`; safe sandbox creation/replacement remains
unimplemented. Explicit workspace inference is
applied and read back; legacy provider model/NemoClaw settings are rejected.
Software changes relative to the image-bundled release return
SoftwareUpgradeNotImplemented. Provider verification checks metadata, not masked
credential bytes or successful external authentication.

The preserved `--profiles-dir` legacy path carries the upstream Podman runtime
selection and generic-sandbox fallback fixes: Podman is the default, an
`Error` or `Completed` sandbox is recreated, and fallback sandboxes run a
detached keep-alive command. This does not enable sandboxes in the versioned
mounted-input path, which still rejects them before mutation.

First qualify the clean image build and basic boot against the real runtime.
Only then implement retained-data sandbox lifecycle and workload verification in
apply_bom.py, followed by external OIDC access and remaining ESO/Vault/CDI/CNI,
Argo health and Astra instantiation qualification.

This is a partial installer implementation, not a completed first installer
release. The blueprint stays disabled by default and optional guest VMs should
remain Halted. Source packaging is not a bootable image or runtime qualification.

Re-run make saw-test-fast for the current result; older counts predate rootless,
inference and image-build coverage. No CI run is claimed; Linux unit syntax
validation remains a CI step. The clean image build and isolated smoke-test tools
are described in [image qualification](../guest/image/README.md).

The isolated OpenShift build completed and its private disk imported successfully
in `saw-installer-validation`, but the first VM did not become ready. Its journal
exposed an ordering cycle (guest service attached to `multi-user.target` while
waiting for `cloud-final.service`) and missing `/etc/machine-id` on the initially
read-only root. Sources now attach the guest to `cloud-init.target` and explicitly
leave an empty machine-ID file after offline image sealing. Regression tests
cover both. A successful image build alone is not a successful boot; qualification
must use a fresh disk from the corrected digest, retaining failed disks for diagnosis.

The corrected `saw-installer-4` build completed on 2026-09-19 UTC, producing
`sha256:563283f2218951bb5369253ffd1f63bad82058d32f23d6df8d3f4b117e9977f6`
in the validation namespace's internal `saw-installer` repository. A fresh
`installer-smoke-4` disk imported successfully and booted through machine-ID
commit, D-Bus, cloud-final, read-only virtiofs mounts and guest-service startup.
The QEMU guest agent connected. This resolves the two early-boot defects, **not**
end-to-end readiness: `/readyz` returned 503 and offline inspection found
`InstallerFailed` with no pending journal or gateway state, indicating a preflight
failure. This run exposed a diagnostic gap: the runner discarded the installer's
structured reason. The runner now retains explicitly allowlisted codes and the
failed operation in private status and sanitized journal messages; malformed or
unknown codes become a fixed generic code. Raw subprocess stderr stays suppressed.
SELinux remained enforcing; its denial of private-state access through QEMU's
guest agent was not bypassed. Both smoke VMs were halted and their disks retained.
Rootless engine operation, workspace convergence and sandbox lifecycle remain
unverified against this image.

Read-only preflight probes then identified `UnqualifiedGatewayUnit`: Fedora's
service-wide `/usr/lib/systemd/system/service.d/10-timeout-abort.conf` was rejected
by the original no-drop-ins rule. The image builder now reviews its sole effective
setting (`TimeoutStopFailureMode=abort`) and records its hash. Runtime checks require
the exact attested path and bytes and still reject extra, missing or changed
overrides. The fix and safe diagnostics are included in the next image build;
unit tests alone do not establish that the remaining live-runtime gates pass.

Build 5 passed that preflight check on a fresh VM. Apply then reported
`RootlessCommandFailed`: `ProtectHome=true` also hid `/run/user`, preventing
communication with cloud-user's bus and Podman socket. Both runtime units now use
`ProtectHome=tmpfs` with a read-only `/run/user` bind; `/home` and `/root` stay
hidden, and runtime-directory ownership checks remain mandatory. The remote
Podman client uses an empty, image-controlled configuration rather than the
hidden user home; the independent user service retains its real home/storage.
An opt-in disposable Linux CI test exercises the actual systemd namespace,
verifying runtime visibility, read-only access and hidden home directories.

Build 6 exposed the remaining client-side write requirement: even `podman
--remote info` initializes local configuration and runtime directories. The
installer now gives each invocation a private, temporary HOME and, for Podman,
XDG runtime directory, owned by cloud-user and removed after completion or
failure. The remote engine socket and user D-Bus address remain explicitly pinned
to the real `/run/user/1000` endpoints. The engine retains its own persistent
storage; this does not start a second engine or fall back to rootful Podman.
Regression tests cover the separate systemctl/Podman environments, timeout
cleanup and exclusion of inherited credential environment variables.

## Release workflow

1. Author InstallerBOM with a release name, installerVersion and component versions/
   immutable image digests. The .116 example is not mandatory.
2. Implement/test the selected release in apply_bom.py; increment its installer
   version when releasing changed behavior. No arbitrary script URL in ConfigMaps.
3. Build the guest bundle with SAW_INSTALLER_BOM and SAW_GUEST_BUNDLE. The golden
   image builder consumes the same release, installs payloads and seals tenant state.
4. After qualification, change reviewed Git values; Argo owns deployment. ESO
   supplies only tenant Secrets. No imperative deployment CLI or guest SSH Job.

See [guest contract](../guest/README.md), [design](versioned-vm-bom-installer.md)
and [test plan](versioned-vm-bom-installer-testing.md).

Known unrelated legacy baseline failures remain separate: the full cli/tests had
eight help/default-namespace/config-path/OIDC expectation failures and the old OIDC
template script had six stale script/path assertions. Scoped tests do not claim
whole-repository or live-platform qualification.
