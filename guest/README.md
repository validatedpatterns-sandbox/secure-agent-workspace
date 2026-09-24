# SAW guest service and versioned apply_bom.py

Argo owns VM deployment and mounted configuration. ESO supplies provider Secrets.
The guest service uses image-owned release bootstrap code to retrieve a signed,
digest-pinned OCI bundle. The bundle contains apply_bom.py and the selected
OpenShell payloads; the image contains no release-specific installer or payload.

## Folder responsibilities

- saw_guest/__main__.py: periodic execution and graceful shutdown.
- saw_guest/inputs.py and mounts.py: capture approved read-only mounted inputs.
- saw_guest/reconcile.py: single-writer lock, private pending/accepted progress,
  change detection and generic retention guards.
- saw_guest/release.py: verify, stage and activate the signed release bundle.
- saw_guest/installer.py: invoke only the staged Python script and check its result.
  It does not interpret OpenShell responses or choose software versions.
- saw_guest/health.py: expiring readiness based on completed verification.
- systemd/: boot mounts and service lifecycle.
- ../installer/apply_bom.py: the single release implementation,
  including release validation, deployment and verification.

The existing legacy profile-deployment command remains available. The new mounted
guest path is a refactoring foundation, not a completed autonomous installer.

## Two BOMs, different responsibilities

InstallerBOM selects the installer version and CLI/gateway/supervisor versions and
image digests. SAW-BOM profiles define workspaces, providers, inference and sandboxes;
instances refer to those profiles and bind namespace-local ESO credentials.

Start from ../examples/saw/installer-bom.yaml. Its .116 values are an example, not a
code requirement. New releases can select different versions. The author updates
apply_bom.py when deployment steps change, increments INSTALLER_VERSION, sets the
matching spec.installerVersion, and tests/releases that script and BOM together.
There is no automatic compatibility matrix or API adapter selection.

Digest pins make one release repeatable. They do not freeze future releases or
establish artifact authenticity. Signature/scanning/boot qualification are separate
release gates. Do not place executable commands, installer URLs or credentials in
the installer BOM.

## Current boundary — important

Implemented now: release schema, example, Helm ConfigMap/mount, private script
invocation, software-version checks, local rootless Podman gateway bootstrap, workspace/membership/provider/inference reconciliation,
source packaging and offline tests. The mounted path uses CLI commands directly
inside apply_bom.py, not the permissive legacy runner.

This increment supports explicit workspace inference with an enabled provider,
but does not yet support enabled sandboxes or legacy provider model/NemoClaw
settings. These inputs fail preflight as a whole with SandboxApplyNotImplemented
or ExplicitWorkspaceInferenceRequired, before any workspace or provider changes.
Installer logic has its own signed release version; OpenShell payload changes
still require a matching golden image.
Software changes relative to the bundled release return SoftwareUpgradeNotImplemented;
a later apply_bom.py release must implement controlled installation/upgrades.

The default `data-science` example still requires sandbox support before it can
converge through this guest path. External OIDC access and live platform
qualification remain separate gates. A clean sealed-image build recipe and
isolated boot-smoke renderer are available; see [image build](image/README.md).
Build tooling is not itself proof of a successful boot or a production-qualified
release.

### Local gateway bootstrap

apply_bom.py now generates and starts the local gateway during the apply phase.
Preflight and verification remain read-only. The golden image must have the selected
OpenShell payloads, Python/PyYAML, systemd and Podman installed, plus the bundled
saw-openshell-gateway.service loaded by systemd. No SSH setup or human login is used.

The gateway runs as **cloud-user with rootless Podman**, using that user's
/run/user/<uid>/podman/podman.sock. Bootstrap validates subordinate UID/GID ranges,
starts the user socket with lingering, and requires the engine to report rootless
operation. There is no rootful fallback. The guest reconciler remains root for
mounts, protected configuration and service orchestration. Gateway configuration
is root-owned and group-readable; only runtime state is writable by cloud-user.
The CA signing key remains root-only. The local runtime account can read the
gateway's client identity and is trusted to administer its own gateway, not the OS.
Existing runtime state is not automatically adopted or migrated. No legacy
services or containers are stopped. This boundary still requires live qualification.

- Generate CA, server/client certificates and gateway JWT material in a private
  staging directory using the release's gateway cert generator. Parse TLS material
  and check certificate/private-key pairs before atomic publication. Never rerun
  certificate generation over live state or overwrite existing client credentials.
- /var/lib/saw/gateway/bootstrap.json records enrollment, machine-id, VM DMI UUID
  and PKI checksums. Retained foreign/partial/modified state fails closed. The
  service's startup guard checks the same identity on every start/restart.
- The installed service must match its image-attested hash, have only exact
  image-attested vendor drop-ins and require
  no daemon reload. Only that fixed unit may be started. A conflicting listener on
  port 17670 blocks bootstrap rather than replacing the old gateway.
- The primary admin listener binds 127.0.0.1 with verified mTLS. Dedicated health/
  metrics listeners and plaintext loopback service routing are disabled. Podman's
  driver may create its own bridge/callback listeners; qualify their restrictions
  separately. No external Route/OIDC listener is provisioned by this increment.
- This is OpenShell's local single-user mTLS mode: holders of its local client
  identity are administrators. Do not distribute that key to users or workloads.
  Before enabling sandbox deployment, qualify separate workload identities and
  callback authorization; before external access, implement OIDC and role mapping.
- Podman's supervisor image comes from the selected, digest-pinned InstallerBOM,
  not a fixed version or Docker's supervisor-binary setting. Host bind mounts are
  disabled. Sandbox image/retention operations are still blocked by preflight.
- Start success is not readiness: require an authenticated CLI round trip, followed
  by profile verification. Failed starts retry with the existing committed identity.
  Recovery after interruption between identity and client publication copies the
  same identity. Partial committed PKI/configuration is never silently regenerated.

Golden-image sealing must omit /var/lib/saw runtime/client/journal state, enrollment
settings and per-VM machine identity. A hard kill during staging can leave an
unreferenced root-only .saw-gateway-* or .saw-client-* directory; it is never used
as active state. Cleanup/backup must not expose these private keys. Certificate
renewal, expiry recovery, runtime upgrades and retained-root migration remain
explicit future release work; no automatic CA rotation is implemented.

### Workspace/provider increment

- Bootstrap supplies the gateway at https://127.0.0.1:17670 and a fresh local
  mTLS identity. Root-owned ca.crt, tls.crt and mode-0600 tls.key are published
  under /var/lib/saw/openshell-client/openshell/gateways/saw-local/mtls/.
  Parent paths must not be symlinks or group/world writable. Other files in the
  saw-local directory are rejected to avoid stored login/auth-mode overrides.
  Never bake this identity into clones.
- Use a new workspace name of at most 19 characters. The script creates an
  enrollment label (full enrollment SHA-256 encoded as lowercase base32). It
  refuses foreign or unlabeled existing workspaces, including built-in default.
  There is no automatic adoption or relabeling of existing user workspaces.
- This label declares exclusive Git ownership of workspace membership and declared
  providers. Profiles must explicitly keep the enrolled owner as admin. Member
  role maps to the CLI's user role; stale access and changed roles are removed
  before provider writes. Removed resources/disabled resources still require the
  guest's explicit migration/decommission workflow; no sandbox/provider deletion.
- Enabled nvidia, openai and anthropic providers accept one explicit Secret-bound
  UTF-8 credential each. No ambient credential lookup. Values are supplied only
  to the relevant CLI child environment using --credential=KEY, never KEY=value
  argv. Root can inspect child environments; VM root remains a trusted boundary.
  Platform provider profiles must exist. Custom/multi-key providers need a release
  implementation rather than tenant-controlled environment-variable mappings.
- Provider type changes fail preflight. CLI failures, malformed/paginated output,
  wrong workspace scope and ownership conflicts cannot be interpreted as absence
  or success. Retries reapply credentials without deleting providers.
- Verification checks owned Active workspaces, exact membership, provider scope,
  type and declared credential-key presence. The gateway masks credential values:
  successful writes plus metadata checks are NOT a provider-authentication or
  inference health test, nor proof of byte equality after out-of-band rotation.
  Concurrent administrative writes are not transactional with this CLI workflow.
- Explicit workspace inference is applied with CLI endpoint verification enabled
  and read back from the workspace-specific result. The system inference route is
  not changed. Removal requires explicit decommissioning; it is not silently ignored.

The CLI flags/JSON contract was checked against the example release's source;
tests simulate those commands. This is not a new compatibility matrix or a fixed
OpenShell version gate. Release authors update/test this same script as needed.

## Argo deployment

Configure a tenant's installerBOM, instance, enrollment and profileConfigMaps in Git.
The chart renders <instance>-installer with installer-bom.yaml. For an opt-in VM:

```yaml
guest:
  enabled: true
  cores: 4
  memoryGi: 8
  runStrategy: Halted
```

Defaults remain disabled. Keep the VM Halted until its image and installer are
qualified. The legacy workload applications are unchanged. Do not attach old and
new VMs to the same writable root.

Mounted paths:

| Guest path | Source |
| --- | --- |
| /run/saw/installer/installer-bom.yaml | InstallerBOM ConfigMap |
| /run/saw/intent/instance.yaml | Instance profile references |
| /run/saw/profiles/<name>/ | Enrolled SAW-BOM ConfigMaps |
| /run/saw/credentials/<name>/<key> | ESO provider Secret |
| /etc/saw/guest.json | Trusted public enrollment settings |
| /var/lib/saw/reconciler/ | Private progress and sanitized readiness |

Provider Secrets are named after the provider (`nvidia`, `brave`, and so on) and
are scoped to the user namespace. The user Vault prefix (for example
`saw/alice`) is used for paths such as `saw/alice/providers/nvidia`; the immutable
OIDC subject remains the tenant ownership identity. Use ConfigMap/Secret virtiofs
filesystems, not ISO disks, for live updates. Qualify
the actual OpenShift/KubeVirt/Astra release, kernel, SELinux and migration behavior.
[KubeVirt volumes](https://kubevirt.io/user-guide/storage/disks_and_volumes/)

The guest reopens inputs every ten seconds and captures twice to detect projection
changes. This is not an atomic transaction across objects. Keep coupled fields in
one profile ConfigMap or provider Secret; coordinated releases need explicit staging.
New mount sources/allowlists require an enrollment lifecycle operation; cloud-init
does not rewrite an existing root automatically.

## Process and security contract

The guest launches `/usr/bin/python3 -I /var/lib/saw/releases/current/apply_bom.py`
with `--guest-phase validate`, `apply` or `verify`. The image-owned bootstrap
verifies and activates that path from the signed OCI release bundle before the
first invocation. Input is bounded private JSON on stdin:
version: 1 and revision containing id, snapshot and planned actions. Output contains
version, revision, ok and an optional nonsecret reason. No generic capability
negotiation or OpenShell verification lives in this process wrapper.

The script and parent paths must be root-owned, nonsymlinked and not group/world
writable. Mounted input cannot choose code or a command. Stdout is a structured
result; stderr and raw subprocess errors are not published. The script owns
verification; the guest only accepts success for the matching revision.
Failed verification permits a fresh preflight before drift repair. Malformed replies
remain failures. Timeout cleanup kills the installer process group, including CLI
children, before releasing the reconciliation lock.

Progress survives restart under a private lock/journal. Changed inputs during a
pending operation block blind replay. Retained state is not proof of runtime rollback.
The revision is an operation ID, not a configuration hash: recovery of stopped
runtime services can accept a new revision for unchanged inputs. Identity and
workspace state must be verified independently after a reboot.
Journal files may contain credentials: protect root storage and backups with access
controls/encryption, and never upload them as CI diagnostics.

No Kubernetes/Vault token is exposed to the guest. Retained Secret bytes cannot
prove ESO/Vault freshness: monitor ESO and revoke/expire credentials at the provider.
Readiness on port 9080 returns only HTTP status and expires after 30 seconds.
It is not a liveness policy that reboots the VM on invalid desired input.

## Build and test

```sh
make saw-test-fast SAW_PYTHON=/path/to/venv/bin/python
make saw-guest-bundle SAW_PYTHON=/path/to/venv/bin/python \
  SAW_INSTALLER_BOM=examples/saw/installer-bom.yaml \
  SAW_GUEST_BUNDLE=/new/path/saw-guest.tar.gz
```

The archive contains guest code, apply_bom.py, selected installer BOM, script hash,
shared pure validators, systemd units and dependency pins. It contains no OpenShell
binaries, credentials or bootable disk. An image build must install and verify the
BOM-selected payloads, install dependencies offline, seal state and boot-test before
promotion. Guest boot does not download a replacement script.

The validation workflow tests this bundle and chart without deployment, gRPC tools,
API compilation or controller image publication.
