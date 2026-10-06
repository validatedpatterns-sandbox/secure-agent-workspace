# Versioned BOM installer

The gateway VM installs itself from a versioned Bill of Materials. The old
setup Job, which logged in to the VM over SSH and ran scripts, is gone.
Signature checks, live input updates, and profile pruning are below.

## What runs where

```text
helm / Argo ──► openshell-saw chart
                 ├─ VirtualMachine (+ root disk clone)
                 ├─ <vm>-installer ConfigMap     installer-bom.yaml, config.json,
                 │                               apply_bom.py, setup-dashboard.sh
                 ├─ saw-bom-profiles ConfigMap   (saw-bom chart: SAW-BOM profiles)
                 ├─ provider Secrets             inference, web-search, ...
                 ├─ <vm>-cloudinit Secret        static units and first-boot files
                 └─ <vm>-prepare Job             cluster-side only, never touches the VM
                            │
                            ▼
              iso9660 disks (default)  or  virtiofs (vm.liveInputs: true)
                            │
                            ▼
VM boot ─► cloud-init ─► saw-install.service ─► saw-apply.service
                          apply_bom.py install    apply_bom.py apply
                          (root)                  (root → profiles as cloud-user)
                            │
                            └─ vm.liveInputs: saw-reconcile on later changes
```

- **saw-install** pulls each BOM component image by digest with podman,
  checking each signed component against a per-pull podman policy built
  from the BOM's `signature` field, copies the binary out, checks
  `--version` against the BOM, installs it atomically into
  `/usr/local/bin`, re-syncs `gateway.env`, `gateway.toml` and the
  route-SAN drop-in from the installer disk, then starts the user-level
  `openshell-gateway.service` (restarting it if a binary or the config
  changed; an owed restart survives a failed attempt). Unchanged components
  are skipped, so reboots pull nothing. `apply_bom.py` itself always runs
  from a root-owned, verified copy under `/var/lib/saw/verified`, not the
  live installer disk/mount — see [Signing](#signing).
- **saw-apply** runs only after `install` finished for the same BOM. It reads
  the profiles and mounted Secrets, then runs the profile step as
  `cloud-user` with the plan on stdin. Provider keys are passed to the CLI
  as `--credential NAME` with the value in the environment, never in argv;
  existing providers get the current key via `provider update`. If the gateway has no profile
  for a provider type (e.g. `brave` when governance is off), the installer imports the copy
  shipped in `charts/openshell-saw/files/provider-profiles/` (kept identical to
  `charts/governance-policy/profiles/`) into that workspace; a type with no shipped profile is
  skipped with a warning. It registers a local **mTLS**
  gateway entry, creates workspaces, providers and
  sandboxes, optionally starts the dashboard, and verifies the result.
  It records what it created and, in the default `report` prune mode, only
  logs what a later profile change would delete. See
  [Removing things from a profile](#removing-things-from-a-profile).
- The prepare Job only bootstraps the golden image DataSource and registers
  the dashboard redirect URI in Keycloak (admin API). It has no VM access.

cloud-init runs once per VM, so it only writes static files (mount script,
units, and the reconcile units when `vm.liveInputs` is true) and first-boot
copies of the gateway config. The BOM, gateway config, profiles, and provider
Secrets are mounted at `/run/saw`. With the default disks, a change is visible
on the next boot. With `vm.liveInputs: true`, virtiofs shows the change while
the VM runs and `saw-reconcile` applies it. See [Live inputs](#live-inputs).

`saw-install` and `saw-apply` also run on every boot. Status is in `/var/lib/saw/status.json`
(one section per step), and `/var/lib/saw/ready` exists only when both
steps succeeded for the same BOM. Logs go to the serial console:

```bash
oc logs -f -l vm.kubevirt.io/name=<vm> -c guest-console-log --tail=-1
# or: make openshell-saw-logs OPENSHELL_SAW_NAME=<vm>
```

## Namespaces

| Namespace | What lives there |
| --- | --- |
| `saw-<name>` (one per SAW) | the SAW's VM, its installer/profile ConfigMaps, its provider Secrets, prepare Job. Labelled `openshell.pattern/saw=true`. |
| `openshell-agents` (shared, `NS`) | golden image DataSource, image builds, governance interceptor + policy |
| `saw-keycloak` (`KEYCLOAK_NS`, any name) | Keycloak and the RHBK operator |

- A VM can only attach ConfigMaps/Secrets from its own namespace, so each
  SAW's `inference`/`web-search` Secrets and `saw-bom-profiles` ConfigMap
  must be in its `saw-<name>` namespace.
- The governance interceptor admits gateway VMs from namespaces labelled
  `openshell.pattern/saw=true` (`make openshell-saw-create` and
  `values-prod.yaml` set it). Without the label, sandbox creation is denied
  (`fail_closed`).
- Each SAW gets a Role in the golden image namespace that lets its
  `default` service account (which KubeVirt clones the root disk as) and its
  prepare Job clone the image (`datavolumes/source`) and create the
  DataSource there on first use.
- Quickstart: `make openshell-saw-create OPENSHELL_SAW_NAME=alice` deploys
  into `saw-alice`; override with `SAW_NS=...`. Keycloak is looked up in
  `KEYCLOAK_NS` (default `saw-keycloak`; `KEYCLOAK_NS=keycloak` to use a Keycloak the cluster already runs there). `make openshell-saw-delete` also
  deletes the namespace if it carries the SAW label.
- Pattern: `values-prod.yaml` puts Keycloak/RHBK in `saw-keycloak` (so it never
  collides with a platform Keycloak in `keycloak`, as on many demo clusters).
  Each person is one entry in [`overrides/saw-users.yaml`](../overrides/saw-users.yaml).
  The `saw-users` chart creates namespace `saw-<name>` and the three apps
  (secrets, bill of materials, and virtual machine `<name>`).

## Authentication

| Who | How | Role |
| --- | --- | --- |
| In-VM installer (`apply_bom.py`) | its own mTLS client certificate `CN=saw-installer, OU=openshell-admin`, gateway entry `saw-installer` | platform admin (`openshell-admin`) |
| Users (laptop CLI, dashboard) | their own OIDC token from Keycloak | from `realm_access.roles`: `openshell-admin` / `openshell-user` |

The installer never logs in to Keycloak and never configures the CLI for
OAuth. Set `accessControl.ownerSubject` (the owner's `openshell whoami`
subject) to make the owner admin of every workspace the installer creates.

To use the gateway from a laptop, register the gateway Route with OIDC in
your local OpenShell CLI and log in with your Keycloak account. You need the
gateway CA (`scripts/extract-gateway-ca.sh`); the Route hostname is added to
the gateway certificate by cloud-init.

The gateway takes an mTLS caller's roles from the client certificate's OU.
The certificate the gateway generates for local use carries
`OU=openshell-user`, which is not enough once OIDC RBAC is on, so the
installer issues its own `CN=saw-installer, OU=openshell-admin` certificate
with the gateway's CA (`~/.local/state/openshell/tls`), keeps it in
`~/.local/state/saw-installer/tls` (re-issued when missing, signed by a
different CA, or within 30 days of expiry) and registers it as the
`saw-installer` gateway entry. The default `openshell` entry is left alone.

## SSH into the VM

Provisioning never uses SSH. For debugging, the VM's `accessCredentials`
point at the `<name>-ssh-pubkey` Secret, which the chart creates empty.
KubeVirt's guest agent writes every key in it into `cloud-user`'s
`authorized_keys`, also while the VM runs
([KubeVirt docs](https://kubevirt.io/user-guide/user_workloads/accessing_virtual_machines/)).

```bash
make openshell-saw-vm-ssh OPENSHELL_SAW_NAME=alice            # interactive shell
make openshell-saw-vm-ssh OPENSHELL_SAW_NAME=alice CMD='sudo cat /var/lib/saw/status.json'
```

The target adds `$(SSH_KEY_PATH).pub` to the Secret under your login name
(`KEY_NAME=` to change), waits until the VM accepts the key, then runs
`virtctl ssh` (stdin closed for a `CMD=` command, so `openshell sandbox exec`
inside it does not wait for input). make expands `$(...)` in `CMD=`, so write
`$$(...)` or call `scripts/openshell-saw-vm-ssh.sh` directly for command
substitution. The chart never sets the Secret's `data`, so added keys
survive upgrades; remove one with
`oc patch secret alice-ssh-pubkey -n saw-alice --type json -p '[{"op":"remove","path":"/data/<name>"}]'`.
The guest needs SELinux boolean `virt_qemu_ga_manage_ssh=on`; cloud-init and
`saw-install` set it.

## Upgrading

`vm.liveInputs` defaults to `false`. The installer ConfigMap, profiles, and
provider Secrets are iso9660 disks filled at boot.

1. Change `bom:` in the chart values (versions + digests; tags are refused
   at render time and by the installer).
2. Sync/upgrade the chart. The installer ConfigMap is part of the VM template
   checksum, so KubeVirt marks the VM `RestartRequired`.
3. `virtctl restart <vm>` (or `make openshell-saw-restart`). On boot,
   `saw-install` installs only the changed components.

A profile or Secret change is not in that checksum. The guest still does not
see it until the next restart, because those disks are filled at boot.

With `vm.liveInputs: true`, a BOM change runs `install` then `apply` without
a restart, and a profile or Secret change runs `apply` only. Turning the
flag on requires recreating the VM. See [Live inputs](#live-inputs).

## Testing

```bash
make test-installer        # installer + chart tests; chart tests need helm
make test-tool-gate        # tool-action gate tests; needs node; not run in CI
```

- `tests/installer`: the real `apply_bom.py` against fake `podman`,
  `openshell`, `nemoclaw` and `sudo` executables: BOM validation, component
  install/skip/upgrade/rollback-on-failure, profile apply and idempotency,
  mTLS-only access, credential masking, status/ready handling, dry-run,
  signature `warn`/`enforce` (including a tampered installer bundle),
  reconcile (`install` then `apply` on a BOM change, `apply` only on a
  profile or Secret change), the `/run/saw/lock` overlap, and pruning
  (provider removal, hand-made objects left in place, `report` as a dry run).
- `tests/scripts`: `openshell-saw-vm-ssh.sh` against fake `oc`/`virtctl`
  (key added via patch file, other keys kept, waits for sync, timeouts).
- `tests/charts`: renders both charts, checks VM disks ↔ mount script ↔
  Secrets, systemd units, gateway TOML (parsed), render-time guards, and
  runs the shipped installer's `validate` against the rendered ConfigMaps.

## Signing

`signing.mode` is `off`, `warn`, or `enforce`. The chart default is `warn`.
On the pattern path set it in `defaults.openshellSaw` in
`charts/saw-users/values.yaml`, or in one user's `values`. `enforce` fails
at render time unless `signing.trustKeys` or both `signing.identity` and
`signing.issuer` are set.

The *effective* mode is the stricter of that chart value and a floor the
golden image can pin at `/etc/saw/signing-mode` (absent = no floor). This
matters because `config.json` — which carries `signing.mode` — ships in the
same, unsigned installer ConfigMap as `apply_bom.py`: without the floor, a
namespace editor could set `mode: off` next to a modified `apply_bom.py`
and defeat `enforce` entirely. The floor can only tighten the mode, never
loosen it, and it is checked in three places that all need to agree: the
bundle verifier, `saw-install.service`'s no-verifier fallback, and
`apply_bom.py` itself (which also enforces component signatures, so the
floor has to apply there too, not just to the bundle check).

The image-builder chart's `signing.floor` (`image-builder-charts/helm/openshell-gateway-image/values.yaml`)
writes that file: empty (the chart default) bakes nothing, so `config.json`
alone decides the mode, same as before the floor existed. **Set
`signing.floor: enforce` when building a production image** — otherwise
the floor described above is not actually in place and a namespace editor
can still set `signing.mode: off`. `make build-gateway-podman` and
`make build-gateway-docker` do not set it; they run
`helm upgrade --install openshell-gateway-image ...` without it, so add
`--set signing.floor=enforce` to that command (or edit the Makefile) for a
production build.

Each OpenShell component in the InstallerBOM may name its signer:

```yaml
signature:
  keyRef: openshell          # /etc/saw/trust/openshell.pub in the golden image
# or, for keyless signing:
# identity: https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1
# issuer: https://token.actions.githubusercontent.com
```

For each component with a `signature`, `apply_bom.py` builds a one-image
`containers-policy.json` from that field — `sigstoreSigned` with
`keyPath: /etc/saw/trust/<keyRef>.pub`, or `fulcio.oidcIssuer` for the
keyless form — and pulls that one image with
`podman pull --signature-policy <generated>`, default `reject` for a
component with no `signature` configured under `enforce`. The policy is
generated per pull, not looked up from a static, registry-scoped file, so
a component from any registry is checked the same way; nothing pulls "for
free" the way a system-wide permissive default would let it. `warn`
installs the component anyway and records `signature: unsigned` (or
`failed`) in `/var/lib/saw/status.json`; `enforce` stops `saw-install`
before any binary is replaced, with the message
`image <ref> is not signed by <signer>`. The result is persisted per
component in `/var/lib/saw/installed.json`: a component whose file and
digest are unchanged is only trusted as still `verified` if that is what
was actually recorded last time, so switching from `off` to `enforce` does
not retroactively call an unchecked binary "verified" — it gets
re-verified.

Keyless (`identity`/`issuer`) is accepted as a BOM shape (validated the
same as any other signature field) but **always fails verification
today**: podman's `policy.json` can only match a Fulcio identity by an
exact `fulcio.subjectEmail`, and `identity` here is required to be an
`https://` URI (a workflow ref, as in the example above), never an email —
so there is no field to check it against. Checking only `oidcIssuer` would
accept any signer from that issuer (with
`https://token.actions.githubusercontent.com`, any GitHub Actions workflow
anywhere), so `_signature_policy` rejects instead of silently enforcing
less than the BOM asked for. A component configured with `identity`/`issuer`
behaves like one with no signer at all: `warn` records it unsigned,
`enforce` fails it. Use `keyRef` until there is a way to match this
identity shape.

`saw-install.service`, `saw-apply.service`, and `saw-reconcile.service`
each run `/usr/local/sbin/saw-stage-installer` before touching
`apply_bom.py`. That script runs the golden image's
`/usr/libexec/saw/verify-bundle` when present (an image built before
signing existed has no verifier: `warn`/`off` still boot unverified,
`enforce` refuses). Either way, the installer tree (`installer-bom.yaml`,
`apply_bom.py`, `setup-dashboard.sh`, `config.json`, the gateway config, the
shipped provider profiles) is copied into a root-owned staging area,
`/var/lib/saw/verified/installer`, and `apply_bom.py` always runs from
*that* copy — never straight off the live ConfigMap/virtiofs mount. This
matters for two reasons: with `vm.liveInputs`, `saw-reconcile` used to run
`apply_bom.py` off the live mount with no verification step at all, the
most direct way to bypass `enforce`; and even `saw-install`/`saw-apply`
verified the live mount in one step and then read that same live mount
again to run it, a window (worse over virtiofs) where the files could
change between the two. `enforce` never publishes a stage that failed
verification — the previous, already-verified revision (if any) keeps
running; `warn` publishes anyway, so a failed/unsigned bundle still takes
effect, matching "warn logs and continues."

The signed payload is a manifest of `<sha256>  <path>` lines — one per
file — not a raw concatenation: shifting bytes across a file boundary
while keeping the total concatenation unchanged used to leave the old
signature valid; each file's hash is now checked independently, so that
does not work. The manifest covers `installer-bom.yaml`, `apply_bom.py`,
`setup-dashboard.sh`, and every shipped `provider-profile-*.yaml` — the
parts of the installer ConfigMap that are identical across every SAW.
`config.json`, `gateway.env`, and `gateway.toml` are **not** covered: they
are rendered per VM (namespace, route host, owner subject, ...), so there
is no one correct rendering for a single CI-signed blob to cover. The
`signing.mode` leak that would otherwise create is what the golden-image
floor above closes; the rest of `config.json` (the mTLS gateway name, the
governance endpoint, dashboard settings) is not signed and relies on the
namespace's own RBAC. `signing.trustKeys`, when set, also restricts which
key names `verify-bundle` accepts for the bundle, instead of trusting
every `*.pub` the image happens to carry.

`scripts/build-installer-manifest.py` builds the exact same manifest for
CI to sign; it must stay in lock-step with `verify-bundle`'s
`manifest_text()` (same file set, same line format) or a genuine,
unmodified installer starts failing `enforce` for no reason.
`installer-tests.yml`'s `bundle-drift-check` job re-renders the chart on
every PR and fails if a *committed* `bundle.sigstore.json` no longer
verifies against that fresh render (skips cleanly if none is committed
yet) — without it, a PR that edits `apply_bom.py`, a shipped provider
profile, or the default BOM, without re-running "Sign installer bundle",
would silently ship a bundle that fails `enforce` for every SAW. Helm's
version is pinned in both that workflow and the signing workflow:
`installer-bom.yaml` is `toYaml .Values.bom`, and a different Helm version
can render that block scalar with different whitespace, changing the
manifest for reasons that have nothing to do with the installer changing.
A SAW whose `bom:` values are overridden per-user also renders a different
`installer-bom.yaml` than the signing workflow's default-values render
signs; give that SAW `signing.mode: warn` (or `off`), not `enforce`.
Checked live once: a manifest built from Argo CD's own `repo-server`
Helm render (not a local one) verified successfully on a real guest via
`verify-bundle`'s exact invocation, with the default (unoverridden) BOM.

The golden image installs `cosign` at `/usr/local/bin/cosign` (version and
sha256 pinned in the image chart's `values.yaml`; the download itself has
no other authentication, so an unpinned checksum would let a compromised
release URL bake a malicious verifier into every image) and ships
`/etc/saw/trust/` (the trust root) and
`/etc/containers/registries.d/saw.yaml` (`use-sigstore-attachments: true`
for `quay.io/opendatahub`, needed to fetch a sigstore signature's
detached data regardless of which policy checks it).

Spike on the `quay.io/opendatahub/odh-openshell-*` digests in
`charts/openshell-saw/values.yaml`: each digest has a cosign `.sig` tag and
an empty certificate, so the signature is key-based, not Fulcio keyless.
The public key is not in the signature and is not published next to the
image. The gateway VM's Podman is 5.8 (newer than 4.4). Rekor answers from
the VM. Key-based trust is the one that works without Fulcio, including
air-gapped, once the publisher key is placed in `/etc/saw/trust`. Until
that key is known, leave `signing.mode` at `warn`. Do not put a guessed key
in the image.

Key custody for the installer bundle: the private key is a GitHub Actions
secret named `COSIGN_PRIVATE_KEY`, never a file in git. The public key is
the matching `*.pub` added to the golden image under `/etc/saw/trust` and
listed in `signing.trustKeys`. Rotation: generate a new cosign key pair,
add the new public key beside the old one, rebuild the golden image, sign
new bundles with the new key (`.github/workflows/sign-installer-bundle.yml`, which uploads `bundle.sigstore.json` and does not commit it),
then drop the old public key on the following image build. A bundle signed
only by the retired key then fails `enforce`.

Out of scope for this story, unchanged: sandbox images
(`quay.io/aipcc/base-images/agentic/openclaw`, `nemoclaw-sandbox`) are not
signature-checked, and `nemoclaw.cliImage` is accepted with a tag (`:latest`)
rather than a digest, with a `WARN` at install time. Signing covers the
gateway components (`spec.openshell.*`) and the installer bundle only;
sandbox images can adopt the same per-pull podman policy approach later.

## Live inputs

`vm.liveInputs` defaults to `false`. The installer ConfigMap, `saw-bom-profiles`,
and provider Secrets are iso9660 disks filled at boot. Set it to `true` to
serve those same objects over virtiofs. The guest mounts them at the same
`/run/saw` paths. A path unit starts `saw-reconcile` after a change, and a
60-second timer is the fallback. Reconcile waits 10 seconds so one Helm
upgrade is one run, holds `/run/saw/lock` together with the boot units, and
then:

- runs `install`, then `apply`, when the installer tree changed (BOM or
  gateway config). Unchanged binaries are skipped. The gateway restarts
  only when a binary or its config changed. Like `saw-install`/`saw-apply`,
  `saw-reconcile.service` runs the golden image's bundle verifier first and
  `apply_bom.py` runs from the staged, verified copy, never the live
  virtiofs mount — before this, reconcile ran straight off the live mount
  with no verification at all, the most direct way to bypass
  `signing.mode: enforce` with live inputs on (see "Signing" above).
- runs `apply` only when profiles or Secrets changed. Existing providers get
  `provider update` with the new key. Sandboxes keep running.
- writes the applied hashes to `inputs` in `/var/lib/saw/status.json`.
  `make openshell-saw-status` shows whether that matches the cluster. A
  failed install or apply is recorded there too (`lastFailedHash`); the
  next reconcile does not retry the exact same failing input for 5 minutes
  (`SAW_RECONCILE_BACKOFF`), so a component that is briefly unreachable
  does not get hammered every ~60s while holding `/run/saw/lock`. A further
  input change is always retried immediately, backoff or not.

Spike on OpenShift 4.22 (virtiofs is part of the API; no extra feature gate):
a ConfigMap attached to a Fedora 44 VM was visible in the guest, a content
change and a new key appeared together in about 37 seconds, and writing to
the mount was denied. The kernel reports the mount `rw`, and the files are
labeled `virtiofs_t`. SELinux has no xattr handler for virtiofs and falls
back to genfs; reads still succeed. Live migration of that VM was refused
because the root disk is ReadWriteOnce. The refusal did not mention
virtiofs. Migration was not retested with a shared disk.

These still need a restart: VM size, disks, and anything cloud-init writes
(the reconcile units included). Turning `vm.liveInputs` on does not edit an
existing VM's cloud-init. Recreate the VM after the value is true. With
live inputs, a change to the installer ConfigMap or a provider Secret does
not set `RestartRequired`. The cloud-init checksum still does. Adding or
removing an entry in `additionalProviderSecrets` (or the `inference`
Secret's name) also needs a restart even with `vm.liveInputs: true`: it
changes the VM template's `filesystems`/`disks` list itself, which KubeVirt
always treats as a restart, independent of any checksum annotation.
`saw-reconcile` does not re-run `saw-mount-inputs`: a content-only virtiofs
change is visible under the existing mount without remounting anything, so
that is by design, not a gap.

Whether the guest's `saw-inputs.path` unit (inotify) actually fires for a
host-side virtiofs write, versus the 60-second `saw-inputs.timer` doing all
the work, was not conclusively settled by the spike above; treat the timer
as the mechanism that is guaranteed to run within about a minute, and the
path unit as a possible, unconfirmed latency improvement on top of that.

## Removing things from a profile

`prune.mode` is `off`, `report`, or `on`. The default is `report`: the
installer logs `would delete ...` and deletes nothing. `on` deletes. Even
then, `prune.sandboxes` defaults to `false`, so sandboxes stay until that is
set to `true`. This is per VM. It is not `pruneOnRemove`, which only decides
whether removing a user from `overrides/saw-users.yaml` also deletes that
user's VM.

The installer records objects it creates in `/var/lib/saw/user/managed.json`
(that directory is owned by the runtime user; `/var/lib/saw` stays root-owned).
Only those objects can be removed. A workspace, provider, or sandbox created
by hand is never deleted. The first successful apply adopts whatever already
matches the current profiles and does not delete anything. Deletion order is
sandboxes, providers, provider profiles the installer imported, then
workspaces. The `default` workspace is never deleted. (An inference route a
0.0.x apply recorded is dropped from the ledger when it is loaded, in every
prune mode: OpenShell 0.1.x removed routes.) A workspace is deleted only when it is
empty afterwards; otherwise it is kept and the log names what is left in it.

Workspaces and sandboxes are labeled `saw.redhat.com/managed=true` (OpenShell
accepts labels on those two kinds, and on no other kind this installer
creates). Providers and imported provider profiles are
identified by the ledger alone. A missing or empty profile ConfigMap fails
the apply and deletes nothing.

Spike on the gateway CLI: `workspace delete`, `sandbox delete`, `provider
delete`, and `provider profile delete` exist. `workspace create` and
`sandbox create` take `--label`. `provider create` does not.

## Not in Stage 1

- Reporting status to the cluster beyond the optional readiness probe
  (`vm.readinessProbe: true`, needs guest-agent exec).
- Docker as the VM container runtime.
- Moving an existing pattern install's Keycloak from `openshell-agents` to
  `saw-keycloak`: the new instance starts with a fresh database (realm, test
  users and clients come from the chart; other data is not migrated).
- Migrating VMs created by the old SSH-based chart in place: cloud-init has
  already run on them, so the installer units are never written. Recreate
  the VM (delete the VM and its `-root` DataVolume) after upgrading the chart.

## Custom inference

A self-hosted OpenAI-compatible endpoint (vLLM, Ollama, ...) is an `openai`
provider with `OPENAI_BASE_URL`, and OpenClaw calls that endpoint directly
(OpenShell 0.1.x has no inference routes). Select the `custom-inference` SAW-BOM
profile and put `provider: openai`, `model`, `url` and `api_key` in the
`inference` Secret; see [Custom inference](custom-inference.md).

## Moving to a new OpenShell release series (0.0.x -> 0.1.x)

OpenShell 0.1.0 cannot upgrade 0.0.x state in place. When `install` replaces
the gateway with one from a different release series (compared on
major.minor), it first records the pending reset in `installed.json` (so a
run that dies half way still resets on the retry), then:

1. stops `openshell-gateway.service`;
2. removes every OpenShell sandbox container (`label=openshell.ai/sandbox-name`);
3. moves `~/.local/state/openshell/gateway` (the SQLite database) aside to
   `gateway.<old version>.<epoch>`.

The gateway then starts empty and `apply` recreates workspaces, providers and
sandboxes from the SAW-BOM. TLS material (`~/.local/state/openshell/tls`) is
kept. **Data in `/sandbox` does not carry over:** each sandbox's `/sandbox` is
the podman volume `openshell-sandbox-<sandbox id>-workspace`, and recreated
sandboxes get new ids and new, empty volumes. The old volumes are kept and the
install log lists them, so data can be copied over by hand. Everything that talks to the gateway must be the
same release: users need the 0.1.x `openshell` CLI, and the governance
interceptor image must be built from the same tag
(`image-builder-charts/helm/governance-interceptor-image`).

0.1.x also changes what the chart writes: `gateway.toml` is schema version 2
(`[openshell] version = 2`, `compute_driver`, driver settings under
`[openshell.drivers.podman]`), `OPENSHELL_DRIVERS` became
`OPENSHELL_COMPUTE_DRIVER`, the BOM gains `spec.openshell.sandbox` (the
sandbox runtime image, image only), provider profiles must list `binaries`,
and agents call their provider's own endpoint instead of
`https://inference.local`.
