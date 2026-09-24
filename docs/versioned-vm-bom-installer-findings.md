# Versioned VM BOM installer: implementation review findings

Latest simplification: apply_bom.py is the single release implementation. A versioned InstallerBOM selects component versions; .116 is only an example. The separate OpenShell adapter, gRPC implementation and vendored APIs have been removed. The guest only handles mounted inputs, process execution/progress and readiness; deployment/verification belongs in the script. See the current design/status for incomplete runtime work.

Current architecture decision: start without a custom Kubernetes controller. Argo CD owns namespace/image/VM/config resources, ESO owns provider Secret contents, and a guest-local service reads live virtiofs inputs and reconciles the runtime. The [reference design](versioned-vm-bom-installer.md) and [implementation status](saw-blueprint-implementation.md) supersede earlier controller/publication proposals. The historical findings below remain useful evidence, not the current implementation specification.

Reviewed on 2026-09-18 against repository commit `f7046f4` and the local proposal [Versioned VM BOM installer for OpenShell SAW](jira/versioned-vm-bom-installer.md). At review time the proposal was under `docs/jira/`, not the requested `docs/versioned-vm-bom-installer.md` path.

Follow-up: the author clarified that the original document and schema were illustrative, then added reusable Astra template and automatic ConfigMap-driven sandbox update requirements. The [Astra blueprint and continuous configuration design](versioned-vm-bom-installer.md) makes the implementation decisions and supersedes this review's architectural recommendations, including installer downloads and the suggested initial disk/restart-only transport. Live delivery and data-preserving sandbox image updates are required by that design. Schema differences below remain compatibility observations, not requirements to preserve the original example.

The current implementation may be refactored or replaced; its scripts, schema and packaging do not constrain the new architecture. Preserve tenant data and explicit supported migration contracts, not legacy bugs or implicit behavior. The companion [test and CI plan](versioned-vm-bom-installer-testing.md) defines the executable coverage and release gates required for implementation.

Authoring clarification: retain SAW-BOM profiles as the first-class workload definition. Instance `spec.workspaces` is an array of profile references, not inline workspace/provider/sandbox definitions. The reference design specifies profile expansion, guest observation of mounted ConfigMap changes, shared-profile update behavior and conflict validation; the old executable profile runner is still replaced.

Tenant follow-up: the sibling `forge-saw` implements namespace separation and shared-image import/cloning, not per-user ESO/Vault isolation. The reference design now requires an isolated namespace per user/SAW, scoped Vault authentication and provider Secrets, profile credential bindings, and shared release-specific golden sources in `saw-images`. These supersede any assumption below that the existing common namespace/shared credential store should remain the deployment boundary.

Reference inspection: `../forge-saw/Makefile-Forge` delegates image setup to `Makefile-Forge-internal` and `scripts/import-golden-image.sh`; its VM chart uses a cross-namespace DataSource, and workspace/platform charts grant source access. Its `scripts/forge_config.py` renders a shared Vault prefix/store, while `scripts/configure-vault-store.py` can use a shared token. Neither establishes per-user Vault authorization. Do not copy the broad source-namespace `cdi.kubevirt.io:edit` grant or all-service-account reader binding into the new tenant design. Reuse the import/clone architecture with explicit enrollment identities, not those permissions unchanged.

## Assessment

The proposed separation between a versioned software manifest, a guest installer, and cluster-side configuration is appropriate. However, the proposal is not yet an implementation-ready specification for a VM that initializes itself from external configuration. Its largest omissions are the actual configuration transport, installer bootstrap, startup ordering, and update semantics. Wrapping today's setup scripts in a systemd service would retain several correctness problems.

The first deliverable should prove that a fresh VM reaches verified application readiness using attached configuration and credentials, without a setup Job logging into the guest. Ongoing updates must have an explicit contract: either applying a new revision on VMI restart, or consuming live updates through a supported transport and a guest reconciliation trigger. These are separate capabilities.

Findings marked **P0** block the first autonomous provisioning path. **P1** findings must be addressed before claiming the proposal's reproducibility, convergence, or upgrade guarantees. Recommendations below are proposed implementation decisions, not existing functionality. This is a source and documentation review; no cluster or VM behavior was tested.

## Current responsibilities and their destination

| Responsibility | Current implementation | Proposed owner |
| --- | --- | --- |
| Import golden image, create DataSource, handle missing root DataVolume | [bootstrap-golden-image.sh](../charts/openshell-saw/files/bootstrap-golden-image.sh) | Cluster provisioning component or declarative CDI resources |
| Materialize cloud-init Secret and inject public SSH key | [wait-for-vm.sh](../charts/openshell-saw/files/wait-for-vm.sh) | Chart or cluster provisioning component, before guest startup |
| Configure gateway identity, OIDC, governance, TLS SANs | [cloudinit-sandbox.yaml](../charts/openshell-saw/templates/cloudinit-sandbox.yaml), [upgrade-openshell.sh](../charts/openshell-saw/files/upgrade-openshell.sh) | Guest installer consuming external instance configuration |
| Install gateway, supervisor, CLI and registry CA | [upgrade-openshell.sh](../charts/openshell-saw/files/upgrade-openshell.sh) | Guest installer, with verified artifacts and explicit failures |
| Establish user systemd manager and gateway service | [golden-image BuildConfig](../image-builder-charts/helm/openshell-gateway-image/templates/buildconfig.yaml) | Base-image bootstrap coordinated with guest installer |
| Deliver profiles and credentials | [setup-bom-profiles.sh](../charts/openshell-saw/files/setup-bom-profiles.sh) | ConfigMap/Secret attachments plus guest parser |
| Create workspaces, providers and sandboxes; onboard agents | [apply_bom.py](../installer/apply_bom.py) | Versioned guest software, after correcting retry/update behavior |
| Discover Routes and register Keycloak redirect URIs | [setup-keycloak-redirect.sh](../charts/openshell-saw/files/setup-keycloak-redirect.sh) | Cluster component; Keycloak administrator credentials stay there |
| Run dashboard and OAuth proxy | [setup-dashboard.sh](../charts/openshell-saw/files/setup-dashboard.sh) | Guest installer with instance configuration and stable cookie Secret |
| Report provisioning progress | Setup Job logs and [CLI log command](../cli/src/openshell_saw/cli.py) | Guest status/report plus a cluster-visible readiness and diagnostics path |

## Findings

### F01 — P0: Specify the configuration transport and update trigger

**Evidence.** The proposal's “GitOps + VM Startup Execution Model” says the manifest is injected at bootstrap and Git changes trigger rollout/recreation, but provides no volume definition, mount contract, or rollout implementation. [virtualmachine.yaml](../charts/openshell-saw/templates/virtualmachine.yaml) currently attaches only root and cloud-init disks. The profiles ConfigMap is consumed by the Job, not the VM.

KubeVirt distinguishes ConfigMap/Secret ISO disks, whose changes do not propagate into a running VMI, from virtiofs filesystem attachments, which support propagation. Both require guest mounts. Do not apply the disk limitation to virtiofs or assume pod projection behavior for a disk. See the [KubeVirt volume documentation](https://kubevirt.io/user-guide/storage/disks_and_volumes/#configmap).

**Required resolution.** Define the supported OpenShift Virtualization/KubeVirt versions and choose a transport after checking their capabilities. Recommended first increment: read-only ConfigMap and Secret disks, consumed on every guest boot, with an explicit VMI restart to adopt a new configuration revision. If updates without restart are required in this feature, validate virtiofs support and implement a timer or watcher plus atomic input snapshots in the same scope. A service enabled at boot alone does not observe later changes.

Specify resource references, device identity, persistent mount units, guest paths, missing-input behavior, and update latency. For disks, use stable serials/labels rather than `/dev/vdb` assumptions. For live delivery, prevent applying a mixture of old and new files by validating a complete revision before activation.

GitOps synchronization is not itself a VM restart controller. KubeVirt's default `Stage` rollout strategy stages changes; unsupported live changes can require restart. Name the component or operator workflow that restarts the VMI and observes completion. A checksum annotation alone is insufficient. See [VM rollout strategies](https://kubevirt.io/user-guide/user_workloads/vm_rollout_strategies/).

### F02 — P0: Remove the existing boot dependencies before disabling the setup Job

**Evidence.** The VM references `<vm>-cloudinit`, but [cloudinit-sandbox.yaml](../charts/openshell-saw/templates/cloudinit-sandbox.yaml) creates a template ConfigMap. [wait-for-vm.sh](../charts/openshell-saw/files/wait-for-vm.sh) creates the actual Secret. The Job also handles golden-image import and DataSource/root DataVolume creation. Deleting the Job without replacing these actions can prevent the VM from booting at all.

**Required resolution.** Render cloud-init directly or retain a cluster preparer that produces the Secret without guest access. Establish explicit prerequisite readiness for the image source, configuration, credentials, Routes and identity configuration. Preserve all three supported VM disk sources: DataSource, registry and HTTP. The image import path must not depend on a service inside the VM whose root disk it is provisioning.

Use separate completion states for “cluster inputs prepared” and “guest installed.” The preparer must not wait for guest readiness before publishing the inputs the guest needs. Amend the proposal's chart exclusion: replacing charts can remain out of scope, but modifying the VM, cloud-init, input resources and setup mode is required by acceptance criterion 7.

### F03 — P0: Define who verifies and launches the installer itself

**Evidence.** “Installer Packaging” pins a tarball, while the startup section says cloud-init writes the entire installer payload. Neither explains which trusted component reads the manifest, fetches the tarball and verifies it before execution. The current [BOM ConfigMap](../charts/saw-bom/templates/configmap-bom.yaml) also embeds executable `apply_bom.py` alongside configuration.

**Required resolution.** Choose one bootstrap model. Recommended: bake a small, versioned bootstrap launcher and its parser/CA prerequisites into the golden image; mount declarative inputs; have the launcher verify and activate a versioned installer bundle. Include `apply_bom.py` and its dependencies in that bundle. Keep per-VM configuration separate from executable payloads.

Document the bootstrap/manifest compatibility range, authenticated artifact access, trusted manifest provenance, and behavior when an artifact is unavailable. A checksum supplied by the same untrusted author as the executable is not an independent authenticity boundary. Restrict release-manifest authorship accordingly. Reject archive path traversal and escaping symlinks, extract into a staging directory, verify before activation, and retain the previous verified bundle. The unpacked bundle's own `checksums.txt` cannot replace verification of the downloaded tarball.

### F04 — P0: The systemd example has permission and sequencing failures

**Evidence.** The proposed service runs as `cloud-user`, including `ExecStartPre=mkdir -p /var/lib/saw-bom /var/log`. On a fresh image that user cannot create `/var/lib/saw-bom`, write the proposed report files under `/var/log`, install system packages, or replace `/usr/local/bin` binaries without explicit privilege handling. `User=` determines service process identity; see the [systemd execution reference](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml).

The gateway is a **user** service. The existing [image setup script](../image-builder-charts/helm/openshell-gateway-image/templates/buildconfig.yaml) starts `user@<uid>.service` and supplies `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS`. The proposed unit supplies neither user-bus context nor a path to a user-installed CLI under `~/.local/bin`. Its `Requires=podman.service` also does not match the default Docker image or the existing rootless Podman socket setup.

**Required resolution.** Use a privileged system installation phase for mounts, directories, trust and binaries, then explicitly run gateway/workspace operations as the configured user with the correct home, executable path and user bus. Preserve lingering and ownership. Select runtime-specific dependencies and wait for actual gateway API readiness.

Order startup after input mounts and required initialization. `ConditionPathExists` skips a start when the file is absent; it does not wait for file creation or arrange a later retry. See [systemd unit conditions](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml). Missing required input must eventually produce an actionable failure. Bound retries and distinguish transient failures from invalid configuration; `StartLimitIntervalSec=0` with unconditional retries otherwise repeats permanent failures indefinitely.

Coordinate with `openshell-gateway-setup.service` and `/var/lib/openshell-gateway-setup.done`; do not leave two services racing to write gateway configuration. If ordering after `cloud-final.service`, avoid synchronously starting and waiting for the installer from cloud-init itself. Install/enable the unit and queue startup without introducing that dependency cycle.

### F05 — P1: The manifest sample is inconsistent with the supported runtime and versions

**Evidence from the legacy path.** The proposal selects Podman while requiring NemoClaw, lists `podman-ce`/`podman-ce-cli` alongside `containerd.io`, and mixes OpenShell CLI `0.0.97+rhaiv.0` with gateway/supervisor `v0.0.103`. The legacy [setup entrypoint](../charts/openshell-saw/files/run-setup.sh) rejects Podman with NemoClaw onboarding. The legacy mode of [apply_bom.py](../installer/apply_bom.py) has Docker-specific pulls, extraction, container inspection and execution even outside that chart-level check. The new mounted installer path is separate and requires rootless Podman.

The [image builder](../image-builder-charts/helm/openshell-gateway-image/templates/buildconfig.yaml) installs Docker CE packages for Docker or uses Fedora's Podman path; it does not implement the proposed package list. Its real image construction is inline in the BuildConfig, not in the adjacent two-line Dockerfile.

**Superseded recommendation.** The initial review suggested Docker to match legacy NemoClaw defaults. The selected design instead requires rootless Podman; it does not carry legacy onboarding into the mounted installer. Qualify each supported sandbox/onboarding combination before enabling it, and define the actual OS release, architecture, runtime version, Python/PyYAML and workload-specific prerequisites. Sandbox lifecycle remains blocked until implemented and tested.

Publish a tested component compatibility tuple. The current [upgrade script](../charts/openshell-saw/files/upgrade-openshell.sh) wraps `openshell --version` to resemble the native binary version. Do not treat that wrapper as evidence of installed-version equality. Report actual package/build identities; permit documented version-format normalization only when the underlying versions match.

### F06 — P1: Tags and package versions do not completely pin a release

**Evidence.** The proposal uses tagged OCI images, an unhashed pip package and an unspecified tree-hash algorithm. `denyLatestTags` does not prevent mutation of another tag or resolve an image with no explicit tag. Existing profiles and the dashboard use `latest`; the golden-image path can also resolve `latest`.

**Required resolution.** Pin OCI artifacts by digest, lock Python wheels and dependencies with hashes, and define reproducible verification for extracted trees (or hash a canonical packaged archive). Include the base VM image identity and OS/runtime dependency contract. Include every enabled sandbox, dashboard and proxy artifact, not just the top-level OpenShell images. Resolve aliases such as `base` to recorded immutable artifacts or explicitly exclude them from reproducibility claims.

Separate the reusable release manifest from per-instance configuration: the release selects compatible software; the instance selects workspace files, endpoints, policy configuration and Secret references. Produce one resolved installation record combining both. Avoid introducing a second independent source of versions alongside Helm values and profile images; define precedence and reject conflicting pins.

### F07 — P0: Define the complete credential and identity contract

**Evidence.** [setup-bom-profiles.sh](../charts/openshell-saw/files/setup-bom-profiles.sh) reads declared `credentialSecret`/`credentialSecretKey`, then converts credentials into `PROV_<NAME>_KEY` environment variables and copies a shell-sourced `bom.env` into the guest. Secrets must also be listed in the Job's mounts. OIDC bootstrap relies on a supplied token or a password grant using the owner name as both username and password. Dashboard setup separately needs Keycloak administrative access.

**Required resolution.** Define a file-based Secret resolver keyed by workspace/provider identity and declared Secret name/key. Validate every enabled provider reference before mutation, preserve provider-type mismatch checks, and avoid `source`/`eval` on credential values. Provider names alone are insufficient: two workspaces can use the same provider name with different credentials, and environment-name normalization can collide.

Keep provider keys, registry credentials, OIDC credentials and dashboard cookie material out of ConfigMaps, Git, reports and command logging. Constrain guest mount and copied-file permissions. Keep the bootstrap report free of reusable secrets and do not publish hashes of secret contents; track opaque credential revisions instead. Separate bootstrap authentication from renewable operational authentication, including who grants initial workspace access. Do not carry the demonstration username/password fallback into unattended provisioning.

Keycloak admin credentials and Kubernetes credentials should remain in the cluster component. Supply only the guest's own credentials, resolved endpoints and trust material. Define renewal and rotation behavior explicitly, including a VMI restart requirement if disk delivery is selected. The dashboard cookie secret must survive retries instead of being regenerated on every setup run.

### F08 — P1: Hashing only manifest.yaml cannot implement convergence

**Evidence.** The manifest references workspace, provider and sandbox files outside itself. Those bytes, attached secrets, route hosts or policy inputs can change while its hash stays constant. An unchanged hash also does not prove that an installed binary or runtime resource still matches desired state.

**Required resolution.** Replace `last-applied-sha` as the sole decision with a resolved input revision covering the manifest, referenced file contents, installer identity, instance settings and opaque credential revisions. Canonicalize inputs, validate complete snapshots and take a single-install lock. Write successful state atomically only after all required verification passes; retain a separate failed-attempt report.

Define no-op as “desired revision already applied and required observed state still valid.” Detect missing/changed resources even when inputs are unchanged. For the first increment, explicitly define supported updates and return `replacement_required` for incompatible changes; do not silently skip them. Specify deletion/disable behavior and ownership so reconciliation never removes unmanaged resources. Resume safely after interruption without repeating destructive onboarding.

### F09 — P1: The current BOM runner needs changes before reuse

**Evidence in the legacy mode of [apply_bom.py](../installer/apply_bom.py):**

- `Shell.run` accepts `check` but does not enforce it; many failures are logged and ignored. Text containing `already exists` is treated as success without comparing configuration.
- `create_sandbox_generic` skips existing non-error sandboxes, ignoring desired changes, and deletes/recreates an Error-state sandbox without an explicit replacement policy.
- `install_nemoclaw_cli` skips installation whenever `which nemoclaw` succeeds, regardless of version.
- `configure_oidc` creates directories and writes token files even during `--dry-run`; those writes bypass `Shell.run`.
- Missing profiles return successfully, missing credentials can trigger `--from-existing`, and type mismatch skips provider creation rather than aborting the whole preflight.
- Inference setup selects the first enabled provider with a model in each workspace and also overwrites the system inference route for each such workspace. Multiple workspaces can therefore compete for the global default.

The final verifier **does** exit nonzero when its checks fail; that behavior already exists and should be retained. However, resource existence and text matching cannot establish all requested fields, runtime health or credential correctness. Existing resources can mask failed updates.

**Required resolution.** Reuse parsing/model knowledge, but implement explicit plan/apply/verify operations, structured command results, meaningful resource comparisons, controlled replacement and end-to-end failure propagation. Dry-run must perform no host or remote mutation, including token/report/state writes, image pulls and restarts. The existing [unit tests](../charts/saw-bom/scripts/test_apply_bom.py) cover parsing and credential/provider selection, not these installer guarantees.

### F10 — P1: Align the new schema with the live parser instead of stale setup assumptions

**Evidence.** The proposal's follow-up references `setup-workspaces.sh`; the current path is `apply_bom.py`. Its schema assumptions differ from today's behavior:

| Proposed assumption | Current behavior / needed decision |
| --- | --- |
| Prefix provider names outside the default workspace | Provider names remain unchanged; commands use `--workspace`. Preserve workspace scoping unless a migration explicitly changes identity. |
| First provider sets inference | First enabled provider **with a model** sets workspace inference; each workspace also sets the system route. Define one explicit global default. |
| Sandbox name defaults from workspace | Parser requires each sandbox's `name`; omitted names fail. |
| Sandbox image falls back to a global image | Parser defaults to an empty image; creation omits `--from`. No manifest-global fallback is implemented there. |
| Flat workspace file references | Parser discovers `<profile>/<workspace>/{workspace,providers,sandbox}.yaml`; the ConfigMap flattens names with `__`. Define an adapter or change the parser. |
| Assert `nemoclaw-sandbox` always exists | Current enabled default sandbox is `notebook`; generate assertions from enabled desired resources. |
| Example Gemini mapping is universally applicable | Current profiles/resolver distinguish `gemini` and `google-vertex-ai`. Validate supported provider types and credential semantics against the selected release. |

**Required resolution.** Publish machine-validatable schemas with required fields, supported versions, enumerations, duplicate/reference validation and rejection of unknown fields. Enforce safe relative file paths and bound file sizes. Define precedence or mutual exclusion between `multi_workspace_bom`, `providerConfig` and `bootstrapSandboxConfig`; otherwise two paths can provision the same resource differently. Treat these YAML kinds as file formats unless CRDs/controllers are deliberately added.

Keep release-authored install paths and any executable verification commands separate from tenant-editable configuration. Prefer built-in typed assertions to arbitrary shell command strings. Explicitly reject unsupported `policy.yaml` rather than implying it is enforced.

### F11 — P0: Preserve gateway, governance and dashboard behavior in external config

**Evidence.** The manifest sample omits several currently active inputs: OIDC issuer/audience and owner grants, governance interceptor settings and bindings, gateway bind address, Route certificate SANs, runtime bridge endpoint/socket, registry CA, dashboard/proxy images and cookie configuration. Moving only `apply_bom.py` into startup does not replace these setup phases.

**Required resolution.** Define a versioned instance-config schema for these settings and their defaults. Retain governance failure policy and verify the configured interceptor path before required sandbox creation. Supply registry trust and pull credentials before artifact/image pulls; avoid making successful startup depend on enabling anonymous registry pulls. Preserve gateway TLS identity across normal restarts and generate separate identity for a fresh clone.

The cluster preparer should resolve Routes and register Keycloak redirects; guest services consume the results. Include dashboard and agent onboarding postconditions when enabled, and report disabled components as skipped. A successful gateway process alone is not full SAW provisioning success.

### F12 — P1: Specify observable readiness, upgrades and recovery

**Evidence.** The proposal stores reports only inside the VM, while [the CLI](../cli/src/openshell_saw/cli.py) follows `job/<name>-setup`. Its rollback plan is deferred even though safer rollback is a stated benefit. Existing [Helm deletion cleanup](../charts/openshell-saw/templates/hook-pre-delete.yaml) deletes the VM and matching PVCs; uninstall/reinstall is therefore not a safe general upgrade mechanism.

**Required resolution.** Define a guest readiness/status endpoint or equivalent guest-to-cluster reporting path that does not need SSH. Include desired/applied revision, real artifact identities, current phase, attempt, timestamps, verification results, failure category and retry guidance. Integrate CLI progress and GitOps health with installation readiness; VMI Running, a listening port, or systemd `active (exited)` is insufficient. Ensure permanent errors remain visible even when the guest booted normally.

Distinguish guest reboot, VMI restart retaining the root PVC, and replacement with a new root disk. Cloud-init tracks first-instance versus subsequent boots; changed user-data must not be assumed to rerun all per-instance work on a retained disk. See [cloud-init first-boot behavior](https://docs.cloud-init.io/en/latest/explanation/first_boot.html). Have the persistent guest service reread attached inputs on each boot.

Stage and verify the complete component set before activation, record phase completion, and retain the last known-good artifacts/configuration. Define compatible upgrades and reject unsupported downgrades. Binary rollback is insufficient if gateway databases or sandbox data were migrated. Document backup/restore boundaries for gateway state, workspaces, persistent sandbox data, TLS identity and installer state. Never advance the successful revision after partial failure.

## Recommended implementation sequence

1. **Freeze contracts and a valid release fixture.** Resolve F01/F05/F10; define release versus instance configuration, Secret mapping, supported runtime/image, transport and update policy. Replace placeholder checksums and contradictory sample versions with a tested fixture.
2. **Prove autonomous boot.** Update the image BuildConfig with bootstrap prerequisites; add guest configuration/Secret mounts and persistent startup units; produce cloud-init without SSH. Retain the cluster preparer for image/input/identity work. Demonstrate a fresh VM installs with no provisioning SSH key.
3. **Implement verified installation.** Package the installer and BOM runtime, validate before mutation, install under explicit privileges, configure the user service, propagate failures and emit status. Correct the runner issues in F09 before treating retries as safe.
4. **Restore full feature parity.** Move gateway, governance, credentials and dashboard guest work into the installer; update CLI logs/readiness and deployment documentation. Select exactly one guest configuration owner per VM through an explicit setup mode during migration.
5. **Implement revision changes and recovery.** Add complete input revision tracking, safe updates, rotation, drift checks, failure recovery and the selected restart/live-update workflow. Retire provisioning SSH/SCP helpers and their port-forward/SSH-key RBAC dependencies after this path passes acceptance tests. Keep optional operator SSH access independent of provisioning.

## Acceptance tests to add before declaring the feature complete

| Scenario | Required result |
| --- | --- |
| Fresh supported image; provisioning SSH unavailable | Cluster inputs are prepared and the VM reaches verified gateway/workspace/provider/sandbox readiness without SSH/SCP, `virtctl ssh`, or remote guest execution. |
| Missing cloud-init input, ConfigMap, Secret/key or image source | Bounded, visible prerequisite failure; no false installation success or partial successful revision. |
| Disk-source variants | DataSource, registry and HTTP provisioning preserve their supported behavior. |
| Invalid schema, unsupported runtime/version, unsafe path, bad checksum | Failure before installation mutation; required artifacts never execute before verification. |
| Same successful revision applied twice and after reboot | No duplicate resources, repeated destructive onboarding, identity rotation or unnecessary service restart; health still verified. |
| Workspace file changes with unchanged manifest | Resolved revision changes and the supported update is applied, or an explicit replacement requirement is reported. |
| Credential rotation, including same provider name in two workspaces | Correct workspace receives its new credential through the declared delivery/restart mechanism; no cross-workspace collision or plaintext leakage. |
| ConfigMap/Secret update on running VMI | Disk mode reports pending revision until explicit VMI restart; live mode proves propagation and eventual application within a stated bound. |
| Dry-run with an OIDC token and existing resources | No files, images, services, credentials or remote resources are modified. |
| Existing resource differs or is in Error state | Installer compares desired state and follows documented update/replacement policy without implicit data deletion. |
| Two concurrent runs or interruption during activation | Single writer; coherent artifacts/configuration; failed attempt recorded; safe retry; previous successful revision retained. |
| Governance denial, expired bootstrap identity or gateway API failure | Required phase fails visibly; existence of older resources cannot mask failure. |
| Enabled dashboard and multiple workspaces | OIDC redirect, TLS trust and dashboard work; provider attachment and explicit inference defaults match desired state. |
| Upgrade on retained PVC; incompatible downgrade | Persistent state/identity preserved; supported upgrade verified; incompatible transition rejected with recovery instructions. |
| Report and CLI/GitOps integration | Operator can distinguish prepared, installing, ready, failed and restart-required without guest login; reports contain no secrets. |

Validate rendered Helm resources and cloud-init before VM tests. Run `systemd-analyze verify` and startup tests in the supported guest OS, where referenced executables and runtime units exist. Extend the existing Python tests for plan/apply behavior, then run integration tests on the declared OpenShift Virtualization version; source inspection alone cannot establish transport propagation or restart behavior.
