# Astra SAW guest installer: test and CI plan

Status: the guest foundation, workspace/provider application in apply_bom.py and
clean image builder are implemented. Sandbox lifecycle and full platform/release
qualification are not complete. See the dated evidence in
[implementation status](saw-blueprint-implementation.md). This plan
follows the [no-controller reference design](versioned-vm-bom-installer.md).

Argo CD owns cluster resources; ESO owns provider Secret contents; the guest owns
application reconciliation. No custom Kubernetes publisher, controller image,
watch/CAS service, or controller admission policy is required. Existing KubeVirt,
CDI, Argo CD and ESO controllers retain their normal responsibilities.

## 1. Implemented gates and their limits

The current executable suites are in [tests/saw](../tests/saw/) and include:

| Gate | Implemented assertions | Not established by this gate |
| --- | --- | --- |
| Blueprint and profile contracts | Strict YAML/schema validation, owner-derived namespace identity, safe Vault paths, profile references and credential bindings, immutable image references, retained sandbox data | Actual authorization by Vault, OpenShell or Kubernetes |
| GitOps rendering | Public intent/profile ConfigMaps, namespace-local ESO resources, scoped source clone permission, retained standalone root DataVolume, optional guest VM and least-privileged launcher ServiceAccount | Successful CDI cloning, network isolation or Argo synchronization on the installed platform |
| Guest inputs | Mount allowlists, path isolation, projection symlink handling, bounded reads, duplicate/malformed input rejection, two-pass stable capture, no environment credential fallback | Atomic transactions across separate ConfigMaps/Secrets, or freshness of the upstream Vault value |
| Guest planning | Create/update actions, credential rotation only on byte changes, immutable data declarations, rejection of implicit resource removal and shared data ownership | Actual sandbox replacement, provider update or retained runtime data |
| Guest journal | Private durable state, exclusive lock, restart reuse of transaction ID, drift verification, pending-input mismatch blocks replay, failed verification never commits | Runtime rollback or recovery from every partially completed container/storage operation |
| Mounted profile CLI contracts | Workspace creation/ownership, exact membership and revocation, namespace-local provider binding, secret-safe CLI argv/environment, credential rotation, pagination, failure/retry, journal-driven drift repair, private mTLS files and process-group timeout cleanup | Real CLI/gateway compatibility, provider authentication, concurrent external administrators, inference or retained sandbox lifecycle |
| Local Podman bootstrap | Real filesystem staging/publication and TLS parsing with synthetic PEMs; simulated cert-generator/systemd commands; identity preservation, partial failure recovery, clone/foreign-state rejection, service hash/drop-in checks, startup guard, loopback/mTLS configuration and BOM-selected supervisor image | Real gateway PKI generation, Podman API and bridge authorization, SELinux behavior, OIDC, certificate renewal, sealed-VM boot |
| Guest readiness/security | Convergence-only expiring readiness, private credential snapshots, safe status fields, trusted fixed installer path, bounded subprocess timeout and credential transport over stdin | Guest SELinux/socket permissions or the release-specific apply_bom.py implementation's complete security properties |
| Source packaging | Deterministic archive metadata/content, fixed file allowlist, exact requested OpenShell tag set, refusal to overwrite output | A bootable, sealed, signed, vulnerability-qualified or runtime-compatible VM image |

The guest state-machine tests use a synthetic installer. The actual apply_bom.py
has release validation, private-input/result, version-selection and CLI-contract
tests using a simulated gateway. A combined test drives its actual reconciliation
logic through the guest journal for first apply, unchanged verification, drift
repair and credential rotation. Explicit workspace inference has apply/readback
and malformed-result tests. Enabled sandbox profiles still fail preflight
before any partial deployment. The legacy --profiles-dir command is preserved.
No API descriptor/compiler tests or separate OpenShell adapter remain. These tests
are not live deployment coverage. The existing saw-validate workflow automatically
runs these tests on Python 3.12/3.14; no new controller build/publish CI is needed.
The source bundle now contains 18 files including the gateway service, its
manifest hash and the fixed public error-code vocabulary. CI installs distribution
Podman packages, validates systemd unit syntax and runs an opt-in, root-only test
of the actual service mount namespace on its disposable Linux runner. This checks
hidden homes and read-only runtime visibility without starting a container.
Offline rootless tests simulate privilege dropping, subordinate IDs, user sockets,
engine rootless checks, private client directories and file ownership; they do
not by themselves certify live Podman support. Error tests reject arbitrary or
credential-like reason strings and keep raw subprocess output out of diagnostics.

The fast gate also runs the existing BOM parser tests. Existing CLI and OIDC
baseline failures are recorded in [implementation status](saw-blueprint-implementation.md);
the scoped gate does not claim the entire legacy repository passes.

Implemented commands:

```sh
make saw-test-fast SAW_PYTHON=/path/to/test-venv/bin/python
make saw-render-gitops SAW_PYTHON=/path/to/test-venv/bin/python
make saw-guest-bundle SAW_PYTHON=/path/to/test-venv/bin/python SAW_INSTALLER_BOM=examples/saw/installer-bom.yaml SAW_GUEST_BUNDLE=/new/path/saw-guest.tar.gz
make saw-image-context SAW_PYTHON=/path/to/test-venv/bin/python SAW_INSTALLER_BOM=examples/saw/installer-bom.yaml SAW_IMAGE_CONTEXT=/new/path/saw-image-context
```

The bundle pairs apply_bom.py, its hash and the selected InstallerBOM with guest
code. It contains no tenant inputs, extracted OpenShell payloads, bootable disk or
qualified image release. Image pins are not release qualification.
Test dependencies are pinned in requirements-saw-test.txt; the guest's dependency
file is separate.

The clean Fedora disk build consumes that bundle and digest-selected binaries;
its recipe, sealing checks and isolated BuildConfig are documented in
[image qualification](../guest/image/README.md). The boot-smoke renderer creates
only resources in saw-installer-validation, with a tokenless guest ServiceAccount,
namespace-local ingress and a credential-free workspace profile. CI checks those
inputs offline; a successful render is not evidence of a successful disk build,
guest boot, Argo reconciliation or Vault/ESO integration.

Additional implemented release tests: arbitrary component versions with no .116 gate;
installer/script version mismatch; rejection of mutable image refs, missing components,
commands, script URLs and inline credentials; duplicate keys; non-mutating validation;
safe refusal of unimplemented software upgrades and sandbox application. Inference
removal requires explicit decommissioning and legacy provider model settings fail.

Required next runtime gate: boot the selected software release with Podman and
the bundled units, let apply_bom.py initialize its fresh local mTLS identity,
apply a workspace/provider-only profile, reapply it,
rotate its ESO credential, revoke membership and verify actual gateway behavior.
Check masked credential metadata separately from external authentication; do not
claim credential validity from credential-key presence. Exercise an unlabeled
default workspace, conflicting provider type, unavailable gateway, process timeout
and restart. Test two clean clones get distinct PKI, copied retained state fails its
DMI/enrollment guard, unauthenticated clients are denied, and Podman's callback
listeners do not grant admin API access. Do not run integration tests against a
user's existing sandboxes.

## 2. Test environments and evidence boundaries

| Layer | Environment | Required evidence |
| --- | --- | --- |
| Static/unit/contracts | Unprivileged Linux runner, no cluster credentials | Pure validation, planner and journal faults, Helm resources, source archive reproducibility |
| Tenancy integration | Disposable Kubernetes, Vault KV v2 and ESO with synthetic credentials | Real authentication, policy denial, local Secret rotation and retained/stale Secret behavior |
| Image smoke | Isolated Linux/KVM runner with target kernel and SELinux enforcing | Payload execution, cloud-init/systemd, mounts, sealing, reboot and two independent clones |
| OpenShift VM E2E | Explicit protected test cluster with qualified KubeVirt/CDI/CNI/storage | Live virtiofs propagation, clone admission, VM probes, actual OpenShell APIs and durable replacement |
| Astra qualification | Test Astra environment using that exact candidate | One reusable blueprint/image, parameter-only instantiation, two-user isolation and later updates |

Unit fakes cannot qualify virtiofs, data retention, gateway authorization or Astra.
KVM alone cannot qualify OpenShift volumes/networking. Administrator-powered
positive tests do not establish tenant authorization; repeat access tests with
the actual Argo/enrollment, ESO and tenant identities.

## 3. Required coverage matrix

All cases below are release requirements, not assertions that they already have
executable coverage. Map each ID to tests and report pass, fail, blocked or
not-applicable with a reason. Required cases cannot pass by being skipped.
Current supported input fields are defined by the schemas; extending runtime
configuration requires matching schema, apply_bom.py behavior and tests before advertisement.

### A. Schema, profiles and planning

| ID | Cases and required assertions |
| --- | --- |
| A01 | Profile-reference arrays expand deterministically; reject inline graphs, unknown fields/API versions, duplicate keys/names/references, ambiguous workspace merges and missing selected documents. |
| A02 | Credential slots/bindings resolve only within the consuming namespace/workspace; reject ambiguous binding, missing key, unsupported shape and cross-namespace references. |
| A03 | Same provider name in different workspaces and multiple accounts of one provider never cross-bind credentials. |
| A04 | Owner placeholder resolves to enrolled immutable subject; reject owner replacement, namespace adoption, forged enrollment or malformed identifiers. |
| A05 | Reject traversal, escaping symlinks, unsafe flattened keys, oversized/empty files and alias/depth abuse; preserve supported credential bytes without shell interpretation. |
| A06 | Reject mutable workload image tags and invalid digests; additionally qualify signature/catalog/platform compatibility before production use. A syntactically valid digest is not approval. |
| A07 | Metadata-only changes and identical credential bytes cause no rollout; image/model/provider changes produce the correct scoped action. |
| A08 | Resource deletion/disable and data identity/mount/retention changes block until a separately authorized lifecycle operation exists; no implicit pruning or adoption. |
| A09 | Manual drift repairs only owned fields; unmanaged collisions and missing persistent data never cause destructive recreation. |
| A10 | Non-mutating validation reports unknown runtime state honestly; dry-run must not acquire tokens, write runtime state or create resources. |
| A11 | Same published profile works in separate namespaces with local bindings; selected shared-profile changes affect only intended consumers. |
| A12 | Guest software, mount topology and enrollment changes are lifecycle operations, not ordinary workload updates; reject unsupported migration before disruption. |

Add property-based tests for deterministic resolution, bounded resource counts,
credential isolation and retained-data invariants. Unchanged configuration may
still require runtime drift repair; unchanged healthy runtime must not mutate.

### B. Mounted delivery, journal and credentials

| ID | Cases and required assertions |
| --- | --- |
| B01 | ConfigMap and Secret changes propagate through actual virtiofs with unchanged VMI UID/devices; reopening paths sees new bytes. ISO disk delivery cannot satisfy this requirement. |
| B02 | Missing/malformed input, read error and projection swap preserve accepted state and report unready; never treat empty input as successful apply. |
| B03 | Two-pass capture detects files changing during read; demonstrate explicitly that separate-object updates are not an atomic transaction. |
| B04 | Versioned profiles are published before switching intent; one provider's coupled credential keys originate from one Vault record and one Secret. Cross-resource transactions are unsupported unless a future explicit revision protocol is added. |
| B05 | Credential-only rotation triggers provider update; ESO metadata-only refresh does not. New value reaches only the intended provider. |
| B06 | Crash before/after journal write, apply, verification and commit reuses the durable transaction ID and never falsely commits. Exercise fsync, disk-full and permission failures. |
| B07 | Changed inputs during a pending transaction block automatic replay, including replay of old/revoked credentials. Test authorized runtime recovery before implementing it; no silent journal reset. |
| B08 | Corrupt/public/symlinked journal, enrollment mismatch and competing guest processes fail closed. |
| B09 | Desired input changes during apply prevent aggregate acceptance; last accepted revision remains distinct from partial runtime progress. |
| B10 | Guest restart, projection delay and temporary API/runtime outage recover within measured bounds without an external setup command. |
| B11 | Synthetic secret canaries never appear in logs, public status, process arguments or CI artifacts; private journal/snapshots remain root-only and bounded. |
| B12 | ESO/Vault errors and remote deletion may leave a last Secret mounted: monitor ESO separately, test revocation at the provider, and never infer source freshness from readable bytes. |

There is no publisher ledger, leader election, cluster watch or controller token to
test. The remaining durable transaction is local to the VM. Recovery from a partial
runtime change requires the release-specific apply_bom.py implementation's observations and storage guarantees.

### C. Image build, artifact integrity and first boot

| ID | Cases and required assertions |
| --- | --- |
| C01 | Resolve the selected InstallerBOM component versions to approved platform digests; the .116 example is not mandatory. Test multiple release versions with unchanged guest code. Locked builds must not follow changed tags. |
| C02 | Inspect actual CLI/gateway/supervisor image payload layout, libraries, entrypoints and permissions; execute complete extracted payloads in the target guest. No guessed legacy paths or version-spoofing wrappers. |
| C03 | Real CLI/gateway/supervisor compatibility and each advertised OpenClaw/NemoClaw integration pass. Widening a version guard alone is not qualification. |
| C04 | Shared local/CI/BuildConfig builder consumes the same immutable inputs; failed downloads, corrupt caches or extraction errors cannot publish a release. |
| C05 | Deterministic guest source bundle contains only the allowlist; build-time dependencies are locked/verified. No pip/npm/dnf installation or downloaded scripts during tenant boot. |
| C06 | qcow2/OCI packaging, CDI import and Astra import boot the exact tested disk; record disk checksum, OCI digest and software inventory. |
| C07 | Seal machine identity, cloud-init state, SSH host keys where present, TLS/client keys, gateway state, caches and reconciliation journal. Two clones receive independent identities and never tenant credentials. |
| C08 | Unit ordering, cloud-final completion, nonblocking startup, virtiofs mount flags, service permissions and SELinux enforcing work on the target guest. Never disable enforcement to make smoke tests pass. |
| C09 | Reboot, missing mounts, failed mount helper, reconciler crash and stale readiness are observable; verify actual retry/recovery behavior, not just unit syntax. |
| C10 | Inventory tampering or unsupported guest release fails visibly; no silent runtime binary update. |
| C11 | SBOM, dependency/image vulnerability scans, signatures and provenance bind source and all payload digests; promotion uses exact tested content. |

Do not claim bit-identical qcow2 rebuilds from deterministic source archive tests.
Initially qualify immutable inputs and equivalent software inventory; normalize
disk metadata and test equality before claiming reproducible disk bytes.

### D. apply_bom.py and authorization

| ID | Cases and required assertions |
| --- | --- |
| D01 | Fixed root-owned apply_bom.py implements private input/revision matching, release validation, idempotent apply and runtime verification; unsupported releases/operations block before mutation. No separate API capability layer. |
| D02 | Fresh VM creates gateway/workspaces/providers/sandboxes with no setup Job, provisioning SSH key, port-forward or guest-exec permission. |
| D03 | Narrow machine identity bootstrap/renewal/expiry and correct issuer/audience/TLS validation; no human-password, shared-admin or TLS-bypass fallback. |
| D04 | User A and machine A cannot access gateway B; verify actual gateway grants, not only Kubernetes namespace isolation. |
| D05 | Workspace membership, provider credentials, inference and supported policies are observed through supported APIs after apply; existing resources cannot mask failures. |
| D06 | Timeouts, malformed responses, already-exists conflicts, failed verification and partial progress never count as convergence. |
| D07 | Root-owned apply_bom.py cannot be selected or replaced from profile fields; private stdin carries guest request credentials. No shell execution of declarative data or installer URL from a ConfigMap. |
| D08 | Registry authorization/CA rotation works without leaking platform import credentials to tenants; signed workload approval is enforced where advertised. |
| D09 | Governance failure, dashboard/OIDC/TLS changes and other advertised integrations follow explicit contracts with separate tests, not implicit legacy-script behavior. |
| D10 | Targeted least privilege: runtime identity, socket access, writable paths and SELinux policy are qualified; root guest service does not imply unrestricted tenant command execution. |

### E. Existing sandbox replacement and persistent data

| ID | Cases and required assertions |
| --- | --- |
| E01 | Change only one selected profile's sandbox image digest A to B; actual existing logical sandbox adopts B with unchanged VMI/root PVC and without manual apply. |
| E02 | Durable history/config sentinel bytes and data-volume identity survive replacement; provider/member/policy bindings remain correct. |
| E03 | Unrelated sandboxes and another VM retain their runtime generations, data and availability. |
| E04 | Invalid/unapproved image, failed pull, governance denial or disk-full during staging leaves old workload serving; no premature quiesce. |
| E05 | Drain timeout and incompatible data migration fail without unexpected kill, data deletion or two simultaneous writers. |
| E06 | Candidate health failure follows a qualified rollback/recovery policy; newest desired revision remains failed and destructive retry is latched. |
| E07 | Crash at stage, quiesce, detach, start, verify, commit and rollback preserves at most one writer and recoverable data. |
| E08 | Rapid A/B/C edits coalesce only at safe boundaries; changed pending input requires controlled recovery, not blind replay. |
| E09 | Same digest and healthy unchanged state cause no rollout; owned drift may require repair without changing durable data identity. |
| E10 | Disable/removal/rename/teardown requires explicit authorization and retention handling; present foundation rejects implicit removal. |
| E11 | Multi-sandbox partial failure never commits aggregate success; qualify rollout concurrency and max-unavailable behavior before exposing controls. |
| E12 | Legacy adoption includes inventory, backup, ownership and durable-data migration; reject unsafe automatic adoption. |

E01/E02/E03/E07 are mandatory. Creating a new unrelated sandbox, rejecting every
existing-image update, or changing an expected-image status string cannot pass.

### F. GitOps, Astra and operations

| ID | Cases and required assertions |
| --- | --- |
| F01 | One published Astra template creates two users' VMs from parameters and the same image digest; no repository fork or per-instance image rebuild. |
| F02 | Pattern install registers Argo-managed manifests; Argo remains the sole desired-state writer. No imperative workspace CLI fights self-heal. |
| F03 | Cold Argo dependency ordering, delayed ESO Secret/CDI clone and guest readiness cannot deadlock input creation. |
| F04 | Guest readiness is false before runtime verification, while blocked, and after status expires; test actual KubeVirt HTTP probe networking and resulting Argo health. |
| F05 | No liveness policy restarts the VM merely because newest desired configuration is invalid; last-good workloads/data stay intact where safe. |
| F06 | Mount topology, root image, CPU and enrollment changes use explicit lifecycle handling; cloud-init is not assumed to rerun on an existing disk. |
| F07 | Diagnostics are nonsecret and accessible under explicit authorization; current /readyz returns only HTTP status, not a public configuration or command API. |
| F08 | Node drain/migration/reboot match the qualified storage/virtiofs platform capabilities; unsupported combinations are rejected rather than silently advertised. |
| F09 | Measured observation/apply/rotation deadlines, outages and bounded retries distinguish failure from success without deleting retained PVCs. |
| F10 | Cancellation and cleanup use exact per-run resource ownership/UIDs; never broad namespace-prefix deletion or a shared-cluster reset. |

### G. Namespace isolation, Vault/ESO and shared images

| ID | Cases and required assertions |
| --- | --- |
| G01 | Namespace per issuer/immutable owner/SAW tuple; duplicate enrollment is idempotent, conflicting ownership/reassignment rejected. |
| G02 | Username rename/reuse, same username under another issuer and malicious path segments cannot grant another subject's Vault subtree. Platform enrollment owns the authorized alias. |
| G03 | Tenant RBAC, quotas and actual CNI/VM NetworkPolicy behavior deny cross-tenant Secret/VM/data access while allowing required service and probe traffic. |
| G04 | Namespace-local SecretStore uses narrowly scoped Vault Kubernetes auth identity/audience/path; forged role/namespace/path and another user's records are denied. No shared privileged token. |
| G05 | Per-provider record or explicitly aggregated profile Secret works with multiple profiles/accounts and exact key bindings; no double writer or secret crossover. |
| G06 | Real Vault-to-ESO-to-virtiofs-to-provider rotation succeeds without a profile edit or reboot and without affecting another user. |
| G07 | Missing properties, denied reads, remote deletion and ESO/Vault outage expose separate sync health; retained Secret bytes are not proof of freshness or revocation. |
| G08 | Coupled provider keys are extracted from one Vault record/Secret; metadata-only refresh does not rotate a provider. |
| G09 | Shared golden import is immutable, content-identified and owned in saw-images; duplicates/import failures cannot overwrite ready in-use sources. |
| G10 | Two private root clones use one shared qualified source; changes in either guest cannot alter the other root or golden source. |
| G11 | Actual Argo clone requester is authorized narrowly; tenant/rogue identities cannot mutate source, read source registry credentials or create source pods. |
| G12 | Advertised CSI/snapshot/host-assisted clone paths work with storage modes, sizes, quotas and NetworkPolicies; do not solve failure by granting broad source edit. |
| G13 | Platform-only registry auth/CA permits golden import while runtime provider/pull credentials stay independent and namespace-scoped. |
| G14 | Teardown/source retention/interrupted clone respects ownership and retained data; namespace deletion is a separately authorized operation, not ordinary Argo prune. |
| G15 | Common-namespace migration uses backup/restore or explicit adoption, not in-place namespace rewrite; never publish an existing tenant disk as a golden source. |

Forge is a reference for namespace/shared-image behavior, not evidence that
per-user ESO is implemented. G04–G08 require real disposable Vault/ESO negative
tests; G09–G14 require actual CDI/storage admission using least-privileged identities.

## 4. Mandatory end-to-end acceptance

1. Build and seal one candidate from the selected OpenShell digests. Record source,
   lock, disk checksum, inventory and artifact digests; import once into saw-images.
2. Through Astra/Argo, enroll Alice and Bob in separate namespaces with private
   roots, profile references and synthetic provider credentials from real Vault/ESO.
   No deployment identity receives provisioning SSH or guest-exec rights.
3. Observe initial verified runtime readiness. Write known durable sentinel data
   through an authenticated test workload; record sandbox generations, actual image
   digests, data identities, VMI UIDs and root PVC UIDs.
4. Change only Alice's selected profile ConfigMap image A to B. Observe guest apply
   without setup/restart/manual commands. The intent ConfigMap remains unchanged.
5. Read B's independently baked build identifier and the original sentinel bytes.
   Cross-check actual gateway/runtime image identity. Alice's second sandbox and
   Bob's entire VM retain their generations and data.
6. Reapply identical bytes over multiple polling intervals: no extra rollout.
   Rotate Alice's Vault credential and verify downstream acceptance and Bob's
   isolation. Deny cross-user Secret/Vault reads and golden-source mutation.
7. Inject apply interruption and candidate-health failure. Verify data preservation,
   no duplicate writer, failed newest readiness and controlled recovery.
8. Prove authorized retention/cleanup and capture only sanitized evidence.

Use deterministic test workload images A/B and a deliberately unhealthy C. Also run
the lifecycle with each advertised real OpenClaw/NemoClaw integration; a tiny fixture
does not qualify agent history persistence. Use a deterministic provider stub for
routine tests and bounded protected real-provider smoke tests where advertised.
Test-only fault injection must not repair a failing case or ship in a release image.

## 5. CI and build work

Implemented: [.github/workflows/saw-validate.yml](../.github/workflows/saw-validate.yml)
runs pinned Python 3.12/3.14 test dependencies, generated schema checks, scoped tests,
Helm lint/render, GitOps rendering, guest source-bundle construction and Linux
systemd unit syntax validation. Its aggregate
gate fails when required jobs do not succeed. It runs with read-only repository
permissions and does not deploy or publish a controller image.

Required next workflows/responsibilities (not yet implemented):

| Workflow | Gate and security boundary |
| --- | --- |
| Tenancy integration | Disposable Vault/ESO/Kubernetes with synthetic keys; actual auth, denial, rotation and stale-secret cases; no production credentials. |
| Shared guest image builder | Refactor existing gateway build/BuildConfig to one locked build path; selected-release payload compatibility, systemd/cloud-init validation, SBOM/scans, sealing and KVM smoke. |
| Protected OpenShift VM E2E | Exact candidate, real virtiofs/ESO/CDI/CNI/OpenShell lifecycle; per-run isolated tenant resources and scoped identities. |
| Astra qualification | Import one candidate and prove no-fork two-user instantiation and ConfigMap-only image replacement. |
| Nightly faults/soak | Bounded crash/outage/rapid-update/drift/rotation/load runs and resource-growth checks. |
| Release promotion | Verify all evidence matches candidate/source/lock; sign and promote exact tested guest/workload/blueprint digests without rebuilding. |

There is deliberately no controller build, GHCR controller publication, leader
failover suite or custom admission-policy installation. GHCR may still host the
qualified golden image when registry permissions and artifact format are chosen.

CI additions still needed include JUnit/coverage reports, branch coverage and
property/mutation testing for critical modules, workflow lint, target-guest
systemd/cloud-init validation, and sanitized artifact upload. Proposed minimums
are 90% statement and 85% branch coverage per critical resolver/planner/journal
package; these floors are not currently enforced or claimed as achieved.

Pin actions/toolchains and verify guest dependencies with hashes. Build once, stage
a digest-addressed candidate, qualify it, then promote that exact content with
provenance/signatures and SBOM. A successful build or scan is not runtime qualification.
Do not run untrusted PR code on persistent KVM/cluster-connected runners or combine
privileged pull_request_target with untrusted checkout. Separate build, test and
publish identities and use protected environments for credentials.

Provision ephemeral KVM capacity, disposable Vault/ESO, an isolated OpenShift test
context and Astra credentials before requiring those gates. Missing infrastructure
means blocked qualification, not a passing skip. Never silently replace actual
authorization tests with cluster-admin runs.

## 6. Reporting, qualification matrix and completion

Every integration suite must emit JUnit and a sanitized structured report containing
required/selected/skipped IDs, classification, attempts, source/lock/artifact identities,
platform versions, timestamps and cleanup result. Preserve the first failure; do not
turn flakiness green with unlimited retries.

Allowlist evidence fields: runtime image/generation and VMI/PVC IDs, sentinel checksums,
public phase transitions, nonsecret Events and explicitly sanitized diagnostics.
Never upload raw Secrets, private journals, token caches, authenticated URLs or a
tenant-used disk. Seed canaries and verify redaction before upload.

Start with one measured platform tuple: guest OS/kernel/architecture/runtime,
the three selected OpenShell digests, supported agent catalog, Astra transport,
OpenShift Virtualization/KubeVirt/CDI/CNI/storage and Vault/ESO/identity versions.
Rootless Podman under cloud-user is the current bootstrap contract. The root
reconciler starts the user service; the gateway itself is unprivileged. Do not
advertise it as qualified, or claim legacy-state migration, extra
architectures, live migration or storage variants, until each is tested. No exact
platform version is declared certified yet.

Measure projection latency separately from the guest's ten-second polling interval
and installer apply time. Current readiness expires after thirty seconds without a
verified refresh and installer calls time out at 120 seconds; qualify/tune these for
real operations rather than treating them as a guaranteed rollout SLA.
Measure Vault-to-provider rotation end to end, including ESO refresh and failed
upstream revocation. Establish resource/size/rollout concurrency limits from tests.

Run at least eight hours of bounded nightly fault/rotation soak and a 24-hour initial
release qualification on the first platform tuple. Track CPU/RSS, file handles,
disk use, journal size, retry counts and data integrity; growth must stabilize.
Cleanup only exact owned test resources and record cleanup failure independently.

Implementation order:

1. Completed foundation: schemas, Argo manifests, mounted-input guest journal,
   synthetic fault tests and reproducible source packaging.
2. Implement and test the selected release in apply_bom.py, including gateway setup,
   profile/provider application, existing sandbox replacement and interruption recovery.
3. Build/seal the reusable image through one shared builder; qualify startup and
   actual runtime behavior before enabling guest VM deployment.
4. Qualify per-user ESO/Vault, shared-image cloning, live virtiofs and GitOps health
   on protected OpenShift; complete the Astra two-user acceptance.
5. Add evidence-bound promotion/soak gates; only then make this path the default.

Completion requires the real E2E/data/isolation gates, not just a larger unit-test
count. The old SSH setup path remains separate for existing installations; it is
not a fallback that can satisfy autonomous guest acceptance.
