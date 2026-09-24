# Installer image build and first-boot qualification

This build uses a clean Fedora 44 cloud disk, verified against the published
SHA-256, and a digest-pinned Fedora builder. The image contains the guest service,
rootless Podman, Python/PyYAML, QEMU guest agent and the signed-release verifier;
it does not contain OpenShell payloads or apply_bom.py. Those are delivered by the
platform-selected OCI release bundle. It does not modify or copy a tenant-used disk.

The image has no enrollment, provider credentials, gateway PKI or reconciliation
journal. cloud-user is locked, has no supplementary groups or cloud-init sudo
grant, and receives subordinate IDs for rootless Podman. Rootful Podman services
are disabled. The cloud-init enrollment enables the guest; no SSH setup is needed.

For an isolated diagnostic image only, add `SAW_IMAGE_ENABLE_SSH=1` to
`make saw-image-context`. This installs and enables `sshd` in that image so a
temporary test key can be used for guest inspection. Do not use that variant as
the production golden image.

Generate a new context (the target must not exist):

```sh
make saw-image-context SAW_INSTALLER_BOM=examples/saw/installer-bom.yaml \
  SAW_IMAGE_CONTEXT=/new/path/saw-image-context \
  SAW_RELEASE_PUBLIC_KEY=/path/to/release-signing-public-key.pem
```

For an explicitly authorized isolated OpenShift qualification, keep the build
namespace disposable and pass it to the existing image-build command:

```sh
make saw-image-build SAW_IMAGE_CONTEXT=/new/path/saw-image-context \
  SAW_IMAGE_BUILD_NAMESPACE=saw-installer-validation
```

Build and publish the signed release bundle separately with
`tools/saw/build_release_bundle.py`, then obtain its immutable digest. After a
successful guest-image build, obtain its `status.output.to.imageDigest` and the
ImageStream's repository. Build and publish the signed release bundle separately
with `tools/saw/build_release_bundle.py`, then render a fresh smoke manifest with
both immutable digests:

```sh
python3 tools/saw/render_boot_smoke.py --installer-bom examples/saw/installer-bom.yaml \
  --namespace saw-installer-validation \
  --name installer-smoke-run1 \
  --image REGISTRY/saw-installer-validation/saw-installer@sha256:DIGEST \
  --bundle-ref REGISTRY/saw-release@sha256:BUNDLE_DIGEST \
  --bundle-digest sha256:BUNDLE_DIGEST \
  --output /new/path/saw-boot-smoke.yaml
oc create --dry-run=server -f /new/path/saw-boot-smoke.yaml
oc create -f /new/path/saw-boot-smoke.yaml
oc get vm,vmi,dv,pvc -n saw-installer-validation
```

Do not apply the placeholder `DIGEST`. The renderer refuses mutable image tags.
Choose a fresh lowercase `--name` for each run: it isolates the VM, root disk,
ConfigMaps and service account, retaining failed disks for diagnosis.
The manifest uses a new private root disk, readonly projected ConfigMaps, a
tokenless guest service account and namespace-local ingress. No SSH keys, passwords,
provider credentials, Routes or cluster-wide permission grants are added.
Optional `--diagnostics` adds a smoke-only, read-only preflight probe and sends
safe diagnostics to the serial console under the same guest-service restrictions.
Larger cloud-init payloads use a namespace-local Secret because KubeVirt limits
inline data to 2 KiB; this Secret contains test bootstrap configuration, not
provider credentials. The probe never calls apply or repairs a failed case.
The diagnostic timer also independently verifies runtime state and reports only
the revision, counts, actual gateway UID, rootless result, SELinux state and public
identity fingerprints. It refuses to report success if inputs change during its
checks. These observers are not included in the golden image or production chart.
It does not borrow or overwrite the shared golden images. There is no automatic
cleanup: inspect the exact test resources and retain diagnostic evidence before
explicitly deleting the disposable namespace.

Use `oc logs -n saw-installer-validation POD -c guest-console-log` for guest boot
and opt-in diagnostics. The `compute` container logs libvirt/KubeVirt instead.
The guest's private `status.json` records allowlisted installer reason codes and
the failed operation (`validate`, `apply`, or `verify`); raw exception text and
child-process stderr remain suppressed. Unknown reason values become a fixed
generic code. A negative readiness response still has no diagnostic body.

Fedora's global `10-timeout-abort.conf` is reviewed and hash-attested during image
construction. Runtime verification checks its exact path and bytes alongside the
gateway unit; any additional, missing or modified drop-in fails preflight.

Runtime units hide user homes while exposing `/run/user` read-only for Unix
socket access. Installer-side remote Podman clients get private temporary
configuration and runtime directories; the independent rootless engine retains
its persistent home/storage. No writable host-runtime mount or rootful fallback
is needed.

The BuildConfig's Docker strategy describes OCI artifact construction, **not**
the VM compute driver. libguestfs uses software emulation while building; no
host KVM access, custom privileged SCC grant or host mount is requested. A running
test VM still requires KVM. Output is a `/disk/disk.qcow2` OCI image in an isolated
ImageStream. Pin its resulting digest before importing a DataVolume. Production
VMs continue to belong to Argo; this diagnostic build is not a production release.

CI checks scripts, context allowlisting, BOM validation, source bundle and chart
contracts. It does not yet build/push a disk or claim a boot-test pass. The clean
base checksum is an integrity pin retrieved over HTTPS, not a verified Fedora
signature. Package repositories are not snapshotted, so disk output is not
bit-for-bit reproducible. Signed publication, vulnerability scanning, package
inventory and automated build/boot promotion remain release gates.

Qualification must verify: boot without SSH configuration; read-only virtiofs
inputs; fresh per-clone identity; actual rootless engine and gateway user; workspace
convergence and idempotency; ConfigMap projection; and reboot recovery. Providers,
Vault/ESO, OIDC and sandboxes are separate gates, not implied by a basic boot pass.
