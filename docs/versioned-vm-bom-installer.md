# Versioned VM installer BOM and apply_bom.py

## Decision

Keep one installer, one small guest service and Argo as the deployment owner.
This supersedes the earlier custom-controller and separate OpenShell-adapter designs.
The original example schema and the initially requested .116 images are not permanent
architecture constraints.

```text
Git -> pattern.sh make install -> Argo / Helm -> namespaces, images, VM, ConfigMaps
Vault/<user>/<provider> -> ESO -> namespace-local Secrets
                                |
                      read-only virtiofs mounts
                                |
                       guest systemd service
                                |
                          apply_bom.py
```

The guest detects changes, handles single-writer execution/private progress and
reports results. apply_bom.py owns installation, updates and verification. No
controller, mandatory deployment CLI, direct guest Kubernetes access, gRPC framework,
vendored OpenShell API or version-specific adapter registry is required.

## Versioned software and workspace configuration

There are two separate inputs:

- InstallerBOM selects the installer release plus CLI/gateway/supervisor versions
  and immutable image references.
- SAW-BOM profiles declare workspaces/providers/sandboxes. Instance workspaces is an
  array of profile references with explicit credential bindings, not an inline graph.

See [installer BOM example](../examples/saw/installer-bom.yaml). Each component
has version and image. spec.installerVersion identifies the packaged apply_bom.py
release; metadata.name identifies the software BOM. No commands, script URLs,
credentials or paths to executables are accepted as release data.

The author changes the BOM when software changes and updates apply_bom.py when the
new software needs different deployment steps. Release the tested script and BOM
together. Do not add automatic compatibility discovery or one adapter per version.
Keep version-appropriate CLI behavior in the script; qualifying that behavior is
still necessary even though no separate API layer exists.

A release pins digests for repeatability, not forever. A future release chooses new
digests. The supplied .116 example is only an initial candidate, not a hard-coded
requirement or proof of security/compatibility.

## Deployment and golden image

Argo owns namespaces, image imports, private root clones, VM resources, public
installer/profile/intent ConfigMaps and ESO resources. ESO owns provider Secret
contents. The guest owns local runtime state; it does not write Kubernetes desired
resources. Argo sync alone does not mean the workspace is ready.

One reusable golden image contains only OS/dependencies, the guest service and
the release-bundle verifier. The signed OCI release bundle contains
apply_bom.py, the release BOM and the qualified OpenShell payloads. No username,
provider credential, OIDC token, gateway identity, cloud-init instance state or
private reconciliation journal may be baked into either artifact. Two independent
users must instantiate the same image and release bundle through parameters.

tools/saw/build_release_bundle.py creates the signed OCI bundle context. The image
pipeline embeds only the release verification public key and bootstrap code. At
boot, the guest pulls the platform-selected bundle by digest through rootless
Podman, verifies its signature and file hashes, stages it atomically under
/var/lib/saw/releases, and executes only that staged release. The image pipeline
must still qualify service startup, seal state, boot-test, scan/sign and promote
the exact tested image and bundle together.

The guest image no longer contains OpenShell binaries or apply_bom.py. A changed
bundle is a controlled release activation: the signed digest is staged and the
previous verified release remains available if validation fails. The release
reference is platform-owned; tenant-mounted input cannot select an arbitrary URL
or executable.

## Tenant and credential boundaries

One namespace belongs to the immutable (OIDC issuer, owner subject, SAW ID) tuple.
Username is an authorized Vault-path alias, not the isolation identity. Platform
enrollment controls rename/reassignment and rejects foreign namespace adoption.

Prefer one provider Secret per Vault record at <mount>/<prefix>/<username>/<provider>.
Coupled credential fields originate from one record. Profiles declare logical
credential slots; instances bind them to namespace-local Secret names and keys.

Namespace-local SecretStores use Vault Kubernetes auth roles bound to exact service
accounts, namespaces, audiences and read paths. The chart does not create Vault
policies. Do not copy a shared privileged Vault token or broad source namespace
permissions from the Forge reference; Forge implemented namespace/shared-image
separation, not per-user ESO authorization.

Import content-addressed golden images once into saw-images and clone a private
retained saw-root per tenant. Scope clone permission to the actual Argo apply identity.
No tenant data belongs in saw-images. Retention annotations are not backups or
protection against authorized namespace deletion.

## Live mounted delivery

The chart mounts the installer BOM, instance, enrolled profiles and ESO provider
Secrets through virtiofs. ConfigMap/Secret ISO disks do not satisfy live update
requirements. Qualify the actual virtualization version, guest kernel, SELinux,
CNI, storage and migration behavior.
[KubeVirt volume documentation](https://kubevirt.io/user-guide/storage/disks_and_volumes/)

The guest reopens input files periodically and captures them twice to detect changes
during collection. This does not create an atomic transaction across separate
objects. Keep coupled profile files together and use one Secret per provider record.
New mount sources/allowlists require explicit enrollment migration; cloud-init is
not assumed to rewrite existing roots on reboot.

Readable Secret bytes cannot establish ESO or Vault freshness. Monitor ESO health
separately; upstream credential revocation must occur at the provider. Removing a
Secret does not erase credentials already loaded into a guest/runtime.

## Execution, failure and security

The guest invokes the verified root-owned release under
/var/lib/saw/releases/current using isolated Python and bounded private stdin. It
cannot execute a mounted script or arbitrary BOM command. The small
validate/apply/verify process interface has no OpenShell API types or
capability-negotiation layer. Verification belongs to the script.

Keep a single writer, durable pending/accepted progress and protected credential
snapshots. A changed input during partial apply must not replay revoked credentials
or start a second destructive rollout. Corrupt/foreign state is not silently reset.
A journal alone does not prove runtime rollback or data preservation.

Version checks cannot prove image-digest provenance; the image build must attest
what it installed. Unsupported operations and software mismatches fail explicitly.
No text such as already exists may be treated as proof of convergence without
observing the intended resource.

Preserve named persistent data during sandbox replacement and verify the actual
new workload, not merely the requested image string. Runtime upgrades and sandbox
image updates are distinct lifecycle operations. Do not promise hot replacement
where a selected release requires a restart or migration.

Keep tenant credentials out of Git, image layers, public status, logs and command
arguments. Root/container-engine administrators remain a privileged boundary.
Encrypt guest storage/backups; protect installer code, enrollment values, Argo
projects, Vault policies and shared-image permissions. No claim of zero security
risk follows from using a simpler architecture.

## Current implementation and release gates

The schema, Helm/mount wiring, fixed script invocation and paired source build are
implemented. The legacy apply_bom.py command is preserved. The mounted path now
reconciles workspace/provider/inference profiles using the CLI in that same script,
including ownership checks, membership revocation and Secret-bound provider
creation/rotation. It now bootstraps a local Podman gateway and per-VM mTLS identity
using a bundled system service running as cloud-user. The driver uses that user's
rootless Podman socket at /run/user/<uid>/podman/podman.sock, with the supervisor
image selected by InstallerBOM and no rootful fallback. The reconciler remains
root for protected configuration and service orchestration. No
Docker dependency, automatic legacy-state migration, external OIDC setup or
adoption of built-in default/other unlabeled workspaces is implemented.
Enabled sandbox profiles and software upgrades remain blocked before
mutation. Metadata verification does not establish external provider authentication.
This is not yet a completed autonomous installer.

Implement the release-specific guest behavior in apply_bom.py, then qualify fresh
provisioning, ConfigMap-only image replacement, Vault rotation, two-user denial,
retained data, interrupted apply and independent clone identity. Keep defaults
disabled until those gates pass. See [status](saw-blueprint-implementation.md) and
[test plan](versioned-vm-bom-installer-testing.md).
