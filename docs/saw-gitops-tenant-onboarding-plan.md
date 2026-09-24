# SAW GitOps tenant onboarding plan

Status: proposed implementation sequence.

This plan delivers secure per-tenant SAW provisioning before enabling the
guest-local OpenShell reconciler. It is intentionally compatible with the
no-custom-controller architecture: Argo CD owns Kubernetes desired state, ESO
owns Secret synchronization, Vault owns source credentials, and the VM only
consumes mounted inputs. No setup Job, guest SSH configuration, guest-exec RBAC,
or imperative post-deploy CLI is part of the production path.

The existing guest installer and `apply_bom.py` remain the later consumer of
these inputs. They do not block proving tenant isolation, image delivery, VM
creation, ESO rotation, or Argo reconciliation first.

## Decisions

- Provision one namespace per SAW instance. A user may have more than one SAW;
  the namespace identity therefore includes both the immutable owner subject and
  SAW name.
- Use the immutable OIDC `(issuer, subject)` identity for authorization,
  namespace derivation, Vault policy and ownership. A username is display
  metadata only and must not select Secrets or grant access.
- Keep approved golden image sources in `saw-images`. Tenant namespaces receive
  only the minimum CDI/source access required to create their own root disk.
- Argo CD/ApplicationSet renders tenant resources from reviewed Git records.
  It does not discover Vault users or infer tenant state from the cluster.
- ESO synchronizes provider credentials into the tenant namespace. Neither
  Git, ConfigMaps, VM cloud-init nor guest logs contain provider secret values.
- ConfigMaps hold public instance intent and SAW-BOM profile definitions.
  Secrets hold only referenced credential values. Both are mounted read-only in
  the VM when the guest reconciler is enabled.
- Start without a custom SAW controller. Re-evaluate only if Git-driven tenant
  records, Argo ApplicationSet, ESO and CDI cannot meet an explicit operational
  requirement.

## Target resource flow

```text
Reviewed tenant enrollment in Git
        |
        v
Argo CD / ApplicationSet renders one tenant application
        |
        +--> tenant Namespace, ServiceAccounts, RBAC, NetworkPolicies
        +--> ESO SecretStore/ExternalSecret and tenant-scoped Vault auth
        +--> public instance/profile ConfigMaps
        +--> VM and tenant root DataVolume from saw-images
        |
        v
ESO writes provider Secrets only in the tenant namespace
        |
        v
VM mounts explicitly allowlisted ConfigMaps and Secrets read-only
        |
        v
Later: guest apply_bom.py reconciles OpenShell resources
```

## Identity and naming contract

Define a deterministic, DNS-safe namespace from an immutable identity:

```text
tenantKey = sha256(canonical-json([issuer, subject, sawName]))
namespace = "saw-" + dnsSafe(sawName, 33 chars) + "-" + first 24 hex characters of tenantKey
```

The exact rendering helper must be shared by schema validation, Git rendering
and tests. It must reject changes to issuer, subject or SAW name that would
silently adopt another tenant's namespace.

Suggested Vault layout:

```text
saw/users/<tenant-key>/providers/<provider-name>
```

For example, an ESO `ExternalSecret` for provider `inference-main` maps only its
declared property (such as `api_key`) into one namespaced Kubernetes Secret. Do
not use relative filesystem-like paths such as `../<username>/provider1`: they
make authorization and rename behavior ambiguous.

## Implementation phases

### Phase 1: Git-defined tenant enrollment

- [x] Define the reviewed `SawEnrollment` input: owner issuer/subject/display
  username, SAW name, selected approved image, selected profile ConfigMaps and
  declared provider credential slots.
- [x] Make namespace derivation deterministic and test it for collisions,
  username changes and invalid identifiers.
- [x] Render one Argo application per enrollment using ApplicationSet or an
  equivalent Git generator. The source of truth remains Git.
- [x] Render a tenant Namespace with restricted Pod Security labels and no
  broad default ServiceAccount access. Resource quotas/limits are optional
  enrollment policy and remain rendered by the tenant blueprint path.
- [x] The Phase-1 tenant chart renders no tenant RBAC; subsequent phases may
  add only namespace-local service accounts, Roles and RoleBindings.
  Do not grant tenant service accounts cluster-admin, guest-exec, SSH, or broad
  cross-namespace Secret read permissions.

Acceptance: adding one reviewed enrollment creates exactly one isolated tenant
application and namespace; changing only display username does not change its
identity or namespace.

### Phase 2: shared golden image and VM delivery

- [x] Publish approved release-specific golden VM images/DataSources in
  `saw-images`, pinned by digest and release metadata.
- [x] Reuse the narrow image-source/clone pattern from `forge-saw`, but review
  and minimize source-namespace CDI RBAC rather than copying its broad grants.
- [x] Render a tenant-local root DataVolume/PVC referring only to the approved
  shared source. The tenant ApplicationSet passes a vetted DataSource name,
  never a registry reference or registry credential, to the tenant chart.
- [ ] Run the VM with a tokenless service account unless a specific mounted
  volume requires an identity; never put image registry credentials in the VM.
- [ ] Add tenant-scoped NetworkPolicies. Permit only necessary DNS, Vault/ESO
  control-plane traffic and explicitly approved VM traffic.

Acceptance: two tenant VMs have different root disks and namespaces while using
the same approved shared image source. A tenant cannot read or overwrite another
tenant's DataVolume, VM or source-image configuration.

### Phase 3: Vault and ESO credential delivery

- [x] Define one Vault policy/role binding per tenant identity, limited to that
  tenant's provider subtree and only required read operations.
- [x] Configure ESO authentication with a tenant namespace ServiceAccount and
  Vault audience/CA contract. Avoid shared static Vault tokens.
- [x] Render one ExternalSecret per declared provider Secret. Map only allowed
  fields and use predictable target Secret names owned by Argo/ESO.
- [x] Set refresh policy/interval, deletion policy and ownership semantics
  explicitly. Do not let an ESO failure silently imply credential revocation.
- [ ] Ensure Secret values, hashes and raw ESO/Vault error responses never enter
  Argo values, ConfigMaps, guest status, logs or CI artifacts.

Acceptance: a synthetic credential appears only in its intended tenant Secret;
rotation updates that Secret; another tenant and an unprivileged service account
are denied access to both its Vault path and Kubernetes Secret.

### Phase 4: public intent/profile delivery and VM input contract

- [x] Render `SawInstance` intent and selected SAW-BOM profile ConfigMaps as
  public, reviewed data. Profile documents reference credential slots, never
  inline values.
- [x] Mount only declared ConfigMaps and provider Secret keys into fixed,
  read-only paths in the VM. Do not mount a Kubernetes API token.
- [ ] Initially deploy an empty workspace selection or keep the guest reconciler
  disabled while validating platform delivery. The VM may establish its local
  runtime identity but must not configure a tenant workspace via SSH.
- [ ] Test ConfigMap and Secret projection updates without VMI replacement.

Acceptance: Argo changes are reflected in mounted inputs; no imperative setup
command is needed; the guest cannot enumerate namespace Secrets or call the
Kubernetes API using an inherited token.

### Phase 5: guest reconciler enablement

- [ ] Enable the fixed, image-installed `apply_bom.py` only after Phases 1–4
  pass in a disposable environment.
- [ ] Reconcile workspace membership, providers, credentials and inference from
  the mounted inputs; retain allowlisted failure codes without secret text.
- [ ] Verify idempotency, ConfigMap-driven updates, ESO credential rotation,
  restart recovery, rootless Podman and `/readyz` behavior.
- [ ] Keep OpenShell software release changes as image/BOM lifecycle operations,
  not arbitrary ConfigMap-provided code or downloads.

Acceptance: a profile update changes only the intended tenant OpenShell
workspace/provider state and does not affect a second tenant.

### Phase 6: sandbox lifecycle (separate gate)

- [ ] Establish a supported OpenShell contract for a named retained data volume
  mounted at `/sandbox/persist` before enabling sandbox profiles.
- [ ] Do not use undocumented/experimental driver JSON from ConfigMaps as the
  persistence contract.
- [ ] Implement staged sandbox replacement with old-workload safety, health
  verification, durable data identity preservation and recovery semantics.
- [ ] Qualify image change, pull failure, drain failure, crash recovery and
  cross-tenant isolation with retained-data sentinels.

The current pinned OpenShell CLI supports create/start/stop/upload/download but
does not document a stable persistent-volume/mount option. Download-delete-
recreate-upload is not an acceptable replacement strategy because it is not
atomic and can lose data. Sandbox replacement therefore remains disabled until
the runtime contract exists.

## Required test matrix

`make saw-test-tenant-integration` is the opt-in live-cluster gate for namespace
RBAC, CDI clone denial, Vault/ESO rotation and Argo reconciliation. It requires
two already-reconciled disposable enrollments plus explicit `SAW_TEST_*` and
Vault environment variables; its rotation probe restores the provider record.

| Area | Required proof |
| --- | --- |
| Identity | Subject/issuer, not username, selects the namespace and Vault policy. Rename does not transfer access. |
| Argo | Add/change/delete enrollment follows reviewed Git state; manual cluster changes are reconciled or reported. |
| Namespace isolation | Tenant A cannot list/read/write tenant B ConfigMaps, Secrets, VMs, DataVolumes or Pods. |
| Image sharing | Tenants can clone the approved `saw-images` source but cannot mutate it or use arbitrary sources. |
| ESO/Vault | Tenant-scoped auth, denied cross-tenant reads, Secret rotation, stale-source/error behavior, no secret logs. |
| VM inputs | Read-only allowlisted mounts update correctly; VM has no service-account token or setup SSH dependency. |
| Guest later | Rootless engine, exact workspace/provider readback, retries, reboot recovery, ConfigMap/Secret updates. |
| Sandboxes later | Stable retained volume, replacement rollback/recovery, no cross-tenant data exposure. |

## Non-goals for the initial platform milestone

- Dynamic discovery of users directly from Vault, Keycloak or the cluster.
- A custom SAW reconciliation controller.
- Provider authentication success as proof of ESO delivery; validate that in a
  provider-specific integration gate.
- OpenShell sandbox creation or image replacement before its persistent-storage
  contract is available.
- OIDC end-user login, dashboard exposure, certificate renewal and production
  release promotion.

## Completion criteria for the platform milestone

The platform milestone is complete when a reviewed Git enrollment creates an
isolated tenant namespace, a VM cloned from a shared approved image, public
profile/intent ConfigMaps, and ESO-synchronized provider Secrets backed by a
tenant-scoped Vault policy. Updates must reconcile through Argo/ESO without SSH
or a setup Job, and negative tests must prove cross-tenant access is denied.

This is not yet a claim that OpenShell workspaces, providers, sandboxes, OIDC or
external provider calls are configured successfully. Those become explicit gates
in Phases 5 and 6.
