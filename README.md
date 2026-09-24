# Secure Agent Workspace

Deploy isolated, per-user AI workspaces on OpenShift Virtualization with GitOps-managed tenant boundaries and credentials.

## Table of Contents

- [Secure Agent Workspace](#secure-agent-workspace)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Detailed description](#detailed-description)
    - [Architecture diagrams](#architecture-diagrams)
      - [Reference Architecture](#reference-architecture)
      - [GitOps Policy Model](#gitops-policy-model)
      - [Storage Layout](#storage-layout)
      - [Implementation Overview](#implementation-overview)
  - [Requirements](#requirements)
    - [Minimum hardware requirements](#minimum-hardware-requirements)
    - [Minimum software requirements](#minimum-software-requirements)
    - [Required user permissions](#required-user-permissions)
  - [Deploy](#deploy)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
      - [Option A: Validated Pattern (GitOps multi-user)](#option-a-validated-pattern-gitops-multi-user)
      - [Option B: Standalone Helm (one user at a time)](#option-b-standalone-helm-one-user-at-a-time)
    - [Global installer release](#global-installer-release)
    - [Per-user instances](#per-user-instances)
      - [Creating and managing users and Vault paths](#creating-and-managing-users-and-vault-paths)
    - [Supported inference providers](#supported-inference-providers)
    - [Validate tenant provisioning](#validate-tenant-provisioning)
    - [Delete](#delete)
  - [Repository structure](#repository-structure)
  - [References](#references)
  - [Technical details](#technical-details)
    - [Security model](#security-model)
  - [Tags](#tags)

## Overview

Secure Agent Workspace provisions one isolated KubeVirt VM workspace per enrolled
user/SAW identity. Desired state is reviewed in Git and reconciled by Argo CD;
provider credentials flow from Vault through External Secrets Operator (ESO), never
through Git or Helm values.

## Detailed description

Organizations adopting AI coding and knowledge agents need strong isolation guarantees: each user's agent must run in its own boundary, with auditable access to enterprise systems, controlled network egress, and centralized identity management. Traditional container-based isolation is insufficient when agents can execute arbitrary code and tool calls.

This implementation uses the NVIDIA Secure Agent Workspace architecture on Red Hat
OpenShift. Each enrollment receives a dedicated Fedora VM. Its namespace, private
root disk, Vault authorization, ESO-managed provider Secrets, and optional VM are
all derived from reviewed Git configuration. The VM receives only explicitly
projected, read-only inputs; it does not receive Kubernetes API credentials.

The current guest reconciler supports NVIDIA, OpenAI, and Anthropic single-key
credentials in newly owned workspaces. Other providers, web search, sandbox
lifecycle, and full workspace readiness remain unimplemented or unqualified.
The image pipeline customizes a pinned Fedora Cloud QCOW2 with the guest service,
rootless Podman, and the release-verification key, then publishes the disk in an
OCI image for CDI import. A separate signed OCI release bundle supplies the
versioned installer and pinned OpenShell payloads at guest startup; cloud-init
does not install packages.

### Architecture diagrams

The following diagrams are from the [NVIDIA Secure Agent Workspace OpenShift Virtualization Reference Implementation](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/openshift-virtualization-reference-implementation.html).

#### Reference Architecture

![OpenShift Virtualization Reference Implementation](docs/images/openshift-reference-shape.png)

#### GitOps Policy Model

![GitOps Policy Model — End-to-End Policy Flow](docs/images/gitops-policy-model.png)

#### Storage Layout

![NFS storage layout for policy bundles and workspace persistence](docs/images/nfs-storage-layout.png)

#### Implementation Overview

```
                     OpenShift Cluster
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  Operators (deployed by Validated Pattern or manually):  │
│  ┌──────────────────┐  ┌──────────────────┐              │
│  │ OpenShift        │  │ Red Hat Build    │              │
│  │ Virtualization   │  │ of Keycloak      │              │
│  └──────────────────┘  └──────────────────┘              │
│                                                          │
│  Infrastructure (ArgoCD-managed):                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────────┐  │
│  │ Vault    │ │ ESO      │ │ Keycloak (OIDC provider) │  │
│  └──────────┘ └──────────┘ └──────────────────────────┘  │
│       │                              │                   │
│       │ secrets sync                 │ JWKS validation   │
│       ▼                              ▼                   │
│  ┌──────────────────────────────────────────┐            │
│  │ Golden VM disk (QCOW2 in OCI)            │            │
│  │ Fedora 44 + guest service + Podman       │            │
│  │ CDI imports approved disk DataSource     │            │
│  └─────────────────┬────────────────────────┘            │
│                    │ clone per user                      │
│       ┌────────────┼────────────┐                        │
│       ▼            ▼            ▼                        │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐                     │
│  │ alice   │ │ bob     │ │ carol   │  Per-user VMs       │
│  │ guest   │ │ guest   │ │ guest   │  pulls signed       │
│  │  VM     │ │  VM     │ │  VM     │  OpenShell bundle   │
│  └─────────┘ └─────────┘ └─────────┘                     │
│       │            │            │                        │
│       └────────────┼────────────┘                        │
│                    │                                     │
│  Routes:  TLS passthrough (gRPC) + edge (dashboard)      │
└──────────────────────────────────────────────────────────┘
        │
        ▼
   User (openshell CLI / browser)
```

| Component | Technology | Purpose |
|---|---|---|
| VM isolation | OpenShift Virtualization (KubeVirt) | One VM per user with process and network isolation |
| Identity | Red Hat Build of Keycloak (RHBK) | OIDC authentication, user management, SSO |
| Guest runtime | NVIDIA OpenShell | Workspace and provider reconciliation from approved input |
| Golden image | Fedora 44 disk OCI artifact + CDI | Qualified, digest-pinned shared source cloned per tenant |
| Secrets | HashiCorp Vault + External Secrets Operator | Namespace-scoped provider credentials |
| GitOps | ArgoCD (Validated Patterns) | Declarative cluster configuration |
| Tenant boundary | Namespace, Vault role, private DataVolume | Prevents cross-tenant resource and credential access |

## Requirements

### Minimum hardware requirements

| Resource | Per sandbox VM | Cluster overhead |
|---|---|---|
| CPU | 4 cores | 8 cores (operators, Keycloak, Vault) |
| Memory | 8 GiB | 16 GiB |
| Storage | 40 GiB (VM disk) | 50 GiB (golden image, registry) |

### Minimum software requirements

| Software | Version |
|---|---|
| Red Hat OpenShift | 4.22+ |
| OpenShift Virtualization operator | stable channel |
| Red Hat Build of Keycloak operator | stable-v26 channel |
| Helm CLI | 3.x |
| oc CLI | matching cluster version |
| openshell CLI | [latest release](https://github.com/NVIDIA/OpenShell/releases) |

### Required user permissions

**Cluster admin** is required for platform installation and for the approved image/Vault
setup. Tenant provisioning itself is Git/Argo-driven. External end-user OIDC access
remains a qualification gate for the current guest implementation.

## Deploy

### Prerequisites

Complete these prerequisites before starting either deployment option:

- An OpenShift 4.22+ cluster and an administrator account for platform setup.
- A Vault administrator for the tenant policy and Kubernetes-auth role setup.
- `oc`, Helm 3, Python 3, Mike Farah `yq`, and the repository tools installed.
- OpenShift Virtualization/CDI and External Secrets Operator APIs available.
- A configured OIDC issuer (bundled Keycloak or an external provider) and a
  Vault Kubernetes-auth role/ESO store for each tenant.
- Before enabling a tenant VM, an approved CDI `DataSource`, an immutable
  golden-image digest, and an approved signed installer bundle with its
  InstallerBOM and SHA-256 digests.
- The golden image must be publicly pullable for the documented boot smoke
  renderer, which currently has no registry-secret option. CDI import can use a
  pull Secret in `saw-images` for a private image.
- The signed installer bundle must be publicly pullable from the guest. The
  current rootless Podman bootstrap does not yet install private registry
  credentials.
- A storage class that lets CDI bind the tenant root disk before the VM is
  scheduled. If the cluster default uses `WaitForFirstConsumer` and the disk
  remains pending, set an immediately binding class on the image: use
  `sawBlueprint.goldenImages[].storageClass` for GitOps or
  `sawPlatform.image.storageClassName` for standalone Helm.
- Guest egress to cluster DNS and HTTPS registries. The tenant NetworkPolicy
  allows DNS on UDP/TCP 53 and OpenShift DNS on UDP/TCP 5353, plus HTTPS on 443.

The steps below begin with the shared cluster login and preflight. Complete
them once, then follow **Option A or Option B** below. Do not mix both tenant
provisioning paths for the same tenant.

Never commit a Vault administrator token, provider API key, or mutable image tag
to Git.

Install the repository tools and log in first:

```bash
oc login <cluster-api>
oc whoami
make saw-platform-check
```

`saw-platform-check` is read-only. OpenShift Virtualization/CDI and External
Secrets Operator are required for both deployment modes. Argo CD/ApplicationSet
and the bundled Red Hat Build of Keycloak are optional. Configure an external
OIDC issuer in `config/saw-platform.yaml`, or require the bundled Keycloak
operator explicitly with `SAW_REQUIRE_KEYCLOAK=1`. Vault Kubernetes
authentication is verified by the Vault administrator in the Vault policy step
below.

If the check reports missing APIs, bootstrap the platform before creating a
user. For GitOps, use `./pattern.sh make install`. For standalone Helm, a
cluster administrator can apply the repository’s OperatorHub subscriptions and
wait for them to become ready:

```bash
make saw-platform-operators
make saw-platform-check
```

If you choose the bundled Keycloak provider, deploy it after the Red Hat Build
of Keycloak API is available and print its issuer:

```bash
make saw-keycloak-operator
# Wait for the CSV/API to become ready, then:
SAW_REQUIRE_KEYCLOAK=1 make saw-platform-check
make keycloak
make keycloak-issuer
make configure-keycloak
```

`configure-keycloak` creates or verifies the `saw` realm, creates the
confidential `saw` OIDC client, and stores its generated client secret as
`Secret/saw-oidc-client` in the Keycloak namespace. It requires Keycloak admin
credentials from the operator-generated Secret, or explicit
`KEYCLOAK_ADMIN_USER` and `KEYCLOAK_ADMIN_PASSWORD` values.

The bundled Keycloak default namespace is `keycloak`. If the RHBK operator or an
existing `openshell-keycloak` instance is found in another namespace, the
command asks before using it; set
`KEYCLOAK_AUTO_NS=1` for a non-interactive deployment or pass
`KEYCLOAK_NS=<namespace>` explicitly. If multiple Keycloak resources exist,
select one with `KEYCLOAK_NS=<namespace> KEYCLOAK_NAME=<resource-name>`.

For an external OIDC provider, leave the Keycloak operator uninstalled and set
the provider’s issuer directly in `config/saw-platform.yaml`; discovery will
preserve an explicitly configured issuer. To make the preflight enforce the
bundled provider instead, run:

```bash
SAW_REQUIRE_KEYCLOAK=1 make saw-platform-check
```

Vault/ESO setup is owned by this repository. Run `make setup-vault` to install
the SAW OperatorHub dependencies and validate Vault/ESO connectivity. Each
tenant flow renders its Vault policy and Kubernetes-auth role plan for an
administrator to review before deployment. `configure-vault-user` validates or
publishes provider records separately. If Vault already exists, discovery reads
the existing `vault-backend` ClusterSecretStore. These commands never place a
Vault administrator token or provider credential in Git.

### Installation

Two deployment options are available after completing the shared prerequisites:

1. **Option A — Validated Pattern / GitOps (multi-user):** reviewed tenant
   records in Git are reconciled through Argo CD/ApplicationSet.
2. **Option B — Standalone Helm (one user at a time):** an administrator sets
   the shared platform defaults once, then each user supplies one small
   `sawUser` YAML file and runs `make saw-user-install`.

#### Option A: Validated Pattern (GitOps multi-user)

This repository's deployment path is the tenant blueprint. Do **not** use
`make copy-images`, `values-secret.yaml`, or `make openshell-saw-create` for this
path: they belong to the legacy direct-provisioning flow and mirror legacy
0.0.103 images. Tenant workspaces instead use a qualified VM disk built from a
digest-pinned InstallerBOM.

> **Current release status:** a disposable end-to-end run built and imported a
> candidate image, cloned it into a tenant VM, and booted the VM on 2026-09-24.
> The guest `/readyz` endpoint still returned `503`, so guest reconciliation and
> workspace readiness are not qualified. The current installer also rejects
> enabled sandbox profiles before mutation; the bundled `data-science` example
> cannot converge until that feature is implemented. Do not promote this
> candidate or enable production VMs until image, Vault/ESO, runtime, and
> readiness qualification is complete. See
> [implementation status](docs/saw-blueprint-implementation.md).

The deployment owner is Argo CD:

```text
Reviewed tenant records in Git
  -> saw-blueprint: shared approved image + ApplicationSet
  -> one openshell-saw Argo Application per record
  -> isolated namespace, private root clone, ESO provider Secrets
  -> optional VM with read-only ConfigMap and Secret mounts
  -> image-owned guest service reconciles approved workspace inputs
```

Follow these steps in order for a new environment.

1. Confirm the common platform check passes and require Argo CD for this option.

   ```bash
   SAW_REQUIRE_ARGO=1 make saw-platform-check
   ```

   The preflight is read-only. Install any missing required operator before
   proceeding.

2. Choose the release BOM. An **InstallerBOM** is the versioned release record
   for the three OpenShell images installed in the guest: CLI, gateway, and
   supervisor. It pins every image by SHA-256 digest, so a later registry tag
   change cannot alter a workspace. Start with
   [`examples/saw/installer-bom.yaml`](examples/saw/installer-bom.yaml), copy it
   into your release repository, review its image digests, and give it a release
   name. The example is a reference, not a production approval.

3. Build the immutable VM disk from that BOM.

   ```bash
   mkdir -p /tmp/saw-release
   cp examples/saw/installer-bom.yaml /tmp/saw-release/installer-bom.yaml

   make saw-image-context \
     SAW_INSTALLER_BOM=/tmp/saw-release/installer-bom.yaml \
     SAW_IMAGE_CONTEXT=/tmp/saw-release/image-context \
     SAW_RELEASE_PUBLIC_KEY=/path/to/release-signing-public-key.pem

   make saw-image-build \
     SAW_IMAGE_CONTEXT=/tmp/saw-release/image-context \
     SAW_IMAGE_BUILD_NAMESPACE=saw-installer-validation
   ```

   `saw-image-context` only prepares the allowlisted build files. Add
   `SAW_IMAGE_ENABLE_SSH=1` only for a disposable diagnostic image; the default
   image remains SSH-free. `saw-image-build`
   creates/uses the isolated BuildConfig in `SAW_IMAGE_BUILD_NAMESPACE` and starts
   a binary build. It prints the candidate immutable `repository@sha256:digest`.
   Do not use that image for tenants yet.

   Build the signed release bundle separately. It contains the selected
   `apply_bom.py`, InstallerBOM and OpenShell payloads; the VM image contains
   only the verifier and bootstrap:

   ```bash
   python3 tools/saw/build_release_bundle.py \
     --installer-bom /tmp/saw-release/installer-bom.yaml \
     --name saw-example-2026-09 \
     --signing-key /path/to/release-signing-key.pem \
     --output /tmp/saw-release/bundle-context
   ```

   Publish that context as an immutable OCI image and record both its
   `bundleRef` and `bundleDigest`. The current guest bootstrap uses unauthenticated
   rootless Podman, so the bundle image must be publicly pullable from the guest.

   Configure the `saw-golden-image` GitHub environment with
   `SAW_RELEASE_PUBLIC_KEY`, containing the PEM public key paired with the
   release signing key. The manually triggered
   [`Build SAW golden VM image`](.github/workflows/build-saw-golden-image.yml)
   workflow builds a production image and a separate `-ssh` diagnostic image
   directly on the GitHub runner, then pushes both to GHCR using the workflow's
   `GITHUB_TOKEN`. Only the SSH-free production image can enter qualification
   and promotion; never use the diagnostic image for tenant VMs. The workflow
   does not require OpenShift credentials. Configure package-write permission,
   then provide the release name and BOM path when dispatching it. It uploads
   immutable image references and build inputs, and stops before promotion and
   CDI `DataSource` creation so each image can complete its smoke, scan,
   signature, and approval gates. Make the production golden-image package
   public before running the smoke renderer; a private CDI import instead needs
   a pull Secret in `saw-images` and `registrySecret` in the image definition.

4. Render and run the disposable boot smoke test.

   ```bash
   make saw-image-smoke-render \
     SAW_INSTALLER_BOM=/tmp/saw-release/installer-bom.yaml \
     SAW_SMOKE_NAMESPACE=saw-installer-validation \
     SAW_SMOKE_IMAGE=<repository@sha256:digest-printed-by-the-build> \
     SAW_SMOKE_BUNDLE_REF=<bundle-repository@sha256:bundle-digest> \
     SAW_SMOKE_BUNDLE_DIGEST=sha256:<bundle-digest> \
     SAW_SMOKE_OUTPUT=/tmp/saw-release/boot-smoke.yaml

   oc create --dry-run=server -f /tmp/saw-release/boot-smoke.yaml
   oc create -f /tmp/saw-release/boot-smoke.yaml
   oc get vm,vmi,dv,pvc -n saw-installer-validation
   ```

   This disposable renderer creates exactly one VM per invocation. Use a fresh
   name for each retry; do not create multiple VMs as a substitute for the
   documented one-workspace tenant test.

   Complete your organization’s scan, signature, and approval gates. Then place
   the approved disk digest in `sawBlueprint.goldenImages[].registryURL` and copy
   the BOM’s `spec` into `sawBlueprint.installer.releases[].bom` as shown below.
   [Guest image qualification](guest/image/README.md) explains the expected
   smoke evidence and failure diagnosis.

   For a manual deployment, import the image only after those gates pass:

   ```bash
   # First edit examples/saw/golden-image.yaml with the approved image digest.
   make setup-golden-image
   oc get dv,datasource -n saw-images -w
   ```

   This uses `examples/saw/golden-image.yaml` and does not run the legacy
   `copy-images` target, which mirrors multiple tagged runtime images into the
   internal registry. After the DataVolume succeeds, rerun
   `make saw-platform-discover` to record the generated CDI `DataSource` in
   `config/saw-platform.yaml`.

The repository includes a release workflow at
`.github/workflows/publish-saw-installer.yml`. Create a tag in the form
`saw-installer-<release-name>` (for example, `saw-installer-saw-example-2026-09`), or run the workflow from
the Actions tab with an explicit BOM path. Configure the `saw-golden-image`
GitHub environment secret `SAW_RELEASE_SIGNING_KEY` with the matching private
key. The workflow validates the BOM, signs the release manifest, builds an OCI
image containing the installer, BOM, and pinned OpenShell payloads, then pushes
it to GHCR. The image is pullable by the guest with rootless Podman:

```text
ghcr.io/<organization>/saw-installer@sha256:<artifact-digest>
```

Set the published installer package visibility to public so the guest can pull
it without registry credentials.

The workflow summary and downloadable artifact contain `bundleRef` and
`bundleDigest`. Copy those values, along with the BOM content, into
`sawPlatform.installerRelease` in `config/saw-platform.yaml`; do not use the
mutable release tag as `bundleRef`.

5. For GitOps mode, discover the Argo CD apply identity.

   ```bash
   make saw-argo-discover
   # If more than one candidate is printed:
   SAW_ARGO_NAMESPACE=<namespace> SAW_ARGO_DEPLOYMENT=<deployment> make saw-argo-discover
   ```

   Copy the emitted `deployerServiceAccount` block into the blueprint. The parent
   chart grants this identity only the CDI source-clone permission for approved
   golden images.

6. Create the blueprint values file. Copy the complete `sawBlueprint` example in
   [Per-user instances](#per-user-instances) to `overrides/saw-blueprint.yaml`.
   Set `enabled: true`, the Argo repository/revision, the approved disk digest,
   platform issuer/Vault details, and at least one tenant. Run this before
   committing:

   ```bash
   make saw-test-fast
   make saw-render-gitops SAW_VALUES=overrides/saw-blueprint.yaml
   ```

7. Have the Vault administrator create a least-privilege role before enabling the
   tenant. The helper derives the exact namespace, immutable tenant key, policy
   paths, and `vault` commands without contacting Vault or applying changes:

   ```bash
   make saw-vault-plan SAW_VALUES=overrides/saw-blueprint.yaml SAW_TENANT=research \
     > /tmp/research-vault-plan.txt
   less /tmp/research-vault-plan.txt
   ```

   Review the plan, save the displayed HCL policy, and run the displayed commands
   using an authorized Vault administrator session. Add the provider value at the
   generated path. The role is bound only to that tenant namespace and its
   `saw-vault-reader` ServiceAccount.

8. For GitOps mode, commit and push the values file to the exact revision configured in
   `applicationSet.targetRevision`, then install/reconcile the Pattern:

   ```bash
   ./pattern.sh make install
   oc get applicationset -n saw-system saw-tenants
   oc get application -A -l app.kubernetes.io/part-of=openshell-saw
   ```

   Argo creates the tenant namespace, DataVolume, ESO resources, and optional VM.
   ESO creates the provider Secret only after Vault authentication succeeds.

#### Option B: Standalone Helm (one user at a time)

Use this for a disposable test or a cluster where Argo CD is intentionally not
installed. The manual flow keeps its local platform contract outside the
checked-in `overrides` directory. Follow the complete sequence below; create
and publish the shared platform ConfigMap only after identity and Vault setup.
It also requires the approved golden-image `DataSource` and publicly pullable
signed release bundle listed in the shared prerequisites.

The standalone sequence is:

1. If you installed operators after the shared preflight, verify the APIs again:

   ```bash
   make saw-platform-check
   ```

   OpenShift Virtualization, CDI, and External Secrets Operator are required.
   If they are missing, a cluster administrator can run `make saw-platform-operators`,
   wait for the CSVs/CRDs, and run the check again.
2. Configure identity. For the bundled or administrator-managed Keycloak:

   ```bash
   make keycloak
   make keycloak-issuer
   make configure-keycloak
   ```

   `make keycloak` detects an existing Keycloak resource and asks before using an
   instance in another namespace. Use `KEYCLOAK_NS=<namespace>` (and, when needed,
   `KEYCLOAK_NAME=<resource>`) to select one explicitly. For an external OIDC
   provider, skip these commands and set `sawPlatform.platform.issuer` manually.
3. Configure Vault and ESO:

   ```bash
   make setup-vault
   ```

   `setup-vault` installs/checks the SAW ESO prerequisites and deploys only a
   standalone Vault release plus `ClusterSecretStore/vault-backend` when they are
   absent. It never runs `pattern.sh` or deploys the full application in Option B.
   The standalone Vault uses the chart's development mode and is suitable for
   evaluation: the Vault namespace is created automatically and Vault is
   initialized/unsealed automatically. It has no production seal/unseal or
   durable-storage workflow; use an approved production Vault configuration for
   production.
   An existing `vault-backend` ClusterSecretStore is reused. The per-user Vault
   policy and Kubernetes-auth role plan is rendered after the user file is ready.
4. Copy `config/saw-platform.yaml.example` to the ignored local
   `config/saw-platform.yaml`, discover safe values, and review the result:

   ```bash
   cp config/saw-platform.yaml.example config/saw-platform.yaml
   make saw-platform-discover
   ```

   The golden-image CDI `DataSource` is the named CDI object that points to the
   approved VM disk in `saw-images`; it is not the registry URL or the disk image
   digest. If discovery reports no DataSource, CDI or the golden-image import is
   not ready. Inspect the available objects with:

   ```bash
   oc get datasource -n saw-images
   oc get datasource -n saw-images <name> -o yaml
   ```

   Set the selected object name under `sawPlatform.image.dataSource` (and change
   `sawPlatform.image.namespace` if the image lives elsewhere). If multiple
   DataSources exist, choose the one approved for the SAW golden image. Fill any
   other values that cannot be discovered, especially the approved immutable
   `installerRelease`/InstallerBOM. The release owner supplies these values;
   they are not inferred from a running cluster. The shape is:

   ```yaml
   sawPlatform:
     image:
       namespace: saw-images
       dataSource: qualified-saw-release-2026-09
       diskSizeGi: 40
     installerRelease:
       name: saw-example-2026-09
       bundleRef: registry.example.com/saw-installer@sha256:<64-hex-digest>
       bundleDigest: sha256:<64-hex-digest>
       bom:
         installerVersion: 0.1.0
         openshell:
           cli: {version: <approved-version>, image: <image@sha256:digest>}
           gateway: {version: <approved-version>, image: <image@sha256:digest>}
           supervisor: {version: <approved-version>, image: <image@sha256:digest>}
   ```

   `installerRelease.bom` comes from the reviewed
   [`examples/saw/installer-bom.yaml`](examples/saw/installer-bom.yaml), with
   the release owner’s approved image digests. `bundleRef` and
   `bundleDigest` come from the immutable installer bundle published for that
   release. Do not use a mutable tag or the golden VM image digest in these
   fields; the golden VM digest belongs to the CDI import/DataSource.
5. Create one admin-owned user enrollment file under `config/users/`:

   ```bash
   make create-user USERNAME=alice PROFILES=data-science
   ```

   This creates `config/users/alice/user.yaml` and a local-only
   `config/users/alice/secret.yaml` with default guest/profile settings. Set its
   immutable OIDC `subject` before rendering. The profile list is required. For
   bundled Keycloak, run `make configure-keycloak-user SAW_USER=<username>` to
   create the account or confirm it is enabled, grant `openshell-user`, and record its
   immutable subject. Set the user's password through your approved Keycloak
   enrollment process. Set `KEYCLOAK_CA_BUNDLE` when the Keycloak route uses a
   private CA. For an external OIDC provider, the administrator must
   supply the subject. Provider records belong only in `secret.yaml`; that file
   is ignored by Git.
   The tracked templates are [`config/users.example.yaml`](config/users.example.yaml)
   and [`config/secrets.example.yaml`](config/secrets.example.yaml).

6. Edit the user file as needed. Set the username, declared credential names
   and keys, profile ConfigMaps and bindings, and guest sizing/settings. Preview
   the resulting values:

   ```bash
   make saw-user-values SAW_USER=<username>
   ```

   The bundled `data-science` profile includes an enabled sandbox, which the
   current guest installer rejects before mutation. It will not reach Ready
   until sandbox support is implemented and qualified.
7. Fill the complete local provider records in
   `config/users/<username>/secret.yaml`. Render the per-user Vault policy and
   Kubernetes-auth role plan, have the Vault administrator review and apply it,
   then validate/publish the provider records:

   ```bash
   make configure-vault-plan SAW_USER=<username>
   make configure-vault-user SAW_USER=<username>
   ```

   This is a dry run by default. Set `VAULT_APPLY=1` with a Vault
   administrator token to write records. Use `make configure-vault` to validate
   or publish provider records for all local users.
8. Publish the reviewed shared configuration once:

   ```bash
   make saw-platform-configmap
   ```

   This creates `ConfigMap/saw-platform-config` in `saw-system`. It is shared and
   is not recreated in every user namespace.
9. Preview the generated tenant values:

   ```bash
   make saw-user-values SAW_USER=<username>
   ```

10. Create the user’s isolated SAW namespace and workspace:

   ```bash
   make saw-user-install SAW_USER=<username>
   ```

11. Verify the resulting resources:

   ```bash
   helm list -A | grep saw-
   oc get vm,vmi,dv,pvc,secretstore,externalsecret -A
   ```

`saw-platform-discover` can fill the Keycloak issuer, Vault server and CA bundle,
and an unambiguous CDI `DataSource`. It leaves values empty when the cluster
cannot prove which resource is correct. The approved immutable installer release
must still be reviewed by an administrator. `saw-user-install` reads the
`saw-platform-config` ConfigMap when it exists and falls back to the local file.

`sawUser.name` is the SAW instance name and becomes part of a deterministic,
isolated Kubernetes namespace such as `saw-research-<identity-hash>`. It is not
the guest workspace name: guest workspaces are the items under
`sawUser.instance.workspaces` and may be named `default`, `research`, or another
reviewed profile workspace.

The direct installer deliberately rejects an Argo-managed request:

```bash
make saw-user-install SAW_USER_VALUES=overrides/users/research.yaml SAW_TENANT_MANAGEMENT=argocd
# Refuses: Argo-managed tenants must be created by the parent ApplicationSet.
```

When using standalone Helm, Helm owns the tenant resources; do not later enable
the ApplicationSet for that same tenant until you have intentionally transferred
ownership and reconciled the existing resources.

### Global installer release

Define the installer once in `sawBlueprint.installer`. The parent chart selects
the default immutable release (or a reviewed tenant canary override), then
ApplicationSet passes that resolved release to every `openshell-saw` Application.
Each tenant chart writes a namespace-local copy of the release ConfigMap because
Kubernetes does not allow a VM to mount a ConfigMap from another namespace.

The ConfigMap carries the installer bundle reference/digest and InstallerBOM. The
image-owned bootstrap pulls the bundle with rootless Podman, stages it in a
writable directory under `/var/lib/saw`, verifies its signature and file digests,
then atomically installs it under `/var/lib/saw/releases/<digest>`. It executes
the `/var/lib/saw/releases/current/apply_bom.py` entrypoint only after verification.

### Per-user instances

The tenant blueprint is the multi-user deployment path. A reviewed Git record
creates one Argo CD Application and one deterministic namespace for each unique
`(OIDC issuer, immutable subject, SAW name)` tuple. The username is display
metadata and the default Vault-prefix suffix; changing it does not transfer a
namespace or change an explicitly configured Vault prefix.

The flow is:

```text
Reviewed plain tenant values in Git
  -> parent Argo application / ApplicationSet
  -> one tenant Argo application and namespace
  -> tenant root DataVolume cloned from saw-images
  -> one ESO provider Secret per selected provider in that tenant namespace
  -> optional VM mounts reviewed ConfigMaps and provider Secrets read-only
```

#### Creating and managing users and Vault paths

Create one enrollment for each `(OIDC issuer, immutable subject, SAW name)` tuple.
In GitOps mode, add the user to `sawBlueprint.tenants` in the reviewed blueprint.
Set `name`, `subject`, and a lowercase Kubernetes-safe `username`; use the
identity provider's immutable subject (the Keycloak user UUID for bundled
Keycloak). Create bundled-Keycloak accounts
through the approved identity administration process, assign the `openshell-user`
realm role, and record the UUID in Git. For an external identity provider, the
identity administrator supplies its immutable `sub`. In standalone mode,
`make create-user USERNAME=alice PROFILES=data-science` creates a local enrollment
and secret file; `make configure-keycloak-user SAW_USER=alice` can create or verify
the bundled-Keycloak account and write its UUID into that enrollment. Passwords
are set through the identity provider's enrollment process, never stored in SAW
configuration.

Git enrollment contains only identity, selected profiles, provider names, and
allowed field names. Provider values stay in Vault. Give each user a distinct
`vaultPrefix`; for example, `saw/engineering/alice`. If omitted, the tenant chart
uses `<platform Vault prefix>/<username>`. The standalone `create-user` helper
starts with `saw/<username>`; administrators can change it in `user.yaml` to use
another path. The KV v2 record for a provider is:

```text
<mount>/<vaultPrefix>/providers/<remoteKey>
```

For example, mount `secret`, prefix `saw/engineering/alice`, and provider key
`nvidia` resolve to `secret/data/saw/engineering/alice/providers/nvidia` in a
Vault policy and `saw/engineering/alice/providers/nvidia` in `vault kv` and ESO
configuration. Store the provider's related fields together in that record. The
tenant enrollment declares the allowed fields under `credentials[].keys`; ESO
projects only those fields into a namespace-local Secret named for `remoteKey`.
Workspace credential bindings select which Secret keys the VM receives as
read-only inputs. A different user gets a different prefix, policy, namespace,
and Secret even when both users select the same provider.

To add a GitOps user, render and have the Vault administrator apply the policy
and Kubernetes-auth role for the new enrollment before enabling its tenant, then
commit the reviewed tenant record. To add a standalone user, fill the generated
local `config/users/<username>/secret.yaml`, review
`make configure-vault-plan SAW_USER=<username>`, apply the resulting role with a
Vault administrator identity, then run
`make configure-vault-user SAW_USER=<username>`. That command validates records by default; `VAULT_APPLY=1`
publishes them to Vault. Never commit the local secret file, Vault tokens, or
provider values.

Manage workspace intent and allowed credential bindings through reviewed Git
changes. Rotate provider values in Vault with `make configure-vault-user` for a
standalone enrollment (or the approved Vault process for GitOps), then allow ESO
to refresh its tenant Secret. Revoke the old value at the provider as well.
Offboarding is separate from identity disablement: disable the IdP account,
remove or revoke its Vault role and records, and follow the approved tenant data
retention and teardown process. Removing a Git entry alone is not a data-erasure
operation because tenant resources use no-prune and retention protections.

Create one `tenants` item for each user/SAW tuple in the Git-tracked
`overrides/saw-blueprint.yaml` (or a reviewed environment-specific value file).
The following is a complete shape for an enabled VM; replace every example
identity, Vault endpoint, CA, registry location, and digest with reviewed values.
Provider values themselves never belong in this file.

```yaml
sawBlueprint:
  enabled: true
  imageNamespace: saw-images
  deployerServiceAccount:
    # The actual Argo application-controller apply identity for this cluster.
    name: argocd-application-controller
    namespace: openshift-gitops
  # Shared platform settings. They are set once, never copied into a tenant.
  platform:
    issuer: https://identity.example.com/realms/saw
    vault:
      server: https://vault.example.com
      mount: secret
      prefix: saw/users
      authMount: kubernetes
      audience: vault
      # Public trust anchor, not a Vault token. ESO needs this before it can
      # authenticate to Vault, so it cannot be fetched through ESO.
      caBundle: |-
        -----BEGIN CERTIFICATE-----
        REPLACE-WITH-ENTERPRISE-VAULT-CA
        -----END CERTIFICATE-----
  applicationSet:
    enabled: true
    repoURL: https://github.example.com/platform/secure-agent-workspace.git
    targetRevision: main
    destinationServer: https://kubernetes.default.svc
    project: default
    tenantChartPath: charts/openshell-saw
  installer:
    defaultRelease: saw-example-2026-09
    releases:
      - name: saw-example-2026-09
        bundleRef: registry.example.com/saw-installer@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        bundleDigest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        bom:
          # Versioned components are global. The chart builds the internal
          # InstallerBOM document consumed by the guest.
          installerVersion: 0.1.0
          openshell: {cli: {version: 0.0.116-rhaiv.0, image: quay.io/opendatahub/odh-openshell-cli@sha256:REPLACE}, gateway: {version: 0.0.116-rhaiv.0, image: quay.io/opendatahub/odh-openshell-gateway@sha256:REPLACE}, supervisor: {version: 0.0.116-rhaiv.0, image: quay.io/opendatahub/odh-openshell-supervisor@sha256:REPLACE}}
  goldenImages:
    - name: qualified-saw-release
      # Replace this example digest with the qualified VM image digest.
      registryURL: docker://registry.example.com/saw-vm@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      diskSizeGi: 40
  tenants:
    - goldenImageRef: qualified-saw-release
      name: research
      subject: immutable-oidc-subject
      username: alice
      vaultPrefix: saw/alice
      credentials:
        - name: nvidia
          remoteKey: nvidia
          keys: [type, model, endpoint, api_key]
      # Instance intent, profiles, and optional VM configuration are reviewed
      # Git data. Never put provider values here.
      profileConfigMaps:
        - name: alice-profiles
          data:
            profiles__data-science__default__workspace.yaml: |-
              apiVersion: saw.redhat.com/v1alpha1
              kind: Workspace
              metadata: {name: default}
              spec: {inference: {provider: nvidia, model: nvidia/nemotron-3-super-120b-a12b}}
            profiles__data-science__default__providers.yaml: |-
              apiVersion: saw.redhat.com/v1alpha1
              kind: Providers
              metadata: {name: default, profile: data-science}
              spec:
                providers:
                  - name: nvidia
                    type: nvidia
                    credentialRef: inference-main
      instance:
        workspaces:
          - profileRef: {name: data-science, configMapRef: {name: alice-profiles}}
            credentialBindings:
              inference-main:
                secretRef: {name: nvidia, key: api_key}
      # Omit this to inherit installer.defaultRelease. Set it only for an
      # approved canary or exceptional tenant release.
      installerReleaseRef: saw-example-2026-09
      guest:
        enabled: true
        cores: 4
        memoryGi: 8
        runStrategy: Halted
```

Copy the tenant item, give the new user a different SAW name and immutable OIDC
subject, and change the display username, Vault record, profile, and instance as
needed. Each item becomes an independently reconciled Argo Application and an
isolated namespace. Do not change an existing tenant's issuer, subject, or SAW
name in place.

Commit and push to the revision Argo watches. The source revision must exist on
the remote because both the parent application and generated tenant Applications
fetch it from Git. Then reconcile the pattern:

```bash
./pattern.sh make install
oc get applicationset -n saw-system saw-tenants
oc get application -n openshift-gitops
```

For a manual deployment, use the same reviewed values and install only the parent
chart; never manually install a generated tenant Application:

```bash
helm upgrade --install saw-blueprint charts/saw-blueprint \
  --namespace saw-system --create-namespace \
  -f tenant-blueprint-values.yaml

oc get applicationset -n saw-system saw-tenants
oc get namespace -l app.kubernetes.io/managed-by=argocd
```

Do not manually create tenant namespaces, VMs, DataVolumes, or provider Secrets:
Argo owns desired Kubernetes resources and ESO owns Secret contents. To change a
profile or instance, change that tenant's reviewed Git values; the VM receives the
allowlisted projected inputs without a Kubernetes API token.

Provider credentials are user-scoped. Set `vaultPrefix: saw/alice` (or let the
standalone renderer derive `saw/<username>` from the platform prefix). ESO reads
`saw/alice/providers/nvidia` and creates `Secret/nvidia` in Alice's isolated
namespace. Profile bindings select which provider Secrets the VM mounts; they do
not create a shared profile Secret.

Use the disposable live-cluster isolation gate after onboarding two tenants:

Do not run the legacy root `make test` headless quickstart against an Option A
GitOps deployment; it creates its own sandbox. Use `make saw-test-fast` for
offline contracts and the disposable tenant integration gate below for live
GitOps isolation checks.

```bash
make saw-test-tenant-integration \
  SAW_TEST_ALICE_NAMESPACE=saw-... \
  SAW_TEST_BOB_NAMESPACE=saw-... \
  SAW_TEST_APPROVED_DATASOURCE=<approved-datasource> \
  SAW_TEST_PROFILE_CONFIGMAP=profiles \
  SAW_TEST_PROFILE_KEY=profiles__data-science__default__workspace.yaml \
  SAW_TEST_ALICE_APPLICATION=saw-... \
  SAW_TEST_BOB_APPLICATION=saw-... \
  VAULT_ADDR=https://vault.example.com VAULT_TOKEN=<disposable-test-token>
```

The test checks cross-tenant denial, Vault role separation, ESO rotation, and
Argo reconciliation. It temporarily rotates a provider value and restores it;
run it only against disposable test credentials.

#### Supported inference providers

| Provider | Key | Example model |
|---|---|---|
| NVIDIA | `nvidia` | `nvidia/nemotron-3-super-120b-a12b` |
| OpenAI | `openai` | release-specific |
| Anthropic | `anthropic` | release-specific |

The current guest reconciler supports these single-key provider types in newly
owned workspaces. Provider metadata is reviewed in profiles; only the credential
value comes from Vault/ESO.

### Validate tenant provisioning

```bash
# Validate schema/chart contracts before committing.
make saw-test-fast
make saw-render-gitops

# Confirm Argo produced one tenant Application per entry and each namespace/root clone.
oc get applicationset -n saw-system saw-tenants
oc get application -A -l app.kubernetes.io/part-of=openshell-saw
oc get namespace -l app.kubernetes.io/managed-by=argocd
oc get datavolume,vm -A

# Run the disposable two-tenant isolation/ESO/Argo gate only with disposable credentials.
make saw-test-tenant-integration SAW_TEST_ALICE_NAMESPACE=saw-... SAW_TEST_BOB_NAMESPACE=saw-... \
  SAW_TEST_APPROVED_DATASOURCE=<approved-datasource> SAW_TEST_PROFILE_CONFIGMAP=profiles \
  SAW_TEST_PROFILE_KEY=profiles__data-science__default__workspace.yaml \
  SAW_TEST_ALICE_APPLICATION=saw-... VAULT_ADDR=https://vault.example.com \
  VAULT_TOKEN=<disposable-test-token>
```

### Delete

```bash
# Remove a tenant by removing its Git entry, committing, and reconciling Argo.
# Tenant resources intentionally use retain/no-prune protections; handle data
# retention and approved teardown according to your platform policy.

# Uninstall the parent pattern only when all tenant data has been handled.
./pattern.sh make uninstall
```

## Repository structure

```
.
├── Makefile                          # Root Makefile
├── Makefile-saw                      # Tenant/image validation and rendering targets
├── values-global.yaml                # Pattern config (name, ArgoCD, secret loader)
├── values-prod.yaml                  # ClusterGroup (operators, subscriptions, applications)
├── overrides/
│   └── saw-blueprint.yaml            # Git-tracked tenant blueprint defaults
├── charts/                           # ArgoCD-managed Helm charts
│   ├── saw-blueprint/            # Parent GitOps chart: shared images + ApplicationSet
│   ├── openshell-saw/            # Per-user namespace, ESO inputs, VM, installer release
│   └── saw-bom/                  # Profile and legacy installer packaging inputs
├── guest/                            # Image build, guest service, and qualification tooling
├── installer/                        # Versioned apply_bom.py implementation
├── examples/saw/                     # Enrollment, BOM, image, and instance contracts
├── tests/saw/                        # Tenant isolation and chart-contract tests
├── cli/                              # Blueprint rendering CLI
├── pattern.sh                        # VP utility container wrapper
└── ansible.cfg                       # VP ansible config
```

## References

- [NVIDIA Secure Agent Workspace Reference Design](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/)
- [OpenShift Virtualization Reference Implementation](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/openshift-virtualization-reference-implementation.html)
- [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)
- [Red Hat Validated Patterns](https://validatedpatterns.io/)
- [Red Hat Build of Keycloak](https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/)

## Technical details

### Security model

The tenant path implements layered isolation:

1. **VM-level isolation** — Each user gets a dedicated KubeVirt VM (one VM per user, no shared agent process space)
2. **Immutable enrollment identity** — Namespace identity derives from the OIDC
   issuer, immutable subject, and SAW name; display usernames do not authorize access.
3. **Scoped Vault/ESO access** — A tenant ServiceAccount can read only its own
   provider records; ESO writes only tenant-local Secrets.
4. **Shared-image protection** — Argo has narrowly scoped clone access to a named
   DataSource; tenants cannot modify the shared golden image.
5. **Tokenless guest** — The guest VM mounts only allowlisted ConfigMaps and Secret
   keys read-only and has no Kubernetes API token.

## Tags

| Field | Value |
|---|---|
| **Title** | Secure Agent Workspace |
| **Description** | Deploy isolated, per-user AI agent sandboxes on OpenShift Virtualization |
| **Industry** | Cross-industry |
| **Product** | Red Hat OpenShift |
| **Use case** | AI agent sandboxing, secure coding environments |
| **Partner** | NVIDIA |
