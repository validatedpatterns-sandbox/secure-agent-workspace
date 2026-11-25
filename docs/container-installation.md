# Installing container workspaces

Container mode adds a backend to the existing SAW installation and profile
model. VM remains the default. The [architecture](container-workspaces.md)
describes components, trust boundaries and data paths; this page describes
operator inputs and installation. There is no additional SAW workspace CRD.

## Choose the installation owner

| Entry point | Desired configuration | Component lifecycle |
|---|---|---|
| Validated Pattern | Static entries in `overrides/saw-users.yaml`, with `projection.enabled: true` | Pattern owns the root chart; its ApplicationSet and Argo own container component applications. |
| Standalone Make | Operator-owned values file; `DEPLOYMENT_MODE=container` | Helm owns one root `saw-users` release; ApplicationSet and Argo own component applications. Developer Hub is not required. |
| RHDH self-service | Authenticated create/update/delete request plus operator-provided `portal.containerSites` | Existing portal pipelines and generator own the registration; Argo uses the same component charts. |

Use one entry point per registration. Do not Helm-install a workspace already
owned by the pattern or RHDH. Both VM and container users can coexist in a
`saw-users` installation. Each registration has one backend; it is not an
in-place VM-to-container migration setting.

## Shared platform prerequisites

Start with the SAW platform services: Keycloak/owner accounts, governance,
Vault and External Secrets, image availability and OpenShift GitOps. The
container Make path uses GitOps even when the root chart is installed manually.
It does not require KubeVirt for its workload. Keep KubeVirt installed when also
hosting VM workspaces.

Additional requirements:

- OpenShift with enforced `AdminNetworkPolicy` and native
  `ValidatingAdmissionPolicy`; the baseline is OpenShift 4.22+ with OVN-Kubernetes.
- The pinned stock Agent Sandbox controller and `agents.x-k8s.io/v1beta1` API.
  Install [charts/agent-sandbox](../charts/agent-sandbox) once per cluster, or
  reuse a compatible platform-owned installation. Do not adopt an existing
  release or replace its CRDs from a per-workspace install.
- Argo CD ApplicationSet plugin generators, a project permitting the configured
  destinations/resource kinds, and permission for Argo to manage the workload,
  control, UI and history namespaces. The standalone projector's namespace is
  separate from Argo CD and labelled `argocd.argoproj.io/managed-by`.
- RWO storage for gateway state, workspace data, the controller ledger and the
  tool gate's audit log. With [audit receipts](#audit-receipts), also a shared
  filesystem class for the audit exchange.
- Reachable DNS, Kubernetes API, trusted OIDC issuer, governance, registry and
  approved provider endpoints. No cluster addresses are configured: see
  [Network access and storage](#network-access-and-storage).
  Workspaces share one AdminNetworkPolicy priority (each policy selects only
  its own namespace); enrollment refuses a workspace if any other policy
  covering its namespace comes at or before it.
- `oc`, Helm 3 and `uv` on the installation machine. Provider credentials stay
  in Vault; local files and Git contain references and public configuration.

Argo CD can retain an older list of API versions after the stock Agent Sandbox
CRD is installed. For a generated gateway Application, the parent supplies the
two API versions used by its Helm chart when the parent, gateway and identity
charts share one immutable revision. Mixed revisions retain normal Helm
discovery. The identity Job reads the live API
server over verified TLS and checks the group, version, resource, kind and scope
of both Sandbox and AdminNetworkPolicy before creating or projecting any keys.
Missing discovery stops identity bootstrap. The policy chart also applies the
actual AdminNetworkPolicy objects. Direct gateway Helm installs keep their
existing capability checks.

If the cluster uses a private CA, configure client trust with a combined bundle
containing the normal system roots **and** the independently verified cluster CA.
For example, set `SSL_CERT_FILE` to that combined file for Python/`uv` commands.
A cluster-only bundle removes public trust and can break dependency downloads;
do not disable certificate verification to work around this.

For a platform that does not already own Agent Sandbox, its manual installation
is:

```sh
helm upgrade --install agent-sandbox charts/agent-sandbox \
  --namespace agent-sandbox-system --create-namespace \
  --set enabled=true --wait
```

For a GitOps platform, declare the same chart as a platform Application.
Provision its destination namespace `agent-sandbox-system` in the cluster group
or enable `CreateNamespace=true` on that Application. The Helm command above
creates the namespace with `--create-namespace`. The chart
source lock pins the upstream manifest and controller digest. Removing an
individual workspace must not uninstall this cluster-wide dependency.

## Public inputs and credential references

For Kata workload placement, follow the [Kata installation and Developer Hub guide](kata-workspaces.md). Both modes use the same Kubernetes lifecycle and workspace BOM.

The same site object is used as `containerSites.<owner>` for static installs or
`portal.containerSites.<owner>` for RHDH. It is administrator-owned, not a form
field. The component wiring (namespaces, service accounts, SANs, the
workspace egress policy, governance endpoint, enrollment build namespace,
resources and relay Keycloak settings) defaults in
[`siteDefaults`](../charts/saw-portal-container/values.yaml); a site sets only
what differs, and its values win (maps merge, lists replace). Start from the
component charts' values and schemas:

| Site input | Contents / source |
|---|---|
| `subject` | Resolved Keycloak subject UUID matching the owner. Static inputs supply it explicitly; RHDH resolves the authenticated owner and requires a matching site. |
| `stack.identity` | Pinned revision and [identity chart values](../charts/saw-kubernetes-identity/values.yaml): installation identity, gateway SANs, stock generator/helper images and the bootstrap's egress (`network.bootstrapEgress`, DNS by default). Administrator sessions use the VM's shared temporary-identity mechanism; no administrator certificate or renewal input is supplied. |
| `stack.policy` | Pinned revision and [admission/network values](../charts/saw-runtime-policies/values.yaml): runtime namespace, service accounts, explicit egress and priority. |
| `stack.gateway` | Pinned revision and [gateway values](../charts/openshell-saw-kubernetes/values.yaml): stock gateway/driver images, storage, OIDC and network configuration. |
| `stack.audit` | Pinned revision and [audit values](../charts/saw-audit-writer/values.yaml): history/exchange storage classes, image and owner identity. Targets derive from the BOM. |
| `governanceNamespace` | Shared governance location (default `openshell-agents`); the gateway's interceptor endpoint and egress follow it. |
| `automaticEnrollment` | `enabled` (enrollment runs only when `true`), pinned helper image/revision, build namespace, resource limits, approved profile digests and reviewed boundary reference. |
| `automaticEnrollment.relay` | Pinned relay chart revision, issuer (defaults to the cluster's Keycloak route), Keycloak namespace and realm registrar Secret **name**, and egress (DNS and HTTPS by default). See [relay values](../charts/saw-workspace-relay/values.yaml). |
| `profileImageOverrides`, `profileBoundaries` | Optional per-profile pinned image overrides and reviewed boundary `reference`. Changing the profile requires its own approval. |
| `imagePull` | Optional namespace and ImageStream names for access to an OpenShift internal registry. |
| `customInferenceURL` (per user) | `custom-inference` only: the owner's OpenAI-compatible base URL (HTTPS, port 443, ending `/v1`), from the portal form or the user's entry in `overrides/saw-users.yaml`. Its host must be the only endpoint in `overrides/governance-profiles/custom-inference.yaml`, where OpenShell sends the API key; the runtime controller otherwise refuses the provider (`ProviderProfileMismatch`). |

RHDH offers **Container** on the create form when `portal.deploymentModes`
includes `container` and at least one configured owner site has a catalog profile
in `automaticEnrollment.approvedProfiles`. The form lists the union of those
profiles. The registration pipeline checks the signed-in owner's own site and
approved profile. For a first registration, pin the reviewed profile digest
and keep `automaticEnrollment.enabled: false` until the operator reviews
the live foundation. Static GitOps and Make can start that review without an
approved profile digest.

The portal checks the current Keycloak subject before changing a container's
registration or Vault credentials. Configure `portal.adminSubjects` with the
immutable Keycloak subject for each portal administrator who may act for another
owner. The portal Task needs the existing read-only directory client projection
`saw-generator-keycloak` when container sites are enabled.

### Prepare large images on cold nodes

The pinned stock OpenShell driver rolls back a sandbox whose bootstrap remains
unfinished for five minutes. A slow first image pull can consume that entire
window. Check cold nodes when qualifying a profile. For large images, install
the optional `charts/saw-image-cache` chart through the clustergroup before
creating workspaces. Give it the same immutable digests selected by the BOM
and site overrides. [Pinned driver](https://github.com/opendatahub-io/openshell/blob/305c8b3d7bbdb97a6f2f7264c3ad43b0087c307f/crates/openshell-driver-kubernetes/src/driver.rs#L284)

```yaml
# Site values
clusterGroup:
  namespaces:
    saw-image-cache:
      operatorGroup: false
  applications:
    saw-image-cache:
      name: saw-image-cache
      namespace: saw-image-cache
      path: charts/saw-image-cache
      extraValueFiles:
        - /overrides/workspace-image-cache.yaml
```

```yaml
# overrides/workspace-image-cache.yaml
enabled: true
images:
  - <approved-registry>/<workspace-image>@sha256:<64-hex-digest>
nodeSelector:
  kubernetes.io/os: linux
```

Kubelet pulls the images as read-only OCI image volumes. The DaemonSet runs a
separate nonroot holder with an immutable image, no service-account token,
dropped capabilities, a read-only root filesystem and no pod network access.
The workload images are never executed by the holder. Set `imagePullSecrets`
to authorized namespaced references for a private registry. For OpenShift
internal images in another namespace, grant the holder service account only
`get` on the required `imagestreams/layers` resource names.
[Image volume behavior](https://v1-35.docs.kubernetes.io/docs/concepts/storage/volumes/#image)

```sh
oc -n saw-image-cache rollout status daemonset/saw-image-cache --timeout=30m
oc -n saw-image-cache get daemonset/saw-image-cache -o json |
  jq -e '.status.desiredNumberScheduled > 0 and
         .status.numberReady == .status.desiredNumberScheduled and
         .status.updatedNumberScheduled == .status.desiredNumberScheduled'
```

Confirm that the ready holders cover every node eligible for the workload.
Match workload selectors and tolerations, and recheck after adding nodes or
changing digests. Each node needs space for the selected images. Keep the
holder running while the profile is in use.

### Keycloak registration setup

No manual step. With `relayProvisioner.enabled` (on in `values-prod.yaml`),
the `openshell-keycloak` chart runs a `saw-relay-provisioner` Deployment in the
Keycloak namespace. It uses the operator's `<keycloak>-initial-admin` Secret to
create a confidential service account with only the realm-management
`create-client` permission, registers an administrator-defined client scope
`saw-workspace-relay` for the OpenShell audience and user role, and allows that
scope for authenticated dynamic registration. It keeps the credential in the
`saw-relay-provisioner` Secret, which it creates itself so a GitOps self-heal
cannot clear it, and re-verifies every five minutes. Set
`automaticEnrollment.relay.keycloakProvisionerSecret: saw-relay-provisioner`
and use a full Git commit for `automaticEnrollment.relay.revision`. For an
issuer with a private CA, set `relayProvisioner.caBundle`.

The registrar can create clients in the workspace realm. The Job enforces the
registration-specific client name. Protect the registrar Secret and restrict who
can schedule Jobs in its namespace. The cleanup Job mounts only its script and
uses its service account to read the individual registration receipt.

Relay Jobs use the registration API to create one client and retain its
per-client registration access token in the Keycloak namespace for deletion.
An ambiguous creation without a registration receipt requires administrator
recovery of that exact client. A client ID collision fails closed. The browser
Pods receive only their own login/forwarding material.

The Kubernetes runtime and governance image workflows run pull-request builds
with read-only repository access. Only main-branch publication and manifest
merge jobs receive package-write permission.

### Admission and upgrade

Supply digest-pinned images for enabled sandbox slots through the shared BOM
or its site image overrides. The composition derives the allowed slot image,
runtime bootstrap, supervisor command and per-slot claims from those inputs.
The five admitted Pod classes are the gateway StatefulSet, Sandbox workload,
supervisor, gate-preparation Job and audit-forwarder ReplicaSet. Unknown Pods,
foreign Secret projections and in-place executable changes are denied.
The gateway can remove scheduling gates. It can create internal boundary
Services and immutable Pod-owned bootstrap Secrets. Argo installs the stock
network fences and the gateway can only read them. The static projector may
create only its named Opaque plugin credential in the two designated namespaces.

Re-review and capture the revised admission policies, bindings, gateway Role
and network fences during foundation installation. Existing published
boundaries and compiled plans reference the old specifications. Qualify a new
registration before migrating an existing installation. For registrations made
with the old relay scheme, retire the old client with the old installation's
cleanup procedure before replacing its credentials.

Component `values` accept the composition placeholders `@OWNER@`, `@SUBJECT@`,
`@INSTALLATION@`, `@RUNTIME@`, `@TRUSTED@`, `@ARCHIVE@`, `@UI@` and `@DOMAIN@`.
The composition substitutes these as data; it does not evaluate user input as
Helm templates. Do not author `targets`, `enrollment`, `providerPolicy` or relay
subjects manually; the common projector and trusted bootstrap derive them.

The relay membership Job reads Pod identities and updates the named public
client-trust Secret before connecting to OpenShell, so it reaches the
Kubernetes API like the other platform pods
([Network access and storage](#network-access-and-storage)). The gateway can
create the workspace before the reconciler grants the owner its administrator
role. The binding Job waits up to 210 seconds after authentication for both
observations, pins the workspace UUID once observed, and rejects a changed UUID
or unexpected owner role. The browser relay has no Kubernetes token or
trust-write RBAC. Changing the relay inputs creates a new input-hashed binding
Job through GitOps.

Public trust publication is asynchronous: the Kubernetes Secret volume must
refresh, then the stock gateway must reload it. Initial TLS failures, including
`BadSignature` while an older temporary CA is still mounted, can occur during
this interval. Keep the configured bounded authenticated readiness wait; do not
disable certificate verification. Confirm a subsequent successful operation and
fresh controller progress. Persistent errors or an exhausted wait are failures,
not evidence of a harmless delay.

Static registration shape, to merge with the complete operator site values:

```yaml
global:
  repoURL: https://github.com/your-org/secure-agent-workspace.git
  targetRevision: <reviewed-commit>
  vpArgoNamespace: vp-gitops
  clusterDomain: cluster.example.com # ingress is apps.cluster.example.com
projection:
  enabled: true
  # Defaults to <Argo namespace>-applicationset-controller; set it only for
  # an instance named differently.
  # applicationSetControllerLabels:
  #   app.kubernetes.io/name: <applicationset-controller-pod-label>
users:
  - name: alice
    ownerSubject: <keycloak-subject-uuid>
    registration: <16-lowercase-hex-characters>
    # installationID: optional; defaults to the portal's
    #   uuid5(NAMESPACE_URL, "urn:saw:portal:<name>:<registration>")
    vaultPrefix: secret/data/hub/saw-alice
    profiles: [data-science]
    pruneOnRemove: true
    intentGeneration: 1
    lifecycleVersion: 1
    desiredState: Running
    restartGeneration: 1
    initialModelInputs: # public selectors from the selected BOM's catalog
      inference.model: <approved-model>
      inference.cuda_model: <approved-model>
    modelInputs: # initially equal to initialModelInputs
      inference.model: <approved-model>
      inference.cuda_model: <approved-model>
    values:
      deployment: {mode: container}
containerSites:
  alice:
    subject: <same-keycloak-subject-uuid>
    # Complete stack, network, storage, provider and relay inputs from the table.
    automaticEnrollment:
      enabled: false # foundation review; enable after approval
      # Complete pinned helper, resources and relay inputs from the table.
```

This shows the input contract, not a runnable site with omitted fields. Generate
a unique registration and keep it stable for the installation. Omit
`installationID` to use the derived value; set it only to keep an existing one.
Never reuse an old registration to adopt retained storage or credentials.

Enrollment also pins the initial compiled plan. A runtime/compiler change that
changes that plan cannot be authorized merely by changing an image digest,
source revision or intent generation. An in-place operator reapproval/migration
workflow is not implemented. Use the documented deletion and a new registration
for such a change; runtime/workspace storage is removed, while the separate
audit history remains retained. Do not remove the plan check or edit the
immutable enrollment publication. Ordinary supported public-model updates use
the existing model-input lifecycle and do not require a new registration.

For an internal-registry runtime image, `automaticEnrollment.buildNamespace`
identifies its build namespace. The enrollment and preparation pull grants are
restricted to the image stream named by the configured digest-pinned image.

The selected BOM determines provider Secret names and fields. For example, with
the default NVIDIA-backed `data-science` profile, store its key in
`secret/data/hub/saw-alice/inference` as `api_key`. Configure any
additional enabled provider inputs under the same per-user prefix. RHDH uses
the existing request-to-Vault pipeline; standalone operators use their normal
Vault provisioning. Neither the Make helper nor projector loads raw keys.

Native OpenAI, Anthropic and NVIDIA inference use the same provider profiles as
VMs. Anthropic uses its Messages protocol; NVIDIA model selectors preserve the
vendor/model slash. Select the provider in the approved BOM, then reapprove its
destination and profile inputs through the normal enrollment path. See
[provider qualification](provider-driver-qualification.md) for the BOM shape,
probe commands and current live-test limits.

## Pin the built components

Use published release digests or follow the
[candidate build commands](container-images.md#building-a-container-backend-candidate)
to build and publish the runtime and governance images into the internal
registry. A green PR image build does not publish an image or deploy it.
Record the source SHA and both output digests before configuring the site.
For the shipped data-science notebook, also run the
[notebook image preparation target](container-images.md#prepare-the-data-science-notebook-for-container-workspaces)
before any of the three container registration paths. Its output supplies the
notebook image and scoped pull values used in the profile approval below.

| Input | Value / consumer |
|---|---|
| `global.targetRevision` | Reviewed site/chart Git commit. The Make checkout must contain the same chart and shared projector code. |
| `containerSites.<owner>.automaticEnrollment.revision` | Full reviewed Git SHA for controller and composition charts. Use the same field under `portal.containerSites` for RHDH. |
| `automaticEnrollment.image` | Runtime image digest. The projector passes it to enrollment, gate/harness/model preparation, the reconciler and relay membership binding. Do not hand-edit their generated images. |
| `automaticEnrollment.buildNamespace` | Namespace containing the runtime ImageStream; charts grant only the named image's pull access to their service accounts. |
| `stack.<component>.revision`, `automaticEnrollment.relay.revision` | Reviewed chart revisions for each component and the browser relay. |
| Governance Application `source.targetRevision` and Helm `image` | Reviewed governance chart revision and governance image digest. Governance is a shared platform dependency, not a per-workspace image override. |

For an internal governance image, include its pull grant in the platform GitOps
configuration. The current governance Deployment uses the `default` service
account. Replace both namespace placeholders; the grant permits only this
ImageStream. Runtime pull grants are generated by the workspace charts.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: governance-image-pull, namespace: <build-namespace>}
rules:
  - apiGroups: [image.openshift.io]
    resources: [imagestreams/layers]
    resourceNames: [governance-interceptor]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: governance-image-pull, namespace: <build-namespace>}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: governance-image-pull}
subjects: [{kind: ServiceAccount, name: default, namespace: <governance-namespace>}]
```

Keep stock gateway, supervisor, OpenClaw, proxy and audit images at their approved
pins unless those components are deliberately being changed. The standalone
`projection.image` is a separate Python helper; its shipped pin does not need to
change merely because the runtime image changed.

Commit these public pins to the operator's configuration repository, then use
its normal Argo sync or the documented Make entry point. Wait for component
rollouts before capturing the boundary below. Changed helper inputs produce
new immutable Job names. A changed enrolled boundary still fails closed;
replacing its approved hash does not replace the immutable enrollment or
authorize adopting different resource identities.

## Standalone installation and first-site approval

Save the complete public configuration as `container-users.yaml`, then:

```sh
export DEPLOYMENT_MODE=container
export OPENSHELL_SAW_NAME=alice
export SAW_USERS_VALUES_FILE="$PWD/container-users.yaml"
export SAW_INSTALL_NAMESPACE=saw-workspaces
make saw-create
```

The helper renders the chart before making changes, checks the target ingress
domain and required APIs, rejects a foreign installation identity and installs
`workspace-alice`. It creates an Argo-managed installation namespace if absent;
it does not relabel an existing namespace. With enrollment disabled the result
is `AwaitingApproval`, **not** a running-workspace claim. Argo reconciles the
foundation while the application sandbox remains absent.

On a cold static installation, the projector identity Job and ApplicationSet
start asynchronously. A missing plugin Secret error can precede identity
publication; the ApplicationSet then recovers on its automatic retry. Wait for
its `ParametersGenerated=True` condition and healthy foundation Applications
before reviewing the boundary. To verify creation, inspect the generated
Application's `metadata.ownerReferences` in the Argo namespace. Its controller
reference must match the ApplicationSet name **and UID**. Check the child
Application's sync and health independently of its downstream workspace Pods
and PVCs. Record any failed bootstrap attempts separately from the final
installation result.

Wait for foundation Applications to be Synced/Healthy. Inspect the exact public
objects and normalized boundary separately:

```sh
oc get applications -n vp-gitops -l openshell.pattern/owner=alice
uv run --locked python scripts/portal-container/inspect-boundary.py \
  --owner alice --registration "$REGISTRATION" \
  --installation-id "$INSTALLATION_ID" \
  --governance-namespace "$GOVERNANCE_NAMESPACE" \
  --api-server "$EXPECTED_API_SERVER" --show-objects > boundary-objects.json
uv run --locked python scripts/portal-container/inspect-boundary.py \
  --owner alice --registration "$REGISTRATION" \
  --installation-id "$INSTALLATION_ID" \
  --governance-namespace "$GOVERNANCE_NAMESPACE" \
  --api-server "$EXPECTED_API_SERVER" > boundary-reference.json
uv run --locked python scripts/portal-container/inspect-boundary.py \
  --owner alice --registration "$REGISTRATION" \
  --installation-id "$INSTALLATION_ID" \
  --governance-namespace "$GOVERNANCE_NAMESPACE" \
  --api-server "$EXPECTED_API_SERVER" --profile-digest
```

These commands read public objects and do not grant approval or read Secrets.
The RHDH create pipeline stays pending while the operator reviews a fresh container
registration. Its intent wait uses `portal.sandboxReadyTimeoutMinutes` (at least
10 minutes). Approve within this budget or the request fails. The VM provisioning
stage retains its 10-minute wait.

Review the resource specifications against the intended configuration. Put the
approved reference under `automaticEnrollment.reference` and enable enrollment
in the values file. Review the rendered BOM and put its digest under
`automaticEnrollment.approvedProfiles.data-science`; foundation mode requires
neither placeholder hashes nor a previously approved profile digest. Re-run
`make saw-create`. For a previously approved site,
enrollment can be enabled on its first install.

`approvedProfiles` hashes the exact rendered BOM ConfigMap data, including image
overrides and optional harness bundles. Recompute it when effective inputs differ;
a standalone approval applies to RHDH only when their rendered data is identical.
`harnessEnabled` controls optional `harnessRef` bundles. Enrollment attaches the
audited tool gate independently to each supported agent sandbox.

The projector reads the immutable enrollment and relay publications; no one
copies generated intent or resource UIDs back into Git. Argo then enables the
reconciler, prepared mounts and owner-only browser relay. `make saw-create`
waits for the same current-generation, BOM and browser-readiness conditions as
RHDH. During bootstrap a missing enrollment or relay subject is expected. Both
projectors can read their existing generated Application to distinguish bootstrap
from a lost publication. For the same owner, registration and installation, they
retain the exact prior child parameters if an enrolled binding or published relay
subject disappears. Other declared owners continue to update. An unreadable
child, malformed enrollment or ownership mismatch fails projection. Removal of
a declared static owner remains an intentional prune. When the last static
container entry is removed with projection still enabled, only the empty
projector configuration remains for that backend. Argo can prune its children
without enabling empty-application sync or retaining any projector RBAC. Static sites must sync the
new namespaced Role granting GET on their named children before using the updated
projector. No migration of ApplicationSets or child ownership is required.
If the required Keycloak owner lookup fails, the shared VM/container projection
also stops until lookup recovers. An unavailable identity service must not be
interpreted as a missing owner or an empty membership list.

```sh
make saw-status # JSON readiness and authenticated UI links
make saw-delete # foreground deletion of this owned registration
```

The shared installation namespace and retained audit history are not removed
by per-workspace deletion. Provider material provisioned directly in Vault is
operator-owned; deleting the standalone Helm release does not erase it.

## Pattern and RHDH enablement

### Minimal static entries

The pattern reads two files for `saw-users`. The platform admin sets the
cluster-wide container settings once in `overrides/saw-container-defaults.yaml`
(`projection` and `containerDefaults`, the site every container user gets).
Users only add an entry to `overrides/saw-users.yaml`:

```yaml
users:
  - name: alice
    ownerSubject: <keycloak subject>   # make keycloak-user-info KC_USER=alice
    profiles: [custom-inference]
    vaultPrefix: secret/data/hub       # credential base path
    values:
      deployment: {mode: container}
```

The chart fills in the rest; an explicit value always wins:

| Field | Default |
|---|---|
| `registration` | `sha256("<name>:<generation>")[:16]`; to start over, remove the entry and let Argo delete it, then add it back with a higher `generation` (default 1); two generations of a user cannot overlap |
| `installationID` | `uuid5(NAMESPACE_URL, "urn:saw:portal:<name>:<registration>")` |
| `vaultPrefix` | base path + `/saw-<name>`, the same for every generation; credentials go under it (for example `.../inference`) |
| `pruneOnRemove`, `intentGeneration` | `true`, `1` |
| site | `containerDefaults`, overlaid by `containerSites.<name>`; `subject` is the user's `ownerSubject` |
| chart revisions | Reviewed sites: none. Set `stack.*.revision`, `automaticEnrollment.revision` and `relay.revision` to full commit SHAs; the workspace chart and preflight reject a branch or a missing revision. `autoApprove` sites: `global.targetRevision`, so they follow the pattern's branch like VM users. |

Enrollment stays off unless a site sets `automaticEnrollment.enabled: true`
(and `autoApprove` defaults to `false`): a new workspace deploys its foundation and waits for
the reviewed flow below. After the review, set `enabled: true`, the reviewed
`reference` and the `approvedProfiles` digest under
`containerSites.<name>.automaticEnrollment`, and pin its chart revisions to
full SHAs.

Development and demo clusters can skip the review by listing
`overrides/saw-container-demo.yaml` after `saw-container-defaults.yaml` in the
`saw-users` and `openshell-rhdh` `extraValueFiles`. It sets `autoApprove: true`:
the enrollment Job still runs its health, admission and network checks, then
publishes the boundary and BOM it observes instead of comparing them with a
reviewed `reference` and `approvedProfiles` digest. Later changes to an
enrolled boundary still fail closed; start a new `generation` to re-enroll.
`containerSites.<name>.automaticEnrollment.autoApprove: false` puts one user
back on the reviewed flow. Never list the demo file in production values.

**Upgrading from the credential-proxy controller.** Container workspaces
enrolled before OpenShell-native providers cannot be upgraded in place: their
approved boundary lists the removed proxy objects, and their controller state
records proxy-era providers. They report `ReenrollRequired` and make no
changes. Re-enroll each one by starting a new generation (`generation: <n+1>`
in `overrides/saw-users.yaml`, or a new request in the portal), copying its
credentials to the new registration's Vault path first. With
`pruneOnRemove` (the default) the old registration's namespaces are removed.

Before install, `make saw-init` checks the cluster for these entries: OVN-Kubernetes,
AdminNetworkPolicy and ValidatingAdmissionPolicy and an anonymous pull of the
runtime image from inside the cluster. With [audit receipts](#audit-receipts) it
also needs a shared-filesystem (ReadWriteMany) StorageClass for the audit
exchange, and creates `saw-shared`, the class name the charts use, as a copy of
it. `pattern-install` and `make saw-create DEPLOYMENT_MODE=container|kata` run it
first.

With receipts and no ReadWriteMany class, `saw-init` stops and lists the options; it
creates nothing unless asked. Install a real shared filesystem first (ODF
CephFS, EFS, vendor NFS) and `saw-init` only adds its `saw-shared` copy. Two
opt-ins:

- `SAW_SHARED_STORAGE=efs` offers to create EFS on AWS (filesystem, mount
  targets, security group, the AWS EFS CSI Driver Operator and StorageClass
  `saw-efs`) with working `aws` credentials.
- `SAW_SHARED_STORAGE=nfs`, for development and demo clusters only, creates a
  privileged NFS server Pod on a default-class volume in namespace `saw-nfs`,
  the upstream NFS subdirectory provisioner (with a cluster-scoped role) and
  StorageClass `saw-nfs`, then verifies a read/write mount. It is a single Pod
  with no replication.

A container entry without `ownerSubject` waits: it renders nothing and is listed
in the `saw-users-awaiting-owner` ConfigMap, so other users still sync. Set it
from `make keycloak-user-info KC_USER=<name>` once the account exists. With
`make saw-create`, an omitted `ownerSubject` is resolved from Keycloak.

For static pattern users, put the same values under `overrides/saw-users.yaml`,
enable `projection`, commit them and let the existing `saw-users` Application
reconcile. Its namespace must be separate from Argo CD. VM users keep their
existing Applications and owner-resolution behavior. A container user's
resolved `ownerSubject` does not enable an owner override for VM users.

For RHDH, use `portal.containerSitesSecretName` when the site includes owner
subjects or cluster resource identifiers and the pattern repository is public.
Create a Secret in `saw-portal` with a `container-sites.json` key. Its JSON
value is the same owner-to-site map used by `portal.containerSites`. Set only
the Secret name in the cluster's values file. The create pipeline checks the
owner and selected profile against this map. The form shows catalog profiles
for each enabled site mode, so an unapproved owner can see a choice but cannot
register it.

```yaml
clusterGroup:
  applications:
    openshell-rhdh:
      overrides:
        - name: portal.containerSitesSecretName
          value: saw-portal-container-sites
          forceString: true
```

### Approve the first RHDH container profile

1. **Review the profile before offering it.** From the reviewed chart revision,
   render the public BOM with the effective inputs for this owner. Set
   `profiles: [data-science]` in `bom-values.yaml`. Include its effective
   `imageOverrides`, `webSearch.enabled` and `harnessEnabled`, matching the
   intended workspace. Inspect the rendered providers, models, sandbox images
   and harness files. Hash the ConfigMap's `data` with the same function the
   live verifier uses.

   ```sh
   helm template review charts/saw-bom -f bom-values.yaml \
     --show-only templates/configmap-bom.yaml > rendered-bom.yaml
   less rendered-bom.yaml
   PROFILE_DIGEST=$(PYTHONPATH=kubernetes-runtime uv run --locked python -c \
     'import yaml; from saw_kubernetes.boundary import fingerprint; print(fingerprint(yaml.safe_load(open("rendered-bom.yaml"))["data"]))')
   printf '%s\n' "$PROFILE_DIGEST"
   ```

2. **Offer the approved profile through GitOps.** Merge the following fields
   into the owner's complete site in `overrides/saw-users.yaml`. Replace the
   two placeholders with the resolved Keycloak subject and the printed 64-hex
   digest. Keep the existing component, relay and policy settings.

   ```yaml
   portal:
     deploymentModes: [vm, container]
     pruneOnRemove: true
     containerSites:
       alice:
         subject: <resolved-owner-subject>
         automaticEnrollment:
           enabled: false
           approvedProfiles:
             data-science: <reviewed-profile-digest>
   ```

   Commit and push the site change. Wait for `openshell-rhdh` to sync that
   revision and for the Developer Hub Deployment to finish rolling out. Sign
   in as the owner, open **Create or update my agent workspace**, choose
   **Container** and **data-science**, supply the profile's requested
   credentials in the form, and submit. Argo generates a child Application
   after the portal's `register` task succeeds. The operator can then inspect
   the new registration while the pipeline waits for readiness.

3. **Verify the live BOM and approve enrollment.** For a portal registration
   the registry ConfigMap supplies the registration ID. The inspection tool
   derives the installation UUID. Set `OWNER`, `GOVERNANCE_NAMESPACE` and
   the expected cluster API URL before running:

   ```sh
   REGISTRATION=$(oc -n saw-portal get cm "saw-ws-$OWNER" -o json |
     jq -er '.data["user.json"] | fromjson | .vaultPrefix | split("/") | last | select(test("^[0-9a-f]{16}$"))')
   inspect_owner() {
     uv run --locked python scripts/portal-container/inspect-boundary.py \
       --owner "$OWNER" --registration "$REGISTRATION" \
       --governance-namespace "$GOVERNANCE_NAMESPACE" \
       --api-server "$EXPECTED_API_SERVER" "$@"
   }
   LIVE_DIGEST=$(inspect_owner --profile-digest) && test "$LIVE_DIGEST" = "$PROFILE_DIGEST"
   ```

   Continue only after the comparison succeeds. If it differs, review the
   effective inputs and the live BOM. Run `inspect_owner --show-objects` and
   review those specifications, then run `inspect_owner > boundary-reference.json`.
   Put that reviewed reference in the **same owner's** `automaticEnrollment.reference`,
   change `enabled` to `true` and commit the change to site Git within the
   configured approval timeout. Verify the create task reaches ready and open
   the owner-only chat. The audit and gate claims must be Bound on an
   RWX-capable filesystem for the audited workspace to run.

Keep `projection.enabled` off for the RHDH-generated child values. The portal
performs that projection. The Delete form and state actions use the backend
recorded in the registration.

## Updates and current limitations

Code rollout can be pinned per owner without changing their registration. The
operator sets `workspaceRevisions` in `saw-users` values (static/Make), or the same
map under `sawUsers.workspaceRevisions` in the RHDH chart:

```yaml
sawUsers: # RHDH values; omit this outer key for static/Make values
  workspaceRevisions:
    existing-owner: <full-existing-commit-sha>
    candidate-owner: <full-reviewed-candidate-sha>
```

Each pin must be a full lowercase Git commit SHA in the configured
`global.repoURL`. Unlisted owners continue using `global.targetRevision`. The
shared projector selects the revision for both the owner Application and its
children, for VM and container registrations. Direct static VM Applications
honor the same map. Forms and registration records cannot set these pins or
select a different repository. A recreated registration uses the operator's
current pin for that owner.

When chart and values live in the same Git repository, keep them on one Argo
source revision. Argo rejects different revisions of that repository for the
chart and a `$values` reference. Integrate the reviewed portal chart into the site
revision, or publish it as a separately versioned Helm artifact. Owner pins still
control the generated workload revisions.

Both RHDH and static projector parent Applications preserve Argo's two
controller-owned `pre-delete-finalizer.argocd.argoproj.io` finalizers (plain and
`/cleanup`) during comparison and sync. The exact-value JQ rule plus
`RespectIgnoreDifferences=true` prevents repeated parent self-heal from removing
hook state. Resource-deletion finalizers, source revisions and workload specs
remain managed and checked; this does not disable deletion hooks or pruning.

Pin existing owners before upgrading shared portal code when their child charts
must stay unchanged. The portal's chart revision and its generated workload
revisions are separate: retain the site's `global.targetRevision` fallback and
use the map to move only reviewed owners. A source pin does not approve a new
BOM, image, boundary or storage identity; those retain their normal checks.

Update public `modelInputs`, increment `intentGeneration` and
`restartGeneration`, then reapply through the same entry point. Keep
`initialModelInputs` and registration identity fixed. For stop/start, change
`desiredState` and increment `intentGeneration`; storage remains attached to the
registration. Do not switch an enrolled workspace back to foundation mode.

There is no additional upgrade controller. Argo reconciles pinned chart/image
changes; immutable preparation Jobs get input-derived revision names. An
enrolled boundary change requires deliberate approval, not automatic trust in
a newly observed hash. VM installation keeps its current signed installer,
live-input reconciliation and reboot path.

Administrator sessions are created per operation using the shared VM mechanism.
Their private material stays in memory-backed volumes; the charts grant the
controller and membership Job access only to their named public client-trust
Secret. No retained admin key, `adminDays` setting, renewal controller or operator
credential injection is needed. Server TLS and retained gateway identity remain
separate from this mechanism; a normal resync never rotates that identity.

VM guest commands
(`saw-vm-ssh`, installer logs and VM restart) remain VM-only. Container logs come
from the reconciler in `saw-ctl-<registration>` and the application Pods; lifecycle
changes use public intent or RHDH. See the architecture page's
[current boundaries](container-workspaces.md#current-boundaries) for the remaining
security and access limitations.

To reproduce the Pod admission regression on an enrolled container workspace,
use a kubeconfig authorized to impersonate its gateway and Agent Sandbox
controller. This requires running workload and supervisor Pods. The probes use
API-server dry-run, including a malicious template submitted as the legitimate
controller and an attempt to remove the workload’s role during an update.

```sh
python3 scripts/portal-container/check-pod-admission.py \
  --kubeconfig "$KUBECONFIG" --namespace "$RUNTIME_NAMESPACE" --gateway "$GATEWAY"
```

Each probe must report denial by the workspace Pod policy. An RBAC error,
missing API, or collision with an existing Pod fails the check.

The Task reads the Tekton-owned `tekton.dev/pipelineRun` Pod label through the
downward API to identify its credential reservation. If a pending writer disappears, inspect its PipelineRun and the owned
Vault generation before clearing the writer annotation. A missing holder fails
closed. A terminated failed run can be retried for the same registration.


### Interrupted creates and updates

RHDH reserves the registration before writing credentials. The catalog keeps
the owner component visible during publication. A terminal writer with an
incomplete reservation displays retry/delete instructions. A missing writer
requires operator diagnosis. On an interrupted update, GitOps continues to
project the last committed public configuration. Retry the create form with
all required inputs to finish the same registration. Vault writes to multiple
secrets are independent; an earlier write may already be visible to ESO.

The reconciler records the ID from a successful sandbox create before waiting
for readiness. It replays an interrupted create with the original request ID
on a Running pass. If shutdown encounters an outstanding create with no proven
receipt, its reason is `StartToRecoverSandboxReceipt`. Request start to recover
the receipt, then stop. Shutdown will never create a missing sandbox.

The intent CLI accepts `--restart-generation`. When updating with
`--previous-intent`, omitting the option preserves the previous value,
including absence on legacy intents. The value ranges from zero through the
intent generation and cannot decrease.

### Network access and storage

Container workspaces need no cluster addresses. Each workspace namespace
starts from default-deny, and its platform pods get only what they use:

- **Kubernetes API.** The gateway, controller, identity and enrollment Jobs,
  relay and projector carry the label `saw.redhat.com/kubernetes-api: allow`.
  An AdminNetworkPolicy (`saw-<registration>-kubernetes-api`, and one for the
  projector) lets those pods, and no sandbox pod, reach the control-plane
  nodes on port 6443. Its priority (70) comes after the runtime's own
  supervisor policy (51). On a hosted control plane, set
  `kubernetesApi.to` to the API addresses: `[{networks: ["<ip>/32"]}]`.
- **DNS.** The cluster DNS pods, selected by label.
- **OIDC issuer.** The gateway and relay may use HTTPS (TCP 443) to any
  address, because the issuer can sit behind a load balancer or an ingress
  virtual IP. The issuer URL defaults to the cluster's Keycloak route
  (`https://openshell-keycloak-ingress-saw-keycloak.apps.<clusterDomain>/realms/openshell`);
  set `stack.gateway.values.oidc.issuerUrl` and `automaticEnrollment.relay.issuer`
  together for another issuer.
- **Sandboxes** keep their own fences: OpenShell's workload policy and the
  runtime's supervisor AdminNetworkPolicy, which allows only the hosts the
  profile approves.

Rules you add to the egress lists (governance, a proxy) still apply; the lists
replace the defaults, so keep the DNS and HTTPS rules when you set one.

Storage needs no configuration either: volumes use the cluster's default
StorageClass, as upstream OpenShell does. Set
`stack.gateway.values.kubernetes.storage.className` or
`stack.audit.values.storageClass` in `containerDefaults` to use another class.

### Audit events and receipts

By default audit is best-effort, as in upstream OpenShell. The gateway and each
sandbox's supervisor export OCSF events (authentication, refused API calls,
network and request decisions) over OTLP/gRPC to the collector in
`openshell-agents` (`charts/saw-telemetry`, Red Hat build of OpenTelemetry).
Its debug exporter writes them to the collector's log; replace it with your
SIEM or log store in `charts/saw-telemetry/values.yaml`. Set
`telemetry.ocsfEndpoint: ""` in `containerDefaults` to turn export off.
OpenShell drops events it cannot export, and nothing waits for the collector.
OpenShell 0.1.6 does not export the agent's own tool calls; those are in the
tool gate's log below.

#### Audit receipts

By default the agent's tool gate checks every tool call against its policy,
asks for approval where the policy says so, and appends each decision to a
best-effort log on the sandbox's own audit volume (`/sandbox/.saw/audit`), as
VM workspaces do. The agent can modify that log, and it is removed with the
workspace.

Set `auditReceipts: true` in `containerDefaults` (or one owner's
`containerSites` entry) for signed, fail-closed receipts instead. Each
workspace then gets an audit writer in `saw-history-<registration>`, which keeps
an append-only history outside the workload, kept after the workspace is
deleted, and signs a receipt for each record. An approved tool action does not
run until its receipt arrives. The sandbox reaches the writer through a shared
(ReadWriteMany) exchange volume, named `saw-shared`: `make saw-init` creates it
as a copy of the cluster's shared-filesystem class (an existing `saw-shared` is
kept; set `stack.audit.values.exchangeStorageClass` for another class).
Changing the model at run time (`lifecycleVersion: 1`) requires receipts.
Changing `auditReceipts` changes the enrolled boundary: recreate the workspace.
