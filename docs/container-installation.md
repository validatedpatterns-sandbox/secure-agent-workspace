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
- RWO storage for gateway state, workspace data, controller ledger and audit
  history; a shared filesystem class for the preparation/audit exchange PVCs.
- Reachable DNS, Kubernetes API, trusted OIDC issuer, governance, registry and
  approved provider endpoints. Supply explicit network rules and allocate a
  distinct AdminNetworkPolicy priority for each workspace.
- `oc`, Helm 3 and `uv` on the installation machine. Provider credentials stay
  in Vault; local files and Git contain references and public configuration.

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

For a GitOps platform, declare the same chart as a platform Application. Its
source lock pins the upstream manifest and controller digest. Removing an
individual workspace must not uninstall this cluster-wide dependency.

## Public inputs and credential references

The same site object is used as `containerSites.<owner>` for static installs or
`portal.containerSites.<owner>` for RHDH. It is administrator-owned, not a form
field. Start from the component charts' values and schemas:

| Site input | Contents / source |
|---|---|
| `subject` | Resolved Keycloak subject UUID matching the owner. Static inputs supply it explicitly; RHDH resolves the authenticated owner and requires a matching site. |
| `stack.identity` | Pinned revision and [identity chart values](../charts/saw-kubernetes-identity/values.yaml): installation identity, gateway SANs and stock generator/helper images. Administrator sessions use the VM's shared temporary-identity mechanism; no administrator certificate or renewal input is supplied. |
| `stack.policy` | Pinned revision and [admission/network values](../charts/saw-runtime-policies/values.yaml): runtime namespace, service accounts, explicit egress and unique priority. |
| `stack.proxy` | Pinned revision and [credential-proxy values](../charts/saw-kubernetes-proxy/values.yaml): trusted namespace and egress. Provider bindings/digest derive from the shared catalog. |
| `stack.gateway` | Pinned revision and [gateway values](../charts/openshell-saw-kubernetes/values.yaml): stock gateway/driver images, storage, OIDC and network configuration. |
| `stack.audit` | Pinned revision and [audit values](../charts/saw-audit-writer/values.yaml): history/exchange storage classes, image and owner identity. Targets derive from the BOM. |
| `governanceNamespace`, `providerAllowHosts` | Shared governance location and permitted provider destinations. |
| `automaticEnrollment` | `enabled`, pinned helper image/revision, build namespace, resource limits, approved profile digests and reviewed boundary reference. |
| `automaticEnrollment.relay` | Pinned relay chart revision, issuer, Keycloak namespace and realm registrar Secret **name**, and explicit DNS, OIDC and Kubernetes API egress. See [relay values](../charts/saw-workspace-relay/values.yaml). |
| `profileImageOverrides`, `profileBoundaries` | Optional per-profile pinned image overrides and explicit provider/boundary approval. Changing the profile requires its own approval. |
| `imagePull` | Optional namespace and ImageStream names for access to an OpenShift internal registry. |

The portal checks the current Keycloak subject before changing a container's
registration or Vault credentials. Configure `portal.adminSubjects` with the
immutable Keycloak subject for each portal administrator who may act for another
owner. The portal Task needs the existing read-only directory client projection
`saw-generator-keycloak` when container sites are enabled.

### One-time Keycloak registration setup

Use a dedicated Keycloak realm. Run this once from the checkout with an
explicit kubeconfig for the intended cluster. The bootstrap Job needs the
existing master bootstrap Secret only during setup. If the issuer requires
a private CA, supply `--ca-configmap NAME` with key `ca-bundle.crt`.

```sh
python3 scripts/portal-container/setup-relay-provisioner.py \
  --namespace "$KEYCLOAK_NAMESPACE" --issuer "$KEYCLOAK_ISSUER" \
  --bootstrap-secret "$PLATFORM_BOOTSTRAP_SECRET" |
  oc --kubeconfig="$KUBECONFIG" apply --server-side -f -
oc --kubeconfig="$KUBECONFIG" -n "$KEYCLOAK_NAMESPACE" wait \
  --for=condition=Complete job/saw-relay-provisioner --timeout=4m
```

Setup creates a confidential service account with only the realm-management
`create-client` permission. It registers an administrator-defined client scope
`saw-workspace-relay` for the OpenShell audience and user role, and allows that
scope for authenticated dynamic registration. Its credential is stored in
`saw-relay-provisioner` in the Keycloak namespace. Set
`automaticEnrollment.relay.keycloakProvisionerSecret: saw-relay-provisioner`
and use a full Git commit for `automaticEnrollment.relay.revision`.

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

`automaticEnrollment.relay.egress` must permit the cluster's Kubernetes API
Service/backends and their ports, using the same approved destinations as the
controller's bootstrap egress, as well as DNS and the OIDC issuer. The relay
membership Job reads Pod identities and updates the named public client-trust
Secret before connecting to OpenShell. DNS/OIDC access alone cannot complete
that Job. The browser relay has no Kubernetes token or trust-write RBAC. Changing
the relay inputs creates a new input-hashed binding Job through GitOps.

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
  applicationSetControllerLabels:
    app.kubernetes.io/name: <actual-applicationset-controller-pod-label>
  egress: # explicit Kubernetes API and DNS NetworkPolicy rules
    - to:
        - ipBlock: {cidr: <api-address>/32}
      ports: [{protocol: TCP, port: 6443}]
    # Add the cluster's API Service and DNS paths as required by its networking.
users:
  - name: alice
    ownerSubject: <keycloak-subject-uuid>
    registration: <16-lowercase-hex-characters>
    installationID: <installation-uuid>
    vaultPrefix: secret/data/hub/saw-alice/<same-registration>
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
unique registration/installation IDs and keep them stable for the installation.
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
`secret/data/hub/saw-alice/<registration>/inference` as `api_key`. Configure any
additional enabled provider inputs in the same registration prefix. RHDH uses
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
before reviewing the boundary. Record any failed bootstrap attempts separately
from the final installation result.

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
a declared static owner remains an intentional prune. Static sites must sync the
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

For static pattern users, put the same values under `overrides/saw-users.yaml`,
enable `projection`, commit them and let the existing `saw-users` Application
reconcile. Its namespace must be separate from Argo CD. VM users keep their
existing Applications and owner-resolution behavior. A container user's
resolved `ownerSubject` does not enable an owner override for VM users.

For RHDH, configure:

```yaml
portal:
  deploymentModes: [vm, container]
  containerSites:
    alice: # the same approved site object; no provider credentials here
      subject: <resolved-owner-subject>
      # stack, automaticEnrollment, approved profiles and site policy
```

Keep `projection.enabled` off for the RHDH-generated child values: the portal
already performs that projection. The Create/update form includes the deployment
selector; the server checks mode, approved profile, owner and cleanup policy.
The Delete form and state actions use the backend recorded in the registration.
Enabling the selector without a matching approved site does not permit creation.

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
