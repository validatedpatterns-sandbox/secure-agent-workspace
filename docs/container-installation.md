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
  approved provider endpoints. Use the [container topology preflight](#discover-and-review-container-egress)
  to derive API, DNS and issuer rules, or supply those rules explicitly.
  Allocate a distinct AdminNetworkPolicy priority for each workspace.
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
that Job. The gateway can create the workspace before the reconciler grants the
owner its administrator role. The binding Job waits up to 210 seconds after
authentication for both observations, pins the workspace UUID once observed,
and rejects a changed UUID or unexpected owner role. The browser relay has no Kubernetes token or trust-write RBAC. Changing
the relay inputs creates a new input-hashed binding Job through GitOps.

For sites with split-horizon DNS, run the [topology preflight](#discover-and-review-container-egress)
from a trusted in-cluster Pod. The gateway and relay need the issuer address
that Pod resolves on TCP 443. A successful browser login from the workstation
does not test this path.

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

### Discover and review container egress

The optional container topology preflight reuses the VM's API Service and ready
EndpointSlice discovery. It also reads the OpenShift DNS Service and endpoint
ports. It runs HTTPS discovery from an existing, administrator-selected Pod to
find the issuer addresses in the cluster's DNS view. Use a trusted Pod with
Python 3, the correct CA trust, DNS and HTTPS access. The caller needs read
access to those cluster resources and exec access to that Pod. The probe sends
no credentials, follows no redirects, and verifies the issuer hostname and
discovery document at every IPv4 answer. IPv6 issuer answers are unsupported.

Keep governance, proxy and other administrator-approved rules in your base site
file. When migrating an existing site, remove the hand-maintained API, issuer
and DNS rules from the base lists first. Every base rule is preserved. A stale
address left in the base remains allowed. Configure the gateway or relay issuer
once, or omit both to discover the Keycloak host in the relay's configured
namespace with the same helper used by VM Make. The default realm is
`openshell`; set `KEYCLOAK_REALM` for another realm. Explicit gateway and relay
issuer URLs must agree.

```sh
export SAW_USERS_VALUES_FILE="$PWD/container-users.yaml"   # base values
# On a stock SAW platform, the portal generator has Python 3 and access to its issuer.
PROBE_POD=$(oc -n saw-portal get pods -l app.kubernetes.io/name=saw-workspaces-generator -o json |
  jq -er '[.items[] | select(.metadata.deletionTimestamp == null and
    any(.status.conditions[]?; .type == "Ready" and .status == "True"))][0].metadata.name')
export SAW_TOPOLOGY_PROBE="saw-portal/$PROBE_POD"
export SAW_TOPOLOGY_CONTAINER=generator
export SAW_TOPOLOGY_OVERLAY="$PWD/container-network.yaml"
# Set SAW_TOPOLOGY_CONTAINER if the Pod has multiple containers.
make container-topology > "$SAW_TOPOLOGY_OVERLAY.new" &&
  mv "$SAW_TOPOLOGY_OVERLAY.new" "$SAW_TOPOLOGY_OVERLAY"
make check-container-topology
```

For GitOps, commit the generated file and include it **after** the base file
in the Application's Helm value files. Generate from `containerSites` for
saw-users or `portal.containerSites` for RHDH. A base file containing both
produces both sets of overrides. Run the check against the original base file
and the committed overlay before enrollment and when DNS or API endpoints
change. A mismatch exits nonzero. Review the regenerated diff before syncing.

For a Pattern site with both sources, store the reviewed overlay at
`overrides/container-network.yaml` and declare the value file order in the
site's cluster-group values. Preserve any other value files the site already
uses.

```yaml
clusterGroup:
  applications:
    saw-users:
      extraValueFiles: [/overrides/saw-users.yaml, /overrides/container-network.yaml]
    openshell-rhdh:
      extraValueFiles: [/overrides/saw-users.yaml, /overrides/container-network.yaml]
```

For standalone Make, keep the base and overlay paths for the installation.
Run the Ready Pod selection above again before each `make saw-create`,
including enrollment after the boundary review. A portal rollout can replace
the probe Pod between those steps. Check the **existing** overlay against
the current trusted Pod. Regenerate it only after reviewing a topology change.
On first
foundation apply (`automaticEnrollment.enabled: false`), Make can create the
specified overlay if absent. Later applies require the saved values to match
live discovery. Status and delete can use that file without contacting the
issuer. Keep the file per installation. Existing deployments using explicit
egress inputs can continue to use that workflow.

Generated rules grant individual addresses and ports to the gateway and relay.
API and DNS rules also go to bootstrap and, for static sites, the projector.
Workload/supervisor policies, provider host approvals, storage and enrollment
approval still come from their existing sources. This preflight validates the
probe Pod's view; workload readiness after deployment verifies the actual
gateway path.
