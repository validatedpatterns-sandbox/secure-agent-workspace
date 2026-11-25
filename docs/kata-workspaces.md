# Kata workspace qualification

Kata is under private qualification. The application workload Pod uses the
stock OpenShell Kubernetes driver and a local Kata RuntimeClass. Its separate
supervisor Pod runs in the same RuntimeClass, so every sandbox is two Kata VMs:
the supervisor, which handles the agent's network traffic and credentials, never
shares the workload's guest kernel (OpenShell 0.1.10 and later,
`supervisor_runtime_class_name`). The gateway runs as an ordinary Pod. Each data-science slot is a
separate workload Pod. The workspace BOM, images, storage, credential routing,
relay and audit flows are shared with container workspaces.

## Qualification status

On 2026-11-17, one RHDH data-science Kata canary completed. Both workload
Pods were Ready with the Kata RuntimeClass. Each Pod mapped to a different
host QEMU process. The gateway and both supervisors used the default runtime.
Both owner chat links returned fresh model replies.

On 2026-11-25, on OpenShell 0.1.10, a GitOps-deployed Kata workspace (a
custom-inference user bound to `saw-kata` automatically) passed
`make e2e-workspace DEPLOYMENT_MODE=kata`, next to a container workspace on
the same cluster: Argo CD healthy; the workload and the supervisor each in
`saw-kata`, so two VMs; a real model turn through the custom inference
endpoint; the tool gate denying and recording an `exec`; and OCSF events at
the pattern's collector. Removing and recreating both workspaces through GitOps
also worked.

Not yet covered: network denial and secret isolation tests, persistence across
a Pod restart, stop/start, VM-mode regression, two simultaneous Kata owners on
one worker, and the self-service portal's Kata path (it still needs an
explicit RuntimeClass binding).

## Check worker KVM access before installing OSC

Run this from a platform administrator's existing OpenShift login. Supply the
expected API address independently and a selector for the intended worker
pool. The command reads host sysfs through the existing machine-config daemon
on each selected worker. It creates no Pods, operators or machine configs.

```sh
KATA_API_SERVER=https://api.example.com:6443 \
KATA_NODE_SELECTOR='saw.example.com/kata-pool=true' make kata-worker-check
```

Each selected node must report either `UEFI KVM` or `legacy-BIOS KVM`. An
empty selector, a control-plane node, a missing host probe or missing KVM
prevents a pass. The firmware value is context only. Red Hat's OSC guide lists
CPU virtualization flags and KVM modules for node eligibility; it does not
list UEFI as a requirement. This check does not replace OSC node eligibility
checks or a live workload test.
The running Kata handler, guest seccomp behavior, RWX mounts and the OpenShell
supervisor connection require live qualification. Configure eligible workers
before installing OSC. Creating a KataConfig can reboot workers.
[Red Hat OSC node eligibility checks](https://docs.redhat.com/en/documentation/openshift_sandboxed_containers/1.12/html/deploying_openshift_sandboxed_containers_on_bare-metal_servers/install-osc-overview_metal-osc#install-osc-node-eligibility-checks_metal-osc)

## Prepare OpenShift sandboxed containers

The pattern installs the Red Hat OpenShift sandboxed containers Operator in
`openshift-sandboxed-containers-operator` (`values-prod.yaml`: a Namespace, an
OperatorGroup scoped to it, and a Subscription from `redhat-operators` on the
`stable` channel). The operator alone changes no node. Check that the
Subscription has an installed CSV and that the CSV is `Succeeded`.

The `saw-kata` application (`charts/saw-kata`) creates the KataConfig below
when enabled, selecting plain workers only (never control-plane nodes, even
where they are schedulable). It is off by default because it reboots the
selected nodes. Enable it per cluster with an override on that application:

```yaml
clusterGroup:
  applications:
    saw-kata:
      overrides:
        - {name: enabled, value: "true"}
```
See the [Red Hat installation procedure](https://docs.redhat.com/en/documentation/openshift_sandboxed_containers/1.12/html/deploying_openshift_sandboxed_containers_on_bare-metal_servers/install-osc-overview_metal-osc).

Install the local Kata runtime on an approved worker pool with a platform-owned
`KataConfig`. This example uses the same pool label as the preflight command.
Use the selected cluster's supported OSC version and node eligibility rules.

```yaml
apiVersion: kataconfiguration.openshift.io/v1
kind: KataConfig
metadata:
  name: saw-kata-pool
spec:
  enablePeerPods: false
  checkNodeEligibility: true
  kataConfigPoolSelector:
    matchLabels:
      saw.example.com/kata-pool: "true"
```

Wait for the selected nodes to complete their machine config updates and
reboots. Check `oc get kataconfig`, `oc get mcp`, and
`oc get runtimeclass kata saw-kata -o yaml`. The operator creates the `kata`
class. The `saw-kata` application also creates `saw-kata`, a copy of it (same
handler, pod overhead and `kata-oc` node selector) that carries the
`openshell.ai/sandbox-attachable=true` label OpenShell requires, so nobody
labels the operator's class by hand.

Kata users run in `saw-kata` unless their site names another class
(`kata.runtimeClassName` in saw-users changes the default). On an
`autoApprove` site the workspace projector binds the user to that class's live
UID and placement digest when it first projects the workspace, after the same
checks a reviewed binding gets (Kata handler, attachable label, a node
selector); enrollment then fails closed if the class is later replaced or its
placement changes. A reviewed site binds the class explicitly, as shown in
[Standalone workspace on an existing Kata pool](#standalone-workspace-on-an-existing-kata-pool).

## Verify a deployed worker

1. Check the OSC installation and pool. `oc get kataconfig -o yaml` must show
   the intended installed nodes and a ready count equal to the selected count.
   Check `oc get mcp` and `oc get runtimeclass kata -o yaml`. The expected
   handler is `kata`; scheduling must limit Pods to the configured pool.
2. Schedule a restricted nonroot Pod with `runtimeClassName: kata` and a
   disposable filesystem RWX claim. Write and read a marker from the guest.
   Record the Pod UID, actual node, SCC, and guest boot ID.
3. On that node, match the Pod UID with `crictl inspectp` for the sandbox.
   CRI-O can leave the summary runtime handler empty. Its generated OCI
   configuration carries the annotation `io.kubernetes.cri-o.RuntimeHandler`.
   Correlate that value and the QEMU process with the same sandbox ID.
4. Run the pinned OpenShell workload runtime's `/openshell-sandbox capability-probe`
   as a separate Kata Job. Use the workspace's nonroot UID/GID, strict
   supplemental groups, `RuntimeDefault` seccomp, all capabilities dropped,
   privilege escalation disabled, and the stock unprivileged-port sysctl.
   Require exit 0 and `qualified: true`. The executable exercises Landlock,
   seccomp notifications, socket policy and DNS. Gateway creation, supervisor
   authentication and chat require a separate workspace test.

## Deployment mode and placement

The registration API accepts `vm`, `container` and `kata` as deployment modes.
A registration keeps its mode for its entire lifetime. The `container` and
`kata` modes share the Kubernetes backend. For `kata`, the administrator
binds a named class to the owner and site before enrollment.

The Kubernetes backend accepts administrator bindings for the workload
RuntimeClass name, Kubernetes UID and SHA-256 of the canonical JSON object
containing `handler`, `overhead` and `scheduling`. Missing optional fields hash
as JSON null. The controller checks UID, the stock OpenShell attachable label,
the `kata` handler and the placement digest before attaching resources. Ordinary
container plans retain their original representation. The gateway reads only
the selected class, and the admission policies require that class on the
Sandbox template, the workload Pod and the supervisor Pod. The controller also
refuses a gateway whose configuration does not place the supervisor in it. The portal advertises Kata only when the platform administrator enables the
mode and supplies a reviewed site class and approved profile.

### Allow time for Kata startup

OpenShell 0.1.10 uses 300-second startup windows by default. Kata VM startup can
take longer. In Kata mode, the Kubernetes gateway chart sets the provisioning
repair window, runtime bootstrap grace period and sandbox attach request timeout
to 900 seconds. Set `kubernetes.startupTimeouts` to adjust these values. Each
value must be from 1 to 86400 seconds. Container mode keeps the OpenShell
defaults. These longer windows allow more startup time; they do not change the
runtime readiness checks or make an unhealthy sandbox ready.

## Gated preflight

Run the read-only preflight before creating a workspace:

```sh
DEPLOYMENT_MODE=kata OPENSHELL_SAW_NAME=alice \
  SAW_USERS_VALUES_FILE="$PWD/container-users.yaml" \
  make -f Makefile-quickstart saw-preflight
```

The command renders the workspace chart and submits it with server-side dry
run. It checks the active API, cluster version, Agent Sandbox APIs, admission
and network inputs, Argo access, storage classes, Vault and External Secrets health,
image digest pins, provider host allowlists, source revisions, KataConfig,
worker placement and RuntimeClass approval. A KataConfig passes only when its
ready node count matches its nonzero node count, installation is not in
progress, and an installed node matches the approved worker selector. This
follows the [OSC status reference](https://docs.redhat.com/en/documentation/openshift_sandboxed_containers/1.12/html/deploying_openshift_sandboxed_containers_on_bare-metal_servers/reference_metal-osc).
The Make path also checks `/dev/kvm` through the existing machine-config
daemon. RHDH and GitOps use KataConfig's installed-node status. The preflight
does not create a namespace, release, registration or credential. Run local
Python tools through `uv`.

Before RHDH reserves a workspace or writes credentials, it checks the selected
profile's approved admission hashes. If the owner's namespace exists, it reads
the live runtime validation policy and binding. Kata mode also checks the Kata
placement policy and binding. The Make preflight performs the same checks for
an existing workspace namespace. A changed hash stops the request before the
portal writes credentials or the registry entry. Review the rendered policy,
source revision and site approval before changing a hash.

A first registration has no workspace namespace or policy to compare. In that
case, RHDH, Make, and the static GitOps projector require complete, valid
approval hashes. The projector checks the Kata platform and approved
RuntimeClass before it emits a child Application. If the workspace namespace
exists, it also checks the live admission policies and bindings against the
approved hashes. A failed projector check returns an error to ApplicationSet
and does not return an empty desired set that could prune existing owners.
The projector reads public resources only and cannot read Secrets.

Argo's enrollment Job verifies a first registration's generated boundary
before it publishes the immutable enrollment binding. That Job runs after
Argo has applied the workspace resources. A first GitOps registration can
therefore create policy resources before a stale policy hash is detected.
Review the pinned policy source and approved hash before that first sync.

The Make path needs an `oc` context whose API hostname resolves from the
machine that runs Make. RHDH and GitOps run their checks inside the cluster.
RHDH checks the owner and live platform before it writes credentials to Vault.
The `saw-portal-kata-preflight` ClusterRoleBinding must grant read-only access
to both the portal provisioner and the `saw-workspaces-generator` ServiceAccount.
The RHDH create handler runs in the generator Pod. A missing `get` permission
for RuntimeClasses returns `403` and blocks the preflight before enrollment.
The enrollment job checks the approved Kata placement again before it publishes
the immutable runtime binding. A failure stops the request with a fixed reason.
When an API request fails, the enrollment log shows its HTTP status and
Kubernetes API path. It does not show the response body, headers, or query
parameters. Use that status and path to check the matching API permission or
resource. GET requests send an `Accept` header only. PATCH requests also send
the merge-patch `Content-Type`. A `415` on API discovery can point to a wrong
request content type. Other errors keep the current type-only log.
The read-only Make command also needs the Argo-managed installation namespace
to exist so the API server can validate namespaced resources. On a first
`make saw-create`, platform checks run first; the command then creates that
namespace if needed and performs server-side dry run before Helm applies the
workspace chart.

This gate checks configuration and live API state. It cannot prove that every
node can pull every image or that provider, denied-tool, network-denial, chat,
audit, persistence, restart, stop/start and deletion flows work. Verify those
items on one canary only after the preflight passes. If a canary fails, collect
the pipeline log, Argo sync and health state, controller status, Pod events,
RuntimeClass UID and placement digest before another request.

If RHDH reports a RuntimeClass preflight error, check that the generator can
read the live class. The fixed reasons separate a missing approval, a missing
class, a name or UID change, a wrong handler, a missing attachable label, an
invalid scheduling rule, and a changed placement digest. Compare the approved
name, UID, handler, scheduling and overhead with the live object. Do not change
an owner approval to match the live class until the platform owner has reviewed
the class placement.

If RHDH reports `BoundaryApprovalChanged:validation` or a binding reason, the
selected profile's approved hash does not match the live admission resource.
Do not submit another request against that approval. Check the pinned policy
revision and compare the live resource with its rendered source. Update the
site approval only after the platform owner reviews the difference. Existing
registrations keep their immutable approval and need a fresh registration to
use a reviewed change.

The pinned AIPCC OpenClaw notebook image has `/sandbox` owned by `1000:0`
with mode `0770`. A workspace Pod that uses an OpenShift namespace UID cannot
enter that directory. The shared preflight now returns
`WorkloadImageNotNamespaceAccessible` when an enabled sandbox uses that digest
without a pinned profile image override. This check uses the known image digest;
it is not a general image filesystem inspection. Prepare the notebook image
with `make container-notebook-image BUILD_NS=<build-namespace> BUILD_ARCH=amd64`
as described in [Container images](container-images.md#prepare-the-data-science-notebook-for-container-workspaces).
Use the resulting digest in `profileImageOverrides.data-science.notebook` and
grant the scoped `imagePull` access. Review the changed compiled profile and
approve its new digest before a new registration. The validation admission
policy also pins each workload image. Render that policy and approve its new
normalized `validation` digest when an image override changes. Check that the
new policy differs only in the reviewed image reference. The portal generator
reads the site Secret through an environment variable, so restart its
Deployment after a site approval change. Verify the owner Argo Application
and the enrollment bootstrap use the new digest before waiting for the
workspace runtime. A failed registration keeps its old immutable approval
until the normal delete completes, unless it has not yet published an
enrollment binding and the corrected site projection can reconcile it.

## Standalone workspace on an existing Kata pool

Start with the [container installation](container-installation.md). Keep its
profile approval, topology overlay, scoped Vault input, RWX claims and owner
registration. The following fields are a fragment to merge into the site file.

```yaml
users:
  - name: alice
    values:
      deployment:
        mode: kata
containerSites:
  alice:
    kataRuntimeClass:
      name: saw-kata
      uid: <live RuntimeClass metadata.uid>
      sha256: <placement digest>
```

A reviewed site (no `autoApprove`) must carry this binding; an `autoApprove`
site may leave out `uid` and `sha256` and the projector fills them from the
live class. Manage the class in platform GitOps. The class name used by OpenShell must have
the label `openshell.ai/sandbox-attachable=true`. If you define a separate
class for workspaces, copy the OSC class's handler, overhead and scheduling
constraints when defining it. Inspect the live object before approving it.
Compute the digest using the same canonical serialization as the reconciler.

```sh
oc get runtimeclass saw-kata -o json | uv run --locked python -c '
import hashlib, json, sys
obj = json.load(sys.stdin)
placement = {key: obj.get(key) for key in ("handler", "overhead", "scheduling")}
print(obj["metadata"]["uid"])
print(hashlib.sha256(json.dumps(placement, sort_keys=True, separators=(",", ":")).encode()).hexdigest())'
```

Set `DEPLOYMENT_MODE=kata` and run the documented two-stage `make saw-create`.
Add `--kata-runtime-class saw-kata` to each boundary inspection. Review the
Sandbox admission policy and binding along with the gateway configuration and
the Pod policy before enabling enrollment. The same workspace projector and
controller drive both slots through the stock gateway.

For each slot, inspect the workload Pod's runtime class, UID, SCC, node and
Ready condition. Match its UID to the host-side Kata handler as above. Verify
the associated supervisor Pod uses the same Kata RuntimeClass and maps to its
own QEMU process. Finally sign in as the
owner and send a fresh challenge through each slot's browser relay. Record the
observed text independently for each slot. The CUDA slot name identifies a
profile entry; this test exercises chat and does not qualify GPU passthrough.

### Check a new installation through browser readiness

After the second `make saw-create` returns successfully, run `make saw-status`
with the same site values and owner. Record its `ready` result, then follow
each slot's owner chat link and verify an independent model reply. For RHDH,
follow the links from the owner's catalog entry. A clean workspace replay uses
a new registration, Vault scope and PVCs. Record separately whether the cluster
already had the shared platform and OSC installed.

To diagnose a readiness timeout, set `OWNER` and `REGISTRATION` from the site
values. These commands read workload state and component health.

```sh
oc -n "saw-$OWNER" get sandboxes.agents.x-k8s.io \
  -o 'custom-columns=NAME:.metadata.name,MODE:.spec.operatingMode,READY:.status.conditions[?(@.type=="Ready")].status,REASON:.status.conditions[?(@.type=="Ready")].reason'
oc -n "saw-$OWNER" get pods -o wide
oc -n "saw-ctl-$REGISTRATION" get jobs
oc -n vp-gitops get applications -o json | jq -r --arg prefix "saw-c-$REGISTRATION-relay-" \
  '.items[] | select(.metadata.name | startswith($prefix)) | [.metadata.name, .status.sync.status, .status.health.status] | @tsv'
```

The identity bootstrap creates the public gateway CA ConfigMap in
`saw-ctl-<registration>`. The enrollment Job and runtime controller also run
there. Separate Argo applications can start these components at different
times. A volume mount can fail before identity bootstrap creates the ConfigMap.
Both components read the named CA through the Kubernetes API and retry if it is
not ready. Grant each ServiceAccount `get` on that ConfigMap name in the
control namespace. Do not grant broad ConfigMap access. If the Job reaches
`BackoffLimitExceeded`, check its Pod events for `FailedMount` and `Evicted`
before retrying. A low ephemeral-storage eviction is a separate cluster
resource issue; record it with the Job failure.

The runtime controller publishes the immutable enrollment binding only after
the Job completes. If the Job failed, expect no relay binding or Kata worker
Pods. The Argo applications for the gateway and policy can be healthy while the
workspace remains unavailable.

An enrollment or relay binding Job can succeed before OpenClaw serves the
browser UI. If the stock gateway reports that its supervisor is unavailable
and suspends the workload, inspect the supervisor Pod events and the workload
Pod events in the same namespace. A relay can subsequently exceed its
Deployment progress deadline while waiting for the sandbox's UI port.
Preserve the installer exit status and event timestamps for that run.

If RHDH waits at `Intent for this registration and update`, check that both
the RHDH workspace generator and portal provisioner can read
`saw-runtime-intent`, `saw-runtime-status`, and `saw-bom-profiles` in the
workspace namespace. A static projector may also need access to enrollment
publications. Keep its ServiceAccount in the same RoleBinding; do not replace
the portal readers with it. The runtime observer Role grants `get` on only
those three ConfigMaps.

### Verify a replacement

1. On a disposable registration, record each workload Pod UID and the UID and
   bound PV name of each PVC. Write a different marker file under
   `/sandbox/workspace` in each slot and record its SHA-256. Sign in as the owner,
   request a distinct reply from each slot and keep the value for comparison.
2. For a static registration, commit `desiredState: Stopped` and increment
   `intentGeneration`. Wait for the controller to report that generation as
   `Stopped` and for both agent Pods to disappear. Commit `desiredState: Running`
   with the next generation. Keep the same registration, profile and PVCs.
3. Check that the new generation reaches `GenericReady`, both slots have new
   Pod UIDs, and every PVC retains its UID and bound PV. Verify both marker
   hashes, the earlier assistant replies in each slot's conversation history,
   and a fresh owner chat through each route. Record browser timeouts separately
   from successful subsequent attempts.
4. To test an explicit restart while running, increment `intentGeneration`
   and set `restartGeneration` to that new value. Repeat the checks and
   correlate the new Pod UIDs with the host-side CRI-O sandbox identities.

## Developer Hub site configuration

Enable `kata` in `portal.deploymentModes` and configure the owner's reviewed
class in `portal.containerSites.<login>.kataRuntimeClass`. Use the same three
fields shown above. The create and create-for-user forms display the profiles
approved for each deployment mode. The selected mode is immutable for the
registration. The server checks the owner's identity, mode, profile and site
placement before reserving credentials or writing to Vault. Owners never
supply a RuntimeClass or a security policy in the form.

The portal delegates projection and reconciliation to the same components as
Make. A site can enable VM, Container and Kata together. Each active Kubernetes
registration uses the placement approved for that login. Stop, start, model
update, status, chat links and foreground deletion use the existing Kubernetes
lifecycle implementation.
