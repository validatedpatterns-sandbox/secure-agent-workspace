# Kata workspace qualification

Kata is under private qualification. The application workload Pod uses the
stock OpenShell Kubernetes driver and a local Kata RuntimeClass. The gateway
and separate supervisor run as ordinary Pods. Each data-science slot is a
separate workload Pod. The workspace BOM, images, storage, credential routing,
relay and audit flows are shared with container workspaces.

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

The qualification cluster installed the Red Hat OpenShift sandboxed containers
Operator from OperatorHub in `openshift-sandboxed-containers-operator`. A GitOps
installation uses a Namespace, an OperatorGroup scoped to that namespace, and a
Subscription from `redhat-operators`. Select the channel supported by the
cluster. Keep these platform resources outside the SAW workspace charts. Check
that the Subscription has an installed CSV and that the CSV is `Succeeded`.
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
`oc get runtimeclass kata -o yaml`. The operator creates the `kata` class. SAW
uses a reviewed RuntimeClass YAML with the live handler, scheduling and overhead
fields. Bind that class's name, UID and placement digest in the site YAML below.
The class also needs `openshell.ai/sandbox-attachable=true`. Keep the class and
the owner approval under platform control.

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
the selected class, and the admission policies require that class on both the
Sandbox template and the workload Pod. The supervisor keeps the default
runtime. The portal advertises Kata only when the platform administrator enables the
mode and supplies a reviewed site class and approved profile.

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

Manage the class in platform GitOps. The class name used by OpenShell must have
the label `openshell.ai/sandbox-attachable=true`. If you define a separate
class for workspaces, copy the OSC class's handler, overhead and scheduling
constraints when defining it. Inspect the live object before approving it.
Compute the digest using the same canonical serialization as the reconciler.

```sh
oc get runtimeclass saw-kata -o json | python3 -c '
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
the associated supervisor Pod uses the default runtime. Finally sign in as the
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

An enrollment or relay binding Job can succeed before OpenClaw serves the
browser UI. If the stock gateway reports that its supervisor is unavailable
and suspends the workload, inspect the supervisor Pod events and the workload
Pod events in the same namespace. A relay can subsequently exceed its
Deployment progress deadline while waiting for the sandbox's UI port.
Preserve the installer exit status and event timestamps for that run.

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
