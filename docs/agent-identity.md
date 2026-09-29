# SAW agent identity (implementation in progress)

This feature is experimental and disabled by default. **Full acceptance has not
passed.** The shared identity stack has been deployed, but VM enrollment is
still being debugged. Neither transport has completed the grant, isolation,
rotation and recovery suite. The live runner currently executes compatibility
probes and explicitly reports the remaining scenarios as incomplete.

## Architecture

`charts/spire-identity` installs the ZTWIM subscription and its SPIRE server,
cluster agents, CSI driver and HTTPS discovery operands. Installation is staged
by `scripts/deploy-spire-identity.py`. A separately built Go registrar uses a
CSI-projected, explicitly authorized administrator workload identity to call
the SPIRE API. Server persistence retains the trust domain and signing state.

The registrar watches SAW VMs and reconciles periodically. Both the namespace
label `openshell.pattern/saw=true` and VM label `saw.redhat.com/spiffe=true` are
required. Each opted-in VM has a namespaced Role for its enrollment Secret,
finalizer and restart operations. The guest diagnostic also needs `pods/exec`
in that namespace. That permission is not restricted to the launcher pod name.
Namespace administrators and VM/root administrators are trusted; sandbox
workloads are not.

Exec into virt-launcher is admitted only if the caller can `use` the OpenShift
constraint that already admits that pod. The registrar ServiceAccount therefore
has a cluster-scoped binding to `use` `kubevirt-controller`. Naming that one
constraint does not make the grant least privilege. The constraint disallows
privileged containers, host network, host ports, host PID, and host IPC. It
allows host-directory volumes, every volume plugin, any UID, any SELinux
context, privilege escalation, and `SYS_NICE` plus `NET_BIND_SERVICE`. `use`
would also allow this account to create pods matching that constraint wherever
it can create pods. It currently cannot create pods. On this cluster the exec
Roles exist only in `saw-identity-a` and `saw-identity-b`, so the working
effect is exec into pods admitted by `kubevirt-controller` in those two
namespaces.

Workload identities are:

```text
spiffe://<trust-domain>/saw/<namespace>/<vm>/gateway
spiffe://<trust-domain>/saw/<namespace>/<vm>/ws/<workspace>/sandbox/<name>
```

The agent's internal node identity is separate. Registration entries are parented
to the join-token-attested agent. Gateway selectors require both the configured
host UID and gateway executable path. Sandbox selectors require gateway-owned
Podman labels for managed status, workspace and sandbox. There is no UID-only
fallback. Rootless Podman selector behavior still needs live validation.

Bootstrap material is stored in the VM-owned `<vm>-spire-join-token` Secret and
delivered on a read-only Secret disk. It is never a Helm value or sandbox mount.
The guest retains agent credentials in `/var/lib/spire/agent` and projects the
local Workload API at `/spiffe-workload-api/agent.sock`. Trust-domain changes are
rejected by the guest and registrar. Ordinary reboot reuses credentials.

The recovery controller uses a fixed root-owned guest diagnostic helper through
QEMU Guest Agent. A narrow SELinux executable transition allows this helper to
read state; SELinux remains enforcing for sandboxes. A diagnostic failure or
server outage does not prove state loss. The optional VM readiness helper
checks installer completion and current agent health separately. Its failure
does not feed recovery and does not by itself start re-enrollment. Confirmed loss or an expired unused
bootstrap token starts a new generation and requests a VM restart. Retries are
bounded and reset after confirmed healthy enrollment. One TCP state-loss
recovery and ordinary reboot passed on the dedicated test VM. The rest of the
lifecycle and fault-injection suite has not.

Deleting a profile registration prevents renewal. Already issued JWT-SVIDs and
access tokens remain usable until expiry, normally five minutes. Bootstrap
tokens default to ten minutes. Configurable registrar TTLs remain outstanding.

## Deployment and examples

Use an explicit context and inspect existing shared infrastructure first:

```sh
python3 scripts/deploy-spire-identity.py --help
python3 scripts/test-agent-identity-live.py --help
```

A provider or profile change is not in effect for a sandbox request until the
sandbox successfully acknowledges the expected content revision. Read the
gateway policy with `policy get --full` and record `hash` and `config_revision`.
`active_version` does not identify that content. Call this snapshot the gateway
policy. After it shows the expected revision, wait for a successful sandbox
acknowledgement of that same revision, then issue the request and collect grant
evidence. The next `ReportPolicyStatus` event is not that acknowledgement unless
it corresponds to the expected revision and reports success. A success before
that acknowledgement can still carry the previous access token. On the measured
default-workspace switch, the gateway hash changed within a second and the
matching successful sandbox acknowledgement followed about six seconds later.
The previous token was reused only before that acknowledgement. That switch did
not show a cache-invalidation defect.

Direct issuer validation passed for the default sandbox JWT-SVID: a valid
assertion was accepted, and the same assertion was rejected after its signature
was tampered and again after expiry. That probe talks to the demo issuer
directly. It does not exercise OpenShell's grant flow or replay a gateway
assertion. Shared validation code explains why signature and expiry are checked
before the grant branch; it does not widen this live result.

Example values are in `examples/agent-identity/`. `cluster-values.yaml` describes
the current cluster installation; `pattern-values.yaml` shows the Pattern
application wiring. A full Pattern deployment has not been verified yet.
Do not let a second Helm/Argo application take ownership of an existing stack.

Build `identity/registrar`, publish its image, and set `registrar.image` to an
immutable digest before enabling it. The source Dockerfile documents the build.
The SPIRE agent component is separately digest pinned and verified during BOM
installation. TCP uses the SPIRE Service on port 443. VSOCK guest configuration
exists, but the host bridge and live validation remain outstanding; do not use
that transport as an accepted deployment option yet. No transport fallback occurs.

Quickstart accepts `DYNAMIC_PROVIDERS=true`, `SAW_VALUES=<file>` and
`SAW_BOM_VALUES=<file>` without an API key. Both files must be explicit. Approved
provider profiles go in `providerProfiles`; BOM profile documents can be supplied
through the `saw-bom` chart's `profileFiles` map. See `provider-values.yaml` and
`bom-values.yaml`. Existing static provider profiles retain their Secret handling.

`runtimeCredentials: true` marks installer-created client-credential providers.
`externallyManaged: true` marks user-created token-exchange providers. The flags
are mutually exclusive and cannot be combined with `credentialSecret`.

The laptop helper uses an authenticated named gateway and its OIDC login:

```sh
make openshell-saw-token-provider OPENSHELL_SAW_NAME=my-gateway \
  WORKSPACE=research PROVIDER=protected PROVIDER_PROFILE=saw-demo-exchange
```

For a separate issuer, `scripts/openshell-saw-token-provider.py --token-stdin`
accepts a token acquired on the laptop through stdin. It passes the token to the
CLI in the environment, never in argv, Helm values or guest configuration. Do
not invoke it under shell tracing. The issuer must accept the subject token's
audience and issuer; a gateway login token is not automatically suitable for
every external service.

`charts/identity-demo` is an optional test fixture, not a production issuer. It
uses a pinned Node image and verifies JWT signatures, issuer, audience and
expiry. Its signing key is ephemeral. The enrollment secret for obtaining demo
user tokens must be generated per run and deleted during cleanup.

## Evidence, blockers and cleanup

The pinned OpenShell build does not include the sandbox identity claims needed
for the required correlated grant audit events. Details and source references
are in [the local dependency report](issues/agent-identity-audit-blocker.md).
No external issue is required to continue independent implementation/testing.
Protected-service logs cannot substitute for the missing audit functionality.

Use only dedicated test namespaces, labelled
`saw.redhat.com/identity-test-run=<run-id>`. Evidence must contain verified claim
summaries and immutable artifact identifiers, never raw bearer/bootstrap tokens.
The internal agent ID includes its join-token identifier and must be redacted
from exported evidence. Exit code 2 from the live runner means incomplete,
not success. Current reports do not establish VM acceptance.

The guest loads a prebuilt SELinux module, built from
`charts/openshell-saw/files/selinux/` against the golden-image baseline
`selinux-policy-43.3-1.fc44` and `selinux-policy-targeted-43.3-1.fc44`. The
installer does not install policy development packages or compile on the guest.
The module does not declare the agent domain permissive. `saw-identity-a` /
`identity-a` is a diagnostic VM: unpinned development-package installs on
2026-09-27 replaced that baseline with `selinux-policy` 44.10. A permissive
domain or `SELinuxContext=` on that VM does not establish enforcement, sandbox
attestation, or isolation. Final acceptance has to be repeated on a fresh VM
from the image baseline. Whether this module loads on 44.10 is unverified.

Delete run-owned VMs through Kubernetes so the registrar finalizer can revoke
their entries and agent. Confirm cleanup before removing run-owned namespaces
and demo resources. Never use broad repository uninstall targets. Preserve
pre-existing SAWs and shared identity infrastructure. Roll back values/images
through the owning Helm or Argo deployment; disabling identity requires removing
dynamic providers and restarting/upgrading the guest configuration safely.
Guest-side removal of all identity services on disable remains to be completed
and tested. Restore run-owned virtualization settings only after confirming no
remaining consumer needs them.
