# Network troubleshooting

Each `saw-<name>` namespace has two outbound controls. The namespaced `NetworkPolicy` selects the VM's `virt-launcher` pod and limits in-cluster peers and outside TCP ports. The OVN-Kubernetes `EgressFirewall` named `default` limits outside destinations by hostname and also evaluates API traffic on the test cluster. A connection must pass both layers. The sandbox proxy and governance profile are another decision point inside the VM.

Use the affected SAW namespace in every command. Check the current context before probing a cluster:

```bash
oc config current-context
oc get networkpolicy -n saw-<name>
oc get egressfirewall default -n saw-<name> -o yaml
oc get pod -n saw-<name> -l openshell.pattern/role=gateway -o wide
```

For a quickstart VM, run a probe through the KubeVirt SSH tunnel (the helper adds your public key to that SAW's Secret if needed):

```bash
SAW_NS=saw-<name> VM_NAME=<name> \
  scripts/openshell-saw-vm-ssh.sh \
  "curl -k -m 8 -sS -o /dev/null -w '%{http_code}' https://HOST/"
```

Compare it with a known allowed destination from the same VM. A `000` HTTP code only means no HTTP response arrived; the curl exit code and error distinguish name resolution, refusal, and timeout. In the 2026-10-11 test cluster, `kubernetes.default.svc` gave curl exit 6 because the short name did not resolve in the guest. The fully qualified `kubernetes.default.svc.cluster.local` and API ClusterIP timed out with exit 28. `169.254.169.254:80` refused the connection with exit 7 when the NetworkPolicy was off. These signatures are observations from that cluster, not a universal way to identify which layer denied a packet. Check policy objects and compare a positive control before concluding which layer is responsible.

## Provider call fails through the credential proxy

Check `oc get deploy,pod,svc -n saw-<name> -l openshell.pattern/role=credential-proxy`
and the proxy's `/healthz` Service port 8081. Its logs report host, binding,
and status without keys. An `unknown or unbound credential marker` 502 means
the marker, Secret provider type, and profile endpoint do not agree. A missing
mounted key makes `/healthz` fail. A proxy outage cannot cause a key fallback
in the VM; restore the Deployment or Secret and retry the request.

## Installer reports a credential key on a VM disk

The VM is still mounting a full provider Secret. Replace its volume source
with `<name>-meta`, create that metadata Secret, and put the full Secret only
on the credential proxy Deployment. The installer stops before applying the
profile to avoid persisting the live key. For custom providers, also add the
binding in `credentialProxy.secrets`.

## Relay forward is refused

Confirm that `saw-relay` is registered with a `OU=openshell-user` certificate
and is a user member of the target workspace. Forward and keepalive units use
`--gateway saw-relay`; the temporary `saw-installer` admin entry exists only
during apply. Re-run `saw-apply` after correcting workspace membership.

## Supervisor approved, but the connection fails

The governance profile can become live through the interceptor before the `openshell-saw` release receives its matching EgressFirewall and NetworkPolicy update. A persistent version of this problem occurs when a profile is added without its exact outside host in `egress.allow` or `egress.extraAllow`, or without a narrow `networkPolicy.extraEgress` rule for an in-cluster Service. Custom provider URLs held only in Vault cannot be inferred by the chart.

Compare the destination and port in the active profile with the `EgressFirewall` and `saw-vm` NetworkPolicy. Probe its hostname from the VM and a known allowed host from the same VM. For an outside host, add it to `egress.extraAllow` and sync the SAW; for an in-cluster Service, add its namespace, pod selector, and port to `networkPolicy.extraEgress` and sync. Keep the profile and allowlist changes together. CI checks the shipped profile hosts and ports against the chart's default allowlist and outside ports; site-specific additions still need review.

In the 2026-10-11 test, the live NVIDIA profile still listed `integrate.api.nvidia.com`. A credential-free request from the notebook sandbox returned HTTP 404 with the firewall rule present, timed out after eight seconds when that one hostname was removed from the EgressFirewall, and returned HTTP 404 again after rollback. The sandbox image lacked curl, so the probe used Node `fetch` and reported `TimeoutError` on the denied request. No supervisor log line was captured; the unchanged live profile and reversible firewall rule establish the configuration skew observed here.

## Routes return 503 or 504

Check that the gateway `virt-launcher` pod has `openshell.pattern/role=gateway` and that `saw-vm` admits the Route's backend port. Check the `openshift-ingress` namespace label `policy-group.network.openshift.io/ingress` and the ingress controller publishing strategy. Host-networked router pods need the ingress peer's empty `podSelector` alongside that namespace selector. Also check that the VM and its service endpoints are ready. The test cluster's webui and sandbox UI Routes answered with HTTP 302 after NetworkPolicy was enabled.

## Disk import or clone is stuck

Check the DataVolume and its events, then the importer pod's labels and logs:

```bash
oc get dv,pod -n saw-<name>
oc describe dv <name>-root -n saw-<name>
oc get pod -n saw-<name> -l app=containerized-data-importer --show-labels
```

The `saw-cdi-import` policy selects `app=containerized-data-importer`. It permits DNS, the internal registry, the router, and outside TCP ports for configured import URLs; it admits ingress from `openshift-cnv` for CDI transfer flows. A registry serving image layers from a separate host also needs that host in the EgressFirewall. The fresh import on the test cluster reached `Succeeded` with the policy already installed. Other source modes, especially host-assisted clones, should be tested with their actual importer path before rollout. If a mode needs a broader rule, record the peer and port and keep `networkPolicy.enabled: false` for that SAW until a scoped rule is available.

## Debug pod cannot reach the network

`saw-default-deny` selects every pod in the namespace. A temporary debug pod does not inherit `saw-vm` merely by running beside it. Probe from the VM with `scripts/openshell-saw-vm-ssh.sh`, or add a temporary, narrowly selected NetworkPolicy for the debug pod in a dedicated test namespace. Do not label a debug pod as the gateway to bypass the selection.

## The VM SSH helper times out

`virtctl ssh` uses `virt-api` to dial the VM on TCP 22. Check the `saw-vm` ingress rule for TCP 22 from `kubevirt.io=virt-api` pods in `openshift-cnv`. On the test cluster, omitting that rule caused the helper to stall after `AccessCredentialsSynchronized=True`; `virt-api` logged a timeout dialing the VM pod IP on port 22. The scoped rule restored the tunnel.

## Uninstall cleanup stalls while deleting the VM

Check the `saw-cleanup-hook` policy, the cleanup Pod's `openshell.pattern/role=cleanup` label, and the exact API endpoint IP and port rules in EgressFirewall. On the 2026-10-11 test cluster, EgressFirewall blocked the cleanup Pod's API call even while NetworkPolicy allowed egress. An API exception was required for uninstall. The chart now discovers or requires the API Service IP and EndpointSlice backends. The cleanup NetworkPolicy admits only those addresses; the VM and CDI outside rules exclude backend IPs, even when an API uses TCP 443. The EgressFirewall exception stays while `cleanupOnDelete: true`, including during a NetworkPolicy rollback. On hosted control planes, update `cleanupApi.endpoints` and sync when API backends rotate. The legacy control-plane node fallback applies only to policy-disabled installs without configured endpoints and does not work on hosted clusters. Curl requests time out and the cleanup Pod has a deadline; inspect its failure reason before retrying deletion.

## Cluster topology differs from the SAW values

Before enabling NetworkPolicy or after an API endpoint change, compare the cluster's pod and Service networks and API backends with the values used by this SAW:

```bash
oc get network.config cluster -o jsonpath='{.status.clusterNetwork[*].cidr} {.status.serviceNetwork[*]}'
oc get service kubernetes -n default -o jsonpath='{.spec.clusterIP}{"\n"}'
oc get endpointslice -n default -l kubernetes.io/service-name=kubernetes -o yaml
helm get values <name> -n saw-<name> -o json | jq '{networkPolicy, cleanupApi}'
```

Set `networkPolicy.clusterNetworkCIDRs` and `serviceNetworkCIDRs` to the reported IPv4 ranges, `cleanupApi.serviceIP` to the API Service ClusterIP, and `cleanupApi.endpoints` to the ready IPv4 EndpointSlice backend IP and TCP port pairs. The outside `ipBlock` excludes those CIDRs, exact API backend IPs, and `169.254.0.0/16`; wrong values can allow unintended traffic on an otherwise allowed port. Quickstart discovers them before writing to the cluster; `make prereqs-check` verifies enabled GitOps users and prints a pasteable override. Argo CD cannot discover them during rendering, so repeat the preflight after endpoint rotation. The live test script checks the exclusions and API block.

## Roll back one SAW

For a test SAW that must regain its previous connectivity while a narrow rule is prepared, disable its NetworkPolicies without changing the VM disk:

```bash
helm upgrade <name> charts/openshell-saw -n saw-<name> \
  --reset-then-reuse-values --set networkPolicy.enabled=false
```

Restore the corrected topology values and scoped rules in the chart or SAW values, then re-enable the policy and repeat `tests/test-network-policy.sh` with a dedicated peer. Disabling NetworkPolicy removes in-cluster isolation; while `cleanupOnDelete: true`, the scoped API EgressFirewall exception remains so a later delete can complete. During that rollback the VM can use that exception until NetworkPolicy is restored.
