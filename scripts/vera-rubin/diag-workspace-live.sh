#!/usr/bin/env bash
set -uo pipefail
NS=saw-alice
echo "=== routes in $NS (the UI hostnames) ==="
oc get route -n $NS -o jsonpath='{range .items[*]}{.spec.host}  -> {.spec.to.name}  tls={.spec.tls.termination}{"\n"}{end}' 2>&1 || echo "(no routes)"
echo
echo "=== services + endpoints (is the in-VM gateway serving?) ==="
oc get svc -n $NS 2>&1 | grep -iE "NAME|webui|gateway|alice|notebook|sandbox"
echo "--- endpoints (populated = gateway reachable) ---"
oc get endpoints -n $NS 2>&1 | grep -iE "NAME|webui|gateway|alice" | head
echo
echo "=== VM: why OutOfSync? (mutation-webhook noise vs real) ==="
oc get vm alice -n $NS -o jsonpath='printableStatus={.status.printableStatus} ready={.status.ready}{"\n"}' 2>&1
echo "  (VM Running+ready => OutOfSync is almost certainly cosmetic webhook-default diff)"
echo
echo "=== orphan golden-image-puller RoleBinding (from the internal-registry path) ==="
oc get rolebinding alice-saw-alice-golden-image-puller -n $NS -o jsonpath='roleRef={.roleRef.name} subjects={range .subjects[*]}{.kind}/{.name} {end}{"\n"}' 2>&1 || echo "(not found)"
echo
echo "=== router IP for /etc/hosts (apps.verac2.nvidia.local wildcard) ==="
oc get svc -n openshift-ingress router-default -o jsonpath='lb={.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname} clusterIP={.spec.clusterIP}{"\n"}' 2>&1
echo "--- or the node/ingress IP already used for keycloak (10.78.214.41?) ---"
oc get nodes -o wide 2>&1 | awk 'NR==1 || /verac2/{print $1, $6}'
echo
echo "=== OpenShell install progress inside the VM (cloud-init / guest-agent reported) ==="
oc get vmi alice -n $NS -o jsonpath='guestOS={.status.guestOSInfo.prettyName} agentConnected={range .status.conditions[?(@.type=="AgentConnected")]}{.status}{end}{"\n"}' 2>&1
