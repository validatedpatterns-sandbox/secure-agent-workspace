#!/usr/bin/env bash
set -uo pipefail
NS=saw-alice
echo "=== gateway.toml [openshell.gateway.oidc] block (issuer/audience/roles_claim) ==="
oc get configmap alice-installer -n $NS -o jsonpath='{.data.gateway\.toml}' 2>/dev/null \
  | grep -iE -A2 -B1 "oidc|issuer|audience|roles_claim|admin_role|user_role|allow_unauth" | head -40
echo
echo "=== config.json: dashboard/oauth2-proxy + accessControl (how the token is passed) ==="
oc get configmap alice-installer -n $NS -o jsonpath='{.data.config\.json}' 2>/dev/null \
  | python3 -c '
import sys,json
d=json.load(sys.stdin)
def walk(o,p=""):
    if isinstance(o,dict):
        for k,v in o.items():
            nk=p+"."+k if p else k
            if any(t in k.lower() for t in ("oidc","issuer","audience","client","role","owner","token","proxy","auth","pass","claim")):
                if not isinstance(v,(dict,list)): print(f"  {nk} = {v}")
            walk(v,nk)
    elif isinstance(o,list):
        for i,v in enumerate(o): walk(v,f"{p}[{i}]")
walk(d)
' 2>&1 | head -50
echo
echo "=== the gateway oidc issuer the CHART rendered vs the token issuer ==="
echo "token iss (minted earlier): https://openshell-keycloak-ingress-saw-keycloak.apps.verac2.nvidia.local/realms/openshell"
oc get configmap alice-installer -n $NS -o jsonpath='{.data.gateway\.toml}' 2>/dev/null | grep -i "issuer" | head
