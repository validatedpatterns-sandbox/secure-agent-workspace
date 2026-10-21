#!/usr/bin/env bash
# Mint a real token for alice via the public CLI client and decode it, to see
# exactly what realm_access.roles + aud the gateway receives.
set -uo pipefail
NS=saw-keycloak; REALM=openshell
HOST=$(oc get route -n $NS -o jsonpath='{.items[0].spec.host}' 2>/dev/null); KC="https://$HOST"
echo "=== keys in the user-passwords secret ==="
oc get secret openshell-keycloak-users -n $NS -o jsonpath='{.data}' 2>/dev/null | python3 -c 'import sys,json;print(list(json.load(sys.stdin).keys()))' 2>&1
AP_ALICE=$(oc get secret openshell-keycloak-users -n $NS -o jsonpath='{.data.alice}' 2>/dev/null | base64 -d)
echo "alice password found: $([ -n "$AP_ALICE" ] && echo yes || echo NO)"
[ -z "$AP_ALICE" ] && { echo "try another key from the list above as KEY=..."; exit 0; }
RESP=$(curl -sk "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=openshell-cli -d username=alice \
  --data-urlencode "password=$AP_ALICE" -d scope="openid profile email")
ATOK=$(echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
if [ -z "$ATOK" ]; then echo "token request FAILED:"; echo "$RESP" | head -c 500; echo; exit 1; fi
echo "=== decoded ACCESS token ==="
echo "$ATOK" | python3 -c '
import sys,base64,json
t=sys.stdin.read().strip().split(".")[1]; t+="="*(-len(t)%4)
p=json.loads(base64.urlsafe_b64decode(t))
print("preferred_username:", p.get("preferred_username"))
print("azp:", p.get("azp"))
print("aud:", p.get("aud"))
print("scope:", p.get("scope"))
print("realm_access:", p.get("realm_access"))
print("resource_access keys:", list((p.get("resource_access") or {}).keys()))
'
