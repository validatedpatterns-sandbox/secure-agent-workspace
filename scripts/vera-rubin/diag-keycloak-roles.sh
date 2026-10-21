#!/usr/bin/env bash
# Runs locally on the Mac (needs oc, curl, python3). Queries Keycloak for
# alice's realm roles via the keycloak route.
set -uo pipefail
NS=saw-keycloak
REALM=openshell
HOST=$(oc get route -n $NS -o jsonpath='{.items[0].spec.host}' 2>/dev/null)
KC="https://$HOST"
echo "keycloak url: $KC"
AU=$(oc get secret openshell-keycloak-initial-admin -n $NS -o jsonpath='{.data.username}' | base64 -d)
AP=$(oc get secret openshell-keycloak-initial-admin -n $NS -o jsonpath='{.data.password}' | base64 -d)
echo "admin user: $AU"
TOKEN=$(curl -sk "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli -d username="$AU" \
  --data-urlencode "password=$AP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
if [ -z "$TOKEN" ]; then
  echo "admin token via route failed; trying port-forward on :18443 ..."
  oc port-forward -n $NS svc/openshell-keycloak-service 18443:8443 >/tmp/kcpf.log 2>&1 &
  PF=$!; sleep 4; KC="https://localhost:18443"
  TOKEN=$(curl -sk "$KC/realms/master/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=admin-cli -d username="$AU" \
    --data-urlencode "password=$AP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
fi
[ -z "$TOKEN" ] && { echo "ERROR: could not get admin token"; kill ${PF:-0} 2>/dev/null; exit 1; }
echo "got admin token OK"
AID=$(curl -sk -H "Authorization: Bearer $TOKEN" "$KC/admin/realms/$REALM/users?username=alice&exact=true" | python3 -c 'import sys,json;u=json.load(sys.stdin);print(u[0]["id"] if u else "")' 2>/dev/null)
echo "alice user id: ${AID:-<NOT FOUND>}"
if [ -n "$AID" ]; then
  echo "=== alice REALM roles (needs openshell-user) ==="
  curl -sk -H "Authorization: Bearer $TOKEN" "$KC/admin/realms/$REALM/users/$AID/role-mappings/realm" \
    | python3 -c 'import sys,json;print([r["name"] for r in json.load(sys.stdin)])' 2>/dev/null
  echo "=== alice groups ==="
  curl -sk -H "Authorization: Bearer $TOKEN" "$KC/admin/realms/$REALM/users/$AID/groups" \
    | python3 -c 'import sys,json;print([g["name"] for g in json.load(sys.stdin)])' 2>/dev/null
fi
echo "=== realm roles that exist (is openshell-user defined?) ==="
curl -sk -H "Authorization: Bearer $TOKEN" "$KC/admin/realms/$REALM/roles" \
  | python3 -c 'import sys,json;print([r["name"] for r in json.load(sys.stdin)])' 2>/dev/null
kill ${PF:-0} 2>/dev/null || true
