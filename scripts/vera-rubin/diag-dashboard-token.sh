#!/usr/bin/env bash
# Temporarily enable direct-grant on openshell-dashboard, mint alice's token,
# decode the ACCESS and ID tokens (roles + aud), then revert. Reversible.
set -uo pipefail
NS=saw-keycloak; REALM=openshell
HOST=$(oc get route -n $NS -o jsonpath='{.items[0].spec.host}'); KC="https://$HOST"
AU=$(oc get secret openshell-keycloak-initial-admin -n $NS -o jsonpath='{.data.username}'|base64 -d)
AP=$(oc get secret openshell-keycloak-initial-admin -n $NS -o jsonpath='{.data.password}'|base64 -d)
APW=$(oc get secret openshell-keycloak-users -n $NS -o jsonpath='{.data.alice}'|base64 -d)
ADM=$(curl -sk "$KC/realms/master/protocol/openid-connect/token" -d grant_type=password -d client_id=admin-cli -d username="$AU" --data-urlencode "password=$AP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
CID=$(curl -sk -H "Authorization: Bearer $ADM" "$KC/admin/realms/$REALM/clients?clientId=openshell-dashboard" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
echo "dashboard client uuid: $CID"
# enable direct access temporarily
curl -sk -X PUT -H "Authorization: Bearer $ADM" -H "Content-Type: application/json" \
  "$KC/admin/realms/$REALM/clients/$CID" -d '{"directAccessGrantsEnabled":true}' >/dev/null
revert(){ curl -sk -X PUT -H "Authorization: Bearer $ADM" -H "Content-Type: application/json" "$KC/admin/realms/$REALM/clients/$CID" -d '{"directAccessGrantsEnabled":false}' >/dev/null; echo "(reverted directAccessGrantsEnabled=false)"; }
trap revert EXIT
sleep 1
RESP=$(curl -sk "$KC/realms/$REALM/protocol/openid-connect/token" -d grant_type=password -d client_id=openshell-dashboard -d username=alice --data-urlencode "password=$APW" -d scope="openid profile email")
decode(){ python3 -c 'import sys,base64,json;t=sys.stdin.read().strip().split(".")[1];t+="="*(-len(t)%4);p=json.loads(base64.urlsafe_b64decode(t));print("  aud:",p.get("aud"));print("  azp:",p.get("azp"));print("  realm_access:",p.get("realm_access"))'; }
echo "=== DASHBOARD access token ==="; echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' | decode
echo "=== DASHBOARD id token ==="; echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id_token",""))' | decode
