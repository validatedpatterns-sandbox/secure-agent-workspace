#!/usr/bin/env bash
# Assign the openshell-admin realm role to alice so she can use the gateway
# admin webui. (Operational, not a branch change — the demo seeds owners as
# openshell-user; admin is a separate role.)
set -uo pipefail
NS=saw-keycloak; REALM=openshell
HOST=$(oc get route -n $NS -o jsonpath='{.items[0].spec.host}'); KC="https://$HOST"
AU=$(oc get secret openshell-keycloak-initial-admin -n $NS -o jsonpath='{.data.username}'|base64 -d)
AP=$(oc get secret openshell-keycloak-initial-admin -n $NS -o jsonpath='{.data.password}'|base64 -d)
ADM=$(curl -sk "$KC/realms/master/protocol/openid-connect/token" -d grant_type=password -d client_id=admin-cli -d username="$AU" --data-urlencode "password=$AP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
AID=$(curl -sk -H "Authorization: Bearer $ADM" "$KC/admin/realms/$REALM/users?username=alice&exact=true" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
ROLE=$(curl -sk -H "Authorization: Bearer $ADM" "$KC/admin/realms/$REALM/roles/openshell-admin")
echo "alice: $AID"
echo "assigning openshell-admin ..."
curl -sk -X POST -H "Authorization: Bearer $ADM" -H "Content-Type: application/json" \
  "$KC/admin/realms/$REALM/users/$AID/role-mappings/realm" -d "[$ROLE]" >/dev/null
echo "=== alice realm roles now ==="
curl -sk -H "Authorization: Bearer $ADM" "$KC/admin/realms/$REALM/users/$AID/role-mappings/realm" \
  | python3 -c 'import sys,json;print([r["name"] for r in json.load(sys.stdin)])'
echo
echo ">>> Now open a FRESH private window and sign in to the webui again."
echo ">>> To revert later: remove openshell-admin from alice in Keycloak."
