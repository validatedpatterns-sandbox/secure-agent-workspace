#!/usr/bin/env bash
# Inspect the live openshell-dashboard + openshell-cli clients: do they emit
# realm_access.roles? Is Full Scope Allowed on?
set -uo pipefail
NS=saw-keycloak; REALM=openshell
HOST=$(oc get route -n $NS -o jsonpath='{.items[0].spec.host}' 2>/dev/null); KC="https://$HOST"
AU=$(oc get secret openshell-keycloak-initial-admin -n $NS -o jsonpath='{.data.username}'|base64 -d)
AP=$(oc get secret openshell-keycloak-initial-admin -n $NS -o jsonpath='{.data.password}'|base64 -d)
TOKEN=$(curl -sk "$KC/realms/master/protocol/openid-connect/token" -d grant_type=password -d client_id=admin-cli -d username="$AU" --data-urlencode "password=$AP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))')
[ -z "$TOKEN" ] && { echo "no admin token"; exit 1; }
for CID in openshell-dashboard openshell-cli; do
  echo "======================== client: $CID ========================"
  CJSON=$(curl -sk -H "Authorization: Bearer $TOKEN" "$KC/admin/realms/$REALM/clients?clientId=$CID")
  echo "$CJSON" | python3 -c '
import sys,json
c=json.load(sys.stdin)
if not c: print("  CLIENT NOT FOUND"); sys.exit()
c=c[0]
print("  id:", c["id"])
print("  fullScopeAllowed:", c.get("fullScopeAllowed"))
print("  publicClient:", c.get("publicClient"), " standardFlow:", c.get("standardFlowEnabled"), " directAccess:", c.get("directAccessGrantsEnabled"))
print("  protocolMappers:")
for m in c.get("protocolMappers",[]) or []:
    cfg=m.get("config",{})
    print("    -", m["name"], "|", m.get("protocolMapper"), "| claim=", cfg.get("claim.name"), "| access.token=", cfg.get("access.token.claim"), "| id.token=", cfg.get("id.token.claim"))
' 2>&1
  # the client id for scope-mappings
  CUUID=$(echo "$CJSON" | python3 -c 'import sys,json;c=json.load(sys.stdin);print(c[0]["id"] if c else "")')
  if [ -n "$CUUID" ]; then
    echo "  scope-mappings (realm roles in client scope):"
    curl -sk -H "Authorization: Bearer $TOKEN" "$KC/admin/realms/$REALM/clients/$CUUID/scope-mappings/realm" | python3 -c 'import sys,json;print("   ",[r["name"] for r in json.load(sys.stdin)])' 2>&1
    echo "  default client scopes:"
    curl -sk -H "Authorization: Bearer $TOKEN" "$KC/admin/realms/$REALM/clients/$CUUID/default-client-scopes" | python3 -c 'import sys,json;print("   ",[s["name"] for s in json.load(sys.stdin)])' 2>&1
  fi
done
