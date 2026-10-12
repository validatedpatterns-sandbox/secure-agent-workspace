#!/usr/bin/env bash
# Keycloak users: generated passwords, never guessable defaults, and no
# self-registration (an admin adds users).
#
#   add-users [FILE]       Create each user in FILE (default
#                          overrides/saw-users.yaml) that is not in the realm
#                          yet, with a generated password; users that exist
#                          are left alone. Passwords stay in Secret $USERS_SECRET.
#   password USER          Show which Secret holds USER's password.
#   reset-password USER    Give USER a new generated password in the Secret.
#   show                   List users that have stored passwords.
#   ensure                 Create or complete Secret $SECRET: a generated
#                          password per test user in the chart's values (the
#                          realm import reads it; `make keycloak-deploy` runs this).
#                          In the Validated Pattern it comes from Vault
#                          (values-secret keycloak-users) instead.
#   harden                 For a realm imported before this: password policy,
#                          brute-force protection, registration off, and the
#                          test users' passwords (an import never changes an
#                          existing realm).
#
# FILE entries (extra keys, e.g. saw-users' profiles, are ignored):
#   - name: carol                # or username:; a lowercase DNS label, at most 19 characters
#     email: carol@example.com   # optional (default <name>@openshell.local), as are firstName and lastName
#     roles: [openshell-user]    # realm roles; default [openshell-user]
#
# add-users, reset-password and harden use the Keycloak admin Secret
# (<KEYCLOAK_NAME>-initial-admin).
#
# Env: KEYCLOAK_NS (saw-keycloak), KEYCLOAK_REALM (openshell),
#      KEYCLOAK_NAME (openshell-keycloak, the Keycloak CR),
#      KEYCLOAK_CHART (charts/openshell-keycloak),
#      SECRET (openshell-keycloak-user-passwords),
#      USERS_SECRET (openshell-keycloak-users)

set -euo pipefail

NS="${KEYCLOAK_NS:-saw-keycloak}"
REALM="${KEYCLOAK_REALM:-openshell}"
KC_NAME="${KEYCLOAK_NAME:-openshell-keycloak}"
CHART="${KEYCLOAK_CHART:-charts/openshell-keycloak}"
SECRET="${SECRET:-openshell-keycloak-user-passwords}"
# Passwords this script set (add-users, reset-password). Separate from SECRET:
# in the pattern that one is owned by External Secrets, which would drop or
# overwrite keys it does not know. Wins over SECRET for the same user.
USERS_SECRET="${USERS_SECRET:-openshell-keycloak-users}"
DEFAULT_USERS_FILE="${DEFAULT_USERS_FILE:-overrides/saw-users.yaml}"

run_python() {
  if [[ "${CI:-}" == true ]]; then
    "${PYTHON:-python}" "$@"
  else
    uv run --locked python "$@"
  fi
}

usernames() {
  run_python - "${CHART}/values.yaml" <<'EOF'
import sys, yaml
kc = (yaml.safe_load(open(sys.argv[1])) or {}).get("keycloak") or {}
for u in kc.get("testUsers") or []:
    if not u.get("password"):
        print(u["username"])
EOF
}

# 24 characters, at least one of each class Keycloak's policy asks for.
# No quotes, $, & or spaces: the password survives shells and form posts.
new_password() {
  run_python - <<'EOF'
import secrets, string
special = "-_.!@#%^*+="
alphabet = string.ascii_letters + string.digits + special
while True:
    pw = "".join(secrets.choice(alphabet) for _ in range(24))
    if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw) and any(c in special for c in pw)):
        print(pw)
        break
EOF
}

secret_json() {  # $1 Secret name; {} when it does not exist
  local out
  if out="$(oc get secret "$1" -n "${NS}" -o json 2>&1)"; then
    :
  elif [[ -z "${out}" || "${out}" == *NotFound* || "${out}" == *"not found"* ]]; then
    out='{}'
  else
    echo "Error: cannot read Secret $1 in ${NS}. Check cluster access." >&2
    return 1
  fi
  printf '%s\n' "${out:-{\}}"
}

secret_keys() {  # $1 Secret name: its keys, one per line
  secret_json "$1" | run_python -c '
import sys, json
print("\n".join(sorted((json.load(sys.stdin).get("data") or {}))))'
}

current_password() {  # user: the one this script set last, else the test-user Secret's
  local pw
  pw="$(password_of "$1" "${USERS_SECRET}")"
  [[ -n "${pw}" ]] || pw="$(password_of "$1")"
  printf '%s' "${pw}"
}

password_of() {  # $1 user [$2 Secret]; empty when the Secret has none
  secret_json "${2:-${SECRET}}" | run_python -c '
import sys, json, base64
data = json.load(sys.stdin).get("data") or {}
v = data.get(sys.argv[1])
print(base64.b64decode(v).decode() if v else "")' "$1"
}

store_passwords() {  # $1 Secret, then user=password ...; existing keys are kept
  local secret="$1" args=() line
  shift
  local namespaces
  namespaces="$(oc get namespaces -o json)"
  if ! jq -e --arg ns "${NS}" '.items | any(.metadata.name == $ns)' \
      <<<"${namespaces}" >/dev/null; then
    oc create namespace "${NS}" >/dev/null
  fi
  for line in "$@"; do args+=("--from-literal=${line}"); done
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    case " $* " in *" ${line%%=*}="*) continue ;; esac   # replaced
    args+=("--from-literal=${line}")
  done < <(secret_json "${secret}" | run_python -c '
import sys, json, base64
for k, v in (json.load(sys.stdin).get("data") or {}).items():
    print(k + "=" + base64.b64decode(v).decode())')
  oc create secret generic "${secret}" -n "${NS}" "${args[@]}" --dry-run=client -o yaml | oc apply -f - >/dev/null
}

ensure() {
  local user new=() added=()
  for user in $(usernames); do
    if [[ -z "$(password_of "${user}")" ]]; then
      new+=("${user}=$(new_password)")
      added+=("${user}")
    fi
  done
  if [[ ${#added[@]} -eq 0 ]]; then
    echo "Keycloak user passwords: Secret ${SECRET} in ${NS} is complete."
    return 0
  fi
  store_passwords "${SECRET}" "${new[@]}"
  echo "Keycloak user passwords: generated for ${added[*]} (Secret ${SECRET} in ${NS})."
  echo "  Password values stay in the Kubernetes Secret."
}

show() {
  local user found=0
  for user in $( (usernames; secret_keys "${USERS_SECRET}") | sort -u); do
    [[ -n "${user}" ]] || continue
    local pw
    pw="$(current_password "${user}")"
    [[ -n "${pw}" ]] || continue
    printf '%-20s stored in a Keycloak user Secret\n' "${user}"
    found=1
  done
  if [[ ${found} -eq 0 ]]; then
    echo "No passwords in Secrets ${SECRET} or ${USERS_SECRET} in ${NS}. Run: make keycloak-deploy" >&2
    exit 1
  fi
}

password() {
  local user="${1:-}" pw
  [[ -n "${user}" ]] || { echo "usage: $0 password USER" >&2; exit 2; }
  pw="$(current_password "${user}")"
  if [[ -z "${pw}" ]]; then
    echo "No password for ${user} in Secrets ${SECRET} or ${USERS_SECRET} in ${NS} (set outside this" >&2
    echo "script?). Give them a new one: make keycloak-reset-password KC_USER=${user}" >&2
    exit 1
  fi
  if [[ -n "$(password_of "${user}" "${USERS_SECRET}")" ]]; then
    echo "${user}: password is in Secret ${USERS_SECRET}, key ${user}, namespace ${NS}."
  else
    echo "${user}: password is in Secret ${SECRET}, key ${user}, namespace ${NS}."
  fi
}

# --- Keycloak admin API -----------------------------------------------------

BASE=""
AUTH=()
admin_login() {
  local host admin_user admin_pass token
  local keycloaks
  keycloaks="$(oc get keycloak -n "${NS}" -o json)"
  host="$(jq -r --arg name "${KC_NAME}" \
    'first(.items[] | select(.metadata.name == $name) | .status.externalURL) // empty' \
    <<<"${keycloaks}")"
  BASE="${host:-https://$("$(dirname "$0")/keycloak-host.sh" "${NS}")}"
  admin_user="$(oc get secret "${KC_NAME}-initial-admin" -n "${NS}" -o jsonpath='{.data.username}' | base64 -d)"
  admin_pass="$(oc get secret "${KC_NAME}-initial-admin" -n "${NS}" -o jsonpath='{.data.password}' | base64 -d)"
  token="$(curl -sk --data-urlencode "username=${admin_user}" --data-urlencode "password=${admin_pass}" \
    -d grant_type=password -d client_id=admin-cli \
    "${BASE}/realms/master/protocol/openid-connect/token" | jq -r '.access_token // empty')"
  if [[ -z "${token}" ]]; then
    echo "Error: could not get a Keycloak admin token from ${BASE}" >&2
    exit 1
  fi
  AUTH=(-H "Authorization: Bearer ${token}" -H "Content-Type: application/json")
}

api_code() {  # METHOD path [json]: prints the HTTP status
  local data=()
  [[ $# -ge 3 ]] && data=(-d "$3")
  curl -sk -o /dev/null -w '%{http_code}' -X "$1" "${AUTH[@]}" "${data[@]}" "${BASE}/admin/realms/${REALM}$2"
}

api_get() {  # path
  curl -sk "${AUTH[@]}" "${BASE}/admin/realms/${REALM}$1"
}

user_id() {  # username; empty when not in the realm
  api_get "/users?exact=true&username=$1" | jq -r '.[0].id // empty'
}

set_password() {  # user id, password, temporary (true|false)
  api_code PUT "/users/$1/reset-password" \
    "$(jq -n --arg pw "$2" --argjson t "$3" '{type: "password", value: $pw, temporary: $t}')"
}

harden() {
  admin_login
  local settings code failed=0
  settings="$(run_python - "${CHART}/values.yaml" <<'EOF'
import sys, json, yaml
kc = (yaml.safe_load(open(sys.argv[1])) or {}).get("keycloak") or {}
bf = kc.get("bruteForce") or {}
out = {"bruteForceProtected": bool(bf.get("enabled")), "permanentLockout": False,
       "failureFactor": bf.get("failureFactor", 5),
       "waitIncrementSeconds": bf.get("waitIncrementSeconds", 60),
       "maxFailureWaitSeconds": bf.get("maxFailureWaitSeconds", 900),
       "maxDeltaTimeSeconds": bf.get("maxDeltaTimeSeconds", 43200),
       "registrationAllowed": bool(kc.get("registrationAllowed", False))}
if kc.get("passwordPolicy"):
    out["passwordPolicy"] = " ".join(kc["passwordPolicy"].split())
print(json.dumps(out))
EOF
)"
  code="$(api_code PUT "" "${settings}")"
  [[ "${code}" == 204 ]] || { echo "Error: setting the realm policy failed (HTTP ${code})" >&2; exit 1; }
  echo "Realm ${REALM}: password policy, brute-force protection and registration setting applied."

  local user pw id
  for user in $(usernames); do
    pw="$(current_password "${user}")"
    if [[ -z "${pw}" ]]; then
      echo "  ${user}: no password in Secret ${SECRET}; run 'ensure' first" >&2
      continue
    fi
    id="$(user_id "${user}")"
    if [[ -z "${id}" ]]; then
      echo "  ${user}: not in the realm, skipped"
      continue
    fi
    code="$(set_password "${id}" "${pw}" false)"
    if [[ "${code}" == 204 ]]; then
      echo "  ${user}: password set from the Secret"
    else
      echo "  ${user}: password reset failed (HTTP ${code})" >&2
      failed=1
    fi
  done
  return "${failed}"
}

# Checks FILE and prints one JSON object per user. User names name the VM
# (saw-<user>, <user>-<workspace>-<sandbox>-ui), so they are lowercase DNS
# labels of at most 19 characters.
read_users() {  # FILE (or -: stdin)
  local prog
  prog="$(cat <<'EOF'
import json, re, sys, yaml
src = sys.stdin if sys.argv[1] == "-" else open(sys.argv[1])
doc = yaml.safe_load(src) or {}
users = doc.get("users") if isinstance(doc, dict) else doc
kc = (yaml.safe_load(open(sys.argv[2])) or {}).get("keycloak") or {}
known_roles = set(kc.get("roles") or [])
errors, seen = [], set()
if not isinstance(users, list) or not users:
    sys.exit("users file: needs a list `users:` with at least one user")
NAME = re.compile(r"^[a-z]([a-z0-9-]{0,17}[a-z0-9])?$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
for i, u in enumerate(users):
    where = f"users[{i}]"
    if not isinstance(u, dict):
        u = {"username": u} if isinstance(u, str) else {}
    name = str(u.get("username") or u.get("name") or "")
    if not NAME.match(name) or name.endswith(("-bom", "-secrets")):
        errors.append(f"{where}: username {name!r} must be a lowercase DNS label of at most 19 "
                      "characters, not ending in -bom or -secrets")
    if name in seen:
        errors.append(f"{where}: {name} is listed twice")
    seen.add(name)
    roles = u.get("roles") or ["openshell-user"]
    unknown = [r for r in roles if r not in known_roles]
    if unknown:
        errors.append(f"{where}: unknown roles {unknown} (realm roles: {sorted(known_roles)})")
    # Keycloak's user profile requires an email: without one, the user is
    # stopped at "Update Account Information" on first sign-in (found live).
    # Same default as the realm import's test users.
    email = u.get("email") or f"{name}@openshell.local"
    if not EMAIL.match(email):
        errors.append(f"{where}: email {email!r} is not an address")
    if not isinstance(u.get("temporaryPassword", False), bool):
        errors.append(f"{where}: temporaryPassword must be true or false")
    print(json.dumps({"username": name, "firstName": u.get("firstName") or name.title(),
                      "lastName": u.get("lastName") or "User", "email": email, "roles": roles,
                      "temporary": u.get("temporaryPassword", False)}))
if errors:
    sys.exit("users file:\n  " + "\n  ".join(errors))
EOF
)"
  run_python -c "${prog}" "$1" "${CHART}/values.yaml"
}

add_users() {
  local file="${1:-${DEFAULT_USERS_FILE}}"
  [[ "${file}" == "-" || -f "${file}" ]] || { echo "Error: ${file} not found" >&2; exit 1; }
  local users
  users="$(read_users "${file}")" || exit 1    # all checked before any change
  admin_login

  local u name id pw code body role roles_json stored=() failed=0
  while IFS= read -r u; do
    name="$(jq -r .username <<< "${u}")"
    if [[ -n "$(user_id "${name}")" ]]; then
      echo "  ${name}: exists, skipped"
      continue
    fi
    pw="$(new_password)"
    body="$(jq --arg pw "${pw}" '{username, firstName, lastName, enabled: true,
        emailVerified: true, requiredActions: [],
        credentials: [{type: "password", value: $pw, temporary: .temporary}]}
      + {email}' <<< "${u}")"
    code="$(api_code POST "/users" "${body}")"
    if [[ "${code}" != 201 ]]; then
      echo "  ${name}: not created (HTTP ${code})" >&2
      failed=1
      continue
    fi
    stored+=("${name}=${pw}")
    id="$(user_id "${name}")"
    roles_json="[]"
    for role in $(jq -r '.roles[]' <<< "${u}"); do
      roles_json="$(jq --argjson r "$(api_get "/roles/${role}")" '. + [$r]' <<< "${roles_json}")"
    done
    code="$(api_code POST "/users/${id}/role-mappings/realm" "${roles_json}")"
    if [[ "${code}" == 204 ]]; then
      echo "  ${name}: created"
    else
      echo "  ${name}: created, but roles not assigned (HTTP ${code})" >&2
      failed=1
    fi
  done <<< "${users}"

  if [[ ${#stored[@]} -gt 0 ]]; then
    store_passwords "${USERS_SECRET}" "${stored[@]}"
    echo "New passwords are in Secret ${USERS_SECRET} in ${NS}."
  fi
  return "${failed}"
}

reset_password() {
  local user="${1:-}" id pw code
  [[ -n "${user}" ]] || { echo "usage: $0 reset-password USER" >&2; exit 2; }
  admin_login
  id="$(user_id "${user}")"
  [[ -n "${id}" ]] || { echo "Error: ${user} is not in realm ${REALM}" >&2; exit 1; }
  pw="$(new_password)"
  code="$(set_password "${id}" "${pw}" false)"
  [[ "${code}" == 204 ]] || { echo "Error: password reset for ${user} failed (HTTP ${code})" >&2; exit 1; }
  store_passwords "${USERS_SECRET}" "${user}=${pw}"
  echo "Password for ${user} was reset in Secret ${USERS_SECRET} in ${NS}."
}

case "${1:-}" in
  ensure) ensure ;;
  show) show ;;
  harden) harden ;;
  add-users) add_users "${2:-}" ;;
  password) password "${2:-}" ;;
  reset-password) reset_password "${2:-}" ;;
  *) echo "usage: $0 add-users [FILE]|password USER|reset-password USER|show|ensure|harden" >&2; exit 2 ;;
esac
