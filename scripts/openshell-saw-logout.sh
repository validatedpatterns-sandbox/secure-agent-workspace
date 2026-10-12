#!/usr/bin/env bash
# Clear locally stored OpenShell gateway credentials without cluster access.
# OPENSHELL_SAW_NAME limits cleanup to one registration when set.

set -euo pipefail

command -v openshell >/dev/null 2>&1 || {
  echo "Error: openshell CLI is required to clear gateway credentials." >&2
  exit 1
}

registrations="$(openshell gateway list -o json)"
names="$(jq -r --arg selected "${OPENSHELL_SAW_NAME:-}" '
  if type != "array" then error("expected a gateway list") else
    [.[] | select($selected == "" or .name == $selected) |
      .name | select(type == "string" and length > 0)] | .[]
  end' <<<"${registrations}")"

failed=0
while IFS= read -r name; do
  [[ -n "${name}" ]] || continue
  if openshell gateway logout "${name}"; then
    echo "Cleared local gateway credentials for ${name}."
  else
    echo "Error: could not clear local gateway credentials for ${name}." >&2
    failed=1
  fi
done <<<"${names}"

if (( failed != 0 )); then
  exit 1
fi
echo "Local gateway credential cleanup complete."
