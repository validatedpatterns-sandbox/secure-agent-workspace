#!/usr/bin/env bash
set -euo pipefail

if patterns="$(oc get patterns -A -o json 2>&1)"; then
  if jq -e '.items | any(.metadata.name == "secure-agent-workspace")' \
      <<<"${patterns}" >/dev/null; then
    exit 0
  fi
  exit 1
fi
if [[ "${patterns}" == *"doesn't have a resource type"* ||
      "${patterns}" == *"the server could not find the requested resource"* ]]; then
  exit 1
fi
echo "Error: cannot determine whether the pattern exists. Check cluster access." >&2
exit 2
