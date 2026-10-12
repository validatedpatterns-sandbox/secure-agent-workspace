#!/usr/bin/env bash
# Route lookup only. Do not put the dashboard token in terminal output.
set -euo pipefail

namespace="${SAW_NS:?SAW_NS is required}"
routes="$(oc get routes -n "${namespace}" \
  -l openshell.pattern/sandbox-ui=true -o json)"
jq -r '.items[] |
  [.metadata.annotations["openshell.pattern/sandbox"],
   .metadata.annotations["openshell.pattern/workspace"],
   ("https://" + .spec.host)] | @tsv' <<<"${routes}"
