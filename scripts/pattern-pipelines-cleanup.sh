#!/usr/bin/env bash
# Remove only marked Pipelines CSVs after the pattern subscription is gone.
set -euo pipefail

namespace=openshift-operators
subscriptions="$(oc get subscriptions.operators.coreos.com -A -o json)"
if jq -e '.items | any(.spec.name == "openshift-pipelines-operator-rh")' \
    <<<"${subscriptions}" >/dev/null; then
  echo "Keeping Pipelines CSV: a Pipelines subscription still exists."
  exit 0
fi

objects="$(oc get csv -n "${namespace}" -o json)"
names="$(jq -r '.items[] | select(
  .metadata.annotations["openshell.pattern/cleanup-on-uninstall"] ==
    "secure-agent-workspace-prod" and
  .metadata.labels["olm.managed"] == "true" and
  (.metadata.labels | has("operators.coreos.com/openshift-pipelines-operator-rh.openshift-operators")) and
  (.metadata.name | test("^openshift-pipelines-operator-rh\\.v[0-9]"))) |
  .metadata.name' <<<"${objects}")"
while IFS= read -r name; do
  [[ -n "${name}" ]] || continue
  echo "Deleting pattern-owned Pipelines CSV ${namespace}/${name}."
  oc delete csv "${name}" -n "${namespace}" --wait=false
done <<<"${names}"
