#!/usr/bin/env bash
# Mark only a Pipelines CSV installed by this pattern for later cleanup.
set -euo pipefail

namespace=openshift-operators
name=openshift-pipelines-operator-rh
tracking="secure-agent-workspace-prod:operators.coreos.com/Subscription:${namespace}/${name}"
subscription="$(oc get subscription "${name}" -n "${namespace}" \
  -o json --ignore-not-found)"
if [[ -z "${subscription}" ]]; then
  echo "Pattern Pipelines subscription is absent."
  exit 0
fi
if ! jq -e --arg tracking "${tracking}" \
    '.metadata.annotations["argocd.argoproj.io/tracking-id"] == $tracking' \
    <<<"${subscription}" >/dev/null; then
  echo "Keeping Pipelines CSV: the subscription has no pattern ownership."
  exit 0
fi

csv="$(jq -r '.status.installedCSV // .status.currentCSV // empty' \
  <<<"${subscription}")"
if [[ -z "${csv}" ]]; then
  echo "Pattern Pipelines subscription has no installed CSV."
  exit 0
fi
if [[ ! "${csv}" =~ ^openshift-pipelines-operator-rh\.v[0-9] ]]; then
  echo "Error: unexpected Pipelines CSV name: ${csv}" >&2
  exit 1
fi
object="$(oc get csv "${csv}" -n "${namespace}" -o json --ignore-not-found)"
if [[ -z "${object}" ]]; then
  echo "Pipelines CSV ${csv} is already absent."
  exit 0
fi
if ! jq -e '.metadata.labels["olm.managed"] == "true" and
    (.metadata.labels | has("operators.coreos.com/openshift-pipelines-operator-rh.openshift-operators"))' \
    <<<"${object}" >/dev/null; then
  echo "Keeping Pipelines CSV ${csv}: it has no matching OLM ownership labels."
  exit 0
fi
oc annotate csv "${csv}" -n "${namespace}" \
  openshell.pattern/cleanup-on-uninstall=secure-agent-workspace-prod --overwrite
