#!/usr/bin/env bash
set -euo pipefail

release="${1:?release name is required}"
namespace="${2:?namespace is required}"
namespaces="$(oc get namespaces -o json)"
if ! jq -e --arg ns "${namespace}" '.items | any(.metadata.name == $ns)' \
  <<<"${namespaces}" >/dev/null; then
  echo "Namespace ${namespace} is already absent."
  exit 0
fi
releases="$(helm list -n "${namespace}" -o json)"
if jq -e --arg release "${release}" '. | any(.name == $release)' \
  <<<"${releases}" >/dev/null; then
  helm uninstall "${release}" -n "${namespace}"
else
  echo "Helm release ${release} is already absent from ${namespace}."
fi
