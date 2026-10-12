#!/usr/bin/env bash
set -euo pipefail

namespace="${KEYCLOAK_NS:-saw-keycloak}"
namespaces="$(oc get namespaces -o json)"
if ! jq -e --arg ns "${namespace}" '.items | any(.metadata.name == $ns)' \
    <<<"${namespaces}" >/dev/null; then
  echo "Namespace ${namespace} is already absent."
  exit 0
fi

releases="$(helm list -n "${namespace}" -o json)"
if jq -e '. | any(.name == "openshell-keycloak")' \
    <<<"${releases}" >/dev/null; then
  values="$(helm get values openshell-keycloak -n "${namespace}" -a -o json)"
  existing="$(jq -r '.keycloak.existing // empty' <<<"${values}")"
  helm uninstall openshell-keycloak -n "${namespace}"
  if [[ -z "${existing}" ]]; then
    oc delete pvc keycloak-db -n "${namespace}" --ignore-not-found=true
    oc delete secret keycloak-db-secret -n "${namespace}" --ignore-not-found=true
  fi
else
  echo "Helm release openshell-keycloak is already absent from ${namespace}."
fi
