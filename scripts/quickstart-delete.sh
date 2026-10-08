#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
"${script_dir}/keycloak-delete.sh"
namespace="${BUILD_NS:-openshell-agents}"
for release in openshell-gateway-image openshell-gateway-docker-image \
  nemoclaw-imagestream nemoclaw-cli-imagestream governance-interceptor-image; do
  "${script_dir}/helm-uninstall-if-present.sh" "${release}" "${namespace}"
done
echo "SAW releases remain. Delete each SAW with make saw-delete."
