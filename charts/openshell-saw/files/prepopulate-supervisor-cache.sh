#!/usr/bin/env bash
# Run as the gateway user before each start. Use the ODH sandbox binary;
# the upstream image's /openshell-supervisor is a different executable.
set -euo pipefail
runtime="${1:-docker}"
image="ghcr.io/nvidia/openshell/supervisor:dev"
"${runtime}" pull "${image}" || true
# Avoid Docker Go templates here: Helm tpl also interprets their delimiters.
digest="$("${runtime}" images --no-trunc -q "${image}" | head -1)"
digest="${digest#sha256:}"
if [[ ! "${digest}" =~ ^[a-f0-9]{64}$ ]]; then
  echo "ERROR: cannot resolve supervisor image digest" >&2
  exit 1
fi
cache_dir="${HOME}/.local/share/openshell/docker-supervisor/sha256-${digest}"
mkdir -p "${cache_dir}"
install -m 755 /usr/local/bin/openshell-supervisor "${cache_dir}/openshell-sandbox.tmp"
mv -f "${cache_dir}/openshell-sandbox.tmp" "${cache_dir}/openshell-sandbox"
echo "Pre-populated supervisor cache sha256:${digest} (ODH binary)"
