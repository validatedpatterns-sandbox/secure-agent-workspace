#!/usr/bin/env bash
# Install the CI-built gateway's bundle verification tools into its mounted disk.
set -euo pipefail

guest="${1:?Usage: install-gateway-verification.sh <mounted-guest>}"
files="${GATEWAY_FILES:-image-builder-charts/helm/openshell-gateway-image/files}"
floor="${SIGNING_FLOOR:-}"
case "$floor" in ''|off|warn|enforce) ;; *) echo 'Error: invalid signing.floor.' >&2; exit 1 ;; esac
[[ "${COSIGN_SHA256:-}" =~ ^[a-fA-F0-9]{64}$ ]] || { echo 'Error: invalid Cosign checksum.' >&2; exit 1; }
archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT
curl -fsSL -o "$archive" "${COSIGN_URL:?COSIGN_URL is required}"
printf '%s  %s\n' "$COSIGN_SHA256" "$archive" | sha256sum -c -
install -d -m 0755 "$guest/etc/saw/trust"
install -D -m 0755 "$files/verify-bundle" "$guest/usr/libexec/saw/verify-bundle"
install -D -m 0644 "$files/registries.yaml" "$guest/etc/containers/registries.d/saw.yaml"
install -D -m 0755 "$archive" "$guest/usr/local/bin/cosign"
if [[ -n "$floor" ]]; then
  printf '%s' "$floor" > "$guest/etc/saw/signing-mode"
  chmod 0644 "$guest/etc/saw/signing-mode"
fi
