#!/usr/bin/env bash
set -euo pipefail

name="${OPENSHELL_SAW_NAME:-}"
if [[ -z "${name}" ]]; then
  echo "Error: OPENSHELL_SAW_NAME is required. Pass OPENSHELL_SAW_NAME=my-saw." >&2
  exit 1
fi
if [[ ${#name} -gt 19 || ! "${name}" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]]; then
  echo "Error: OPENSHELL_SAW_NAME must be a lowercase DNS label of at most 19 characters." >&2
  exit 1
fi
