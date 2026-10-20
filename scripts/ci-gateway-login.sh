#!/usr/bin/env bash
# Configure an OIDC gateway unattended and wait for its installed sandbox.
set -euo pipefail
exec python3 "$(dirname "$0")/ci-gateway-login.py" "$@"
