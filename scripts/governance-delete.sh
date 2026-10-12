#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
namespace="${NS:-openshell-agents}"
"${script_dir}/helm-uninstall-if-present.sh" governance-interceptor "${namespace}"
"${script_dir}/helm-uninstall-if-present.sh" governance-policy "${namespace}"
