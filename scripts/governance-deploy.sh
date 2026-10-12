#!/usr/bin/env bash
set -euo pipefail

namespace="${NS:-openshell-agents}"
oc create namespace "${namespace}" --dry-run=client -o yaml | oc apply -f -
helm upgrade --install governance-policy charts/governance-policy \
  --namespace "${namespace}"
helm upgrade --install governance-interceptor charts/governance-interceptor \
  --namespace "${namespace}"
