#!/usr/bin/env bash
set -euo pipefail

oc get crd -o json | jq -r '
  .items[].metadata.name |
  select(test("kubevirt|hco|cdi|aaq|hpp|ssp|cnao"))'
