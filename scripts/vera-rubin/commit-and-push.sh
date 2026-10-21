#!/usr/bin/env bash
# Commit the Vera Rubin deployment automation + docs and push to the branch.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "repo: $(pwd)   branch: $(git branch --show-current)"
git add scripts/vera-rubin/ docs/vera-rubin-ocp.md README.md
echo "=== staged changes ==="
git status --short
echo
git commit -m "docs(ocp5-rc5): Vera Rubin deployment automation + guide

Add scripts/vera-rubin/ pre/post-install automation and a deployment guide for
SAW on arm64 OpenShift 5.0 rc5 (NVIDIA Vera Rubin / verac2):

- preinstall.sh: create the RHDH community CatalogSource (arm64) and install the
  arm64 patterns-operator (quay.io/sauagarw, out-of-catalog) with its service-CA
  webhook cert.
- postinstall.sh: ensure the saw-hostpath StorageClass uses the HPP CSI
  provisioner, inject the arm64 Postgres image into the RHDH subscription
  config.env, and remove resolution-poisoning orphan subscriptions.
- manifests/: captured patterns-operator (arm64), its CRD, the RHDH
  CatalogSource, RHDH subscription, StorageClass, HPP CR, and the Pattern CR.
- export-*.sh / diag-*.sh: helpers used to capture state and bring the cluster up.
- docs/vera-rubin-ocp.md: end-to-end guide, changes grouped by root cause
  (arch / rc5 catalog gaps / cluster-env), DNS and known caveats; linked from
  README.md.

The chart/values changes this depends on are already committed on this branch.

Assisted-By: Claude"
git push
echo
echo ">>> pushed to $(git branch --show-current) on $(git remote get-url origin)"
