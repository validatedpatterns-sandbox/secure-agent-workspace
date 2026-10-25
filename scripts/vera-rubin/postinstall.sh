#!/usr/bin/env bash
# =============================================================================
# SAW on OpenShift 5.0 rc5 / arm64 (Vera Rubin / verac2) — POST-INSTALL
# -----------------------------------------------------------------------------
# Run AFTER `./pattern.sh make install`, while the operators are installing.
# Each step waits for its prerequisite, so it is safe to run once (or re-run).
#   1. ensure the saw-hostpath StorageClass uses the HPP CSI provisioner name
#   2. inject the arm64 Postgres image into the RHDH subscription config.env
# See docs/vera-rubin-ocp.md.
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; MAN="$HERE/manifests"
oc whoami >/dev/null || { echo "ERROR: not logged in (oc login)"; exit 1; }

echo "== [1/2] storage: saw-hostpath StorageClass must use the HPP CSI name =="
# OpenShift Virtualization's HPP registers provisioner 'kubevirt.io.hostpath-provisioner'
# (dots). A StorageClass with the slash form never binds. StorageClasses are
# immutable, so a wrong one is deleted and recreated.
WANT="kubevirt.io.hostpath-provisioner"
if oc get sc saw-hostpath >/dev/null 2>&1; then
  cur=$(oc get sc saw-hostpath -o jsonpath='{.provisioner}')
  if [ "$cur" != "$WANT" ]; then
    echo "   provisioner is '$cur' -> recreating with '$WANT'"
    oc delete sc saw-hostpath
    oc apply -f "$MAN/storageclass-saw-hostpath.yaml"
  else echo "   ok ($cur)"; fi
else
  echo "   creating saw-hostpath"; oc apply -f "$MAN/storageclass-saw-hostpath.yaml"
fi

echo "== [2/2] RHDH: inject arm64 Postgres image into the subscription config.env =="
# The community RHDH operator defaults to an amd64 Postgres image -> 'Exec format
# error' on arm64. `oc set env` is reverted by OLM; Subscription .spec.config.env
# survives reconcile.
echo "   waiting for subscription/rhdh in rhdh-operator..."
for i in $(seq 1 60); do oc get subscription rhdh -n rhdh-operator >/dev/null 2>&1 && break; sleep 5; done
if oc get subscription rhdh -n rhdh-operator >/dev/null 2>&1; then
  oc patch subscription rhdh -n rhdh-operator --type merge -p \
    '{"spec":{"config":{"env":[{"name":"RELATED_IMAGE_postgresql","value":"registry.redhat.io/rhel9/postgresql-15:latest"}]}}}'
  echo "   patched. (The operator will roll the RHDH DB to the arm64 image.)"
else
  echo "   subscription/rhdh not present yet -> re-run this script once it is."
fi

cat <<'NEXT'

== post-install done ==
Next:
  * Load the pattern secrets once Vault is up (see docs/vera-rubin-ocp.md for the
    /etc/hosts entry the keycloak route needs during load-secrets):
       ./pattern.sh make load-secrets
  * Set up DNS for *.apps.<cluster-domain> on your workstation (dnsmasq or /etc/hosts).
  * Known runtime caveat: a sandbox's openclaw control-UI gateway is launched
    unsupervised; if it dies, its *-ui route 502s. Restart it from the sandbox
    terminal in the RHDH/OpenShell web UI:
       nohup openclaw gateway run --allow-unconfigured --bind lan --port 18789 --force >/tmp/gw.log 2>&1 &
NEXT
