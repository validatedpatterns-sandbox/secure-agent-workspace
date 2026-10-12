#!/usr/bin/env bash
# Will workspace VMs trust the OIDC issuer? Run before `./pattern.sh make
# install` (make check-oidc-ca). Each workspace VM's gateway verifies the
# issuer with Fedora's public CAs and exits when it cannot.
#  - In-cluster Keycloak on OpenShift's self-signed *.apps certificate: the
#    validated pattern trusts the cluster's ingress CA by itself (saw-ingress-ca
#    imperative job); the quickstart needs oidc.caBundle.
#  - External issuer with a private CA: oidc.caBundle, always.
# Prints what to add, and where.
#
#   ISSUER=<url>   check an external issuer instead of the cluster's *.apps
#   CA_OUT=<file>  where to save the cluster's ingress CA (default ingress-ca.pem)
#
# Exit 0: nothing to do. Exit 2: oidc.caBundle is needed. Exit 3: the
# validated pattern handles it; the quickstart needs oidc.caBundle.
# Exit 1: could not tell.
set -uo pipefail

ISSUER="${ISSUER:-}"
CA_OUT="${CA_OUT:-ingress-ca.pem}"
ERR=$(mktemp)
trap 'rm -f "${ERR}"' EXIT

need() {
  echo
  echo "  => Workspace VMs will not trust ${1} on their own. Set oidc.caBundle before"
  echo "     installing, or every workspace's install fails (cannot verify the OIDC"
  echo "     issuer's certificate)."
}

in_cluster() {
  echo
  echo "  => Workspace VMs do not trust this certificate on their own."
  echo "     Validated pattern (./pattern.sh make install): nothing to do. The"
  echo "     saw-ingress-ca imperative job puts the cluster's ingress CA in Vault and"
  echo "     every workspace trusts it (saw-users defaults.clusterCaSecret)."
  echo "     Quickstart (make openshell-saw-create), or with clusterCaSecret turned off:"
  echo "     set oidc.caBundle, below."
}

snippet() {
  echo
  echo "  oidc.caBundle for all users, in overrides/saw-users.yaml:"
  echo
  echo "    defaults:"
  echo "      openshellSaw:"
  echo "        oidc:"
  echo "          caBundle: |"
  sed 's/^/            /' "$1"
  echo
  echo "  Quickstart (make openshell-saw-create) instead: helm upgrade <name> charts/openshell-saw \\"
  echo "    -n <namespace> --reuse-values --set-file oidc.caBundle=$1"
  echo "  See docs/deployment-guide.md, \"The issuer's certificate\"."
}

# Verify like the VM does: public CAs only, so a CA this machine happens to
# trust (added locally) does not hide the problem.
public_ca_bundle() {
  for f in /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/certs/ca-certificates.crt \
           /etc/ssl/cert.pem; do
    [[ -r "$f" ]] && { echo "$f"; return; }
  done
}

verifies() {
  local url="$1" ca
  ca=$(public_ca_bundle)
  curl -sS -o /dev/null --max-time 15 ${ca:+--cacert "$ca"} "$url" 2>"${ERR}"
}

echo "Checking whether workspace VMs will trust the OIDC issuer..."

if [[ -n "${ISSUER}" ]]; then
  url="${ISSUER%/}/.well-known/openid-configuration"
  if verifies "$url"; then
    echo "  ${ISSUER}: certificate from a public CA. Nothing to do."
    exit 0
  fi
  if grep -qiE 'certificate|SSL' "${ERR}"; then
    echo "  ${ISSUER}: $(head -1 "${ERR}")"
    need "${ISSUER}"
    echo "  Set oidc.caBundle to your organisation's root CA (and intermediates), PEM."
    exit 2
  fi
  echo "  Could not reach ${url}: $(head -1 "${ERR}")"
  exit 1
fi

oc whoami >/dev/null 2>&1 || { echo "  Not logged in to OpenShift (oc login first)."; exit 1; }
domain=$(oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}' 2>/dev/null)
custom=$(oc get ingresscontroller default -n openshift-ingress-operator \
  -o jsonpath='{.spec.defaultCertificate.name}' 2>/dev/null)
echo "  Apps domain: ${domain:-unknown}"

save_ca() {
  oc get cm default-ingress-cert -n openshift-config-managed \
    -o jsonpath='{.data.ca-bundle\.crt}' > "${CA_OUT}" 2>/dev/null
  if grep -q 'BEGIN CERTIFICATE' "${CA_OUT}" 2>/dev/null; then
    echo "  Saved the cluster's ingress CA to ${CA_OUT}."
    snippet "${CA_OUT}"
  else
    echo "  Could not read openshift-config-managed/default-ingress-cert; get the CA from your cluster admin."
  fi
}

if [[ -z "${custom}" ]]; then
  echo "  *.apps certificate: OpenShift's self-signed default (no custom certificate on the default IngressController)."
  in_cluster
  save_ca
  exit 3
fi

echo "  *.apps certificate: custom (Secret ${custom} in openshift-ingress)."
if [[ -z "${domain}" ]]; then
  echo "  Could not read the apps domain; check by hand from a workspace VM."
  exit 1
fi
url="https://console-openshift-console.${domain}/"
if verifies "$url"; then
  echo "  It verifies against public CAs. Nothing to do for the in-cluster Keycloak."
  exit 0
fi
if grep -qiE 'certificate|SSL' "${ERR}"; then
  echo "  It does not verify against public CAs: $(head -1 "${ERR}")"
  in_cluster
  save_ca
  exit 3
fi
echo "  Could not reach ${url} from here: $(head -1 "${ERR}")"
echo "  Run this where the cluster's routes are reachable, or check from a workspace VM."
exit 1
