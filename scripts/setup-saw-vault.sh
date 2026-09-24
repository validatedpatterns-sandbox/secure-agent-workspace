#!/usr/bin/env bash
# Install/validate the SAW ESO integration prerequisites.
set -euo pipefail

command -v oc >/dev/null 2>&1 || { echo "Error: oc is required." >&2; exit 2; }
command -v helm >/dev/null 2>&1 || { echo "Error: helm is required to deploy Vault." >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "Error: openssl is required to generate the Vault dev token." >&2; exit 2; }
VAULT_NS="${VAULT_NS:-vault}"
VAULT_RELEASE="${VAULT_RELEASE:-vault}"
VAULT_STORE_NAME="${VAULT_STORE_NAME:-vault-backend}"
VAULT_DEV_ROOT_TOKEN="${VAULT_DEV_ROOT_TOKEN:-$(openssl rand -hex 24)}"
VAULT_IMAGE_REPOSITORY="${VAULT_IMAGE_REPOSITORY:-docker.io/hashicorp/vault}"
VAULT_IMAGE_TAG="${VAULT_IMAGE_TAG:-1.17.2}"

echo "Installing or updating the SAW External Secrets Operator prerequisites..."
oc apply -f examples/saw/manual-operators.yaml >/dev/null
echo "External Secrets Operator subscriptions applied. Wait for their CSVs/CRDs, then run:"
echo "  make saw-platform-check"
existing_server="$(oc get clustersecretstore "$VAULT_STORE_NAME" -o jsonpath='{.spec.provider.vault.server}' 2>/dev/null || true)"
internal_server="http://${VAULT_RELEASE}.${VAULT_NS}.svc.cluster.local:8200"
if [[ -z "$existing_server" || "$existing_server" == "$internal_server" ]]; then
  echo "Deploying standalone Vault in namespace ${VAULT_NS}..."
  oc create namespace "$VAULT_NS" --dry-run=client -o yaml | oc apply -f - >/dev/null
  # The HashiCorp development image runs as UID 100. Grant only the Vault
  # service account the SCC required by this evaluation-only deployment.
  oc adm policy add-scc-to-user anyuid "system:serviceaccount:${VAULT_NS}:${VAULT_RELEASE}" >/dev/null 2>&1 || true
  helm repo add hashicorp https://helm.releases.hashicorp.com >/dev/null 2>&1 || true
  helm repo update hashicorp >/dev/null
  helm upgrade --install "$VAULT_RELEASE" hashicorp/vault \
    --namespace "$VAULT_NS" \
    --set server.dev.enabled=true \
    --set-string "server.dev.devRootToken=${VAULT_DEV_ROOT_TOKEN}" \
    --set-string "server.image.repository=${VAULT_IMAGE_REPOSITORY}" \
    --set-string "server.image.tag=${VAULT_IMAGE_TAG}" \
    --set server.updateStrategyType=RollingUpdate \
    --set injector.enabled=false \
    --wait --timeout 5m
  # The chart defaults to OnDelete; remove an older failed pod so the pinned
  # image is actually picked up after an upgrade.
  oc delete pod "${VAULT_RELEASE}-0" -n "$VAULT_NS" --ignore-not-found >/dev/null 2>&1 || true
  oc wait --for=condition=Ready "pod/${VAULT_RELEASE}-0" -n "$VAULT_NS" --timeout=5m >/dev/null
  echo "Vault is running in development mode; it is initialized and unsealed automatically."
  echo "Do not use this mode for production or persistent credentials."
  oc create secret generic vault-token -n "$VAULT_NS" \
    --from-literal=token="$VAULT_DEV_ROOT_TOKEN" --dry-run=client -o yaml | oc apply -f - >/dev/null
  if ! oc api-resources --api-group=external-secrets.io -o name 2>/dev/null | grep -Fqx clustersecretstores.external-secrets.io; then
    echo "Vault is running, but the ESO ClusterSecretStore CRD is not ready yet." >&2
    echo "Wait for the ESO CSV/CRD, then rerun: make setup-vault" >&2
    exit 0
  fi
  cat <<EOF | oc apply -f - >/dev/null
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata:
  name: ${VAULT_STORE_NAME}
spec:
  provider:
    vault:
      server: http://${VAULT_RELEASE}.${VAULT_NS}.svc.cluster.local:8200
      path: secret
      version: v2
      auth:
        tokenSecretRef:
          name: vault-token
          namespace: ${VAULT_NS}
          key: token
EOF
  echo "Vault and ClusterSecretStore/${VAULT_STORE_NAME} are ready."
else
  echo "Found ClusterSecretStore/${VAULT_STORE_NAME}; leaving the existing Vault unchanged."
fi
