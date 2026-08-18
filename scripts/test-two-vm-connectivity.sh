#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-openshell-agents}"
SSH_KEY_PATH="${SSH_KEY_PATH:-${HOME}/.generated-ssh-keys/sandbox-ssh}"
SSH_USER="${SSH_USER:-cloud-user}"
AGENT_VM="${AGENT_VM:-saw-agent}"
INTEGRATIONS_VM="${INTEGRATIONS_VM:-saw-integrations}"
ALLOWED_SERVICE="${INTEGRATIONS_VM}-gateway"
DENIED_SERVICE="${INTEGRATIONS_VM}-denied"

guest_ssh() {
  local vm="$1"
  local command="$2"
  virtctl -n "${NS}" ssh "${SSH_USER}@vm/${vm}" \
    --identity-file="${SSH_KEY_PATH}" \
    --local-ssh-opts=-oStrictHostKeyChecking=no \
    --local-ssh-opts=-oUserKnownHostsFile=/dev/null \
    --command="${command}"
}

cleanup() {
  oc -n "${NS}" delete service "${DENIED_SERVICE}" --ignore-not-found >/dev/null 2>&1 || true
  guest_ssh "${INTEGRATIONS_VM}" \
    "pkill -f 'python3 -m http.server 18080' || true; pkill -f 'python3 -m http.server 18081' || true" \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT

oc -n "${NS}" wait --for=condition=complete \
  "job/${AGENT_VM}-setup" "job/${INTEGRATIONS_VM}-setup" --timeout=30m

for vm in "${AGENT_VM}" "${INTEGRATIONS_VM}"; do
  guest_ssh "${vm}" "systemctl --user is-active openshell-gateway.service"
done

guest_ssh "${INTEGRATIONS_VM}" \
  "nohup python3 -m http.server 18080 --bind 0.0.0.0 >/tmp/gmail-read-poc.log 2>&1 & nohup python3 -m http.server 18081 --bind 0.0.0.0 >/tmp/denied-poc.log 2>&1 &"

oc -n "${NS}" apply -f deploy/two-vm/networkpolicy.yaml

oc -n "${NS}" apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: ${DENIED_SERVICE}
spec:
  selector:
    app.kubernetes.io/name: ${INTEGRATIONS_VM}
  ports:
    - name: denied-test
      port: 18081
      targetPort: 18081
      protocol: TCP
EOF

allowed_url="http://${ALLOWED_SERVICE}.${NS}.svc.cluster.local:18080/"
denied_url="http://${DENIED_SERVICE}.${NS}.svc.cluster.local:18081/"

guest_ssh "${AGENT_VM}" "curl -fsS --connect-timeout 5 '${allowed_url}' >/dev/null"
echo "PASS: agent VM reached the integrations VM on the reserved Gmail-read port."

if guest_ssh "${AGENT_VM}" "curl -fsS --connect-timeout 3 '${denied_url}' >/dev/null"; then
  echo "FAIL: agent VM reached a denied integrations VM port." >&2
  exit 1
fi
echo "PASS: agent VM could not reach an unapproved integrations VM port."
