#!/usr/bin/env bash
# Phase: create cloud-init secret, label VM, wait for VMI + SSH + cloud-init.
# Expects: VM_NAME, NS, SSH_USER, SSH_SECRET, SSH_KEY, guest_ssh (function)

# --- Create cloud-init Secret from template ConfigMap ---
CLOUDINIT_SECRET="${VM_NAME}-cloudinit"
CLOUDINIT_TEMPLATE="${VM_NAME}-cloudinit-template"
echo "Ensuring cloud-init secret from template..."
USERDATA="$(kubectl get configmap "${CLOUDINIT_TEMPLATE}" -n "${NS}" -o jsonpath='{.data.userData}')"
PUB_KEY=""
if [[ -f /ssh-key/public_key ]]; then
  PUB_KEY="$(cat /ssh-key/public_key)"
fi
if [[ -z "${PUB_KEY}" ]]; then
  PUB_KEY="$(kubectl get secret "${SSH_SECRET}" -n "${NS}" -o jsonpath='{.data.public_key}' 2>/dev/null | base64 -d || true)"
fi
if [[ -n "${PUB_KEY}" ]]; then
  USERDATA="$(echo "${USERDATA}" | sed "s|__SSH_PUBLIC_KEY__|${PUB_KEY}|g")"
  echo "SSH public key injected into cloud-init"
else
  echo "WARNING: No SSH public key found, VM may not be accessible via SSH"
fi
kubectl create secret generic "${CLOUDINIT_SECRET}" -n "${NS}" \
  --from-literal=userData="${USERDATA}" \
  --dry-run=client -o yaml | kubectl apply -f -
echo "Cloud-init secret '${CLOUDINIT_SECRET}' ready"

# --- Label VM ---
echo "Labeling vm/${VM_NAME}..."
kubectl -n "${NS}" label vm "${VM_NAME}" \
  "app.kubernetes.io/name=${VM_NAME}" \
  "app.kubernetes.io/part-of=openshell-cnv-fedora" \
  "openshell.pattern/role=gateway" \
  --overwrite

# --- Wait for VMI Running + Ready ---
echo "Waiting for vmi/${VM_NAME} to be Running and Ready..."
deadline=$((SECONDS + 600))
while true; do
  phase="$(kubectl -n "${NS}" get vmi "${VM_NAME}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  ready="$(kubectl -n "${NS}" get vmi "${VM_NAME}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
  echo "  vmi phase=${phase:-pending} ready=${ready:-false}"
  if [[ "${phase}" == "Running" && "${ready}" == "True" ]]; then
    break
  fi
  if (( SECONDS > deadline )); then
    echo "Timed out waiting for VMI Ready" >&2
    exit 1
  fi
  sleep 8
done

# --- Wait for SSH ---
echo "Waiting for guest SSH on vm/${VM_NAME}..."
deadline=$((SECONDS + 300))
ssh_ok=0
while (( SECONDS <= deadline )); do
  if guest_ssh "echo ssh-ok" >/dev/null 2>&1; then
    ssh_ok=1
    break
  fi
  sleep 8
done
if [[ "${ssh_ok}" -ne 1 ]]; then
  echo "SSH not ready in time" >&2
  exit 1
fi

# --- Wait for cloud-init to finish (installs OpenShell binaries) ---
echo "Waiting for cloud-init to finish..."
deadline=$((SECONDS + 600))
while true; do
  if guest_ssh "cloud-init status 2>/dev/null | grep -q done" 2>/dev/null; then
    echo "Cloud-init finished."
    break
  fi
  if (( SECONDS > deadline )); then
    echo "WARNING: cloud-init did not finish in time, proceeding anyway..."
    break
  fi
  sleep 10
done

# --- Post-clone hygiene ---
echo "Post-clone hygiene (hostname)..."
guest_ssh "sudo hostnamectl set-hostname '${VM_NAME}' || true; openshell gateway select openshell >/dev/null 2>&1 || true" || true

if [[ "${VM_GPU_ENABLED:-false}" == "true" ]]; then
  # --- GPU health check ---
  # The golden image's nvidia-driver-setup.service builds the kernel module and generates
  # the CDI spec on first boot (see image-builder-charts/.../buildconfig.yaml) — this can
  # take a few minutes. This check is best-effort: it warns rather than failing the whole
  # setup Job, since a GPU-enabled VM on hardware that doesn't actually support passthrough
  # (see docs/gpu-passthrough.md) is a real, documented possibility, not necessarily a bug.
  echo "GPU enabled — waiting for nvidia-smi inside the VM..."
  gpu_ok=0
  deadline=$((SECONDS + 300))
  while (( SECONDS <= deadline )); do
    if guest_ssh "nvidia-smi >/dev/null 2>&1"; then
      gpu_ok=1
      break
    fi
    sleep 10
  done
  if [[ "${gpu_ok}" -eq 1 ]]; then
    echo "GPU health check passed:"
    guest_ssh "nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader" || true
  else
    echo "WARNING: nvidia-smi did not succeed inside the VM after 5 minutes." >&2
    echo "WARNING: this is expected on hardware without a real hostDevices-capable GPU passthrough path (see docs/gpu-passthrough.md); continuing setup without GPU." >&2
  fi
fi
