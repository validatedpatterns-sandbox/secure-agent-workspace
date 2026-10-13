#!/usr/bin/env bash
# Device nodes are recreated by udev on every boot. Prepare them before the
# SAW installer starts any rootless Podman sandboxes.
set -euo pipefail

modprobe nvidia
nvidia-smi -L
setsebool -P container_use_devices on
shopt -s nullglob
nodes=()
for node in /dev/nvidia* /dev/nvidia-caps/nvidia-cap*; do
  [[ ! -c "$node" ]] || nodes+=("$node")
done
if (( ${#nodes[@]} == 0 )); then
  echo "No NVIDIA device nodes were created" >&2
  exit 1
fi
caps=(/dev/nvidia-caps/nvidia-cap*)
if (( ${#caps[@]} == 0 )); then
  echo "No NVIDIA capability devices were created" >&2
  exit 1
fi
chmod 0666 "${caps[@]}"
chcon -t device_t "${nodes[@]}"
mkdir -p /etc/cdi
nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml
python3 /usr/local/sbin/saw-patch-cdi-caps.py /etc/cdi/nvidia.yaml
