#!/usr/bin/env bash
# Device nodes are recreated by udev on every boot. Prepare them before the
# SAW installer starts any rootless Podman sandboxes.
set -euo pipefail

modprobe nvidia
modprobe nvidia-uvm
nvidia-smi -L
# CUDA needs both UVM nodes before nvidia-ctk enumerates existing devices.
major="$(awk '$2 == "nvidia-uvm" {print $1}' /proc/devices)"
[[ -n "$major" ]] || { echo "NVIDIA UVM major number is missing" >&2; exit 1; }
[[ -c /dev/nvidia-uvm ]] || mknod -m 0666 /dev/nvidia-uvm c "$major" 0
[[ -c /dev/nvidia-uvm-tools ]] || mknod -m 0666 /dev/nvidia-uvm-tools c "$major" 1
[[ "$(getsebool container_use_devices)" == *"--> on" ]] || setsebool -P container_use_devices on
shopt -s nullglob
nodes=()
for node in /dev/nvidia* /dev/nvidia-caps/nvidia-cap*; do
  [[ ! -c "$node" ]] || nodes+=("$node")
done
if (( ${#nodes[@]} == 0 )); then
  echo "No NVIDIA device nodes were created" >&2
  exit 1
fi
chcon -t device_t "${nodes[@]}"
mkdir -p /etc/cdi
# Keep OpenShell's resolved workload identity: toolkit >=1.19 otherwise adds
# the video group for DRI nodes, which its supplementary-group check rejects.
nvidia-ctk cdi generate --feature-flag=no-additional-gids-for-device-nodes --output=/etc/cdi/nvidia.yaml
# Non-MIG GPUs may expose no capability nodes.
caps=(/dev/nvidia-caps/nvidia-cap*)
if (( ${#caps[@]} )); then
  chmod 0666 "${caps[@]}"
  python3 /usr/local/sbin/saw-patch-cdi-caps.py /etc/cdi/nvidia.yaml
else
  echo "No /dev/nvidia-caps nodes; CDI spec left as generated"
fi
