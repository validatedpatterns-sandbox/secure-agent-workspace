#!/bin/bash
# Mount the chart-provided input disks read-only under /run/saw.
# Disks are found by the serial set in the VirtualMachine spec. The list of
# Secret disks is read from config.json on the installer disk, which the
# chart re-renders, so this script never goes stale after `helm upgrade`.
# Safe to run repeatedly: saw-install and saw-apply both run it.
set -euo pipefail

DEV_DIR="${SAW_DEV_DIR:-/dev/disk/by-id}"
ROOT="${SAW_ROOT:-/run/saw}"
WAIT="${SAW_DEV_WAIT:-30}"

mount_disk() {
  local name="$1" target="$2" need="$3"
  local dev="${DEV_DIR}/virtio-${name}"
  # Already mounted (e.g. by the other unit): nothing to do. This check comes
  # first; touching a read-only mount point would fail.
  if mountpoint -q "${target}" 2>/dev/null; then
    return 0
  fi
  [[ -d "${target}" ]] || install -d -m 0700 "${target}"
  # virtiofs (vm.liveInputs) uses the volume name as the tag and updates
  # without a reboot. The iso9660 disk is the default.
  if [[ ! -e "${dev}" ]] && mount -t virtiofs -o ro,nosuid,nodev,noexec "${name}" "${target}" 2>/dev/null; then
    return 0
  fi
  local waited=0
  while [[ ! -e "${dev}" && "${waited}" -lt "${WAIT}" ]]; do
    sleep 1
    waited=$((waited + 1))
  done
  if [[ ! -e "${dev}" ]]; then
    if [[ "${need}" == required ]]; then
      echo "saw-mount-inputs: required disk $1 is not attached" >&2
      exit 1
    fi
    echo "saw-mount-inputs: optional disk $1 is not attached"
    return 0
  fi
  mount -t iso9660 -o ro,nosuid,nodev,noexec "${dev}" "${target}"
}

[[ -d "${ROOT}" ]] || install -d -m 0700 "${ROOT}"
[[ -d "${ROOT}/secrets" ]] || install -d -m 0700 "${ROOT}/secrets"

mount_disk saw-installer "${ROOT}/installer" required
mount_disk saw-profiles "${ROOT}/profiles" optional
mount_disk saw-proxy-ca "${ROOT}/proxy-ca" required
if grep -q '"ownerSubjectSource": "resolved"' "${ROOT}/installer/config.json"; then
  mount_disk saw-owner "${ROOT}/owner" required
fi

# Secret disks saw-sec-0, saw-sec-1, ... in the order of config.json "secrets".
# An invalid name prints an empty line, so it keeps its disk position.
index=0
while IFS= read -r name; do
  if [[ -n "${name}" ]]; then
    mount_disk "saw-sec-${index}" "${ROOT}/secrets/${name}" optional
  fi
  index=$((index + 1))
done < <(python3 - "${ROOT}/installer/config.json" <<'PY'
import json, re, sys
for name in json.load(open(sys.argv[1])).get("secrets", []):
    if isinstance(name, str) and re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", name):
        print(name)
    else:
        print(f"saw-mount-inputs: skipping invalid Secret name {name!r}", file=sys.stderr)
        print("")
PY
)
