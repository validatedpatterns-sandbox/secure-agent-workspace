#!/usr/bin/env python3
"""Check the selected x86 local-Kata workers before installing OSC."""
import json
import os
import subprocess
import sys


def oc(*args):
    return subprocess.check_output(["oc", "--request-timeout=30s", *args], text=True)


def workers(items):
    if not items:
        raise ValueError("worker selector matched no nodes")
    for node in items:
        meta = node["metadata"]
        labels = meta["labels"]
        roles = {k.removeprefix("node-role.kubernetes.io/") for k in labels
                 if k.startswith("node-role.kubernetes.io/")}
        if "worker" not in roles or roles & {"master", "control-plane"}:
            raise ValueError(f"{meta['name']}: selector must match dedicated workers only")
        if labels.get("kubernetes.io/arch") != "amd64":
            raise ValueError(f"{meta['name']}: this preflight qualifies x86_64 workers only")
        if node["spec"].get("unschedulable") or not any(
            c["type"] == "Ready" and c["status"] == "True" for c in node["status"]["conditions"]
        ):
            raise ValueError(f"{meta['name']}: worker is unavailable")
    return sorted(n["metadata"]["name"] for n in items)


# Inspect the host through the existing machine-config-daemon host mount.
# Reading an inaccessible/missing mount must not count as a firmware verdict.
PROBE = """set -eu
test -r /proc/sys/kernel/random/boot_id && test -d /sys/firmware || exit 1
if test -d /sys/firmware/efi; then echo UEFI; else echo legacy-BIOS; fi
if test -c /dev/kvm; then echo KVM; else echo missing-KVM; fi
"""


def main():
    selector = os.environ.get("KATA_NODE_SELECTOR", "").strip()
    expected = os.environ.get("KATA_API_SERVER", "").strip()
    if not selector or not expected:
        raise ValueError("set KATA_API_SERVER and KATA_NODE_SELECTOR")
    if oc("whoami", "--show-server").strip() != expected:
        raise ValueError("unexpected OpenShift API server")
    names = workers(json.loads(oc("get", "nodes", "--selector", selector, "-o", "json"))["items"])
    ns = "openshift-machine-config-operator"
    passed = True
    for name in names:
        pods = json.loads(oc("-n", ns, "get", "pods", "-l", "k8s-app=machine-config-daemon",
                             "--field-selector", f"spec.nodeName={name},status.phase=Running",
                             "-o", "json"))["items"]
        ready = [p["metadata"]["name"] for p in pods if not p["metadata"].get("deletionTimestamp")
                 and any(c["name"] == "machine-config-daemon" and c["ready"]
                         for c in p["status"].get("containerStatuses", []))]
        if len(ready) != 1:
            raise ValueError(f"{name}: cannot identify a ready machine-config-daemon")
        facts = oc("-n", ns, "exec", ready[0], "-c", "machine-config-daemon", "--",
                   "chroot", "/rootfs", "sh", "-c", PROBE).splitlines()
        print(f"{name}: {' '.join(facts)}")
        passed &= facts == ["UEFI", "KVM"]
    if not passed:
        raise ValueError("OSC local Kata requires UEFI-booted workers with /dev/kvm")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        sys.exit(f"Kata worker preflight failed: {exc}")
