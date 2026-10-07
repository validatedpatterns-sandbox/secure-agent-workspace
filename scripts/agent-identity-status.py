#!/usr/bin/env python3
"""Read sanitized identity diagnostics through the authenticated cluster API."""
import argparse
import base64
import json
import subprocess
import time


def guest_status(context, namespace, vm):
    oc = ["oc", "--context", context, "--request-timeout=30s"]

    def command(args):
        result = subprocess.run(oc + args, capture_output=True, text=True, timeout=40)
        if result.returncode:
            raise RuntimeError("Authenticated guest diagnostic request failed")
        return json.loads(result.stdout)

    pods = command(["get", "pods", "-n", namespace, "-l", "vm.kubevirt.io/name=" + vm, "-o", "json"])
    running = [p for p in pods["items"] if p["status"]["phase"] == "Running"
               and not p["metadata"].get("deletionTimestamp")]
    if len(running) != 1:
        raise RuntimeError("Expected exactly one running launcher")

    def qga(request):
        return command(["exec", "-n", namespace, running[0]["metadata"]["name"],
                        "-c", "compute", "--", "virsh", "-c", "qemu:///session",
                        "qemu-agent-command", namespace + "_" + vm, json.dumps(request)])["return"]

    process = qga({"execute": "guest-exec", "arguments": {
        "path": "/usr/libexec/saw-identity-status", "capture-output": True}})
    for _ in range(15):
        result = qga({"execute": "guest-exec-status", "arguments": {"pid": process["pid"]}})
        if result.get("exited"):
            if result.get("exitcode") != 0 or result.get("out-truncated"):
                raise RuntimeError("Guest diagnostic helper failed")
            return json.loads(base64.b64decode(result["out-data"]))
        time.sleep(1)
    raise RuntimeError("Guest diagnostic timed out")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("context", "namespace", "vm"):
        parser.add_argument("--" + key, required=True)
    args = parser.parse_args()
    print(json.dumps(guest_status(args.context, args.namespace, args.vm), indent=2))
