#!/usr/bin/env python3
"""Remove SAW consumers through Argo before the framework removes their webhooks."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

PATTERN = "secure-agent-workspace"
ARGO_NS = os.environ.get("ARGOCD_NS", "vp-gitops")
PATTERN_NS = "patterns-operator"
# Keys in values-prod.yaml. Both leaf charts create webhook-dependent resources.
CHARTS = {"openshell-rhdh": "charts/openshell-rhdh", "saw-users": "charts/saw-users"}
GROUP = "applications.argoproj.io"
PATTERNS = "patterns.gitops.hybrid-cloud-patterns.io"


def oc(*args, body=None):
    result = subprocess.run(["oc", "--request-timeout=20s", *args],
                            input=json.dumps(body) if body is not None else None,
                            text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "OpenShift API request failed")
    return result.stdout


def get(kind, name, namespace):
    raw = oc("get", kind, name, "-n", namespace, "--ignore-not-found", "-o", "json")
    return json.loads(raw) if raw.strip() else None


def metadata(obj):
    return obj["metadata"]


def patch(kind, obj, edits):
    m = metadata(obj)
    checks = [{"op": "test", "path": "/metadata/uid", "value": m["uid"]}]
    # The Pattern operator writes status between discovery and this request.
    # Compare the complete spec used to compute the overrides. Argo operations
    # below also depend on status and therefore require the resource version.
    if kind == PATTERNS:
        checks.append({"op": "test", "path": "/spec", "value": obj["spec"]})
    else:
        checks.append({"op": "test", "path": "/metadata/resourceVersion", "value": m["resourceVersion"]})
    oc("patch", kind, m["name"], "-n", m["namespace"], "--type=json",
       "--patch-file=/dev/stdin", body=checks + edits)


def local_destination(app):
    destination = app["spec"].get("destination", {})
    return ((destination.get("name"), destination.get("server"))
            in (("in-cluster", None), (None, "https://kubernetes.default.svc")))


def validate_child(child, parent, name, uid):
    m = metadata(child)
    tracking = f"{parent}:argoproj.io/Application:{ARGO_NS}/{name}"
    if (m["uid"] != uid or m["name"] != name or m["namespace"] != ARGO_NS
            or not local_destination(child)
            or (not m.get("deletionTimestamp") and
                "resources-finalizer.argocd.argoproj.io/foreground" not in m.get("finalizers", []))
            or m.get("labels", {}).get("validatedpatterns.io/pattern") != PATTERN
            or m.get("annotations", {}).get("argocd.argoproj.io/tracking-id") != tracking
            or child["spec"].get("source", {}).get("path") != CHARTS[name]):
        raise RuntimeError(f"Refusing to drain unverified or replaced Application {name}")


def disable_consumers(pattern, names):
    # Persist the desired change on the Pattern itself. Patching the child or
    # its generated parent alone would let a reconciler recreate it mid-delete.
    params = pattern["spec"].get("extraParameters", [])
    edits = [] if "extraParameters" in pattern["spec"] else [
        {"op": "add", "path": "/spec/extraParameters", "value": []}]
    for name in names:
        key = f"clusterGroup.applications.{name}.disabled"
        matches = [i for i, param in enumerate(params) if param["name"] == key]
        if len(matches) > 1:
            raise RuntimeError(f"Ambiguous Pattern override for {name}")
        if not matches:
            edits.append({"op": "add", "path": "/spec/extraParameters/-",
                          "value": {"name": key, "value": "true"}})
        elif params[matches[0]]["value"] != "true":
            edits.append({"op": "replace", "path": f"/spec/extraParameters/{matches[0]}/value",
                          "value": "true"})
    if edits:
        patch(PATTERNS, pattern, edits)


def released(parent, name):
    return any(r.get("group") == "argoproj.io" and r.get("kind") == "Application"
               and r.get("namespace") == ARGO_NS and r.get("name") == name
               and r.get("requiresPruning") is True
               for r in parent.get("status", {}).get("resources", []))


def drain_child(child):
    m = metadata(child)
    if child["spec"].get("syncPolicy", {}).get("automated") is not None:
        patch(GROUP, child, [{"op": "remove", "path": "/spec/syncPolicy/automated"}])
    elif child.get("operation") is not None:
        phase = child.get("status", {}).get("operationState", {}).get("phase")
        if phase == "Running":
            # Same transition as Argo's TerminateOperation; the controller
            # terminates the hooks and records the result itself.
            patch(GROUP, child, [{"op": "replace", "path": "/status/operationState/phase",
                                  "value": "Terminating"}])
    elif not m.get("deletionTimestamp"):
        path = f"/apis/argoproj.io/v1alpha1/namespaces/{ARGO_NS}/applications/{m['name']}"
        oc("delete", "--raw", path, "-f", "-", body={
            "apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground",
            "preconditions": {"uid": m["uid"], "resourceVersion": m["resourceVersion"]}})


def main():
    exists = subprocess.run([str(Path(__file__).with_name("pattern-exists.sh"))])
    if exists.returncode == 1:
        return
    exists.check_returncode()
    pattern = get(PATTERNS, PATTERN, PATTERN_NS)
    if not pattern:
        raise RuntimeError("Pattern identity could not be verified in patterns-operator")
    parent_name = PATTERN + "-" + pattern["spec"].get("clusterGroupName", "hub")
    ids = {}
    for name in CHARTS:
        child = get(GROUP, name, ARGO_NS)
        if child:
            uid = metadata(child)["uid"]
            validate_child(child, parent_name, name, uid)
            ids[name] = uid
    if not ids:
        return
    parent = get(GROUP, parent_name, ARGO_NS)
    if (not parent or not local_destination(parent)
            or metadata(parent).get("labels", {}).get("validatedpatterns.io/pattern") != PATTERN):
        raise RuntimeError("Pattern parent Application ownership could not be verified")
    parent_uid = metadata(parent)["uid"]
    if not metadata(pattern).get("deletionTimestamp"):
        disable_consumers(pattern, ids)
    print("Draining SAW Applications before uninstall: " + ", ".join(ids), flush=True)
    deadline = time.monotonic() + 900
    while ids and time.monotonic() < deadline:
        parent = get(GROUP, parent_name, ARGO_NS)
        if parent and metadata(parent)["uid"] != parent_uid:
            raise RuntimeError("Pattern parent Application was replaced during uninstall")
        for name, uid in list(ids.items()):
            child = get(GROUP, name, ARGO_NS)
            if not child:
                del ids[name]
                continue
            validate_child(child, parent_name, name, uid)
            if not metadata(child).get("deletionTimestamp") and not (parent and released(parent, name)):
                continue
            try:
                drain_child(child)
            except RuntimeError:
                # Retry a concurrent update only on the same object. Other
                # failures, including authorization errors, stop uninstall.
                current = get(GROUP, name, ARGO_NS)
                if current and (metadata(current)["uid"] != uid or
                                metadata(current)["resourceVersion"] == metadata(child)["resourceVersion"]):
                    raise
        if ids:
            time.sleep(4)
    if ids:
        raise RuntimeError("Timed out draining " + ", ".join(ids) + "; inspect the parent and leaf Applications")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))
