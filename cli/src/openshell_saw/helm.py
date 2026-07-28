"""Helm subprocess wrappers."""

import json
import subprocess

from . import kube


def install_chart(release, chart_path, namespace, sets=None, set_strings=None,
                  set_files=None, timeout=None, create_namespace=True):
    """Run helm upgrade --install with the given parameters."""
    cmd = ["helm", "upgrade", "--install", release, chart_path,
           "--namespace", namespace]
    if create_namespace:
        cmd.append("--create-namespace")
    for k, v in (sets or {}).items():
        if v:
            cmd.extend(["--set", f"{k}={v}"])
    for k, v in (set_strings or {}).items():
        if v:
            cmd.extend(["--set-string", f"{k}={v}"])
    for k, v in (set_files or {}).items():
        if v:
            cmd.extend(["--set-file", f"{k}={v}"])
    if timeout:
        cmd.extend(["--timeout", timeout])
    r = subprocess.run(cmd, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"Helm install failed for {release}")


def uninstall(release, namespace):
    """Run helm uninstall."""
    subprocess.run(
        ["helm", "uninstall", release, "--namespace", namespace],
        check=True,
    )


def list_releases(namespace, filter_pattern=None):
    """List helm releases as a list of dicts."""
    cmd = ["helm", "list", "-n", namespace, "-o", "json"]
    if filter_pattern:
        cmd.extend(["--filter", filter_pattern])
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        return []
    try:
        return json.loads(r.stdout) or []
    except json.JSONDecodeError:
        return []


def list_sandboxes(namespace):
    """List sandbox releases enriched with VM status."""
    releases = list_releases(namespace)
    sandboxes = [r for r in releases if r.get("chart", "").startswith("openshell-sandbox")]
    vm_statuses = kube.list_vms(namespace)
    result = []
    for sb in sandboxes:
        name = sb["name"]
        result.append({
            "name": name,
            "status": sb.get("status", "unknown"),
            "vm_status": vm_statuses.get(name, "n/a"),
            "updated": sb.get("updated", "").split(".")[0],
        })
    return result


def get_values(release, namespace):
    """Get helm release values as a dict."""
    r = subprocess.run(
        ["helm", "get", "values", release, "-n", namespace, "-o", "json"],
        capture_output=True, text=True, check=False,
    )
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None
