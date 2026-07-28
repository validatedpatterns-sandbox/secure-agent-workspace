"""Kubernetes / OpenShift / virtctl subprocess wrappers."""

import json
import subprocess
import sys


def run(cmd, capture=False, check=True):
    """Run a subprocess, optionally capturing output."""
    if capture:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if check and r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or f"Command failed: {' '.join(cmd)}")
        return r
    return subprocess.run(cmd)


def ensure_namespace(name):
    """Create a namespace if it doesn't already exist."""
    dry_run = subprocess.run(
        ["oc", "create", "namespace", name, "--dry-run=client", "-o", "yaml"],
        capture_output=True, text=True,
    )
    if dry_run.returncode != 0:
        raise RuntimeError(f"Failed to generate namespace manifest: {dry_run.stderr.strip()}")
    subprocess.run(
        ["oc", "apply", "-f", "-"],
        input=dry_run.stdout, text=True,
        capture_output=True,
    )


def get_route_url(name, namespace):
    """Get an OpenShift Route URL."""
    r = run(
        ["oc", "get", "route", name, "-n", namespace,
         "-o", "jsonpath=https://{.spec.host}"],
        capture=True, check=False,
    )
    return r.stdout.strip() if r.returncode == 0 else None


def get_vm_status(name, namespace):
    """Get VM printableStatus."""
    r = run(
        ["kubectl", "get", "vm", name, "-n", namespace,
         "-o", "jsonpath={.status.printableStatus}"],
        capture=True, check=False,
    )
    return r.stdout.strip() if r.returncode == 0 else "n/a"


def ssh_sandbox(name, namespace):
    """SSH into a sandbox VM (interactive)."""
    subprocess.run(
        ["ssh-keygen", "-R", f"vm.{name}.{namespace}"],
        capture_output=True,
    )
    sys.exit(
        subprocess.run(
            ["virtctl", "-n", namespace, "ssh", f"cloud-user@vm/{name}"]
        ).returncode
    )


def ensure_ssh_secret(key_path, namespace):
    """Create or update the SSH private key secret."""
    dry_run = subprocess.run(
        ["oc", "-n", namespace, "create", "secret", "generic", "openshell-aap-ssh",
         f"--from-file=key={key_path}", "--dry-run=client", "-o", "yaml"],
        capture_output=True, text=True,
    )
    if dry_run.returncode != 0:
        raise RuntimeError(f"Failed to create SSH secret: {dry_run.stderr.strip()}")
    apply = subprocess.run(
        ["oc", "apply", "-f", "-"],
        input=dry_run.stdout, text=True,
        capture_output=True,
    )
    if apply.returncode != 0:
        raise RuntimeError(f"Failed to apply SSH secret: {apply.stderr.strip()}")


def run_in_vm(name, namespace, command):
    """Run a command inside a VM via virtctl ssh. Returns (success, stdout)."""
    r = subprocess.run(
        ["virtctl", "-n", namespace, "ssh", f"cloud-user@vm/{name}",
         "--local-ssh-opts=-oStrictHostKeyChecking=no",
         "--local-ssh-opts=-oUserKnownHostsFile=/dev/null",
         "--local-ssh-opts=-oConnectTimeout=5",
         f"--command={command}"],
        capture_output=True, text=True,
    )
    return r.returncode == 0, r.stdout.strip()


def list_vms(namespace):
    """List VMs with their statuses as a dict {name: status}."""
    r = run(
        ["kubectl", "get", "vm", "-n", namespace, "-o", "json"],
        capture=True, check=False,
    )
    if r.returncode != 0:
        return {}
    try:
        items = json.loads(r.stdout).get("items", [])
        return {
            item["metadata"]["name"]: item.get("status", {}).get("printableStatus", "n/a")
            for item in items
        }
    except (json.JSONDecodeError, KeyError):
        return {}


def follow_logs(resource, namespace):
    """Follow logs of a resource (job, pod, build)."""
    sys.exit(
        subprocess.run(
            ["oc", "-n", namespace, "logs", "-f", resource]
        ).returncode
    )


def start_build(name, namespace, follow=True):
    """Start an OpenShift build."""
    cmd = ["oc", "start-build", name, "-n", namespace]
    if follow:
        cmd.append("--follow")
    sys.exit(subprocess.run(cmd).returncode)
