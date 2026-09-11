"""Kubernetes operations for managing Codex VM sessions."""

from __future__ import annotations

import base64
import json
import logging
import subprocess
from dataclasses import dataclass

from kubernetes import client, config as k8s_config

from . import config

logger = logging.getLogger(__name__)

_api_loaded = False


def _ensure_api():
    global _api_loaded
    if not _api_loaded:
        try:
            k8s_config.load_incluster_config()
        except k8s_config.ConfigException:
            k8s_config.load_kube_config()
        _api_loaded = True


@dataclass
class Session:
    name: str
    status: str
    created: str
    owner: str
    ws_url: str | None
    has_secret: bool


@dataclass
class ConnectionInfo:
    ws_url: str
    token: str
    expires_in: int


def list_user_vms(username: str) -> list[Session]:
    _ensure_api()
    ns = config.MANAGED_NAMESPACE
    custom = client.CustomObjectsApi()

    try:
        vms = custom.list_namespaced_custom_object(
            group="kubevirt.io",
            version="v1",
            namespace=ns,
            plural="virtualmachines",
            label_selector=f"openshell.pattern/owner={username}",
        )
    except client.ApiException as e:
        logger.error("Failed to list VMs: %s", e)
        return []

    sessions = []
    v1 = client.CoreV1Api()
    for vm in vms.get("items", []):
        name = vm["metadata"]["name"]
        created = vm["metadata"].get("creationTimestamp", "")
        printable = (
            vm.get("status", {}).get("printableStatus", "Unknown")
        )

        status_map = {
            "Running": "running",
            "Stopped": "stopped",
            "Starting": "creating",
            "Provisioning": "creating",
            "WaitingForVolumeBinding": "creating",
        }
        status = status_map.get(printable, "error" if "Error" in printable else "creating")

        ws_url = _get_route_url(name, ns)

        try:
            v1.read_namespaced_secret(f"{name}-codex-secret", ns)
            has_secret = True
        except client.ApiException:
            has_secret = False

        sessions.append(Session(
            name=name,
            status=status,
            created=created,
            owner=username,
            ws_url=ws_url,
            has_secret=has_secret,
        ))

    return sessions


def _get_route_url(name: str, namespace: str) -> str | None:
    custom = client.CustomObjectsApi()
    route_name = f"{name}-codex"
    try:
        route = custom.get_namespaced_custom_object(
            group="route.openshift.io",
            version="v1",
            namespace=namespace,
            plural="routes",
            name=route_name,
        )
        host = route.get("spec", {}).get("host", "")
        if host:
            return f"wss://{host}:443"
    except client.ApiException:
        pass
    return None


def get_codex_secret(name: str) -> str | None:
    _ensure_api()
    v1 = client.CoreV1Api()
    try:
        secret = v1.read_namespaced_secret(
            f"{name}-codex-secret", config.MANAGED_NAMESPACE
        )
        encoded = secret.data.get("ws-secret", "")
        return base64.b64decode(encoded).decode() if encoded else None
    except client.ApiException:
        return None


def get_vm_owner(name: str) -> str | None:
    _ensure_api()
    custom = client.CustomObjectsApi()
    try:
        vm = custom.get_namespaced_custom_object(
            group="kubevirt.io",
            version="v1",
            namespace=config.MANAGED_NAMESPACE,
            plural="virtualmachines",
            name=name,
        )
        return vm.get("metadata", {}).get("labels", {}).get(
            "openshell.pattern/owner"
        )
    except client.ApiException:
        return None


def helm_install(name: str, owner: str) -> bool:
    ns = config.MANAGED_NAMESPACE
    cmd = [
        "helm", "upgrade", "--install", name, config.SAW_CHART_PATH,
        "--namespace", ns,
        "--set", f"sandboxName={name}",
        "--set", "agent=codex",
        "--set", "containerRuntime=docker",
        "--set", "route.enabled=true",
        "--set", "route.codex=true",
        "--set", "route.dashboard=true",
        "--set", f"accessControl.owner={owner}",
        "--set", "governance.enabled=true",
        "--set", "internalRegistry.allowAnonymousPull=true",
        "--set", f"oidc.issuerUrl={config.OIDC_ISSUER_URL}",
        "--set", "oidc.clientId=openshell-cli",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error("helm install failed: %s", result.stderr)
    return result.returncode == 0


def helm_uninstall(name: str) -> bool:
    cmd = [
        "helm", "uninstall", name,
        "--namespace", config.MANAGED_NAMESPACE,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error("helm uninstall failed: %s", result.stderr)
    return result.returncode == 0
