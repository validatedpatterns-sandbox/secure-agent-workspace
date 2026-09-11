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
    v1 = client.CoreV1Api()

    sessions = []

    try:
        crs = custom.list_namespaced_custom_object(
            group="saw.redhat.com",
            version="v1alpha1",
            namespace=ns,
            plural="codexsessions",
        )
    except client.ApiException:
        crs = {"items": []}

    cr_map = {}
    for cr in crs.get("items", []):
        owner = cr.get("spec", {}).get("owner", "")
        if owner == username:
            name = cr.get("spec", {}).get("name", cr["metadata"]["name"])
            if cr["metadata"].get("deletionTimestamp"):
                phase = "deleting"
            else:
                phase = cr.get("status", {}).get("phase", "Creating").lower()
            cr_map[name] = phase

    try:
        vms = custom.list_namespaced_custom_object(
            group="kubevirt.io",
            version="v1",
            namespace=ns,
            plural="virtualmachines",
            label_selector=f"openshell.pattern/owner={username}",
        )
    except client.ApiException:
        vms = {"items": []}

    for vm in vms.get("items", []):
        name = vm["metadata"]["name"]
        created = vm["metadata"].get("creationTimestamp", "")

        status = cr_map.pop(name, "unmanaged")

        ws_url = _get_route_url(name, ns)

        has_secret = False
        try:
            v1.read_namespaced_secret(f"{name}-codex-secret", ns)
            has_secret = True
        except client.ApiException:
            pass

        sessions.append(Session(
            name=name,
            status=status,
            created=created,
            owner=username,
            ws_url=ws_url,
            has_secret=has_secret,
        ))

    for name, status in cr_map.items():
        sessions.append(Session(
            name=name, status=status, created="", owner=username,
            ws_url=None, has_secret=False,
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


def create_session_cr(name: str, owner: str, oidc_token: str = "") -> bool:
    """Create a CodexSession CR. The controller handles provisioning."""
    _ensure_api()
    custom = client.CustomObjectsApi()
    spec = {"name": name, "owner": owner}
    if oidc_token:
        spec["oidcToken"] = oidc_token
    try:
        custom.create_namespaced_custom_object(
            group="saw.redhat.com",
            version="v1alpha1",
            namespace=config.MANAGED_NAMESPACE,
            plural="codexsessions",
            body={
                "apiVersion": "saw.redhat.com/v1alpha1",
                "kind": "CodexSession",
                "metadata": {"name": name},
                "spec": spec,
            },
        )
        return True
    except client.ApiException as e:
        logger.error("Failed to create CodexSession: %s", e)
        return False


def delete_session_cr(name: str) -> bool:
    """Delete a CodexSession CR. The controller handles teardown."""
    _ensure_api()
    custom = client.CustomObjectsApi()
    try:
        custom.delete_namespaced_custom_object(
            group="saw.redhat.com",
            version="v1alpha1",
            namespace=config.MANAGED_NAMESPACE,
            plural="codexsessions",
            name=name,
        )
        return True
    except client.ApiException as e:
        logger.error("Failed to delete CodexSession: %s", e)
        return False
