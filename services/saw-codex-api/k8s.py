"""Kubernetes operations for managing Codex sessions."""

from __future__ import annotations

import base64
import logging
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
    backend: str


@dataclass
class ConnectionInfo:
    ws_url: str
    token: str
    expires_in: int


def _get_session_cr(name: str) -> dict | None:
    """Read a CodexSession CR by name."""
    _ensure_api()
    custom = client.CustomObjectsApi()
    try:
        return custom.get_namespaced_custom_object(
            group="saw.redhat.com",
            version="v1alpha1",
            namespace=config.MANAGED_NAMESPACE,
            plural="codexsessions",
            name=name,
        )
    except client.ApiException:
        return None


def _session_namespace(cr: dict) -> str | None:
    """Get the session namespace from a CR (k8s backend only)."""
    return cr.get("status", {}).get("namespace")


def _session_backend(cr: dict) -> str:
    """Get the resolved backend from a CR."""
    return (
        cr.get("status", {}).get("backend")
        or cr.get("spec", {}).get("runtime", {}).get("backend", "vm")
    )


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
    cr_details = {}
    for cr in crs.get("items", []):
        owner = cr.get("spec", {}).get("owner", "")
        if owner == username:
            name = cr.get("spec", {}).get("name", cr["metadata"]["name"])
            if cr["metadata"].get("deletionTimestamp"):
                phase = "deleting"
            else:
                phase = cr.get("status", {}).get("phase", "Creating").lower()
            cr_map[name] = phase
            cr_details[name] = cr

    # VM sessions: look up VMs in the managed namespace
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
        cr = cr_details.pop(name, None)
        backend = _session_backend(cr) if cr else "vm"

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
            backend=backend,
        ))

    # Remaining CRs without VMs (k8s backend sessions or pending VM sessions)
    for name, status in cr_map.items():
        cr = cr_details.get(name)
        backend = _session_backend(cr) if cr else "kubernetes"
        created = ""
        ws_url = None
        has_secret = False

        if cr and backend == "kubernetes":
            created = cr.get("metadata", {}).get("creationTimestamp", "")
            sess_ns = _session_namespace(cr)
            if sess_ns:
                ws_url = _get_route_url(name, sess_ns)
                try:
                    v1.read_namespaced_secret(f"{name}-codex-secret", sess_ns)
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
            backend=backend,
        ))

    return sessions


def _get_route_url(name: str, namespace: str) -> str | None:
    custom = client.CustomObjectsApi()
    # K8s sessions use short route name "codex", VM sessions use "{name}-codex"
    route_name = "codex" if namespace.startswith("saw-") else f"{name}-codex"
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


def get_codex_secret(name: str, namespace: str | None = None) -> str | None:
    """Read the codex WebSocket shared secret.

    For VM sessions the secret is in the managed namespace as <name>-codex-secret.
    For K8s sessions the secret is in the session namespace as codex-ws-secret.
    """
    _ensure_api()
    v1 = client.CoreV1Api()

    if namespace and namespace != config.MANAGED_NAMESPACE:
        # K8s backend: secret is in session namespace
        try:
            secret = v1.read_namespaced_secret(
                f"{name}-codex-secret", namespace
            )
            encoded = secret.data.get("ws-secret", "")
            return base64.b64decode(encoded).decode() if encoded else None
        except client.ApiException:
            pass

    # VM backend: secret is in managed namespace
    try:
        secret = v1.read_namespaced_secret(
            f"{name}-codex-secret", config.MANAGED_NAMESPACE
        )
        encoded = secret.data.get("ws-secret", "")
        return base64.b64decode(encoded).decode() if encoded else None
    except client.ApiException:
        return None


def get_session_owner(name: str) -> str | None:
    """Get the owner of a session from the CR or VM label."""
    _ensure_api()

    # First try the CR
    cr = _get_session_cr(name)
    if cr:
        return cr.get("spec", {}).get("owner")

    # Fallback: try VM label (unmanaged sessions)
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


def get_session_info(name: str) -> tuple[str | None, str | None, str | None]:
    """Return (owner, backend, namespace) for a session."""
    cr = _get_session_cr(name)
    if cr:
        owner = cr.get("spec", {}).get("owner")
        backend = _session_backend(cr)
        sess_ns = _session_namespace(cr)
        return owner, backend, sess_ns
    return None, None, None


def create_session_cr(
    name: str, owner: str, oidc_token: str = "", backend: str = ""
) -> bool:
    """Create a CodexSession CR and a short-lived OIDC token Secret."""
    _ensure_api()
    custom = client.CustomObjectsApi()
    v1 = client.CoreV1Api()

    if not backend:
        backend = config.DEFAULT_BACKEND

    if oidc_token:
        try:
            v1.create_namespaced_secret(
                config.MANAGED_NAMESPACE,
                client.V1Secret(
                    metadata=client.V1ObjectMeta(name=f"{name}-oidc-token"),
                    string_data={"token": oidc_token},
                ),
            )
        except client.ApiException as e:
            logger.warning("Failed to create OIDC token secret: %s", e)

    spec = {"name": name, "owner": owner}
    spec["runtime"] = {"backend": backend}

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
