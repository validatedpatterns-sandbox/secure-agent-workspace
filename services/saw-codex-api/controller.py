"""kopf controller for CodexSession CRDs — VM and Kubernetes backends."""

import base64 as b64
import datetime
import ipaddress
import logging
import os
import secrets as secrets_mod
import subprocess

import kopf
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from kubernetes import client, config as k8s_config

logger = logging.getLogger(__name__)

MANAGED_NAMESPACE = os.environ.get("MANAGED_NAMESPACE", "openshell-agents")
SAW_CHART_PATH = os.environ.get("SAW_CHART_PATH", "/app/charts/openshell-saw/")
K8S_CHART_PATH = os.environ.get("K8S_CHART_PATH", "/app/charts/openshell-saw-kubernetes/")
OIDC_ISSUER_URL = os.environ.get("OIDC_ISSUER_URL", "")
DEFAULT_BACKEND = os.environ.get("DEFAULT_BACKEND", "kubernetes")
MAX_SESSIONS_PER_USER = int(os.environ.get("MAX_SESSIONS_PER_USER", "3"))
SANDBOX_IMAGE = os.environ.get(
    "SANDBOX_IMAGE",
    "image-registry.openshift-image-registry.svc:5000/openshell-agents/codex-openshell:latest",
)


def _k8s_api():
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()


_k8s_api()


def _set_status(name: str, namespace: str, phase: str, message: str = "",
                backend: str = "", sess_ns: str = ""):
    custom = client.CustomObjectsApi()
    body = {"status": {"phase": phase, "message": message}}
    if backend:
        body["status"]["backend"] = backend
    if sess_ns:
        body["status"]["namespace"] = sess_ns
    custom.patch_namespaced_custom_object_status(
        group="saw.redhat.com",
        version="v1alpha1",
        namespace=namespace,
        plural="codexsessions",
        name=name,
        body=body,
    )


def _resolve_backend(spec: dict) -> str:
    return spec.get("runtime", {}).get("backend", DEFAULT_BACKEND)


def _check_session_limit(owner: str, cr_name: str, namespace: str):
    custom = client.CustomObjectsApi()
    try:
        crs = custom.list_namespaced_custom_object(
            group="saw.redhat.com",
            version="v1alpha1",
            namespace=MANAGED_NAMESPACE,
            plural="codexsessions",
        )
        count = sum(
            1 for c in crs.get("items", [])
            if c.get("spec", {}).get("owner") == owner
        )
        if count > MAX_SESSIONS_PER_USER:
            msg = f"Session limit reached ({MAX_SESSIONS_PER_USER})"
            _set_status(cr_name, namespace, "Error", msg)
            raise kopf.PermanentError(msg)
    except client.ApiException as e:
        logger.warning("Could not check session limit: %s", e)


def _read_ssh_pubkey() -> str:
    v1 = client.CoreV1Api()
    try:
        secret = v1.read_namespaced_secret("openshell-ssh-pubkey", MANAGED_NAMESPACE)
        return b64.b64decode(secret.data.get("key", "")).decode().strip()
    except client.ApiException:
        logger.warning("SSH public key secret not found")
        return ""


def _consume_oidc_token(session_name: str) -> str:
    v1 = client.CoreV1Api()
    try:
        token_secret = v1.read_namespaced_secret(
            f"{session_name}-oidc-token", MANAGED_NAMESPACE
        )
        token = b64.b64decode(token_secret.data.get("token", "")).decode().strip()
        v1.delete_namespaced_secret(f"{session_name}-oidc-token", MANAGED_NAMESPACE)
        logger.info("OIDC token secret consumed and deleted for %s", session_name)
        return token
    except client.ApiException:
        logger.info("No OIDC token secret for %s, continuing without", session_name)
        return ""


# ---------------------------------------------------------------------------
# TLS certificate generation
# ---------------------------------------------------------------------------

def _generate_session_pki(session_name: str, session_ns: str) -> dict:
    """Generate a per-session CA, server cert, and client cert.

    Returns a dict of Secret data ready for K8s Secret creation.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    validity = datetime.timedelta(days=365)

    # CA key + cert
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{session_name}-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + validity)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Server cert
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_sans = [
        x509.DNSName("localhost"),
        x509.DNSName(f"{session_name}-gateway"),
        x509.DNSName(f"{session_name}-gateway.{session_ns}.svc"),
        x509.DNSName(f"{session_name}-gateway.{session_ns}.svc.cluster.local"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{session_name}-gateway")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + validity)
        .add_extension(x509.SubjectAlternativeName(server_sans), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # Client cert (for forward sidecar + provisioning job)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{session_name}-client")]))
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + validity)
        .sign(ca_key, hashes.SHA256())
    )

    def _pem(obj):
        if hasattr(obj, "private_bytes"):
            return obj.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        return obj.public_bytes(serialization.Encoding.PEM)

    return {
        "ca_cert": _pem(ca_cert),
        "server_cert": _pem(server_cert),
        "server_key": _pem(server_key),
        "client_cert": _pem(client_cert),
        "client_key": _pem(client_key),
    }


def _generate_jwt_keys() -> dict:
    """Generate Ed25519 JWT signing keypair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    signing_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = secrets_mod.token_hex(8)
    return {"signing.pem": signing_pem, "public.pem": public_pem, "kid": kid.encode()}


# ---------------------------------------------------------------------------
# VM backend
# ---------------------------------------------------------------------------

def _create_vm(spec, meta, namespace):
    session_name = spec["name"]
    owner = spec["owner"]
    cr_name = meta["name"]

    _check_session_limit(owner, cr_name, namespace)
    _set_status(cr_name, namespace, "Creating", "Running helm install", backend="vm")

    ssh_pubkey = _read_ssh_pubkey()
    oidc_token = _consume_oidc_token(session_name)

    cmd = [
        "helm", "upgrade", "--install", session_name, SAW_CHART_PATH,
        "--namespace", MANAGED_NAMESPACE,
        "--set", f"sandboxName={session_name}",
        "--set", f"sshPublicKey={ssh_pubkey}",
        "--set", "agent=codex",
        "--set", "containerRuntime=docker",
        "--set", "route.enabled=true",
        "--set", "route.codex=true",
        "--set", "route.dashboard=true",
        "--set", f"accessControl.owner={owner}",
        "--set", "governance.enabled=true",
        "--set", "internalRegistry.allowAnonymousPull=true",
        "--set", f"oidc.issuerUrl={OIDC_ISSUER_URL}",
        "--set", "oidc.clientId=openshell-cli",
    ]
    if oidc_token:
        cmd += ["--set-string", f"oidc.token={oidc_token}"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        msg = result.stderr.strip()[-200:]
        logger.error("helm install failed for %s: %s", session_name, msg)
        _set_status(cr_name, namespace, "Error", f"helm install failed: {msg}")
        raise kopf.TemporaryError(f"helm install failed: {msg}", delay=60)

    _set_status(cr_name, namespace, "Creating",
                "Helm install complete, VM provisioning", backend="vm")
    logger.info("VM helm install succeeded for %s", session_name)


def _delete_vm(spec, meta, namespace):
    session_name = spec["name"]
    cr_name = meta["name"]

    try:
        _set_status(cr_name, namespace, "Deleting", "Running helm uninstall")
    except Exception:
        pass

    result = subprocess.run(
        ["helm", "uninstall", session_name, "--namespace", MANAGED_NAMESPACE],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        msg = result.stderr.strip()[-200:]
        logger.error("helm uninstall failed for %s: %s", session_name, msg)
        raise kopf.TemporaryError(f"helm uninstall failed: {msg}", delay=15)

    v1 = client.CoreV1Api()
    for suffix in ["-cloudinit", "-codex-secret"]:
        try:
            v1.delete_namespaced_secret(f"{session_name}{suffix}", MANAGED_NAMESPACE)
        except client.ApiException:
            pass

    logger.info("VM session cleaned up: %s", session_name)


def _check_vm_status(spec, meta, namespace):
    session_name = spec["name"]
    cr_name = meta["name"]
    custom = client.CustomObjectsApi()
    v1 = client.CoreV1Api()

    try:
        vm = custom.get_namespaced_custom_object(
            group="kubevirt.io", version="v1",
            namespace=MANAGED_NAMESPACE,
            plural="virtualmachines", name=session_name,
        )
    except client.ApiException:
        return

    printable = vm.get("status", {}).get("printableStatus", "Unknown")

    has_secret = False
    try:
        v1.read_namespaced_secret(f"{session_name}-codex-secret", MANAGED_NAMESPACE)
        has_secret = True
    except client.ApiException:
        pass

    connectable = False
    if has_secret:
        try:
            route = custom.get_namespaced_custom_object(
                group="route.openshift.io", version="v1",
                namespace=MANAGED_NAMESPACE,
                plural="routes", name=f"{session_name}-codex",
            )
            host = route.get("spec", {}).get("host", "")
            if host:
                import httpx
                r = httpx.get(f"https://{host}/readyz", timeout=5, verify=False)
                connectable = r.status_code == 200
        except Exception:
            pass

    if printable == "Running" and connectable:
        phase, msg = "Running", "Codex app-server ready"
    elif "Error" in printable:
        phase, msg = "Error", f"VM status: {printable}"
    else:
        phase, msg = "Creating", f"VM status: {printable}, app-server not ready"

    _set_status(cr_name, namespace, phase, msg)


# ---------------------------------------------------------------------------
# Kubernetes backend
# ---------------------------------------------------------------------------

def _create_kubernetes(spec, meta, namespace):
    session_name = spec["name"]
    owner = spec["owner"]
    cr_name = meta["name"]
    session_ns = f"saw-{session_name}"

    _check_session_limit(owner, cr_name, namespace)
    _set_status(cr_name, namespace, "Creating",
                "Preparing session namespace",
                backend="kubernetes", sess_ns=session_ns)

    oidc_token = _consume_oidc_token(session_name)
    v1 = client.CoreV1Api()
    custom = client.CustomObjectsApi()
    rbac = client.RbacAuthorizationV1Api()

    # 1. Create session namespace
    try:
        v1.create_namespace(
            client.V1Namespace(metadata=client.V1ObjectMeta(name=session_ns))
        )
        logger.info("Created namespace %s", session_ns)
    except client.ApiException as e:
        if e.status != 409:
            raise

    # 2. Copy governance ConfigMaps
    for cm_name in ["governance-policy", "governance-profiles"]:
        try:
            src = v1.read_namespaced_config_map(cm_name, MANAGED_NAMESPACE)
            v1.create_namespaced_config_map(
                session_ns,
                client.V1ConfigMap(
                    metadata=client.V1ObjectMeta(name=cm_name),
                    data=src.data,
                ),
            )
        except client.ApiException as e:
            if e.status != 409:
                logger.warning("Failed to copy ConfigMap %s: %s", cm_name, e)

    # 3. Generate TLS certs
    pki = _generate_session_pki(session_name, session_ns)
    _create_secret(v1, session_ns, f"{session_name}-tls", {
        "tls.crt": pki["server_cert"],
        "tls.key": pki["server_key"],
    }, secret_type="kubernetes.io/tls")
    _create_secret(v1, session_ns, f"{session_name}-client-ca", {
        "ca.crt": pki["ca_cert"],
    })
    _create_secret(v1, session_ns, f"{session_name}-client-tls", {
        "tls.crt": pki["client_cert"],
        "tls.key": pki["client_key"],
        "ca.crt": pki["ca_cert"],
    })

    # 4. Generate JWT keys
    jwt_keys = _generate_jwt_keys()
    _create_secret(v1, session_ns, f"{session_name}-jwt-keys", jwt_keys)

    # 5. Generate codex WebSocket secret
    ws_secret = secrets_mod.token_hex(32)
    _create_secret(v1, session_ns, "codex-ws-secret", {
        "ws-secret": ws_secret.encode(),
    })

    # 6. Store OIDC token in session namespace (ephemeral)
    if oidc_token:
        _create_secret(v1, session_ns, "oidc-token", {
            "token": oidc_token.encode(),
        })

    # 7. Helm install
    _set_status(cr_name, namespace, "Creating",
                "Running helm install", backend="kubernetes", sess_ns=session_ns)

    cmd = [
        "helm", "upgrade", "--install", session_name, K8S_CHART_PATH,
        "--namespace", session_ns,
        "--set", f"sessionName={session_name}",
        "--set", f"owner={owner}",
        "--set", f"oidc.issuerUrl={OIDC_ISSUER_URL}",
        "--set", "oidc.clientId=openshell-cli",
        "--set", f"sandboxImage={SANDBOX_IMAGE}",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        msg = result.stderr.strip()[-200:]
        logger.error("K8s helm install failed for %s: %s", session_name, msg)
        _set_status(cr_name, namespace, "Error",
                    f"helm install failed: {msg}",
                    backend="kubernetes", sess_ns=session_ns)
        raise kopf.TemporaryError(f"helm install failed: {msg}", delay=60)

    _set_status(cr_name, namespace, "Creating",
                "Helm install complete, gateway starting",
                backend="kubernetes", sess_ns=session_ns)
    logger.info("K8s helm install succeeded for %s in %s", session_name, session_ns)


def _delete_kubernetes(spec, meta, namespace):
    session_name = spec["name"]
    cr_name = meta["name"]

    # Read session namespace from status
    custom = client.CustomObjectsApi()
    try:
        cr = custom.get_namespaced_custom_object(
            group="saw.redhat.com", version="v1alpha1",
            namespace=namespace, plural="codexsessions", name=cr_name,
        )
        session_ns = cr.get("status", {}).get("namespace", f"saw-{session_name}")
    except client.ApiException:
        session_ns = f"saw-{session_name}"

    try:
        _set_status(cr_name, namespace, "Deleting", "Running helm uninstall")
    except Exception:
        pass

    result = subprocess.run(
        ["helm", "uninstall", session_name, "--namespace", session_ns],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        msg = result.stderr.strip()[-200:]
        if "not found" not in msg.lower():
            logger.error("K8s helm uninstall failed for %s: %s", session_name, msg)
            raise kopf.TemporaryError(f"helm uninstall failed: {msg}", delay=15)

    # Delete the session namespace (cascade deletes all resources)
    v1 = client.CoreV1Api()
    try:
        v1.delete_namespace(session_ns)
        logger.info("Deleted namespace %s", session_ns)
    except client.ApiException as e:
        if e.status != 404:
            logger.warning("Failed to delete namespace %s: %s", session_ns, e)

    logger.info("K8s session cleaned up: %s", session_name)


def _check_k8s_status(spec, meta, namespace):
    session_name = spec["name"]
    cr_name = meta["name"]
    custom = client.CustomObjectsApi()
    v1 = client.CoreV1Api()
    apps = client.AppsV1Api()

    # Read session namespace from status
    try:
        cr = custom.get_namespaced_custom_object(
            group="saw.redhat.com", version="v1alpha1",
            namespace=namespace, plural="codexsessions", name=cr_name,
        )
        session_ns = cr.get("status", {}).get("namespace")
    except client.ApiException:
        return

    if not session_ns:
        return

    # Check gateway StatefulSet
    gateway_ready = False
    try:
        sts = apps.read_namespaced_stateful_set(
            f"{session_name}-gateway", session_ns
        )
        gateway_ready = (sts.status.ready_replicas or 0) >= 1
    except client.ApiException:
        pass

    if not gateway_ready:
        _set_status(cr_name, namespace, "Creating",
                    "Gateway not ready", backend="kubernetes", sess_ns=session_ns)
        return

    # Check Sandbox CR
    sandbox_ready = False
    try:
        sandboxes = custom.list_namespaced_custom_object(
            group="agents.x-k8s.io", version="v1beta1",
            namespace=session_ns, plural="sandboxes",
        )
        for sb in sandboxes.get("items", []):
            conditions = sb.get("status", {}).get("conditions", [])
            for cond in conditions:
                if cond.get("type") == "Ready" and cond.get("status") == "True":
                    sandbox_ready = True
                    break
    except client.ApiException:
        pass

    # Check codex Route readyz
    connectable = False
    try:
        route = custom.get_namespaced_custom_object(
            group="route.openshift.io", version="v1",
            namespace=session_ns,
            plural="routes", name=f"{session_name}-codex",
        )
        host = route.get("spec", {}).get("host", "")
        if host:
            import httpx
            r = httpx.get(f"https://{host}/readyz", timeout=5, verify=False)
            connectable = r.status_code == 200
    except Exception:
        pass

    if connectable:
        phase, msg = "Running", "Codex app-server ready"
    elif sandbox_ready:
        phase, msg = "Creating", "Sandbox ready, app-server starting"
    elif gateway_ready:
        phase, msg = "Creating", "Gateway ready, sandbox provisioning"
    else:
        phase, msg = "Creating", "Starting"

    _set_status(cr_name, namespace, phase, msg,
                backend="kubernetes", sess_ns=session_ns)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_secret(v1, namespace: str, name: str, data: dict,
                   secret_type: str = "Opaque"):
    """Create a Secret, ignoring conflicts."""
    try:
        secret_data = {}
        for k, v in data.items():
            if isinstance(v, bytes):
                secret_data[k] = b64.b64encode(v).decode()
            else:
                secret_data[k] = b64.b64encode(v.encode()).decode()
        v1.create_namespaced_secret(
            namespace,
            client.V1Secret(
                metadata=client.V1ObjectMeta(name=name),
                data=secret_data,
                type=secret_type,
            ),
        )
    except client.ApiException as e:
        if e.status != 409:
            logger.warning("Failed to create secret %s/%s: %s", namespace, name, e)


# ---------------------------------------------------------------------------
# kopf handlers — dispatch to backend
# ---------------------------------------------------------------------------

@kopf.on.create("saw.redhat.com", "v1alpha1", "codexsessions")
def on_create(spec, meta, namespace, **_):
    backend = _resolve_backend(spec)
    if backend == "kubernetes":
        _create_kubernetes(spec, meta, namespace)
    else:
        _create_vm(spec, meta, namespace)


@kopf.on.delete("saw.redhat.com", "v1alpha1", "codexsessions")
def on_delete(spec, meta, namespace, **_):
    backend = _resolve_backend(spec)
    if backend == "kubernetes":
        _delete_kubernetes(spec, meta, namespace)
    else:
        _delete_vm(spec, meta, namespace)


@kopf.timer("saw.redhat.com", "v1alpha1", "codexsessions", interval=30, initial_delay=10)
def check_status(spec, meta, namespace, **_):
    backend = _resolve_backend(spec)
    if backend == "kubernetes":
        _check_k8s_status(spec, meta, namespace)
    else:
        _check_vm_status(spec, meta, namespace)
