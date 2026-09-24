#!/usr/bin/env python3
"""
apply_bom.py — BOM-driven agent configuration for SAW.

Single entry point for provisioning an OpenShell Secure Agent Workspace.
Reads BOM profile directories, sets up the gateway, installs CLIs as needed,
creates workspaces, providers, and sandboxes.

Runs INSIDE the gateway VM.

Usage:
    python3 apply_bom.py --profiles-dir /path/to/profiles \
        --oidc-gateway openshell --mtls-gateway openshell-local
"""

import argparse
import base64
import hashlib
import json
import os
import pwd
import grp
import re
import shlex
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path

import yaml

INSTALLER_VERSION = "0.2.0"
COMPONENT_BINARIES = {
    "cli": "/usr/local/bin/openshell",
    "gateway": "/usr/local/bin/openshell-gateway",
    "supervisor": "/usr/local/bin/openshell-supervisor",
}


class InstallerError(ValueError):
    """Only fixed nonsecret reason codes may cross the guest process boundary."""


def validate_installer_bom(document):
    """Release data, not commands or an API compatibility matrix.

    The release author updates this script when deploying a new combination
    requires different steps. OpenShell versions are deliberately not hard-coded.
    """
    from openshell_saw.blueprints import fields, name, string

    fields(document, {"apiVersion", "kind", "metadata", "spec"},
           {"apiVersion", "kind", "metadata", "spec"}, "installer BOM")
    if document["apiVersion"] != "saw.redhat.com/v1alpha1" or document["kind"] != "InstallerBOM":
        raise InstallerError("InvalidInstallerBOM")
    metadata = fields(document["metadata"], {"name"}, {"name"}, "installer metadata")
    name(metadata["name"], "installer release name")
    spec = fields(document["spec"], {"installerVersion", "openshell"},
                  {"installerVersion", "openshell"}, "installer spec")
    string(spec["installerVersion"], "installer version", r"[0-9]+\.[0-9]+\.[0-9]+")
    if spec["installerVersion"] != INSTALLER_VERSION:
        raise InstallerError("InstallerVersionMismatch")
    components = fields(spec["openshell"], set(COMPONENT_BINARIES), set(COMPONENT_BINARIES), "OpenShell components")
    for component in components.values():
        fields(component, {"version", "image"}, {"version", "image"}, "component")
        string(component["version"], "component version", r"[A-Za-z0-9][A-Za-z0-9.+_-]*", limit=128)
        string(component["image"], "component image", r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", limit=512)
    return document


def load_installer_bom(path):
    from openshell_saw.blueprints import load_document
    return validate_installer_bom(load_document(Path(path).read_text()))


def verify_installed_software(bom):
    """Check the selected release, never a baked-in OpenShell version string.

    Image-digest provenance belongs to the image build. Version output alone is
    not proof of the installed image's digest or release qualification.
    """
    for component, binary in COMPONENT_BINARIES.items():
        result = subprocess.run([binary, "--version"], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, check=False, timeout=15,
                                env={"PATH": "/usr/local/bin:/usr/sbin:/usr/bin", "LANG": "C.UTF-8"})
        words = result.stdout.strip().split()
        expected = bom["spec"]["openshell"][component]["version"]
        if result.returncode or not words or words[-1].removeprefix("v") != expected.removeprefix("v"):
            raise InstallerError("SoftwareReleaseMismatch")


def validate_guest_release(snapshot):
    """All release-specific safety/compatibility decisions live in this file."""
    bom = validate_installer_bom(snapshot["installerBOM"])
    installed = load_installer_bom("/opt/saw/installer/installer-bom.yaml")
    if bom["spec"]["openshell"] != installed["spec"]["openshell"]:
        # Do not overwrite running binaries just because a ConfigMap changed.
        # Installer logic is independently versioned in the signed release;
        # OpenShell payload upgrades still require a matching golden image.
        raise InstallerError("SoftwareUpgradeNotImplemented")
    validate_guest_profiles(snapshot)
    verify_installed_software(bom)
    return bom


GUEST_CLIENT_CONFIG = Path("/var/lib/saw/openshell-client")
GUEST_GATEWAY_ROOT = Path("/var/lib/saw/gateway")
GUEST_GATEWAY_UNIT = Path("/etc/systemd/system/saw-openshell-gateway.service")
GUEST_BUILD_MANIFEST = Path("/opt/saw/installer/build.json")
GUEST_VENDOR_DROPIN = Path('/usr/lib/systemd/system/service.d/10-timeout-abort.conf')
GUEST_INSTALLED_BOM = Path("/opt/saw/installer/installer-bom.yaml")
GUEST_SETTINGS_PATH = Path("/etc/saw/guest.json")
GUEST_RUNTIME_USER = "cloud-user"
GUEST_PKI_FILES = ("ca.crt", "ca.key", "server/tls.crt", "server/tls.key",
                   "client/tls.crt", "client/tls.key", "jwt/signing.pem", "jwt/public.pem", "jwt/kid")
GUEST_OWNER_LABEL = "saw.redhat.com/enrollment"
# Release-owned mapping, never an environment variable name supplied by a CM.
GUEST_CREDENTIAL_KEYS = {
    "nvidia": "NVIDIA_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}


def guest_owner_label(snapshot):
    # Preserve all 256 enrollment bits while fitting the 63-character label limit.
    return base64.b32encode(bytes.fromhex(snapshot["enrollmentIdentity"])).decode().rstrip("=").lower()


def validate_guest_profiles(snapshot):
    """Revalidate the normalized private input using the shared profile parser.

    No permissive conversion into the legacy deployer's dataclasses.
    """
    from openshell_saw.blueprints import fields, string
    from openshell_saw.profiles import resolve_profiles

    string(snapshot["enrollmentIdentity"], "enrollment", r"[0-9a-f]{64}")
    string(snapshot["ownerSubject"], "owner", limit=512)
    selections, configmaps = [], []
    for i, ws in enumerate(snapshot["workspaces"]):
        fields(ws, {"profile", "name", "workspace", "providers", "sandboxes"},
               {"profile", "name", "workspace", "providers", "sandboxes"}, "resolved workspace")
        providers = deepcopy(ws["providers"])
        for provider in providers:
            ref = provider.pop("secretRef", None)
            if ref is not None:
                fields(ref, {"name", "key"}, {"name", "key"}, "credential reference")
                provider.update(credentialSecret=ref["name"], credentialSecretKey=ref["key"])
        cm_name = f"profile-{i}"
        selections.append({"profileRef": {"name": ws["profile"], "configMapRef": {"name": cm_name}}})
        docs = {"workspace.yaml": ws["workspace"],
                "providers.yaml": {"apiVersion": "saw.redhat.com/v1alpha1", "kind": "Providers",
                                   "metadata": {}, "spec": {"providers": providers}},
                "sandbox.yaml": {"apiVersion": "saw.redhat.com/v1alpha1", "kind": "Sandboxes",
                                 "metadata": {}, "spec": {"sandboxes": ws["sandboxes"]}}}
        configmaps.append({"apiVersion": "v1", "kind": "ConfigMap",
                           "metadata": {"name": cm_name, "namespace": "guest"},
                           "data": {f"profiles__{ws['profile']}__{ws['name']}__{key}": yaml.safe_dump(value)
                                    for key, value in docs.items()}})
    resolved = resolve_profiles(selections, configmaps, "guest")
    if resolved != snapshot["workspaces"]:
        raise InstallerError("InvalidResolvedProfiles")
    for ws in resolved:
        spec = ws["workspace"].get("spec", {})
        if not spec.get("enabled", True):
            continue
        if any(s.get("enabled", True) for s in ws["sandboxes"]):
            # The current installer does not implement sandbox type-specific
            # startup, persistent data mounts, or replacement semantics. Fail
            # before creating workspaces or providers instead of reporting a
            # short-lived placeholder command as a ready sandbox.
            raise InstallerError("SandboxApplyNotImplemented")
        if any(p.get("model") or p.get("nemoclawProvider") for p in ws["providers"]):
            raise InstallerError("ExplicitWorkspaceInferenceRequired")
        if "inference" in spec and not any(p["name"] == spec["inference"]["provider"] and
                                          p.get("enabled", True) for p in ws["providers"]):
            raise InstallerError("InferenceProviderMustBeEnabled")
        if len(ws["name"]) > 19:
            raise InstallerError("UnsupportedWorkspaceName")
        members = desired_guest_members(ws)
        if members.get(snapshot["ownerSubject"]) != "admin":
            raise InstallerError("OwnerAdminRequired")
        for provider in ws["providers"]:
            if provider.get("enabled", True):
                guest_credential(snapshot, provider)
    return resolved


def desired_guest_members(ws):
    members = {}
    for member in ws["workspace"].get("spec", {}).get("members", []):
        subject = member.get("subject")
        if not subject or subject in members or "\x00" in subject:
            raise InstallerError("InvalidWorkspaceMembers")
        members[subject] = {"admin": "admin", "member": "user"}[member["role"]]
    return members


def guest_credential(snapshot, provider):
    key = GUEST_CREDENTIAL_KEYS.get(provider["type"])
    if key is None:
        raise InstallerError("UnsupportedProviderCredential")
    try:
        ref = provider["secretRef"]
        raw = base64.b64decode(snapshot["credentials"][ref["name"]][ref["key"]], validate=True)
        value = raw.decode("utf-8")
        if not value.strip() or len(raw) > 65536 or "\x00" in value:
            raise ValueError()
    except (KeyError, ValueError, TypeError):
        raise InstallerError("InvalidProviderCredential") from None
    return key, value


def trusted_guest_path(path, private=False):
    for entry in [path, *path.parents]:
        info = entry.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise InstallerError("UnsafeGatewayState")
    if private and path.stat().st_mode & 0o077:
        # Selected immutable gateway inputs are root-owned, read-only to the
        # runtime account's private group. The CA signing key stays root-only;
        # the runtime account is trusted to administer its own local gateway.
        info = path.stat()
        shared = path == GUEST_GATEWAY_ROOT or path == GUEST_GATEWAY_ROOT / "gateway.toml" or (
            path.is_relative_to(GUEST_GATEWAY_ROOT / "tls") and path.name != "ca.key")
        expected = 0o750 if path.is_dir() else 0o640
        if not shared or stat.S_IMODE(info.st_mode) != expected or info.st_gid != guest_runtime_account().pw_gid:
            raise InstallerError("UnsafeGatewayState")


def guest_runtime_account():
    account = pwd.getpwnam(GUEST_RUNTIME_USER)
    if (account.pw_uid < 1000 or account.pw_gid == 0 or
            grp.getgrgid(account.pw_gid).gr_name != GUEST_RUNTIME_USER):
        raise InstallerError("UnsafeRootlessAccount")
    return account


def guest_user_command(arguments, output=False):
    account = guest_runtime_account()
    runtime = f"/run/user/{account.pw_uid}"
    try:
        # Even a remote Podman client initializes config/runtime directories.
        # Keep those writes in the service's private tmp, never in user-managed
        # config or the read-only bind exposing the real engine/user-bus sockets.
        with tempfile.TemporaryDirectory(prefix='saw-rootless-client-') as home:
            os.chown(home, account.pw_uid, account.pw_gid)
            client_runtime = Path(home) / 'runtime'
            client_runtime.mkdir(mode=0o700)
            os.chown(client_runtime, account.pw_uid, account.pw_gid)
            remote = arguments[:2] == ['/usr/bin/podman', '--remote']
            result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if output else subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False, timeout=20, cwd="/", user=account.pw_uid, group=account.pw_gid, extra_groups=[],
                env={"PATH": "/usr/local/bin:/usr/sbin:/usr/bin", "LANG": "C.UTF-8",
                     "HOME": home, "USER": GUEST_RUNTIME_USER, "LOGNAME": GUEST_RUNTIME_USER,
                     "CONTAINERS_CONF": "/dev/null", "XDG_CONFIG_HOME": home + '/config',
                     "XDG_DATA_HOME": home + '/data', "XDG_CACHE_HOME": home + '/cache',
                     "XDG_RUNTIME_DIR": str(client_runtime) if remote else runtime,
                     "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus"})
        if result.returncode or (output and len(result.stdout) > 65536):
            raise InstallerError("RootlessCommandFailed")
        return result.stdout if output else None
    except (OSError, subprocess.SubprocessError):
        raise InstallerError("RootlessCommandFailed") from None


def prepare_rootless_podman(apply=False):
    account = guest_runtime_account()
    for filename in ("/etc/subuid", "/etc/subgid"):
        ranges = [line.split(":") for line in Path(filename).read_text().splitlines() if not line.startswith("#")]
        if not any(len(row) == 3 and row[0] in {GUEST_RUNTIME_USER, str(account.pw_uid)} and
                   row[1].isdigit() and row[2].isdigit() and int(row[1]) >= 65536 and int(row[2]) >= 65536
                   for row in ranges):
            raise InstallerError("RootlessSubordinateIDsRequired")
    if apply:
        guest_boot_command(["/usr/bin/loginctl", "enable-linger", GUEST_RUNTIME_USER])
        guest_boot_command(["/usr/bin/systemctl", "start", f"user@{account.pw_uid}.service"])
        guest_user_command(["/usr/bin/systemctl", "--user", "start", "podman.socket"])
    socket_path = Path(f"/run/user/{account.pw_uid}/podman/podman.sock")
    if not socket_path.exists():
        if apply:
            raise InstallerError("RootlessSocketUnavailable")
        return False
    for entry, forbidden in ((socket_path, 0o007), (socket_path.parent, 0o002), (socket_path.parent.parent, 0o077)):
        info = entry.lstat()
        if info.st_uid != account.pw_uid or info.st_mode & forbidden or stat.S_ISLNK(info.st_mode):
            raise InstallerError("UnsafeRootlessSocket")
    if not stat.S_ISSOCK(socket_path.stat().st_mode):
        raise InstallerError("UnsafeRootlessSocket")
    # Inspect the remote engine, never fall back to root's local Podman storage.
    raw = guest_user_command(["/usr/bin/podman", "--remote", f"--url=unix://{socket_path}",
                              "info", "--format=json"], output=True)
    if json.loads(raw).get("host", {}).get("security", {}).get("rootless") is not True:
        raise InstallerError("RootlessEngineRequired")
    return True


def grant_gateway_runtime_access():
    account = guest_runtime_account()
    shared = [GUEST_GATEWAY_ROOT, GUEST_GATEWAY_ROOT / "gateway.toml", GUEST_GATEWAY_ROOT / "tls",
              *(GUEST_GATEWAY_ROOT / "tls" / p for p in ("server", "client", "jwt")),
              *(GUEST_GATEWAY_ROOT / "tls" / p for p in GUEST_PKI_FILES if p != "ca.key")]
    for path in shared:
        trusted_guest_path(path)
        os.chown(path, 0, account.pw_gid)
        path.chmod(0o750 if path.is_dir() else 0o640)
    state = GUEST_GATEWAY_ROOT / "state"
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, account.pw_uid} or info.st_mode & 0o077:
        raise InstallerError("UnsafeGatewayRuntimeState")
    os.chown(state, account.pw_uid, account.pw_gid)


def guest_gateway_run():
    account = guest_runtime_account()
    if os.getuid() != account.pw_uid or os.getgid() != account.pw_gid:
        raise InstallerError("RootlessGatewayRequired")
    env = {"PATH": "/usr/local/bin:/usr/sbin:/usr/bin", "LANG": "C.UTF-8",
           "HOME": account.pw_dir, "XDG_RUNTIME_DIR": f"/run/user/{account.pw_uid}",
           "XDG_STATE_HOME": str(GUEST_GATEWAY_ROOT / "state"),
           "XDG_CONFIG_HOME": str(GUEST_GATEWAY_ROOT / "state/config"),
           "OPENSHELL_LOCAL_TLS_DIR": str(GUEST_GATEWAY_ROOT / "tls")}
    os.execve(COMPONENT_BINARIES["gateway"], [COMPONENT_BINARIES["gateway"],
        f"--config={GUEST_GATEWAY_ROOT}/gateway.toml", "--bind-address=127.0.0.1", "--port=17670",
        "--health-port=0", "--metrics-port=0", "--enable-mtls-auth=true"], env)


def guest_private_read(path):
    trusted_guest_path(path, private=True)
    if not path.is_file():
        raise InstallerError("UnsafeGatewayState")
    with path.open("rb") as source:
        data = source.read(65537)
    if not data or len(data) > 65536:
        raise InstallerError("InvalidGatewayState")
    return data


def guest_boot_identity(snapshot):
    machine = Path("/etc/machine-id").read_text().strip().lower()
    product = Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower()
    if (not re.fullmatch(r"[0-9a-f]{32}", machine) or machine == "0" * 32 or
            not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", product) or
            product == "00000000-0000-0000-0000-000000000000"):
        raise InstallerError("InvalidMachineIdentity")
    return {"enrollment": snapshot["enrollmentIdentity"], "machineId": machine, "productUUID": product}


def load_guest_settings():
    from saw_guest.inputs import validate_settings
    try:
        settings = json.loads(guest_private_read(GUEST_SETTINGS_PATH))
        return validate_settings(settings)
    except (ValueError, TypeError):
        raise InstallerError("InvalidOrUnavailableInstallerInput") from None


def guest_gateway_config(settings):
    """Fixed local bootstrap policy, not tenant-supplied TOML or shell content."""
    root = GUEST_GATEWAY_ROOT
    account = guest_runtime_account()
    supervisor_image = load_installer_bom(GUEST_INSTALLED_BOM)["spec"]["openshell"]["supervisor"]["image"]
    issuer = settings.get("oidcIssuer", "")
    audience = settings.get("oidcAudience", "openshell-cli")
    oidc = f'''[openshell.gateway.oidc]
issuer = "{issuer}"
audience = "{audience}"
roles_claim = "realm_access.roles"
admin_role = "openshell-admin"
user_role = "openshell-user"
'''.encode() if issuer else b""
    return f'''[openshell]
version = 1
[openshell.gateway]
name = "saw-local"
bind_address = "127.0.0.1:17670"
compute_drivers = ["podman"]
enable_loopback_service_http = false
provider_profile_sources = [{{ type = "builtin" }}]
[openshell.gateway.auth]
allow_unauthenticated_users = false
[openshell.gateway.mtls_auth]
enabled = true
'''.encode() + oidc + f'''[openshell.gateway.tls]
cert_path = "{root}/tls/server/tls.crt"
key_path = "{root}/tls/server/tls.key"
client_ca_path = "{root}/tls/ca.crt"
[openshell.drivers.podman]
socket_path = "/run/user/{account.pw_uid}/podman/podman.sock"
supervisor_image = "{supervisor_image}"
image_pull_policy = "missing"
network_name = "saw-local"
enable_bind_mounts = false
'''.encode()


def guest_boot_command(arguments, output=False):
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE if output else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False, timeout=20,
                                env={"PATH": "/usr/local/bin:/usr/sbin:/usr/bin", "LANG": "C.UTF-8"})
        if result.returncode or (output and len(result.stdout) > 65536):
            raise InstallerError("GatewayBootstrapCommandFailed")
        return result.stdout if output else None
    except (OSError, subprocess.SubprocessError):
        raise InstallerError("GatewayBootstrapCommandFailed") from None


def guest_gateway_service():
    trusted_guest_path(GUEST_GATEWAY_UNIT)
    trusted_guest_path(GUEST_BUILD_MANIFEST)
    manifest = json.loads(GUEST_BUILD_MANIFEST.read_bytes())
    if hashlib.sha256(GUEST_GATEWAY_UNIT.read_bytes()).hexdigest() != manifest["gatewayUnitSha256"]:
        raise InstallerError("GatewayUnitMismatch")
    raw = guest_boot_command(["/usr/bin/systemctl", "show", GUEST_GATEWAY_UNIT.name,
                              "--all",
                              "--property=LoadState,FragmentPath,DropInPaths,ActiveState,NeedDaemonReload"], output=True)
    properties = dict(line.split("=", 1) for line in raw.decode().splitlines() if "=" in line)
    # Fedora applies this vendor drop-in to every service. Only the image-build
    # attested file is allowed; new overrides or modified contents still fail.
    expected_dropins = manifest.get('gatewayDropIns', {})
    if (not isinstance(expected_dropins, dict) or
            set(expected_dropins) - {str(GUEST_VENDOR_DROPIN)} or
            'DropInPaths' not in properties or
            properties['DropInPaths'].split() != sorted(expected_dropins)):
        raise InstallerError('UnqualifiedGatewayUnit')
    for filename, digest in expected_dropins.items():
        path = Path(filename)
        trusted_guest_path(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise InstallerError('GatewayUnitMismatch')
    if (properties.get("LoadState") != "loaded" or properties.get("FragmentPath") != str(GUEST_GATEWAY_UNIT) or
            properties.get("NeedDaemonReload") != "no"):
        raise InstallerError("UnqualifiedGatewayUnit")
    if properties.get("ActiveState") not in {"active", "inactive", "failed"}:
        raise InstallerError("GatewayServiceTransitioning")
    return properties["ActiveState"] == "active"


def check_guest_gateway_state(identity, settings):
    trusted_guest_path(GUEST_GATEWAY_ROOT, private=True)
    record = json.loads(guest_private_read(GUEST_GATEWAY_ROOT / "bootstrap.json"))
    if record.get("version") != 1 or record.get("identity") != identity:
        raise InstallerError("GatewayIdentityMismatch")
    if guest_private_read(GUEST_GATEWAY_ROOT / "gateway.toml") != guest_gateway_config(settings):
        raise InstallerError("GatewayConfigRequiresMigration")
    if set(record.get("pki", {})) != set(GUEST_PKI_FILES):
        raise InstallerError("InvalidGatewayState")
    for relative in GUEST_PKI_FILES:
        if hashlib.sha256(guest_private_read(GUEST_GATEWAY_ROOT / "tls" / relative)).hexdigest() != record["pki"][relative]:
            raise InstallerError("GatewayPKIMismatch")


def guest_write_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())


def guest_publish_directory(staging, destination):
    # All callers hold the guest's single-writer lock. Never overwrite state.
    if destination.exists() or destination.is_symlink():
        raise InstallerError("GatewayStateAlreadyExists")
    for entry in sorted(staging.rglob("*"), reverse=True):
        trusted_guest_path(entry)
        if entry.is_dir():
            entry.chmod(0o700)
        elif entry.is_file():
            entry.chmod(0o600)
        else:
            raise InstallerError("UnsafeGatewayState")
        fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    os.rename(staging, destination)
    for directory in (destination, destination.parent):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def create_guest_gateway(identity, settings):
    # Generate only in a new private staging directory. Never rerun certgen on
    # active PKI: some releases regenerate the CA when SANs change.
    with tempfile.TemporaryDirectory(prefix=".saw-gateway-", dir=GUEST_GATEWAY_ROOT.parent) as temporary:
        staging = Path(temporary)
        tls = staging / "tls"
        guest_boot_command([COMPONENT_BINARIES["gateway"], "generate-certs", f"--output-dir={tls}",
                            "--server-san=localhost", "--server-san=127.0.0.1",
                            "--server-san=host.openshell.internal"])
        hashes = {}
        for relative in GUEST_PKI_FILES:
            path = tls / relative
            trusted_guest_path(path)
            path.chmod(0o600)
            hashes[relative] = hashlib.sha256(guest_private_read(path)).hexdigest()
        # Parse CA and ensure both TLS certificate/private-key pairs match.
        context = ssl.create_default_context(cafile=str(tls / "ca.crt"))
        for role in ("server", "client"):
            context.load_cert_chain(str(tls / role / "tls.crt"), str(tls / role / "tls.key"))
        guest_write_private(staging / "gateway.toml", guest_gateway_config(settings))
        guest_write_private(staging / "bootstrap.json", json.dumps({"version": 1, "identity": identity,
                                                                    "pki": hashes}, sort_keys=True).encode())
        (staging / "state").mkdir(mode=0o700)
        guest_publish_directory(staging, GUEST_GATEWAY_ROOT)


def ensure_guest_gateway_client(apply=False):
    source = GUEST_GATEWAY_ROOT / "tls"
    expected = {"ca.crt": guest_private_read(source / "ca.crt"),
                "tls.crt": guest_private_read(source / "client/tls.crt"),
                "tls.key": guest_private_read(source / "client/tls.key")}
    if not GUEST_CLIENT_CONFIG.exists() and not GUEST_CLIENT_CONFIG.is_symlink():
        if not apply:
            return False
        with tempfile.TemporaryDirectory(prefix=".saw-client-", dir=GUEST_CLIENT_CONFIG.parent) as temporary:
            staging = Path(temporary)
            for filename, data in expected.items():
                guest_write_private(staging / "openshell/gateways/saw-local/mtls" / filename, data)
            guest_publish_directory(staging, GUEST_CLIENT_CONFIG)
    check_guest_client()
    for filename, data in expected.items():
        if guest_private_read(GUEST_CLIENT_CONFIG / "openshell/gateways/saw-local/mtls" / filename) != data:
            raise InstallerError("GatewayClientIdentityMismatch")
    return True


def prepare_guest_gateway(snapshot, phase):
    """Read-only preflight/verify; only apply may publish identity/start service."""
    settings = load_guest_settings()
    identity = guest_boot_identity(snapshot)
    runtime_ready = prepare_rootless_podman()
    active = guest_gateway_service()
    trusted_guest_path(GUEST_GATEWAY_ROOT.parent)
    exists = GUEST_GATEWAY_ROOT.exists() or GUEST_GATEWAY_ROOT.is_symlink()
    if exists:
        check_guest_gateway_state(identity, settings)
    elif active or GUEST_CLIENT_CONFIG.exists() or GUEST_CLIENT_CONFIG.is_symlink():
        raise InstallerError("UnownedGatewayState")
    if not active:
        # Refuse to take over a listener owned by the legacy setup or another app.
        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 17670))
        except OSError:
            raise InstallerError("GatewayPortInUse") from None
    if phase == "validate":
        return exists and ensure_guest_gateway_client() and active and runtime_ready
    if phase == "verify":
        if not exists or not ensure_guest_gateway_client() or not active or not runtime_ready:
            raise InstallerError("GatewayNotReady")
        guest_list(["workspace", "list"])
        return True
    if not exists:
        create_guest_gateway(identity, settings)
    ensure_guest_gateway_client(apply=True)
    grant_gateway_runtime_access()
    prepare_rootless_podman(apply=True)
    if not active:
        guest_boot_command(["/usr/bin/systemctl", "start", GUEST_GATEWAY_UNIT.name])
    # Type=simple is not readiness. Require a TLS-authenticated CLI round trip.
    for attempt in range(5):
        try:
            guest_list(["workspace", "list"])
            return True
        except InstallerError:
            if attempt == 4:
                raise InstallerError("GatewayNotReady") from None
            time.sleep(1)


def guest_gateway_check():
    """Systemd restart guard: never start retained gateway state on a clone."""
    try:
        from saw_guest.inputs import validate_settings
        settings = load_guest_settings()
        check_guest_gateway_state(guest_boot_identity(settings), settings)
        return 0
    except Exception:
        # Never emit raw settings, keys, errors or tracebacks to the journal.
        return 1


def check_guest_client():
    """Bootstrap must supply fresh per-VM local platform-admin mTLS identity.

    No user login, inherited config, alternate gateway or TLS-verification bypass.
    This directory is NOT to be cloned into the golden image.
    """
    gateway = GUEST_CLIENT_CONFIG / "openshell/gateways/saw-local"
    for filename in ("ca.crt", "tls.crt", "tls.key"):
        path = gateway / "mtls" / filename
        for entry in [path, *path.parents]:
            info = entry.lstat()
            if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
                raise InstallerError("UnsafeGatewayIdentity")
        if not path.is_file() or (filename == "tls.key" and path.stat().st_mode & 0o077):
            raise InstallerError("UnsafeGatewayIdentity")
    if set(p.name for p in gateway.iterdir()) != {"mtls"}:
        raise InstallerError("UnexpectedGatewayClientConfig")


def guest_cli(arguments, credential=None, collection=False, text_output=False):
    """Fixed local CLI; credential bytes exist only in this child's environment.

    The CLI's env-lookup syntax avoids credentials in argv. Root can still read
    process environments: the guest and local gateway remain trusted boundaries.
    Never forward raw CLI output/errors to logs or the public readiness endpoint.
    """
    env = {"PATH": "/usr/local/bin:/usr/sbin:/usr/bin", "LANG": "C.UTF-8",
           "XDG_CONFIG_HOME": str(GUEST_CLIENT_CONFIG)}
    if credential:
        key, value = credential
        if key not in GUEST_CREDENTIAL_KEYS.values():
            raise InstallerError("UnsupportedProviderCredential")
        env[key] = value
    command = [COMPONENT_BINARIES["cli"], "--gateway=saw-local",
               "--gateway-endpoint=https://127.0.0.1:17670", "--color=never", *arguments]
    try:
        # Spool output to a private, unlinked file, not an unbounded RAM buffer.
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.DEVNULL, timeout=20, check=False, env=env)
            if result.returncode:
                raise InstallerError("OpenShellCommandFailed")
            if not collection and not text_output:
                return None
            output.seek(0)
            raw = output.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise InstallerError("OpenShellOutputTooLarge")
            return raw.decode("utf-8") if text_output else json.loads(raw)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        if isinstance(error, InstallerError):
            raise
        raise InstallerError("OpenShellCommandFailed") from None


def guest_list(arguments, identity="name"):
    result = {}
    for offset in range(0, 10000, 100):
        page = guest_cli([*arguments, "--output=json", "--limit=100", f"--offset={offset}"], collection=True)
        if not isinstance(page, list) or len(page) > 100:
            raise InstallerError("InvalidOpenShellCollection")
        for item in page:
            if not isinstance(item, dict) or not isinstance(item.get(identity), str) or item[identity] in result:
                raise InstallerError("InvalidOpenShellCollection")
            result[item[identity]] = item
        if len(page) < 100:
            return result
    raise InstallerError("OpenShellCollectionLimit")


def verify_guest_inference(workspace, inference):
    # This release's CLI has no JSON flag for inference get. Parse only the
    # exact user-route section; it may exit zero even when that section says
    # Error/Not configured. Neither case is allowed to pass verification.
    output = guest_cli(["inference", "get", f"--workspace={workspace}"], text_output=True)
    section = output.split("System inference:", 1)[0].strip().splitlines()
    if not section or section[0] != "Inference:":
        raise InstallerError("InferenceNotConverged")
    fields = {}
    for line in section[1:]:
        if not line.strip():
            continue
        key, separator, value = line.strip().partition(":")
        if not separator or key in fields or key not in {"Workspace", "Provider", "Model", "Version", "Timeout"}:
            raise InstallerError("InferenceNotConverged")
        fields[key] = value.strip()
    if (fields.get("Workspace") != workspace or fields.get("Provider") != inference["provider"] or
            fields.get("Model") != inference["model"] or not fields.get("Version", "").isdigit() or
            int(fields["Version"]) < 1):
        raise InstallerError("InferenceNotConverged")


def inspect_guest_workspaces(snapshot, require_present=False):
    """Read all desired scopes and detect collisions before any mutation."""
    workspaces = guest_list(["workspace", "list"])
    observed = {}
    for ws in snapshot["workspaces"]:
        if not ws["workspace"].get("spec", {}).get("enabled", True):
            continue
        name = ws["name"]
        current = workspaces.get(name)
        if current is None:
            if require_present:
                raise InstallerError("WorkspaceNotConverged")
            observed[name] = ({}, {})
            continue
        if current.get("labels", {}).get(GUEST_OWNER_LABEL) != guest_owner_label(snapshot):
            # Includes the built-in, unlabeled default workspace. Never adopt it.
            raise InstallerError("WorkspaceOwnershipConflict")
        if current.get("status") != "Active":
            raise InstallerError("WorkspaceNotActive")
        members = guest_list(["workspace", "member", "list", f"--workspace={name}"], "subject")
        if any(m.get("role") not in {"user", "admin"} for m in members.values()):
            raise InstallerError("InvalidWorkspaceMembers")
        providers = guest_list(["provider", "list", f"--workspace={name}"])
        if any(p.get("workspace") != name for p in providers.values()):
            raise InstallerError("ProviderWorkspaceMismatch")
        for provider in ws["providers"]:
            actual = providers.get(provider["name"])
            if provider.get("enabled", True) and actual and actual.get("type") != provider["type"]:
                raise InstallerError("ProviderTypeChangeRequiresMigration")
        observed[name] = (members, providers)
    return workspaces, observed


def reconcile_guest_profiles(snapshot, phase):
    enabled = [ws for ws in snapshot["workspaces"] if ws["workspace"].get("spec", {}).get("enabled", True)]
    if not enabled:
        return
    check_guest_client()
    workspaces, observed = inspect_guest_workspaces(snapshot, require_present=phase == "verify")
    if phase == "validate":
        return
    for ws in enabled:
        name = ws["name"]
        scope = f"--workspace={name}"
        wanted = desired_guest_members(ws)
        members, providers = observed[name]
        if phase == "verify":
            if {subject: m["role"] for subject, m in members.items()} != wanted:
                raise InstallerError("WorkspaceMembersNotConverged")
            for provider in ws["providers"]:
                if not provider.get("enabled", True):
                    continue
                actual = providers.get(provider["name"])
                key, _ = guest_credential(snapshot, provider)
                if not actual or key not in actual.get("credential_keys", []):
                    raise InstallerError("ProviderNotConverged")
            if "inference" in ws["workspace"].get("spec", {}):
                verify_guest_inference(name, ws["workspace"]["spec"]["inference"])
            continue
        if name not in workspaces:
            guest_cli(["workspace", "create", f"--name={name}",
                       f"--label={GUEST_OWNER_LABEL}={guest_owner_label(snapshot)}"])
        # The label marks an exclusively Git-managed workspace. Revoke stale
        # memberships/roles before provider writes; never silently keep access.
        for subject, actual in sorted(members.items()):
            if wanted.get(subject) != actual["role"]:
                guest_cli(["workspace", "member", "remove", scope, f"--subject={subject}"])
        for subject, role in sorted(wanted.items()):
            if members.get(subject, {}).get("role") != role:
                guest_cli(["workspace", "member", "add", scope, f"--subject={subject}", f"--role={role}"])
        for provider in ws["providers"]:
            if not provider.get("enabled", True):
                continue
            credential = guest_credential(snapshot, provider)
            if provider["name"] in providers:
                args = ["provider", "update", provider["name"]]
            else:
                args = ["provider", "create", f"--name={provider['name']}",
                        f"--type={provider['type']}", "--global-profile"]
            # Reapplying credentials is deliberate: a previous invocation may
            # have died after server acceptance but before the guest journal commit.
            guest_cli([*args, scope, f"--credential={credential[0]}"], credential=credential)
        if "inference" in ws["workspace"].get("spec", {}):
            inference = ws["workspace"]["spec"]["inference"]
            guest_cli(["inference", "set", scope, f"--provider={inference['provider']}",
                       f"--model={inference['model']}"])


def guest_main(phase):
    """Private stdin/structured result for the generic guest process runner.

    Keep deployment and verification here as the release implementation grows;
    do not add a second OpenShell adapter or download an installer from a BOM.
    """
    revision_id = None
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise InstallerError("InputTooLarge")
        request = json.loads(raw)
        if request.get("version") != 1 or phase not in {"validate", "apply", "verify"}:
            raise InstallerError("InvalidInstallerRequest")
        revision = request["revision"]
        if not isinstance(revision["id"], str) or not re.fullmatch("[0-9a-f]{32}", revision["id"]):
            raise InstallerError("InvalidRevision")
        revision_id = revision["id"]
        validate_guest_release(revision["snapshot"])
        if prepare_guest_gateway(revision["snapshot"], phase):
            reconcile_guest_profiles(revision["snapshot"], phase)
        result = {"version": 1, "revision": revision_id, "ok": True}
        status = 0
    except Exception as error:
        from saw_guest.errors import safe_reason
        code = str(error) if isinstance(error, InstallerError) else "InvalidOrUnavailableInstallerInput"
        result = {"version": 1, "revision": revision_id, "ok": False, "reason": safe_reason(code)}
        status = 1
    print(json.dumps(result))
    return status


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Provider:
    name: str
    type: str
    enabled: bool = True
    nemoclaw_provider: str = ""
    credential_secret: str = ""
    credential_secret_key: str = "api_key"
    model: str = ""


@dataclass
class Sandbox:
    name: str
    type: str = "generic"       # nemoclaw, openclaw, generic
    enabled: bool = True
    agent: str = "openclaw"     # openclaw, hermes
    image: str = ""
    providers: list = field(default_factory=list)
    model: str = ""


@dataclass
class Workspace:
    name: str
    enabled: bool = True
    description: str = ""
    providers: list = field(default_factory=list)
    sandboxes: list = field(default_factory=list)


@dataclass
class Profile:
    name: str
    workspaces: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Shell runner
# ---------------------------------------------------------------------------

class Shell:
    def __init__(self, dry_run=False):
        self.dry_run = dry_run

    def run(self, cmd, env=None, check=True):
        display = re.sub(
            r'(--credential\s+\S+=)\S+',
            r'\1***',
            " ".join(cmd))
        display = re.sub(
            r'(API_KEY=|api_key=|TOKEN=|token=)\S+',
            r'\1***',
            display)
        # openclaw's own "config set gateway.auth.token '<value>'" call style has
        # no '=' at all, so the regex above never touches it — this leaked the
        # raw gateway auth token to Job logs in plaintext. Catch it explicitly.
        display = re.sub(
            r"(gateway\.auth\.token\s+')[^']+(')",
            r'\1***\2',
            display)
        if self.dry_run:
            log(f"[dry-run] {display}")
            return 0, "", ""
        log(f"$ {display}")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                env={**os.environ, **(env or {})}, check=False
            )
        except FileNotFoundError:
            log(f"  WARN: command not found: {cmd[0]}")
            return 1, "", f"{cmd[0]}: not found"
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        if stdout:
            for line in stdout.split("\n"):
                log(f"  {line}")
        if result.returncode != 0:
            if "already exists" in (stdout + stderr):
                log("  (already exists)")
                return 0, stdout, stderr
            if stderr:
                log(f"  WARN: {stderr[:300]}")
        return result.returncode, stdout, stderr


def runtime_command(*args):
    """Return the selected container command, defaulting to rootless Podman."""
    runtime = os.environ.get("CONTAINER_RUNTIME", "podman").strip().lower()
    if runtime not in {"docker", "podman"}:
        raise ValueError(f"unsupported container runtime: {runtime}")
    prefix = ["podman"] if runtime == "podman" else ["sudo", "docker"]
    return prefix + list(args)


def runtime_shell_command(*args):
    """Return a safely shell-quoted command for the selected container runtime."""
    return shlex.join(runtime_command(*args))


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(msg, indent=0):
    prefix = "  " * indent
    print(f"{prefix}{msg}", flush=True)


def banner(title):
    log(f"\n{'=' * 60}")
    log(title)
    log(f"{'=' * 60}")


def section(title):
    log(f"\n  [{title}]")


# ---------------------------------------------------------------------------
# Profile parser
# ---------------------------------------------------------------------------

def load_yaml_file(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def parse_profiles(profiles_dir):
    profiles = []
    for profile_entry in sorted(Path(profiles_dir).iterdir()):
        if not profile_entry.is_dir():
            continue
        profile = Profile(name=profile_entry.name)
        for ws_entry in sorted(profile_entry.iterdir()):
            if not ws_entry.is_dir():
                continue
            ws_file = ws_entry / "workspace.yaml"
            if not ws_file.exists():
                log(f"WARN: {ws_entry} missing workspace.yaml, skipping")
                continue
            ws_data = load_yaml_file(ws_file)
            ws_meta = ws_data.get("metadata", {})
            ws = Workspace(
                name=ws_meta.get("name", ws_entry.name),
                enabled=ws_data.get("spec", {}).get("enabled", True),
                description=ws_meta.get("description", ""),
            )
            prov_file = ws_entry / "providers.yaml"
            if prov_file.exists():
                prov_data = load_yaml_file(prov_file)
                for p in prov_data.get("spec", {}).get("providers", []):
                    ws.providers.append(Provider(
                        name=p["name"],
                        type=p["type"],
                        enabled=p.get("enabled", True),
                        nemoclaw_provider=p.get("nemoclawProvider", ""),
                        credential_secret=p.get("credentialSecret", ""),
                        credential_secret_key=p.get("credentialSecretKey", "api_key"),
                        model=p.get("model", ""),
                    ))
            sb_file = ws_entry / "sandbox.yaml"
            if sb_file.exists():
                sb_data = load_yaml_file(sb_file)
                for s in sb_data.get("spec", {}).get("sandboxes", []):
                    ws.sandboxes.append(Sandbox(
                        name=s["name"],
                        type=s.get("type", "generic"),
                        enabled=s.get("enabled", True),
                        agent=s.get("agent", "openclaw"),
                        image=s.get("image", ""),
                        providers=s.get("providers", []),
                        model=s.get("model", ""),
                    ))
            profile.workspaces.append(ws)
        if profile.workspaces:
            profiles.append(profile)
    return profiles




# ---------------------------------------------------------------------------
# Credential resolver
# ---------------------------------------------------------------------------

PROVIDER_CRED_MAP = {
    "gemini": "GEMINI_API_KEY",
    "google-vertex-ai": "GOOGLE_API_KEY",
    "claude-code": "ANTHROPIC_API_KEY",
    "codex": "OPENAI_API_KEY",
    "nvidia": "NVIDIA_API_KEY",
    "build": "NVIDIA_INFERENCE_API_KEY",
    "brave": "BRAVE_API_KEY",
    "tavily": "TAVILY_API_KEY",
}


def resolve_credential(provider):
    env_var = f"PROV_{provider.name}_KEY".replace("-", "_").upper()
    val = os.environ.get(env_var)
    if val:
        return val
    cred_key = PROVIDER_CRED_MAP.get(provider.type)
    if cred_key:
        val = os.environ.get(cred_key)
        if val:
            return val
    return None


def resolve_configured_type(provider):
    """The credential secret's own `provider:` field (if setup-bom-profiles.sh
    found one alongside the API key), e.g. "gemini" or "build" (NVIDIA
    Build's own provider identifier — distinct from the OpenShell provider
    *type* "nvidia"). Returns None if not present, e.g. for secrets that
    don't carry a provider field at all.
    """
    env_var = f"PROV_{provider.name}_TYPE".replace("-", "_").upper()
    return os.environ.get(env_var) or None


def check_provider_type_mismatch(provider):
    """Validate that the credential secret's own declared provider matches
    what this BOM profile expects, before we create a provider using a
    credential that may belong to an entirely different service. Returns
    an error string if there's a mismatch, or None if it's fine / unknown.

    A profile's `type` (the OpenShell provider type, e.g. "nvidia") and
    `nemoclaw_provider` (a NemoClaw-specific alias, e.g. "build" for NVIDIA
    Build) are both accepted as valid matches, since values-secret.yaml's
    documented provider identifiers ("gemini, anthropic, openai, build
    (NVIDIA), openrouter, ...") use the nemoclaw-style alias, not the
    OpenShell type, for NVIDIA specifically.
    """
    configured = resolve_configured_type(provider)
    if not configured:
        return None
    valid = {v for v in (provider.type, provider.nemoclaw_provider) if v}
    if configured not in valid:
        expected = " or ".join(sorted(valid)) if valid else provider.type
        return (f"BOM profile expects provider type '{expected}' for "
                f"'{provider.name}', but the credential secret is "
                f"configured for provider '{configured}'")
    return None


def find_provider(ws, names):
    """Look up a provider by name from a sandbox's own declared providers list.

    Falls back to the first workspace provider only if the sandbox didn't
    declare any (or none of its declared names match) — previously this
    fallback was the *only* behavior, silently ignoring `sandbox.providers`
    entirely and wiring up whatever happened to be first in the workspace's
    provider list (e.g. attaching a web-search credential as if it were an
    LLM provider, if that provider happened to be declared first).
    """
    for name in names or []:
        for p in ws.providers:
            if p.name == name:
                return p
    return ws.providers[0] if ws.providers else None


# ---------------------------------------------------------------------------
# Gateway setup
# ---------------------------------------------------------------------------

class GatewaySetup:
    def __init__(self, shell, oidc_gw, mtls_gw):
        self.sh = shell
        self.oidc_gw = oidc_gw
        self.mtls_gw = mtls_gw

    def configure_oidc(self, token, issuer, client_id):
        if not token:
            return
        section("Configuring OIDC token")
        gw_name = self.oidc_gw
        token_dir = Path.home() / ".config" / "openshell" / "gateways" / gw_name
        token_dir.mkdir(parents=True, exist_ok=True)
        token_path = token_dir / "oidc_token.json"
        token_data = {
            "access_token": token,
            "issuer": issuer,
            "client_id": client_id,
        }
        with open(token_path, "w", encoding="utf-8") as f:
            json.dump(token_data, f)
        token_path.chmod(0o600)
        log(f"OIDC token written for gateway '{gw_name}'")

    def register_mtls_gateway(self):
        section("Registering mTLS gateway")
        self.sh.run(["openshell", "gateway", "remove", self.mtls_gw],
                     check=False)
        self.sh.run([
            "openshell", "gateway", "add",
            "https://127.0.0.1:17670",
            "--name", self.mtls_gw, "--local"
        ])
        self.sh.run(["openshell", "gateway", "select", self.mtls_gw])

    def grant_default_workspace_access(self):
        section("Granting default workspace access")
        self._with_oidc(lambda: self.sh.run([
            "openshell", "workspace", "member", "add",
            "--workspace", "default",
            "--subject", "openshell-client",
            "--role", "admin"
        ], check=False))

    def enable_providers_v2(self):
        section("Enabling providers_v2")
        self._with_oidc(lambda: self.sh.run([
            "openshell", "settings", "set",
            "--global", "--key", "providers_v2_enabled",
            "--value", "true", "--yes"
        ], check=False))

    def select_oidc(self):
        if self.oidc_gw:
            self.sh.run(["openshell", "gateway", "select", self.oidc_gw],
                         check=False)

    def select_mtls(self):
        self.sh.run(["openshell", "gateway", "select", self.mtls_gw],
                     check=False)

    def _with_oidc(self, fn):
        if self.oidc_gw:
            self.select_oidc()
            fn()
            self.select_mtls()
        else:
            fn()


# ---------------------------------------------------------------------------
# Workspace deployer
# ---------------------------------------------------------------------------

class WorkspaceDeployer:
    def __init__(self, shell, gateway_setup):
        self.sh = shell
        self.gw = gateway_setup

    @staticmethod
    def runtime_command(*args):
        return runtime_command(*args)

    @staticmethod
    def runtime_shell_command(*args):
        return runtime_shell_command(*args)

    def create_workspace(self, ws):
        if ws.name == "default":
            log("Using existing 'default' workspace")
            return
        log(f"Creating workspace '{ws.name}'")
        self.gw._with_oidc(lambda: (
            self.sh.run(["openshell", "workspace", "create",
                         "--name", ws.name], check=False),
            self.sh.run(["openshell", "workspace", "member", "add",
                         "--workspace", ws.name,
                         "--subject", "openshell-client",
                         "--role", "admin"], check=False),
        ))

    def create_provider(self, provider, credential,
                        workspace_name="default"):
        mismatch = check_provider_type_mismatch(provider)
        if mismatch:
            log(f"ERROR: {mismatch} — skipping provider "
                f"'{provider.name}' creation. Fix values-secret.yaml or "
                f"the BOM profile's declared type/nemoclawProvider.")
            return
        args = ["openshell", "provider", "create",
                "--name", provider.name, "--type", provider.type]
        if workspace_name != "default":
            args += ["--workspace", workspace_name]
        cred_key = PROVIDER_CRED_MAP.get(provider.type, "API_KEY")
        if credential and cred_key:
            args += ["--credential", f"{cred_key}={credential}"]
        else:
            args += ["--from-existing"]
        self.sh.run(args, check=False)

    def create_sandbox_generic(self, sandbox, workspace_name="default"):
        ws_args = (["--workspace", workspace_name]
                   if workspace_name != "default" else [])
        rc, out, _ = self.sh.run(
            ["openshell", "sandbox", "get", sandbox.name] + ws_args,
            check=False)
        if rc == 0:
            clean = re.sub(r'\x1b\[[0-9;]*m', '', out)
            if "Error" in clean or "Phase: Completed" in clean:
                state = "Completed" if "Phase: Completed" in clean else "Error"
                log(f"Sandbox '{sandbox.name}' is in {state} state, "
                    "recreating...")
                self.sh.run(
                    ["openshell", "sandbox", "delete",
                     sandbox.name] + ws_args,
                    check=False)
            else:
                log(f"Sandbox '{sandbox.name}' already exists")
                return
        is_full_ref = sandbox.image and ("/" in sandbox.image or ":" in sandbox.image)
        if is_full_ref:
            self.sh.run(self.runtime_command("pull", sandbox.image), check=False)
        args = ["openshell", "sandbox", "create", "--name", sandbox.name]
        if sandbox.image:
            args += ["--from", sandbox.image]
        if workspace_name != "default":
            args += ["--workspace", workspace_name]
        for prov in sandbox.providers:
            args += ["--provider", prov]
        # Keep the sandbox Ready for follow-up `sandbox exec` setup.
        # A detached long-running workload prevents premature completion.
        args += ["--no-tty", "--detach", "--", "sh", "-c", "sleep infinity"]
        rc, out, err = self.sh.run(args, check=False)
        combined = re.sub(r'\x1b\[[0-9;]*m', '',
                          (out or "") + " " + (err or ""))
        if "Error" in combined or "Restarting" in combined:
            log("Sandbox entered Error state, waiting 10s for logs...")
            if not self.sh.dry_run:
                time.sleep(10)
            self.sh.run([
                "bash", "-c",
                f"CNAME=$({self.runtime_shell_command('ps', '-a')} "
                f"--filter 'name=openshell.*{sandbox.name}' "
                "--format '{{.Names}}' | head -1) && "
                "echo \"Container: $CNAME\" && "
                f"echo \"Status: $({self.runtime_shell_command('inspect')} $CNAME "
                "--format '{{.State.Status}} ExitCode={{.State.ExitCode}}')"
                "\" && echo '--- logs ---' && "
                f"{self.runtime_shell_command('logs')} $CNAME 2>&1 | tail -30"
            ], check=False)

    def chown_sandbox_home(self, sandbox_name):
        """Chown /sandbox to the supervisor's sandbox uid.

        The image bakes UID 65532. The supervisor rewrites passwd to
        whatever uid is free (1000, 998, …) and does not chown existing
        files. openshell sandbox exec cannot chown (not root); the configured
        runtime's exec -u 0 can. After passwd rewrite, name 'sandbox' is the
        runtime uid, so this works on any cluster.
        """
        log(f"Chowning /sandbox to sandbox user in '{sandbox_name}'")
        self.sh.run([
            "bash", "-c",
            f"CNAME=$({self.runtime_shell_command('ps', '-a')} "
            f"--filter 'name=openshell.*{sandbox_name}' "
            "--format '{{.Names}}' | head -1) && "
            "[ -n \"$CNAME\" ] && "
            f"{self.runtime_shell_command('exec', '-u', '0')} \"$CNAME\" "
            "chown -R sandbox:sandbox /sandbox",
        ], check=False)

    def install_nemoclaw_cli(self, cli_image):
        if not cli_image:
            return
        rc, _, _ = self.sh.run(["which", "nemoclaw"], check=False)
        if rc == 0:
            log("nemoclaw CLI already installed, skipping")
            return
        section("Installing nemoclaw CLI")
        runtime = self.runtime_shell_command
        self.sh.run([
            "bash", "-c",
            f"{runtime('pull')} '{cli_image}' && "
            f"CID=$({runtime('create')} '{cli_image}') && "
            f"{runtime('cp')} $CID:/opt/nemoclaw /tmp/nemoclaw-cli && "
            f"{runtime('rm')} $CID >/dev/null && "
            f"sudo mv /tmp/nemoclaw-cli /opt/nemoclaw && "
            f"printf '#!/usr/bin/env bash\\nexec node "
            f"/opt/nemoclaw/bin/nemoclaw.js \"$@\"\\n' "
            f"| sudo tee /usr/local/bin/nemoclaw >/dev/null && "
            f"sudo chmod 755 /usr/local/bin/nemoclaw"
        ], check=False)

    def onboard_nemoclaw(self, sandbox, provider, credential):
        state_dir = str(Path.home() / ".local" / "state" / "openshell")
        mgmt_path = str(Path.home() / "gateway-management.json")
        mgmt = {
            "version": 1, "mode": "externally-supervised",
            "endpoint": "https://127.0.0.1:17670",
            "stateDir": state_dir,
            "supervisor": {
                "kind": "systemd-user",
                "serviceName": "openshell-gateway.service",
                "execPath": "/usr/local/bin/openshell-gateway",
            },
        }
        if not self.sh.dry_run:
            os.makedirs(os.path.dirname(mgmt_path), exist_ok=True)
            with open(mgmt_path, "w", encoding="utf-8") as f:
                json.dump(mgmt, f)

        nc_prov = provider.nemoclaw_provider or provider.type
        env = {
            "NEMOCLAW_GATEWAY_MANAGEMENT": mgmt_path,
            "NEMOCLAW_GATEWAY_PORT": "17670",
            "NEMOCLAW_IGNORE_RUNTIME_RESOURCES": "1",
            "NEMOCLAW_OPENSHELL_GATEWAY_BIN":
                "/usr/local/bin/openshell-gateway",
            "NEMOCLAW_OPENSHELL_SANDBOX_BIN":
                "/usr/local/bin/openshell-supervisor",
            "NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE": "1",
            "NEMOCLAW_PROVIDER": nc_prov,
        }
        if sandbox.model or provider.model:
            env["NEMOCLAW_MODEL"] = sandbox.model or provider.model
        if credential:
            env["NEMOCLAW_PROVIDER_KEY"] = credential
            cred_key = PROVIDER_CRED_MAP.get(nc_prov, "")
            if cred_key:
                env[cred_key] = credential
        cmd = [
            "nemoclaw", "onboard",
            "--fresh", "--non-interactive",
            "--name", sandbox.name,
            "--agent", sandbox.agent or "openclaw",
            "--yes", "--yes-i-accept-third-party-software",
        ]
        rc, _, _ = self.sh.run(cmd, env=env, check=False)
        return rc == 0

    def start_openclaw_gateway(self, sandbox_name, dashboard_route,
                               workspace_name="default",
                               provider_id="nvidia",
                               model_id="nvidia/nemotron-3-super-120b-a12b"):
        import secrets as secrets_mod

        ws_args = ["--workspace", workspace_name] if workspace_name else []

        # Wait for sandbox to reach Ready
        if not self.sh.dry_run:
            for i in range(20):
                rc, out, _ = self.sh.run([
                    "openshell", "sandbox", "get", sandbox_name
                ] + ws_args, check=False)
                clean = re.sub(r'\x1b\[[0-9;]*m', '', out or "")
                if "Ready" in clean and "Error" not in clean:
                    log(f"Sandbox '{sandbox_name}' is Ready")
                    break
                log(f"  waiting for sandbox ready... (attempt {i+1})")
                time.sleep(5)

        # Supervisor has rewritten passwd by Ready; match /sandbox to that uid.
        self.chown_sandbox_home(sandbox_name)

        token = secrets_mod.token_hex(16)
        exec_cmd = ["openshell", "sandbox", "exec", "-n",
                     sandbox_name] + ws_args + ["--no-tty", "--"]

        # Configure openclaw: model, agent, gateway token
        oc_env = ("OPENCLAW_HOME=/sandbox "
                  "SQLITE_TMPDIR=/sandbox/.openclaw/state "
                  "TMPDIR=/sandbox/.openclaw/state "
                  "OPENCLAW_NIX_MODE=0")

        log("Running openclaw onboard...")
        self.sh.run(
            exec_cmd + ["sh", "-c",
                        f"{oc_env} CUSTOM_API_KEY=proxy-managed "
                        f"openclaw onboard "
                        f"--non-interactive --accept-risk "
                        f"--mode local "
                        f"--auth-choice custom-api-key "
                        f'--custom-base-url "https://inference.local/v1" '
                        f"--custom-provider-id {provider_id} "
                        f'--custom-model-id "{model_id}" '
                        f"--custom-compatibility openai "
                        f"--skip-channels --skip-health"],
            check=False)
        # Set gateway token
        self.sh.run(
            exec_cmd + ["sh", "-c",
                        f"{oc_env} openclaw config set "
                        f"gateway.auth.token '{token}'"],
            check=False)
        if dashboard_route:
            self.sh.run(
                exec_cmd + ["sh", "-c",
                            f"{oc_env} openclaw config set "
                            "gateway.controlUi.allowedOrigins "
                            f"'[\"https://{dashboard_route}\"]'"],
                check=False)

        log(f"Starting openclaw gateway (token={token[:8]}...)")
        self.sh.run(
            exec_cmd + ["sh", "-c",
                        f"export OPENCLAW_GATEWAY_TOKEN={token} "
                        f"OPENCLAW_HOME=/sandbox "
                        f"SQLITE_TMPDIR=/sandbox/.openclaw/state "
                        f"TMPDIR=/sandbox/.openclaw/state "
                        f"OPENCLAW_NIX_MODE=0 && "
                        f"nohup openclaw gateway run "
                        f"--allow-unconfigured "
                        f"--bind lan --port 18789 "
                        f"> /tmp/openclaw-gateway.log "
                        f"2>&1 &"],
            check=False)

        if not self.sh.dry_run:
            for i in range(10):
                rc, out, _ = self.sh.run(
                    exec_cmd + [
                    "curl", "-sf", "http://127.0.0.1:18789/health"
                ], check=False)
                if rc == 0 and "ok" in out:
                    log("openclaw gateway ready")
                    # Install a systemd user service on the VM that keeps
                    # this sandbox in Ready phase after the setup job exits.
                    # Runs while the sandbox is still active so the first
                    # exec connects immediately; Restart=always revives it
                    # if the session ever drops.
                    service = f"openshell-sandbox-{sandbox_name}"
                    ws_flag = (f"--workspace {workspace_name}"
                               if workspace_name != "default" else "")
                    user = "cloud-user"
                    svc = (
                        f"[Unit]\n"
                        f"Description=OpenShell sandbox keep-alive "
                        f"for {sandbox_name}\n\n"
                        f"[Service]\nType=simple\nUser={user}\n"
                        f"ExecStart=/bin/bash -c 'PATH=$PATH:/home/{user}/.local/bin"
                        f" openshell sandbox exec -n {sandbox_name}"
                        f" {ws_flag} --no-tty -- sleep infinity'\n"
                        f"Restart=always\nRestartSec=5\n\n"
                        f"[Install]\nWantedBy=multi-user.target\n"
                    )
                    encoded = base64.b64encode(svc.encode()).decode()
                    self.sh.run([
                        "bash", "-c",
                        f"echo '{encoded}' | base64 -d"
                        f" | sudo tee /etc/systemd/system/{service}.service && "
                        f"sudo systemctl daemon-reload && "
                        f"sudo systemctl enable {service} && "
                        f"sudo systemctl start {service}"
                    ], check=False)
                    return
                log(f"  waiting for openclaw gateway... (attempt {i+1})")
                time.sleep(3)
            log("WARN: openclaw gateway health check failed")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

class Verifier:
    def __init__(self, shell):
        self.sh = shell
        self.passed = 0
        self.failed = 0

    def check(self, desc, cmd):
        rc, out, _ = self.sh.run(cmd, check=False)
        if rc == 0:
            log(f"PASS  {desc}")
            self.passed += 1
        else:
            log(f"FAIL  {desc}")
            self.failed += 1
        return rc == 0, out

    def _ws_args(self, ws_name):
        if ws_name != "default":
            return ["--workspace", ws_name]
        return []

    def verify_profiles(self, profiles):
        banner("VERIFICATION")
        for profile in profiles:
            log(f"\nProfile: {profile.name}")
            for ws in profile.workspaces:
                if not ws.enabled:
                    continue
                ws_flag = self._ws_args(ws.name)
                log(f"\n  Workspace: {ws.name}")

                if ws.name != "default":
                    ok, out = self.check(
                        f"workspace '{ws.name}'",
                        ["openshell", "workspace", "list"])
                    if ok and ws.name not in (out or ""):
                        log(f"FAIL  workspace '{ws.name}' not in output")
                        self.passed -= 1
                        self.failed += 1

                for prov in ws.providers:
                    if not prov.enabled:
                        continue
                    self.check(
                        f"provider '{prov.name}' in '{ws.name}'",
                        ["openshell", "provider", "get",
                         prov.name] + ws_flag)

                for sb in ws.sandboxes:
                    if not sb.enabled:
                        continue
                    self.check(
                        f"sandbox '{sb.name}' in '{ws.name}'",
                        ["openshell", "sandbox", "get",
                         sb.name] + ws_flag)
                    if sb.providers:
                        _, out = self.check(
                            f"sandbox '{sb.name}' provider list",
                            ["openshell", "sandbox", "provider",
                             "list", sb.name] + ws_flag)
                        for prov_name in sb.providers:
                            if prov_name in (out or ""):
                                log(f"  PASS  '{sb.name}' "
                                    f"has provider '{prov_name}'")
                                self.passed += 1
                            else:
                                log(f"  FAIL  '{sb.name}' "
                                    f"missing provider '{prov_name}'")
                                self.failed += 1

        banner(f"Results: {self.passed} passed, {self.failed} failed")
        if self.failed > 0:
            log("STATUS: INCOMPLETE")
        else:
            log("STATUS: ALL PASSED")
        return self.failed == 0


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="BOM-driven agent configuration for SAW")
    parser.add_argument("--profiles-dir")
    parser.add_argument("--installer-bom", help="Versioned software release; runtime must already match it")
    parser.add_argument("--validate-installer-bom", action="store_true", help="Validate release data only; no deployment")
    parser.add_argument("--guest-phase", choices=("validate", "apply", "verify"), help=argparse.SUPPRESS)
    parser.add_argument("--guest-gateway-check", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--guest-gateway-run", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--oidc-gateway", default="")
    parser.add_argument("--mtls-gateway", default="openshell-local")
    parser.add_argument("--nemoclaw-cli-image", default="")
    parser.add_argument("--dashboard-route", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.guest_phase or args.guest_gateway_check or args.guest_gateway_run:
        if args.profiles_dir or args.installer_bom or args.validate_installer_bom or args.dry_run:
            parser.error("guest input is provided only on private stdin")
        if sum(bool(value) for value in (args.guest_phase, args.guest_gateway_check, args.guest_gateway_run)) > 1:
            parser.error("select only one guest operation")
        # The -I subprocess ignores ambient import paths; only image-owned code
        # is added. No ConfigMap or request field can choose this directory.
        sys.path.insert(0, "/opt/saw/guest")
        if args.guest_gateway_run:
            try:
                guest_gateway_run()
            except Exception:
                raise SystemExit(1) from None
        raise SystemExit(guest_gateway_check() if args.guest_gateway_check else guest_main(args.guest_phase))
    if args.validate_installer_bom and not args.installer_bom:
        parser.error("--validate-installer-bom requires --installer-bom")
    if args.installer_bom:
        bom = load_installer_bom(args.installer_bom)
        if args.validate_installer_bom:
            print("Installer BOM valid; no installation or runtime verification performed")
            return
        if not args.dry_run:
            verify_installed_software(bom)
    if not args.profiles_dir:
        parser.error("--profiles-dir is required for legacy profile deployment")

    # --- Parse profiles ---
    profiles = parse_profiles(args.profiles_dir)
    if any(ws.enabled and sb.enabled
           for profile in profiles for ws in profile.workspaces for sb in ws.sandboxes):
        parser.error("enabled sandbox profiles are not implemented (SandboxApplyNotImplemented)")
    if not profiles:
        log("No profiles found, nothing to do")
        return

    total_ws = sum(len(p.workspaces) for p in profiles)
    banner(f"BOM Apply: {len(profiles)} profile(s), "
           f"{total_ws} workspace(s)")

    sh = Shell(dry_run=args.dry_run)

    # --- Phase 1: Gateway setup ---
    banner("Phase 1: Gateway Setup")
    # Bootstrap and BOM application use only the local mTLS identity. OIDC
    # is configured on the gateway for laptop clients; no user login or
    # password/token is required from the setup path.
    gw = GatewaySetup(sh, "", args.mtls_gateway)
    gw.register_mtls_gateway()
    gw.grant_default_workspace_access()
    gw.enable_providers_v2()

    # --- Phase 2: Deploy profiles ---
    deployer = WorkspaceDeployer(sh, gw)
    for profile in profiles:
        banner(f"Phase 2: Profile '{profile.name}' "
               f"({len(profile.workspaces)} workspace(s))")

        for ws in profile.workspaces:
            log(f"\n  Workspace: {ws.name}")
            log(f"  {'─' * 50}")

            if not ws.enabled:
                log("  (disabled, skipping)")
                continue

            deployer.create_workspace(ws)

            # Create providers in the workspace
            enabled_provs = [p for p in ws.providers if p.enabled]
            if enabled_provs:
                section(f"Providers ({len(enabled_provs)}) "
                        f"in workspace '{ws.name}'")
                inference_set = False
                for prov in enabled_provs:
                    cred = resolve_credential(prov)
                    deployer.create_provider(prov, cred, ws.name)
                    if not inference_set and prov.model:
                        log(f"  Setting inference routes: "
                            f"provider={prov.name} model={prov.model}"
                            f" workspace={ws.name}")
                        sh.run(["openshell", "inference", "set",
                                "--provider", prov.name,
                                "--model", prov.model,
                                "--workspace", ws.name,
                                "--no-verify"], check=False)
                        sh.run(["openshell", "inference", "set",
                                "--system",
                                "--provider", prov.name,
                                "--model", prov.model,
                                "--no-verify"], check=False)
                        inference_set = True

            # Create sandboxes
            nemoclaw_cli_installed = False
            for sb in ws.sandboxes:
                if not sb.enabled:
                    log(f"  Sandbox '{sb.name}' disabled, skipping")
                    continue
                section(f"Sandbox '{sb.name}' (type={sb.type})")

                if sb.type == "nemoclaw":
                    # Nemoclaw flow (matches feat/fix-docker-golden-image):
                    # 1. Install nemoclaw CLI
                    # 2. nemoclaw onboard (configures provider)
                    # 3. Fallback: openshell provider create
                    # 4. openshell sandbox create
                    # 5. Start openclaw gateway inside sandbox
                    if not nemoclaw_cli_installed:
                        cli_img = args.nemoclaw_cli_image or \
                            os.environ.get("NEMOCLAW_CLI_IMAGE", "")
                        if cli_img:
                            deployer.install_nemoclaw_cli(cli_img)
                            nemoclaw_cli_installed = True

                    is_full_ref = sb.image and ("/" in sb.image
                                                or ":" in sb.image)
                    if is_full_ref:
                        deployer.sh.run(
                            deployer.runtime_command("pull", sb.image),
                            check=False)

                    prov = find_provider(ws, sb.providers)
                    cred = resolve_credential(prov) if prov else None
                    mismatch = check_provider_type_mismatch(prov) if prov else None
                    if mismatch:
                        log(f"ERROR: {mismatch} — skipping nemoclaw "
                            f"onboard for '{sb.name}'.")
                    elif prov and cred:
                        nc_prov = prov.nemoclaw_provider or prov.type
                        log(f"nemoclaw onboard --agent {sb.agent or 'openclaw'}"
                            f" (provider={nc_prov})")
                        ok = deployer.onboard_nemoclaw(sb, prov, cred)
                        if not ok:
                            log("nemoclaw onboard failed, "
                                "configuring provider manually")
                            deployer.create_provider(prov, cred, ws.name)

                    deployer.create_sandbox_generic(sb, ws.name)
                    prov_id = prov.type if prov else "nvidia"
                    model = sb.model or (prov.model if prov else "")
                    deployer.start_openclaw_gateway(
                        sb.name, args.dashboard_route or "",
                        workspace_name=ws.name,
                        provider_id=prov_id,
                        model_id=model or "nvidia/nemotron-3-super-120b-a12b")

                elif sb.type == "openclaw":
                    deployer.create_sandbox_generic(sb, ws.name)
                    prov = find_provider(ws, sb.providers)
                    prov_id = prov.type if prov else "nvidia"
                    model = sb.model or (prov.model if prov else "")
                    deployer.start_openclaw_gateway(
                        sb.name, args.dashboard_route or "",
                        workspace_name=ws.name,
                        provider_id=prov_id,
                        model_id=model or "nvidia/nemotron-3-super-120b-a12b")

                else:
                    # Generic: just create the sandbox
                    deployer.create_sandbox_generic(sb, ws.name)

    # --- Phase 4: Verify ---
    if not args.dry_run:
        verifier = Verifier(sh)
        ok = verifier.verify_profiles(profiles)
        if not ok:
            # Without this, the setup Job reports "Complete" even when the
            # BOM apply only partially succeeded — verified live: a run with
            # 9 passed / 1 failed still showed Job status Complete, with the
            # only signal being "STATUS: INCOMPLETE" buried in the full log.
            raise SystemExit(1)


if __name__ == "__main__":
    main()
