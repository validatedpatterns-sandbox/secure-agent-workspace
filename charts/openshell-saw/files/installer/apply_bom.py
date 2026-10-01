#!/usr/bin/env python3
"""
apply_bom.py - in-guest SAW installer (Stage 1).

Runs INSIDE the gateway VM. saw-install.service runs `install` and then
saw-apply.service runs `apply`, on every boot.
There is no SSH and no setup Job: the chart attaches everything this script
needs as read-only disks, or over virtiofs when vm.liveInputs is set.
saw-mount-inputs mounts either kind under /run/saw:

    /run/saw/installer/installer-bom.yaml   versioned Bill of Materials
    /run/saw/installer/config.json          per-VM settings rendered by Helm
    /run/saw/installer/apply_bom.py         this script
    /run/saw/installer/gateway.env|.toml    gateway config, synced on every boot
    /run/saw/installer/setup-dashboard.sh   optional dashboard setup
    /run/saw/profiles/<flat key>.yaml       SAW-BOM profiles (saw-bom chart)
    /run/saw/secrets/<secret>/<key>         provider credential Secrets

Commands:
    validate        check BOM, config, profiles and credentials; changes nothing
    install         step 1 (root): install the BOM components, start the gateway
    apply           step 2 (root): apply SAW-BOM profiles as the runtime user
    reconcile       re-run install and/or apply when virtiofs inputs changed
    apply-profiles  (runtime user) internal; reads its plan from stdin

The installer talks to the gateway only through a local mTLS gateway entry.
End users log in with their own OIDC token; this script never performs an
OIDC login and never configures the CLI for OAuth.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import yaml

API_VERSION = "saw.redhat.com/v1alpha1"
INSTALLER_VERSION = "0.1.0"

DEFAULT_INPUTS = Path("/run/saw")
DEFAULT_STATE_DIR = Path("/var/lib/saw")
GATEWAY_PORT = 17670

# Where each component's binary lives inside its image, and where it goes on
# the VM. A BOM entry may override the in-image path with `path:`.
COMPONENTS = {
    "gateway": {"image_path": "/usr/local/bin/openshell-gateway",
                "dest": "openshell-gateway"},
    # 0.1.x: the supervisor image carries /openshell-supervisor; the static
    # /openshell-sandbox moved to the sandbox runtime image.
    "supervisor": {"image_path": "/openshell-supervisor",
                   "dest": "openshell-supervisor"},
    "cli": {"image_path": "/usr/local/bin/openshell",
            "dest": "openshell"},
}
# Image-only components: pinned in the BOM and checked here (pull and
# signature, as root), but no binary is extracted; the gateway pulls the image
# itself as the runtime user. `sandbox` is the OpenShell 0.1.x sandbox runtime
# image: the podman driver mounts the supervisor from it into every sandbox
# (gateway.toml sandbox_runtime_image). Required: the chart's gateway.toml is
# schema v2 (0.1.x) only.
IMAGE_COMPONENTS = {"sandbox"}
NEMOCLAW_IMAGE_PATH = "/opt/nemoclaw"

DIGEST_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$")
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9./:_@-]*$")
VERSION_RE = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+_-]*$")
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
SECRET_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
SECRET_KEY_RE = re.compile(r"^[-._a-zA-Z0-9]+$")
OPENSHELL_NAME_LIMIT = 19
# The installer's own mTLS identity; the gateway reads roles from the OU.
ADMIN_CERT_SUBJECT = "/O=openshell/OU=openshell-admin/CN=saw-installer"
ALREADY_RE = re.compile(r"already (exists|a member)", re.IGNORECASE)
# The gateway has no profile for this provider type. Profiles such as brave
# come from the governance interceptor, so they are missing when it is off.
# 0.0.x: "provider profile 'x' not found"; 0.1.x: "... 'x' was not found in
# the requested scope".
NO_PROFILE_RE = re.compile(r"provider profile '[^']*' (was )?not\s+found|unsupported provider type",
                           re.IGNORECASE)

PROVIDER_CRED_MAP = {
    "gemini": "GEMINI_API_KEY",
    "google-vertex-ai": "GOOGLE_API_KEY",
    "claude-code": "ANTHROPIC_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "codex": "OPENAI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "nvidia": "NVIDIA_API_KEY",
    "build": "NVIDIA_INFERENCE_API_KEY",
    "brave": "BRAVE_API_KEY",
    "tavily": "TAVILY_API_KEY",
}
SANDBOX_TYPES = {"generic", "openclaw", "nemoclaw"}
# Provider config key that records a provider's base URL. OpenShell 0.1.x has
# no inference router: the agent calls the endpoint itself (see
# NATIVE_BASE_URLS), and the provider profile must name that endpoint's host.
BASE_URL_CONFIG_KEYS = {
    "openai": "OPENAI_BASE_URL",
    "anthropic": "ANTHROPIC_BASE_URL",
    "nvidia": "NVIDIA_BASE_URL",
}
# OpenShell 0.1.x removed managed inference (`openshell inference`,
# https://inference.local). An agent is configured with its provider's native
# OpenAI-compatible endpoint and the placeholder key the sandbox receives in
# the provider's env var; the sandbox proxy swaps in the real key only for
# requests to the profile's endpoints from the profile's binaries. A
# provider's baseUrl overrides these.
NATIVE_BASE_URLS = {
    "nvidia": "https://integrate.api.nvidia.com/v1",
    "build": "https://integrate.api.nvidia.com/v1",
    "openai": "https://api.openai.com/v1",
}


class InstallerError(Exception):
    """A failure with a message that is safe to log and show in status."""


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(msg):
    print(f"[saw-installer] {msg}", flush=True)


def banner(title):
    log("=" * 60)
    log(title)
    log("=" * 60)


# ---------------------------------------------------------------------------
# Shell runner
# ---------------------------------------------------------------------------

@dataclass
class Result:
    rc: int
    out: str = ""
    err: str = ""
    existed: bool = False

    @property
    def ok(self):
        return self.rc == 0


class Shell:
    """Runs commands, hides known secret values in logs, honours dry-run.

    check=True raises InstallerError on a non-zero exit. ok_if_exists=True
    treats "already exists" / "already a member" output as success (with
    Result.existed set), which makes create calls safe to repeat on every boot.
    """

    def __init__(self, dry_run=False, env=None):
        self.dry_run = dry_run
        self.env = dict(env or os.environ)
        self._secrets = set()

    def add_secret(self, value):
        if value and len(value) >= 4:
            self._secrets.add(value)

    def mask(self, text):
        for value in sorted(self._secrets, key=len, reverse=True):
            text = text.replace(value, "***")
        return text

    def run(self, cmd, env=None, check=True, ok_if_exists=False,
            timeout=300, input_text=None, quiet=False):
        display = self.mask(" ".join(str(c) for c in cmd))
        if self.dry_run:
            log(f"[dry-run] {display}")
            return Result(0)
        if not quiet:
            log(f"$ {display}")
        try:
            stdin = {"input": input_text} if input_text is not None else {"stdin": subprocess.DEVNULL}
            proc = subprocess.run(
                [str(c) for c in cmd], capture_output=True, text=True,
                env={**self.env, **(env or {})}, timeout=timeout,
                check=False, **stdin)
        except FileNotFoundError:
            result = Result(127, "", f"{cmd[0]}: command not found")
        except subprocess.TimeoutExpired:
            result = Result(124, "", f"timed out after {timeout}s")
        else:
            result = Result(proc.returncode, proc.stdout.strip(), proc.stderr.strip())
        if not quiet:
            for line in self.mask(result.out).splitlines()[-40:]:
                log(f"  {line}")
        if result.rc != 0 and ok_if_exists and \
                ALREADY_RE.search(result.out + " " + result.err):
            log("  (already exists)")
            return Result(0, result.out, result.err, existed=True)
        if result.rc != 0:
            if result.err:
                log(f"  error: {self.mask(result.err)[-600:]}")
            if check:
                raise InstallerError(f"command failed (exit {result.rc}): {display}")
        return result


# ---------------------------------------------------------------------------
# Bill of Materials
# ---------------------------------------------------------------------------

def _require_keys(obj, required, allowed, where):
    if not isinstance(obj, dict):
        raise InstallerError(f"{where}: expected a mapping")
    missing = sorted(set(required) - set(obj))
    unknown = sorted(set(obj) - set(allowed))
    if missing:
        raise InstallerError(f"{where}: missing {', '.join(missing)}")
    if unknown:
        raise InstallerError(f"{where}: unknown field(s) {', '.join(unknown)}")


def validate_bom(doc):
    """Validate an InstallerBOM document and return it.

    Every OpenShell component must be pinned by image digest. Tags are
    refused because a tag can move and the BOM would stop describing what
    is actually installed.
    """
    _require_keys(doc, {"apiVersion", "kind", "metadata", "spec"},
                  {"apiVersion", "kind", "metadata", "spec"}, "InstallerBOM")
    if doc["apiVersion"] != API_VERSION or doc["kind"] != "InstallerBOM":
        raise InstallerError(f"InstallerBOM: expected apiVersion {API_VERSION} and kind InstallerBOM")
    _require_keys(doc["metadata"], {"name"}, {"name"}, "InstallerBOM metadata")
    name = doc["metadata"]["name"]
    if not isinstance(name, str) or not NAME_RE.match(name) or len(name) > 63:
        raise InstallerError("InstallerBOM metadata.name must be a DNS label")
    spec = doc["spec"]
    _require_keys(spec, {"installerVersion", "openshell"},
                  {"installerVersion", "openshell", "nemoclaw"}, "InstallerBOM spec")
    if spec["installerVersion"] != INSTALLER_VERSION:
        raise InstallerError(
            f"InstallerBOM targets installer {spec['installerVersion']}, "
            f"this installer is {INSTALLER_VERSION}")
    _require_keys(spec["openshell"], set(COMPONENTS) | IMAGE_COMPONENTS,
                  set(COMPONENTS) | IMAGE_COMPONENTS, "spec.openshell")
    for comp, entry in spec["openshell"].items():
        where = f"spec.openshell.{comp}"
        _require_keys(entry, {"version", "image"}, {"version", "image", "path", "signature"}, where)
        if not isinstance(entry["version"], str) or not VERSION_RE.match(entry["version"]):
            raise InstallerError(f"{where}.version is not a version string")
        _check_digest_image(entry["image"], f"{where}.image")
        if "path" in entry and (not isinstance(entry["path"], str) or not entry["path"].startswith("/")):
            raise InstallerError(f"{where}.path must be an absolute path")
        if "signature" in entry:
            _validate_signature(entry["signature"], f"{where}.signature")
    # Every OpenShell component must come from the same release (0.1.x does not
    # support mixed peers); a Helm override of some versions only is refused.
    versions = {normalize_version(e["version"]) for e in spec["openshell"].values()}
    if len(versions) > 1:
        raise InstallerError("spec.openshell components must all have the same version, got "
                             + ", ".join(sorted(versions)))
    if "nemoclaw" in spec:
        _require_keys(spec["nemoclaw"], {"cliImage"}, {"cliImage"}, "spec.nemoclaw")
        image = spec["nemoclaw"]["cliImage"]
        # Optional add-on: a tag is accepted (no digest is published for it
        # yet), but only the OpenShell components are guaranteed pinned.
        if not isinstance(image, str) or not IMAGE_RE.match(image):
            raise InstallerError("spec.nemoclaw.cliImage is not a valid image reference")
        if not DIGEST_IMAGE_RE.match(image):
            log(f"WARN: spec.nemoclaw.cliImage {image} is not pinned by digest")
    return doc


KEY_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")


def _validate_signature(sig, where):
    """A component signature is a key name or a keyless identity, not both."""
    _require_keys(sig, set(), {"keyRef", "identity", "issuer"}, where)
    key_ref = sig.get("keyRef", "")
    identity = sig.get("identity", "")
    issuer = sig.get("issuer", "")
    if key_ref and (identity or issuer):
        raise InstallerError(f"{where}: set keyRef or identity and issuer, not both")
    if key_ref:
        if not isinstance(key_ref, str) or not KEY_REF_RE.match(key_ref):
            raise InstallerError(f"{where}.keyRef must name a file under /etc/saw/trust")
        return
    if identity or issuer:
        if not (isinstance(identity, str) and isinstance(issuer, str)
                and identity.startswith("https://") and issuer.startswith("https://")):
            raise InstallerError(f"{where}: identity and issuer must both be https URLs")
        return
    raise InstallerError(f"{where}: set keyRef or both identity and issuer")


def _check_digest_image(image, where):
    if not isinstance(image, str) or not DIGEST_IMAGE_RE.match(image):
        raise InstallerError(f"{where} must be pinned by digest (repo@sha256:<64 hex>)")


def load_bom(path):
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise InstallerError(f"cannot read InstallerBOM {path}: {exc}") from None
    return validate_bom(doc)


def normalize_version(value):
    """0.0.116+rhaiv.0, v0.0.116-rhaiv.0 and 0.0.116-rhaiv.0 are the same."""
    return value.strip().removeprefix("v").replace("+", "-")


def reported_version(output):
    """Pull the version out of `<binary> --version` output."""
    match = re.search(r"v?[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+_-]*", output or "")
    return match.group(0) if match else None


# ---------------------------------------------------------------------------
# Per-VM config (config.json rendered by the chart)
# ---------------------------------------------------------------------------

CONFIG_DEFAULTS = {
    "runtimeUser": "cloud-user",
    "mtlsGateway": "saw-installer",
    "ownerSubject": "",
    "sandboxDashboardRoute": "",
    "dashboard": {"enabled": False},
    "signing": {"mode": "off"},
    "prune": {"mode": "off", "sandboxes": False},
}

SIGNING_MODE_ORDER = {"off": 0, "warn": 1, "enforce": 2}
# The golden image can pin a minimum signing.mode (e.g. a production image
# forces enforce). config.json ships in the same, unsigned ConfigMap as
# apply_bom.py, so a namespace editor could otherwise set signing.mode: off
# next to a modified apply_bom.py and defeat enforce entirely (PR #54
# review, 1). Absent = no floor, i.e. today's default behavior.
SIGNING_FLOOR_FILE = Path(os.environ.get("SAW_SIGNING_FLOOR_FILE", "/etc/saw/signing-mode"))


def signing_mode_floor():
    try:
        value = SIGNING_FLOOR_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return "off"
    return value if value in SIGNING_MODE_ORDER else "off"


def effective_signing_mode(configured_mode):
    """The stricter of the golden-image floor and config.json's mode."""
    floor = signing_mode_floor()
    if SIGNING_MODE_ORDER.get(floor, 0) > SIGNING_MODE_ORDER.get(configured_mode, 0):
        return floor
    return configured_mode


def load_config(path):
    try:
        cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InstallerError(f"cannot read installer config {path}: {exc}") from None
    if not isinstance(cfg, dict):
        raise InstallerError("installer config must be a JSON object")
    merged = {**CONFIG_DEFAULTS, **cfg}
    if not merged.get("vmName"):
        raise InstallerError("installer config: vmName is required")
    if not NAME_RE.match(merged["runtimeUser"].replace("_", "-")):
        raise InstallerError("installer config: invalid runtimeUser")
    if not NAME_RE.match(merged["mtlsGateway"]):
        raise InstallerError("installer config: invalid mtlsGateway name")
    signing = merged.get("signing") or {}
    if not isinstance(signing, dict):
        raise InstallerError("installer config: signing must be an object")
    mode = signing.get("mode", "off")
    if mode not in ("off", "warn", "enforce"):
        raise InstallerError("installer config: signing.mode must be off, warn, or enforce")
    merged["signing"] = {**CONFIG_DEFAULTS["signing"], **signing, "mode": effective_signing_mode(mode)}
    prune = merged.get("prune") or {}
    if not isinstance(prune, dict):
        raise InstallerError("installer config: prune must be an object")
    prune_mode = prune.get("mode", "off")
    if prune_mode not in ("off", "report", "on"):
        raise InstallerError("installer config: prune.mode must be off, report, or on")
    merged["prune"] = {**CONFIG_DEFAULTS["prune"], **prune, "mode": prune_mode,
                       "sandboxes": bool(prune.get("sandboxes", False))}
    dash = merged.get("dashboard") or {}
    if dash.get("enabled"):
        for key in ("image", "proxyImage", "clientId"):
            if not dash.get(key):
                raise InstallerError(f"installer config: dashboard.{key} is required when the dashboard is enabled")
    return merged


# ---------------------------------------------------------------------------
# Profiles
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
    # Secret keys the base URL and the model are read from (optional).
    base_url_secret_key: str = ""
    model_secret_key: str = ""
    inference_timeout: int = 0
    base_url: str = ""


@dataclass
class Sandbox:
    name: str
    type: str = "generic"
    enabled: bool = True
    agent: str = "openclaw"
    image: str = ""
    providers: list = field(default_factory=list)
    model: str = ""
    harness_ref: dict = field(default_factory=dict)


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


@dataclass
class HarnessBundle:
    name: str
    agent: str = "openclaw"
    digest: str = ""
    files: dict = field(default_factory=dict)   # relpath -> base64 text


def tree_digest(files):
    """Shared contract: sha256 over sorted "<relpath>\\0<sha256_hex>\\n" lines.

    `files` maps a POSIX relative path to file bytes. Helm computes the same
    value at render time; templates/configmap-bom.yaml must agree.
    """
    digest = hashlib.sha256()
    for rel in sorted(files):
        digest.update(f"{rel}\x00{hashlib.sha256(files[rel]).hexdigest()}\n".encode())
    return "sha256:" + digest.hexdigest()


# -- Harness bundles ---------------------------------------------------------
#
# A harness bundle is the tree OpenClaw loads (plugin.json, skills/, mcp.json,
# plugins/). It reaches the sandbox only by being mounted read-only at
# HARNESS_MOUNT; the files are mounted exactly as written, never converted.
#
#   harnessRef.image  an OCI image pinned by digest (harness-bundles/, built
#                     and pushed by CI). The installer pulls it by digest and
#                     unpacks its tree, unchanged, into the sandbox's volume.
#   harnessRef.name   an inline bundle packed into the saw-bom ConfigMap,
#                     copied unchanged into the sandbox's volume.
#
# Both sources end up in one podman named volume per sandbox, mounted with
# --driver-config-json. OpenShell 0.1.x does not allow an image mount while
# resource admission is on (the default: "host bind or image mount cannot be
# attached while resource admission is enabled"), and it only admits a volume
# that carries the openshell.ai/sandbox-attachable labels for the sandbox's
# workspace (openshell-core resource_admission.rs, driver-podman driver.rs).
# The gateway also needs allow_driver_config = true in [openshell.drivers.podman]
# (the openshell-saw chart sets it). A changed bundle refills the volume in
# place: the volume is never recreated under a running sandbox, because the
# podman driver records each attached volume's identity and stops a sandbox
# whose volume changed.
#
# Flow, per sandbox with a harnessRef (ProfileApplier, as the runtime user):
#   1. prepare_harness        read the bundle (the volume when it already holds
#                             this source intact; else image: pull + export,
#                             inline: the ConfigMap files)
#   2. check_harness_governance
#                             every governanceProfile must be served by the
#                             gateway in the sandbox's workspace, the sandbox
#                             must have a provider of that type (its endpoints
#                             and key reach the sandbox only through one), and
#                             a remote MCP server's host must be one of the
#                             profile's endpoints; nothing is filled before
#                             this passes
#   3. HarnessVolume          create the labelled volume, fill it if needed
#   4. create_sandbox         --driver-config-json mounts the volume; a running
#                             sandbox that mounts anything else at
#                             HARNESS_MOUNT (or mounts a harness it no longer
#                             has) is recreated
#   5. configure_harness      point OpenClaw at HARNESS_MOUNT
#   6. verify_harness         the volume holds the source intact, the container
#                             mounts it, and the sandbox reads it
#   7. cleanup_harness_volumes
#                             remove harness volumes no sandbox wants
#
# Checked live on OpenShell 0.0.116 (podman 5.8) and OpenClaw 2026.9.5: volume
# mounts through --driver-config-json, read-only in the sandbox; skills,
# native plugins and an Agent Plugins bundle's MCP servers loaded from the
# mount; how podman reports the mount (see sandbox_harness_mount). The 0.1.x
# admission rules above are from the v0.1.2 source.

HARNESS_MOUNT = "/sandbox/harness"
HARNESS_MARKER = ".saw-harness-revision"  # written into the volume with the bundle
HARNESS_VOLUME_PREFIX = "saw-harness-"
HARNESS_VOLUME_LABEL = "saw.redhat.com/harness-volume"
# The podman driver's workload container (its supervisor has the same
# sandbox labels but not the user's mounts): isolation.rs WORKLOAD_FILTER.
WORKLOAD_ROLE_LABEL = "openshell.ai/isolation-role=sandbox"
# The labels OpenShell 0.1.x resource admission requires on a mounted volume.
ATTACHABLE_LABEL = "openshell.ai/sandbox-attachable"
ATTACHABLE_WORKSPACE_LABEL = "openshell.ai/sandbox-attachable-workspace"


def harness_image(ref):
    """The digest-pinned image of an OCI harnessRef, or "" for an inline one."""
    return (ref or {}).get("image", "") or ""


def harness_volume_name(workspace, sandbox):
    """One volume per sandbox. Names are DNS labels, so "<ws>-<sb>" alone
    is ambiguous ("a-b"/"c" and "a"/"b-c"); a short hash of the pair keeps
    it unique and the name readable."""
    tag = hashlib.sha256(f"{workspace}/{sandbox}".encode()).hexdigest()[:8]
    return f"{HARNESS_VOLUME_PREFIX}{workspace}-{sandbox}-{tag}"


def harness_mounts_json(volume):
    """--driver-config-json for OpenShell's podman driver: the sandbox's
    harness volume, read-only at HARNESS_MOUNT."""
    return json.dumps({"podman": {"mounts": [{
        "type": "volume", "source": volume, "target": HARNESS_MOUNT, "read_only": True}]}},
        separators=(",", ":"))


def read_harness_tar(path):
    """{relpath: (bytes, executable)} from `podman export` of a harness image.

    The bundle tree is the image root (FROM scratch, COPY . /). Directories and
    macOS AppleDouble files are skipped; links, devices and paths that escape
    the tree are refused. The tree (with each file's executable bit) is what
    goes into the sandbox's harness volume.
    """
    files = {}
    with tarfile.open(path) as tar:
        for member in tar.getmembers():
            rel = member.name
            while rel.startswith("./"):
                rel = rel[2:]
            rel = rel.lstrip("/")
            if not rel or member.isdir() or rel.rsplit("/", 1)[-1].startswith("._"):
                continue
            parts = rel.split("/")
            if any(part in ("", ".", "..") for part in parts):
                raise InstallerError(f"harness image: unsafe path {member.name!r}")
            if not member.isfile():
                raise InstallerError(f"harness image: {member.name!r} is not a regular file")
            files[rel] = (tar.extractfile(member).read(), bool(member.mode & 0o111))
    if "harness.yaml" not in files:
        raise InstallerError("harness image has no /harness.yaml at its root")
    return files


def write_harness_tar(path, files, marker):
    """The tarball `podman volume import` fills the harness volume with -- the bundle files unchanged plus the marker. Owned by root in the user
    namespace (that is the runtime user on the host, so the installer can read
    and wipe the volume without `podman unshare`), world-readable, so the
    sandbox user can read it through the read-only mount."""
    dirs = set()
    for rel in files:
        parts = rel.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    with tarfile.open(path, "w") as tar:
        def add(name, data=None, mode=0o644, isdir=False):
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = 0
            if isdir:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tar.addfile(info)
            else:
                info.mode = mode
                info.size = len(data)
                tar.addfile(info, fileobj=io.BytesIO(data))
        for d in sorted(dirs):
            add(d, isdir=True)
        for rel in sorted(files):
            data, executable = files[rel]
            add(rel, data, 0o755 if executable else 0o644)
        add(HARNESS_MARKER, (json.dumps(marker, sort_keys=True) + "\n").encode())


def harness_tree_digest(files):
    """tree_digest of a {relpath: (bytes, executable)} tree (the marker's
    treeDigest), so a volume edited on the VM is detected and refilled."""
    return tree_digest({rel: data for rel, (data, _) in files.items()})


def read_volume_tree(root):
    """{relpath: (bytes, executable)} of a filled volume, without the marker."""
    root = Path(root)
    files = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        if rel != HARNESS_MARKER:
            files[rel] = (path.read_bytes(), bool(path.stat().st_mode & 0o111))
    return files


def describe_harness_tree(files, inline=False):
    """What OpenClaw has to be pointed at, and what governance must allow.

    Reads harness.yaml (metadata, spec.agent, and the governance entries in
    spec.plugins / spec.mcpServers) and mcp.json. OpenClaw never reads
    harness.yaml; it is the installer's view of the bundle. Returns:
      name, agent
      skills               the bundle has skills/
      agentPluginsBundle   plugin.json at the root (OpenClaw loads skills/ and
                           mcp.json from the bundle root)
      mcp                  the bundle has mcp.json
      pluginDirs           native plugins under plugins/
      governance           [{kind, name, governanceProfile, hosts}] to check
                           against the gateway's catalog and the sandbox's
                           providers

    Keys never travel in a bundle. A plugin or MCP server that calls a
    service names the provider profile (governanceProfile) that governs it;
    the sandbox must have a provider of that type, which gives the process
    the profile's env var holding a placeholder, and the sandbox's egress
    proxy puts the real key in only for the profile's endpoints and
    binaries. `inline` bundles come from a ConfigMap, which keeps no file
    modes, so a stdio server cannot run a bundled file directly.
    """
    doc = _yaml(files["harness.yaml"][0].decode("utf-8"), "harness.yaml")
    spec = doc.get("spec") or {}
    name = (doc.get("metadata") or {}).get("name", "")
    plugin_dirs = sorted({rel.split("/")[1] for rel in files
                          if rel.startswith("plugins/") and rel.count("/") >= 2})
    governance = []
    for item in spec.get("plugins") or []:
        if item.get("governanceProfile"):
            governance.append({"kind": "plugin", "name": item.get("name", ""),
                               "governanceProfile": item["governanceProfile"], "hosts": []})
    declared = {m.get("name"): m for m in spec.get("mcpServers") or []}
    for server, decl in sorted(declared.items()):
        stale = sorted(k for k in ("credentialSecret", "credentialSecretKey", "credentialEnvVar")
                       if k in decl)
        if stale:
            raise InstallerError(
                f"harness '{name}': mcp server '{server}' sets {', '.join(stale)}; keys no longer "
                "reach the sandbox that way. Set governanceProfile to the provider type whose "
                "key the server needs and give the sandbox a provider of that type: the server "
                "reads a placeholder from the provider's env var (for example BRAVE_API_KEY) "
                "and the sandbox's egress proxy adds the real key")
    if "mcp.json" in files:
        try:
            servers = json.loads(files["mcp.json"][0]).get("mcpServers") or {}
        except ValueError as exc:
            raise InstallerError(f"harness '{name}': mcp.json is not valid JSON ({exc})") from None
        for server, conf in sorted(servers.items()):
            if not isinstance(conf, dict) or conf.get("type") not in ("stdio", "streamable-http", "sse"):
                raise InstallerError(
                    f"harness '{name}': mcp.json server '{server}' needs \"type\": \"stdio\", "
                    "\"streamable-http\" or \"sse\" (OpenClaw ignores it otherwise)")
            profile = (declared.get(server) or {}).get("governanceProfile", "")
            if conf["type"] == "stdio":
                command = conf.get("command")
                if inline and isinstance(command, str) and "${PLUGIN_ROOT}" in command:
                    raise InstallerError(
                        f"harness '{name}': mcp server '{server}' runs {command!r}, a file in the "
                        "bundle; an inline bundle keeps no file modes, so run it through its "
                        "interpreter (for example command: node, args: [${PLUGIN_ROOT}/...]) "
                        "or ship the bundle as an image")
                # A stdio server runs inside the sandbox, under its policy. It
                # needs a governanceProfile only when it calls a service.
                if profile:
                    governance.append({"kind": "MCP server", "name": server,
                                       "governanceProfile": profile, "hosts": []})
                continue
            host = urlsplit(conf.get("url") or "").hostname
            if not host:
                raise InstallerError(f"harness '{name}': mcp.json server '{server}' has no url host")
            if not profile:
                raise InstallerError(
                    f"harness '{name}': remote MCP server '{server}' ({host}) needs a "
                    "governanceProfile in harness.yaml spec.mcpServers")
            governance.append({"kind": "MCP server", "name": server,
                               "governanceProfile": profile, "hosts": [host]})
    return {
        "name": name,
        "agent": spec.get("agent", "openclaw"),
        "skills": any(rel.startswith("skills/") for rel in files),
        "agentPluginsBundle": "plugin.json" in files,
        "mcp": "mcp.json" in files,
        "pluginDirs": plugin_dirs,
        "governance": governance,
    }


def parse_profile_catalog(output):
    """{profile id: set of endpoint hosts} from
    `openshell provider list-profiles -o json` (checked on OpenShell 0.0.116)."""
    try:
        doc = json.loads(output or "")
    except ValueError:
        raise InstallerError("openshell provider list-profiles -o json did not return JSON") from None
    if isinstance(doc, dict):
        doc = doc.get("profiles") or doc.get("items") or []
    catalog = {}
    for item in doc if isinstance(doc, list) else []:
        if isinstance(item, dict) and item.get("id"):
            catalog[item["id"]] = {e.get("host") for e in item.get("endpoints") or []
                                   if isinstance(e, dict) and e.get("host")}
    return catalog


def openclaw_harness_config(info):
    """OpenClaw config that makes it load the mounted bundle.

    An Agent Plugins bundle (plugin.json at the root) brings its skills/ and
    mcp.json (MCP servers) with it, so the bundle root goes on
    plugins.load.paths. Otherwise skills/ is an extra skill directory.
    plugins/ holds native OpenClaw plugins (tool code); OpenClaw discovers
    every plugin under it from the one parent path, so adding or removing a
    plugin in the bundle needs no config change (checked live on OpenClaw
    2026.9.5).
    """
    config = {}
    paths = []
    if info["agentPluginsBundle"]:
        paths.append(HARNESS_MOUNT)
    elif info["skills"]:
        config["skills.load.extraDirs"] = [f"{HARNESS_MOUNT}/skills"]
    if info["pluginDirs"]:
        paths.append(f"{HARNESS_MOUNT}/plugins")
    if paths:
        config["plugins.load.paths"] = paths
    return config


def parse_harness_files(files):
    """Build bundles from flat ConfigMap keys harness__<bundle>__<relpath>.

    The digest is computed, never authored here: the pin lives in
    sandbox.yaml harnessRef, outside the hashed tree.
    """
    trees = {}
    for key, raw in files.items():
        parts = key.split("__")
        if len(parts) < 3 or parts[0] != "harness":
            raise InstallerError(f"unexpected harness file name: {key}")
        trees.setdefault(parts[1], {})["/".join(parts[2:])] = raw
    bundles = {}
    for name in sorted(trees):
        tree = trees[name]
        if "harness.yaml" not in tree:
            raise InstallerError(f"harness bundle {name!r} has no harness.yaml")
        doc = _yaml(tree["harness.yaml"].decode("utf-8"), f"harness/{name}/harness.yaml")
        spec = doc.get("spec") or {}
        bundles[name] = HarnessBundle(
            name=(doc.get("metadata") or {}).get("name", name),
            agent=spec.get("agent", "openclaw"),
            digest=tree_digest(tree),
            files={rel: base64.b64encode(raw).decode() for rel, raw in tree.items()},
        )
    return bundles


def read_profile_files(directory):
    """Read the flattened saw-bom ConfigMap.

    Returns (profile files as text, harness files as bytes, harness index).
    Profile keys are profiles__<profile>__<ws>__<file>.yaml; harness keys are
    harness__<bundle>__<relpath> and hold base64 (see the digest contract in
    templates/configmap-bom.yaml).
    """
    directory = Path(directory)
    if not directory.is_dir():
        return {}, {}, {}
    files, harness, index = {}, {}, {}
    for entry in sorted(directory.iterdir()):
        if entry.name.startswith(".") or not entry.is_file():
            continue  # kubelet/ISO housekeeping entries
        if entry.name.startswith("profiles__") and entry.name.endswith(".yaml"):
            files[entry.name] = entry.read_text(encoding="utf-8")
        elif entry.name.startswith("harness__"):
            try:
                harness[entry.name] = base64.b64decode(
                    entry.read_text(encoding="utf-8"), validate=True)
            except (ValueError, UnicodeDecodeError) as exc:
                raise InstallerError(
                    f"harness file {entry.name} is not valid base64 ({exc}); "
                    "the chart must b64enc every harness key") from None
        elif entry.name == "harness-index.yaml":
            index = _yaml(entry.read_text(encoding="utf-8"), entry.name)
        else:
            # A wrong key layout must not look like "no profiles".
            raise InstallerError(f"unexpected file in the profiles ConfigMap: {entry.name}")
    return files, harness, index


def _yaml(text, where):
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise InstallerError(f"{where}: invalid YAML ({exc})") from None


def parse_profiles(files):
    """Build profiles from {flat key: yaml text}.

    Only keys of the form profiles__<profile>__<workspace>__<file>.yaml are
    used, where <file> is workspace, providers or sandbox.
    """
    grouped = {}
    for key, text in files.items():
        parts = key.split("__")
        if len(parts) != 4 or parts[0] != "profiles":
            raise InstallerError(f"unexpected profile file name: {key}")
        _, profile, ws_dir, filename = parts
        if filename not in ("workspace.yaml", "providers.yaml", "sandbox.yaml"):
            raise InstallerError(f"unexpected profile file: {key}")
        grouped.setdefault(profile, {}).setdefault(ws_dir, {})[filename] = (key, text)

    profiles = []
    for profile_name in sorted(grouped):
        profile = Profile(name=profile_name)
        for ws_dir in sorted(grouped[profile_name]):
            docs = grouped[profile_name][ws_dir]
            if "workspace.yaml" not in docs:
                raise InstallerError(f"profile {profile_name}/{ws_dir} has no workspace.yaml")
            key, text = docs["workspace.yaml"]
            ws_doc = _yaml(text, key)
            meta = ws_doc.get("metadata") or {}
            spec = ws_doc.get("spec") or {}
            ws = Workspace(name=meta.get("name", ws_dir),
                           enabled=spec.get("enabled", True),
                           description=meta.get("description", ""))
            if "providers.yaml" in docs:
                key, text = docs["providers.yaml"]
                for p in (_yaml(text, key).get("spec") or {}).get("providers") or []:
                    if "name" not in p or "type" not in p:
                        raise InstallerError(f"{key}: every provider needs name and type")
                    ws.providers.append(Provider(
                        name=p["name"], type=p["type"],
                        enabled=p.get("enabled", True),
                        nemoclaw_provider=p.get("nemoclawProvider", ""),
                        credential_secret=p.get("credentialSecret", ""),
                        credential_secret_key=p.get("credentialSecretKey", "api_key"),
                        model=p.get("model", ""),
                        base_url_secret_key=p.get("baseUrlSecretKey", ""),
                        model_secret_key=p.get("modelSecretKey", ""),
                        inference_timeout=int(p.get("inferenceTimeout", 0) or 0)))
            if "sandbox.yaml" in docs:
                key, text = docs["sandbox.yaml"]
                for s in (_yaml(text, key).get("spec") or {}).get("sandboxes") or []:
                    if "name" not in s:
                        raise InstallerError(f"{key}: every sandbox needs a name")
                    ws.sandboxes.append(Sandbox(
                        name=s["name"], type=s.get("type", "generic"),
                        enabled=s.get("enabled", True),
                        agent=s.get("agent", "openclaw"),
                        image=s.get("image", ""),
                        providers=list(s.get("providers") or []),
                        model=s.get("model", ""),
                        harness_ref=dict(s.get("harnessRef") or {})))
            profile.workspaces.append(ws)
        profiles.append(profile)
    return profiles


def enabled_workspaces(profiles):
    for profile in profiles:
        for ws in profile.workspaces:
            if ws.enabled:
                yield profile, ws


def pinned_bundle(sb, bundles):
    """The inline bundle a sandbox's harnessRef.name points at. The bundle
    and the pin ship in the same ConfigMap, so harnessRef.digest is
    optional; when it is set it must match."""
    ref = sb.harness_ref or {}
    bundle = bundles.get(ref.get("name"))
    if bundle is None:
        raise InstallerError(f"sandbox '{sb.name}' references unknown harness bundle "
                             f"'{ref.get('name')}'")
    want = ref.get("digest") or ""
    if want and want != bundle.digest:
        raise InstallerError(
            f"harnessRef digest mismatch for sandbox '{sb.name}': sandbox.yaml says {want}, "
            f"the bundle hashes to {bundle.digest}")
    return bundle


def check_harness_index(bundles, index):
    """harness-index.yaml holds the digest Helm computed for each shipped
    bundle; the installer recomputes it from the files it read. A mismatch
    means the chart and the installer disagree on the tree_digest contract
    or on the files (an encoding change on the way), so nothing is trusted."""
    listed = (index or {}).get("bundles") or {}
    for name, digest in sorted(listed.items()):
        bundle = bundles.get(name)
        if bundle is None:
            raise InstallerError(f"harness-index.yaml lists bundle '{name}', but no files for it "
                                 "were shipped")
        if digest != bundle.digest:
            raise InstallerError(
                f"harness bundle '{name}': the chart computed {digest}, the installer "
                f"{bundle.digest}; the files changed on the way or the tree_digest contract "
                "differs between templates/configmap-bom.yaml and apply_bom.py")
    for name in sorted(set(bundles) - set(listed)):
        if listed or index:
            raise InstallerError(f"harness bundle '{name}' is missing from harness-index.yaml")


def check_driver_config_allowed(toml_path):
    """A harness is mounted through caller driver config, which OpenShell
    0.1.x refuses unless gateway.toml allows it (openshell-saw
    allowDriverConfig). Checked before anything changes, instead of failing
    at sandbox create. A missing file is left to install to report."""
    try:
        text = Path(toml_path).read_text(encoding="utf-8")
    except OSError:
        return
    if not re.search(r"^\s*allow_driver_config\s*=\s*true\s*(#.*)?$", text, re.M):
        raise InstallerError(
            "a sandbox has a harnessRef, but gateway.toml does not set allow_driver_config = "
            "true, so OpenShell would refuse to mount it; set allowDriverConfig in the "
            "openshell-saw chart")


def validate_harness(profiles, bundles):
    """Check every sandbox harnessRef against the delivered bundles.

    Returns {sandbox name: harness source} for the status report, where the
    source is the pinned image, or "<bundle>@<digest>" for a bundle shipped in
    the saw-bom ConfigMap. Raises before anything is mutated. Governance
    (each item's governanceProfile against the gateway's live catalog) is
    checked at apply time, when the gateway can be asked.
    """
    revisions = {}
    for _, ws in enabled_workspaces(profiles):
        for sb in ws.sandboxes:
            ref = sb.harness_ref or {}
            if not (sb.enabled and ref):
                continue
            if sb.type != "openclaw":
                raise InstallerError(
                    f"sandbox '{sb.name}' has a harnessRef but type '{sb.type}'; "
                    "only openclaw sandboxes load a harness")
            image = harness_image(ref)
            if image:
                if not DIGEST_IMAGE_RE.match(image):
                    raise InstallerError(
                        f"sandbox '{sb.name}' harnessRef.image must be pinned by digest "
                        f"(repo@sha256:<64 hex>), got {image!r}")
                if ref.get("digest") or ref.get("name"):
                    raise InstallerError(
                        f"sandbox '{sb.name}' harnessRef: set image, or name (and "
                        "optionally digest), not both")
                revisions[sb.name] = image
                continue
            bundle = pinned_bundle(sb, bundles)
            revisions[sb.name] = f"{bundle.name}@{bundle.digest}"
    return revisions


def validate_profiles(profiles):
    """Catch mistakes before anything touches the gateway."""
    errors = []
    seen = {}
    for profile, ws in enabled_workspaces(profiles):
        where = f"{profile.name}/{ws.name}"
        if not NAME_RE.match(ws.name) or len(ws.name) > OPENSHELL_NAME_LIMIT:
            errors.append(f"{where}: workspace name must be a DNS label of at most {OPENSHELL_NAME_LIMIT} characters")
        if ws.name in seen:
            errors.append(f"{where}: workspace '{ws.name}' is also defined by profile {seen[ws.name]}")
        seen[ws.name] = profile.name
        provider_names = [p.name for p in ws.providers if p.enabled]
        if len(provider_names) != len(set(provider_names)):
            errors.append(f"{where}: duplicate provider names")
        for p in ws.providers:
            if not p.enabled:
                continue
            if p.type not in PROVIDER_CRED_MAP:
                errors.append(f"{where}: provider '{p.name}' has unsupported type '{p.type}'")
            if not p.credential_secret:
                errors.append(f"{where}: provider '{p.name}' has no credentialSecret")
            elif not SECRET_NAME_RE.match(p.credential_secret):
                errors.append(f"{where}: provider '{p.name}' has an invalid credentialSecret name")
            if not SECRET_KEY_RE.match(p.credential_secret_key or ""):
                errors.append(f"{where}: provider '{p.name}' has an invalid credentialSecretKey")
            for field_name, value in (("baseUrlSecretKey", p.base_url_secret_key),
                                      ("modelSecretKey", p.model_secret_key)):
                if value and not SECRET_KEY_RE.match(value):
                    errors.append(f"{where}: provider '{p.name}' has an invalid {field_name}")
            if p.base_url_secret_key and p.type not in BASE_URL_CONFIG_KEYS:
                errors.append(f"{where}: provider '{p.name}' of type '{p.type}' does not take a base URL "
                              f"(supported: {', '.join(sorted(BASE_URL_CONFIG_KEYS))})")
            if p.inference_timeout < 0:
                errors.append(f"{where}: provider '{p.name}' has a negative inferenceTimeout")
        sandbox_names = set()
        for s in ws.sandboxes:
            if not s.enabled:
                continue
            if s.name in sandbox_names:
                errors.append(f"{where}: duplicate sandbox '{s.name}'")
            sandbox_names.add(s.name)
            if len(s.name) > OPENSHELL_NAME_LIMIT or not NAME_RE.match(s.name):
                errors.append(f"{where}: sandbox name '{s.name}' must be a DNS label of at most {OPENSHELL_NAME_LIMIT} characters")
            if s.type not in SANDBOX_TYPES:
                errors.append(f"{where}: sandbox '{s.name}' has unsupported type '{s.type}'")
            for ref in s.providers:
                if ref not in provider_names:
                    errors.append(f"{where}: sandbox '{s.name}' uses provider '{ref}' which is not an enabled provider in this workspace")
            if s.type in ("openclaw", "nemoclaw") and not provider_names:
                errors.append(f"{where}: {s.type} sandbox '{s.name}' needs at least one provider")
    if errors:
        raise InstallerError("invalid profiles:\n  - " + "\n  - ".join(errors))


def check_profiles_against_bom(profiles, bom):
    """Software a profile needs must be in the BOM."""
    if "nemoclaw" in bom["spec"]:
        return
    for _, ws in enabled_workspaces(profiles):
        for s in ws.sandboxes:
            if s.enabled and s.type == "nemoclaw":
                raise InstallerError(
                    f"sandbox '{s.name}' in workspace '{ws.name}' is type nemoclaw, but the "
                    "InstallerBOM has no spec.nemoclaw.cliImage; add it or disable the sandbox")


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

def check_provider_type(provider, configured):
    """The Secret may carry a `provider` key naming the service the key is
    for. Refuse to hand, say, a Gemini key to an NVIDIA provider."""
    if not configured:
        return
    valid = {v for v in (provider.type, provider.nemoclaw_provider) if v}
    if configured not in valid:
        raise InstallerError(
            f"provider '{provider.name}' expects a {' or '.join(sorted(valid))} "
            f"credential, but its Secret '{provider.credential_secret}' is for '{configured}'")


def resolve_credentials(profiles, secrets_dir):
    """Return {workspace: {provider: key}} read from mounted Secret files.

    A missing credential is an error: the old flow silently fell back to
    `--from-existing`, which created providers without keys.
    """
    secrets_dir = Path(secrets_dir)
    creds = {}
    for _, ws in enabled_workspaces(profiles):
        for p in ws.providers:
            if not p.enabled:
                continue
            base = secrets_dir / p.credential_secret
            key_file = base / p.credential_secret_key
            try:
                value = key_file.read_text(encoding="utf-8").strip()
            except OSError:
                value = ""
            if not value:
                raise InstallerError(
                    f"credential for provider '{p.name}' in workspace '{ws.name}' not found: "
                    f"Secret '{p.credential_secret}' key '{p.credential_secret_key}'. "
                    "List the Secret in openshell-saw additionalProviderSecrets and make sure it exists.")
            type_file = base / "provider"
            configured = type_file.read_text(encoding="utf-8").strip() if type_file.is_file() else ""
            check_provider_type(p, configured)
            if p.model_secret_key:
                p.model = read_secret_value(base, p.model_secret_key) or p.model
            if p.base_url_secret_key:
                p.base_url = read_secret_value(base, p.base_url_secret_key)
                if p.base_url:
                    try:
                        p.base_url = check_base_url(p.base_url)
                    except ValueError as exc:
                        raise InstallerError(f"provider '{p.name}' in workspace '{ws.name}': {exc} "
                                             f"(Secret '{p.credential_secret}' key "
                                             f"'{p.base_url_secret_key}')") from None
            creds.setdefault(ws.name, {})[p.name] = value
    return creds


def read_secret_value(base, key):
    try:
        return (Path(base) / key).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


# Characters a base URL never needs and a shell would interpret; the URL ends
# up in an OpenClaw command line inside the sandbox.
SHELL_UNSAFE = set("\"'`$\\;|&<>(){}")


def check_base_url(url):
    """An http(s) base URL without credentials, query or fragment. The value
    is not echoed in errors: a pasted URL may contain a token."""
    try:
        parts = urlsplit(url)
        ok = (parts.scheme in ("http", "https") and parts.hostname
              and parts.username is None and parts.password is None
              and not parts.query and not parts.fragment
              and not any(c.isspace() or c in SHELL_UNSAFE for c in url))
        if ok:
            parts.port  # raises ValueError on a bad port
    except ValueError:
        ok = False
    if not ok:
        raise ValueError("base URL must be http(s)://host[:port][/path] without credentials, "
                         "query or fragment")
    host = parts.hostname
    if host in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("base URL must not be localhost: inside the sandbox that is the "
                         "sandbox itself (use a cluster Service or Route host)")
    return url.rstrip("/")


# ---------------------------------------------------------------------------
# State (what is installed)
# ---------------------------------------------------------------------------

def write_json_atomic(path, data, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Component installation (root)
# ---------------------------------------------------------------------------

class ComponentInstaller:
    """Installs the BOM's OpenShell binaries from their pinned images.

    Each binary is copied out of its image with podman, version-checked, and
    only then moved into place. A component whose recorded digest and file
    hash still match is left alone, so reboots do not re-pull anything.
    """

    def __init__(self, shell, bin_dir, state_file, podman="podman", opt_dir="/opt",
                 signing_mode="off", trust_dir="/etc/saw/trust"):
        self.sh = shell
        self.bin_dir = Path(bin_dir)
        self.state_file = Path(state_file)
        self.podman = podman
        self.opt_dir = Path(opt_dir)
        self.signing_mode = signing_mode
        self.trust_dir = Path(trust_dir)
        self.signatures = {}

    def load_state(self):
        return read_json(self.state_file, {"components": {}})

    def _is_current(self, state_entry, image, dest):
        return (state_entry
                and state_entry.get("image") == image
                and dest.exists()
                and state_entry.get("sha256") == sha256_file(dest))

    def _is_current_comp(self, comp, state_entry, image):
        if comp in IMAGE_COMPONENTS:
            return bool(state_entry) and state_entry.get("image") == image
        return self._is_current(state_entry, image, self.bin_dir / COMPONENTS[comp]["dest"])

    def _extract(self, image, path_in_image, target):
        self.sh.run([self.podman, "pull", "--quiet", image], timeout=900)
        created = self.sh.run([self.podman, "create", image])
        cid = created.out.strip().splitlines()[-1] if created.out.strip() else ""
        if not cid:
            raise InstallerError(f"podman create returned no container id for {image}")
        try:
            self.sh.run([self.podman, "cp", f"{cid}:{path_in_image}", str(target)])
        finally:
            self.sh.run([self.podman, "rm", "-f", cid], check=False, quiet=True)

    def signer_label(self, signature):
        if not signature:
            return "a configured signer"
        if signature.get("keyRef"):
            return signature["keyRef"]
        return signature.get("identity") or "the configured identity"

    def check_signatures(self, bom):
        """Record a signature result per component. enforce fails before install.

        A component whose file and digest are already current is only
        trusted as still "verified" if that is what was actually recorded
        the last time it was installed -- not just assumed. Otherwise a
        component installed while signing.mode was off (or unsigned under
        warn) would keep reporting "verified" forever, including right
        after switching to enforce, without ever having been checked
        (PR #54 review, 4).
        """
        self.signatures = {}
        if self.signing_mode == "off" or self.sh.dry_run:
            return self.signatures
        installed = self.load_state().get("components", {})
        for comp, entry in bom["spec"]["openshell"].items():
            signature = entry.get("signature")
            if not signature:
                if self.signing_mode == "enforce":
                    raise InstallerError(
                        f"image {entry['image']} is not signed by {self.signer_label(None)}")
                log(f"WARN: image {entry['image']} is not signed by {self.signer_label(None)}")
                self.signatures[comp] = "unsigned"
                continue
            record = installed.get(comp) or {}
            if self._is_current_comp(comp, record, entry["image"]) and \
                    record.get("signature") == "verified":
                self.signatures[comp] = "verified"
                continue
            self.signatures[comp] = self._verify_signature(comp, entry)
        return self.signatures

    def _signature_policy(self, signature):
        """A one-image containers-policy.json: reject by default, or
        require exactly the configured signer. Built here, in Python, from
        the BOM's (already shape-validated) signature field, and used only
        for this one pull via `podman pull --signature-policy`. Building it
        dynamically is only trustworthy because this code itself only runs
        after apply_bom.py passed the installer bundle's own signature
        check (verify-bundle, PR #54 review, 2); the key material it points
        at (/etc/saw/trust) is still golden-image-rooted, never taken from
        the namespace. Default reject (not the image's system policy,
        which stays permissive for warn/off) closes the gap where any
        image from a registry the static policy did not special-case
        pulled fine under "enforce" (PR #54 review, 4)."""
        if not signature:
            return {"default": [{"type": "reject"}]}
        if signature.get("keyRef"):
            key_path = self.trust_dir / f"{signature['keyRef']}.pub"
            return {"default": [{"type": "sigstoreSigned", "keyPath": str(key_path),
                                 "signedIdentity": {"type": "matchRepository"}}]}
        # Keyless: podman's policy.json can only match a Fulcio-issued
        # certificate by an exact fulcio.subjectEmail. _validate_signature
        # requires `identity` to be an https:// URI (matching the docs'
        # GitHub-Actions-workflow-ref example), so no identity that ever
        # passes BOM validation can be email-shaped -- there is no field in
        # podman's policy.json this schema's identity can be checked
        # against. Checking oidcIssuer alone would accept any signer from
        # that issuer: with https://token.actions.githubusercontent.com,
        # that is any GitHub Actions workflow anywhere (PR #54 review
        # round 2, 2). Reject rather than silently enforce less than the
        # BOM asked for: a keyless signature behaves like no signer
        # configured until there is a way to match this identity shape.
        # Use keyRef.
        return {"default": [{"type": "reject"}]}

    def _verify_signature(self, comp, entry):
        image = entry["image"]
        signer = self.signer_label(entry.get("signature"))
        policy = self._signature_policy(entry.get("signature"))
        fd, policy_path = tempfile.mkstemp(prefix="saw-policy-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(policy, fh)
            result = self.sh.run([self.podman, "pull", "--quiet", "--signature-policy",
                                  policy_path, image], check=False, timeout=900)
        finally:
            os.unlink(policy_path)
        if result.rc == 0:
            return "verified"
        message = f"image {image} is not signed by {signer}"
        if self.signing_mode == "enforce":
            raise InstallerError(message)
        log(f"WARN: {message}")
        return "unsigned"

    def install(self, bom):
        """Install every component. Returns the names of changed components."""
        self.check_signatures(bom)
        state = self.load_state()
        installed = state.setdefault("components", {})
        changed = []
        if not self.sh.dry_run:
            self.bin_dir.mkdir(parents=True, exist_ok=True)
        for comp, entry in bom["spec"]["openshell"].items():
            image = entry["image"]
            if comp in IMAGE_COMPONENTS:
                # Pulled for the gateway, which uses it by reference; nothing
                # to extract or run.
                if self._is_current_comp(comp, installed.get(comp), image):
                    log(f"{comp}: {entry['version']} already pulled")
                    continue
                log(f"{comp}: pulling {entry['version']} image {image}")
                self.sh.run([self.podman, "pull", "--quiet", image], timeout=900)
                installed[comp] = {"image": image, "version": entry["version"],
                                   "signature": self.signatures.get(comp, "unsigned")}
                changed.append(comp)
                continue
            dest = self.bin_dir / COMPONENTS[comp]["dest"]
            if self._is_current(installed.get(comp), image, dest):
                log(f"{comp}: {entry['version']} already installed")
                continue
            log(f"{comp}: installing {entry['version']} from {image}")
            if self.sh.dry_run:
                self.sh.run([self.podman, "pull", "--quiet", image])
                changed.append(comp)
                continue
            with tempfile.TemporaryDirectory(dir=self.bin_dir, prefix=".saw-") as tmp:
                staged = Path(tmp) / dest.name
                self._extract(image, entry.get("path", COMPONENTS[comp]["image_path"]), staged)
                if not staged.is_file():
                    raise InstallerError(f"{comp}: {image} did not contain a file at the expected path")
                os.chmod(staged, 0o755)
                version = self.sh.run([str(staged), "--version"], check=False)
                found = reported_version(version.out + " " + version.err)
                if version.rc != 0 or not found or \
                        normalize_version(found) != normalize_version(entry["version"]):
                    raise InstallerError(
                        f"{comp}: image reports version {found or 'unknown'}, "
                        f"BOM expects {entry['version']}")
                os.replace(staged, dest)
            installed[comp] = {"image": image, "version": entry["version"],
                               "sha256": sha256_file(dest),
                               "signature": self.signatures.get(comp, "unsigned")}
            changed.append(comp)
        nemoclaw = bom["spec"].get("nemoclaw")
        if nemoclaw and self._install_nemoclaw(nemoclaw["cliImage"], installed):
            changed.append("nemoclaw")
        state["bom"] = bom["metadata"]["name"]
        if not self.sh.dry_run:
            write_json_atomic(self.state_file, state)
        return changed

    def _install_nemoclaw(self, image, installed):
        target = self.opt_dir / "nemoclaw"
        wrapper = self.bin_dir / "nemoclaw"
        if installed.get("nemoclaw", {}).get("image") == image and target.is_dir() and wrapper.exists():
            log("nemoclaw: already installed")
            return False
        log(f"nemoclaw: installing CLI from {image}")
        if self.sh.dry_run:
            return True
        self.opt_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=self.opt_dir, prefix=".saw-") as tmp:
            staged = Path(tmp) / "nemoclaw"
            self._extract(image, NEMOCLAW_IMAGE_PATH, staged)
            if not (staged / "bin" / "nemoclaw.js").is_file():
                raise InstallerError(f"nemoclaw: {image} has no {NEMOCLAW_IMAGE_PATH}/bin/nemoclaw.js")
            old = Path(tmp) / "previous"
            if target.exists():
                os.replace(target, old)
            os.replace(staged, target)
        script = f'#!/usr/bin/env bash\nexec node {target}/bin/nemoclaw.js "$@"\n'
        tmp_wrapper = wrapper.with_name(".nemoclaw.tmp")
        tmp_wrapper.write_text(script, encoding="utf-8")
        os.chmod(tmp_wrapper, 0o755)
        os.replace(tmp_wrapper, wrapper)
        installed["nemoclaw"] = {"image": image}
        return True


# ---------------------------------------------------------------------------
# Gateway service (user systemd manager of the runtime user)
# ---------------------------------------------------------------------------

def user_env(user):
    import pwd
    info = pwd.getpwnam(user)
    runtime_dir = f"/run/user/{info.pw_uid}"
    return info, {
        "HOME": info.pw_dir,
        "USER": user,
        "LOGNAME": user,
        "XDG_RUNTIME_DIR": runtime_dir,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_dir}/bus",
        "PATH": f"/usr/local/bin:/usr/bin:/bin:{info.pw_dir}/.local/bin",
        "CONTAINER_RUNTIME": "podman",
    }


def as_user(user, env, argv):
    """Build a command that runs argv as `user` with a clean environment."""
    return ["runuser", "-u", user, "--", "env", "-i",
            *[f"{k}={v}" for k, v in sorted(env.items())], *argv]


def wait_for_port(host, port, timeout, sleep=2.0):
    deadline = time.monotonic() + timeout
    while True:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(sleep)


def allow_guest_agent_ssh_keys(shell):
    """SSH keys are provisioned dynamically by KubeVirt accessCredentials via
    the qemu guest agent. Fedora's SELinux policy only lets the agent write
    authorized_keys when virt_qemu_ga_manage_ssh is on. Best effort: a
    missing tool or boolean only means no dynamic SSH keys."""
    if not shutil.which("getsebool", path=shell.env.get("PATH")):
        return
    state = shell.run(["getsebool", "virt_qemu_ga_manage_ssh"], check=False, quiet=True)
    if state.ok and state.out.strip().endswith("on"):
        return
    if not state.ok:
        log("SELinux boolean virt_qemu_ga_manage_ssh not available; skipping")
        return
    result = shell.run(["setsebool", "-P", "virt_qemu_ga_manage_ssh", "on"], check=False)
    if not result.ok:
        log("WARN: could not enable virt_qemu_ga_manage_ssh; SSH keys may not reach the VM")


def ensure_user_manager(shell, env, timeout=90, sleep=1.0):
    """At boot the runtime user's systemd manager may not be up yet (linger
    starts it asynchronously). Start it and wait for its bus socket, the same
    way the golden image's first-boot setup does."""
    runtime_dir = env.get("XDG_RUNTIME_DIR")
    if not runtime_dir:
        return
    uid = Path(runtime_dir).name
    shell.run(["systemctl", "start", f"user@{uid}.service"])
    if shell.dry_run:
        return
    bus = Path(runtime_dir) / "bus"
    deadline = time.monotonic() + timeout
    while not bus.exists():
        if time.monotonic() >= deadline:
            raise InstallerError(f"user systemd manager for uid {uid} did not start ({bus} missing)")
        time.sleep(sleep)


def ensure_gateway(shell, user, env, restart, timeout=120):
    """Start the user-level openshell-gateway.service; restart it if the
    binaries changed. Waits until the gateway accepts TCP connections."""
    ensure_user_manager(shell, env, timeout=90)
    systemctl = lambda *a, **kw: shell.run(as_user(user, env, ["systemctl", "--user", *a]), **kw)
    systemctl("daemon-reload")
    systemctl("enable", "openshell-gateway.service", check=False)
    systemctl("restart" if restart else "start", "openshell-gateway.service")
    if shell.dry_run:
        return
    if not wait_for_port("127.0.0.1", GATEWAY_PORT, timeout):
        shell.run(as_user(user, env, ["journalctl", "--user", "-u", "openshell-gateway.service",
                                      "--no-pager", "-n", "30"]), check=False)
        raise InstallerError(f"openshell-gateway did not listen on port {GATEWAY_PORT} within {timeout}s")
    log("openshell-gateway is up")


def release_series(version):
    """0.0.116-rhaiv.0 -> (0, 0); 0.1.2-rhaiv.0 -> (0, 1). Before 1.0 a minor
    bump is a breaking release."""
    major, minor = normalize_version(version).split(".")[:2]
    return int(major), int(minor)


def needs_state_reset(old_version, new_version):
    """OpenShell 0.1.0 cannot upgrade a 0.0.x gateway in place: its database
    and every sandbox must be recreated (docs/upgrade/0-1-0)."""
    if not old_version or not new_version:
        return False
    return release_series(old_version) != release_series(new_version)


def reset_gateway_state(shell, wrap, home, old_version, new_version, dry_run=False):
    """Move the gateway to a new release series.

    Stops the gateway, removes every OpenShell sandbox container, and moves
    the gateway state (its SQLite database) aside as a backup. The apply
    step then recreates workspaces, providers and sandboxes from the
    SAW-BOM, as on a first boot. TLS material is kept. The old sandboxes'
    /sandbox volumes are kept too, but recreated sandboxes get new IDs and
    new, empty volumes: the old ones are listed for manual recovery."""
    log(f"OpenShell {old_version} -> {new_version} is a new release series: "
        "recreating gateway state and sandboxes")
    systemctl = lambda *a: shell.run(wrap(["systemctl", "--user", *a]), check=False)
    systemctl("stop", "openshell-gateway.service")
    listed = shell.run(wrap([
        "podman", "ps", "-a", "--filter", "label=openshell.ai/sandbox-name",
        "--format", "{{.Names}}"]), check=False, quiet=True)
    names = [n for n in listed.out.split() if n]
    if names:
        log(f"removing {len(names)} sandbox container(s) from {old_version}")
        shell.run(wrap(["podman", "rm", "-f", *names]), check=False)
    volumes = shell.run(wrap([
        "podman", "volume", "ls", "--format", "{{.Name}}"]), check=False, quiet=True)
    kept = [v for v in volumes.out.split() if v.startswith("openshell-sandbox-")]
    if kept:
        log(f"kept {len(kept)} /sandbox volume(s) of the old sandboxes (new sandboxes get new "
            f"ones; copy data over by hand if needed): {', '.join(kept)}")
    state = Path(home) / ".local" / "state" / "openshell" / "gateway"
    if state.exists() and not dry_run:
        backup = state.with_name(f"gateway.{normalize_version(old_version)}.{int(time.time())}")
        try:
            os.rename(state, backup)
        except OSError as exc:
            raise InstallerError(f"could not move the gateway state aside: {exc}") from None
        log(f"gateway state moved to {backup}")


# ---------------------------------------------------------------------------
# Gateway configuration (re-synced from the installer disk on every boot)
# ---------------------------------------------------------------------------

SAN_DROPIN = Path(".config/systemd/user/openshell-gateway.service.d/route-san.conf")


def _env_keys(text):
    keys = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            keys[line.split("=", 1)[0]] = line
    return keys


# Keys an earlier chart wrote that must not survive as "extra" keys.
# OPENSHELL_DRIVERS became OPENSHELL_COMPUTE_DRIVER in OpenShell 0.1.x; the
# old name is only a deprecated alias there.
RETIRED_ENV_KEYS = {"OPENSHELL_DRIVERS", "OPENSHELL_CONFIG_FILE", "OPENSHELL_SSH_GATEWAY_PORT"}


def merge_user_env(chart_env, current):
    """The chart's gateway.env wins; keys only the golden image's first-boot
    setup adds (runtime bridge endpoint, podman socket) are kept."""
    chart_keys = _env_keys(chart_env)
    extra = [line for key, line in _env_keys(current).items()
             if key not in chart_keys and key not in RETIRED_ENV_KEYS]
    text = chart_env.rstrip("\n") + "\n"
    return text + ("\n".join(extra) + "\n" if extra else "")


def san_dropin(route_host):
    return ("[Service]\nExecStartPre=\n"
            "ExecStartPre=/usr/local/bin/openshell-gateway generate-certs "
            "--output-dir ${OPENSHELL_LOCAL_TLS_DIR} --server-san host.openshell.internal "
            f"--server-san {route_host}\n")


def write_if_changed(path, text, mode=0o644, owner=None):
    """Write text atomically if it differs. Returns True when it changed."""
    path = Path(path)
    if path.is_file() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp, mode)
        if owner and os.geteuid() == 0:
            os.chown(tmp, *owner)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return True


def sync_gateway_config(inputs, cfg, etc_dir, home, owner=None, dry_run=False):
    """Bring gateway.env/gateway.toml and the route-SAN drop-in in line with
    the chart. cloud-init only writes them on the first boot of a VM, so
    this is what makes chart changes reach an existing VM after a restart.
    Returns True when anything changed (the gateway must then restart)."""
    env_file, toml_file = inputs.installer / "gateway.env", inputs.installer / "gateway.toml"
    if not env_file.is_file() or not toml_file.is_file():
        raise InstallerError("installer disk has no gateway.env/gateway.toml")
    chart_env = env_file.read_text(encoding="utf-8")
    chart_toml = toml_file.read_text(encoding="utf-8")
    home, etc_dir = Path(home), Path(etc_dir)
    user_dir = home / ".config" / "openshell"
    current_env = (user_dir / "gateway.env").read_text(encoding="utf-8") \
        if (user_dir / "gateway.env").is_file() else ""
    wanted = {
        etc_dir / "gateway.env": (chart_env, None),
        etc_dir / "gateway.toml": (chart_toml, None),
        user_dir / "gateway.env": (merge_user_env(chart_env, current_env), owner),
        user_dir / "gateway.toml": (chart_toml, owner),
    }
    route_host = cfg.get("routeHost") or ""
    dropin = home / SAN_DROPIN
    if dry_run:
        stale = [str(p) for p, (text, _) in wanted.items()
                 if not p.is_file() or p.read_text(encoding="utf-8") != text]
        log(f"[dry-run] gateway config files to update: {stale or 'none'}")
        return False
    changed = False
    for path, (text, file_owner) in wanted.items():
        if write_if_changed(path, text, 0o644, file_owner):
            log(f"updated {path}")
            changed = True
    if route_host:
        if write_if_changed(dropin, san_dropin(route_host), 0o644, owner):
            log(f"updated {dropin} (gateway certificate SAN {route_host})")
            changed = True
    elif dropin.exists():
        dropin.unlink()
        changed = True
    if owner and os.geteuid() == 0:
        for directory in (home / ".config", user_dir, dropin.parent.parent, dropin.parent):
            if directory.is_dir():
                os.chown(directory, *owner)
    return changed


# ---------------------------------------------------------------------------
# Profile application (runtime user, mTLS only)
# ---------------------------------------------------------------------------

def openclaw_replacement_profile(output):
    """The credential id in OpenClaw's "Replacement credential saved but
    inactive ... openclaw models auth activate <id> --agent main" message
    (approach from #50), or None. Only a well-formed id is accepted: the
    value is used in a shell command."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", output)
    if "Replacement credential saved but inactive" not in text:
        return None
    ids = re.findall(r"openclaw models auth activate ([a-z0-9][a-z0-9_.-]*:setup-[0-9a-f]{8}-"
                     r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) --agent main", text)
    return ids[0] if len(set(ids)) == 1 else None


def ws_args(name):
    return [] if name == "default" else ["--workspace", name]


MANAGED_LABEL = "saw.redhat.com/managed=true"
PRUNE_ORDER = ("sandbox", "provider", "profile", "workspace")


class Ledger:
    """Objects the installer created. Only these can be pruned."""

    def __init__(self, path, dry_run=False):
        self.path = Path(path)
        self.dry_run = dry_run
        self.data = {"version": 1, "adopted": False, "objects": []}
        if self.path.is_file():
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.data.update(loaded)
        # OpenShell 0.1.x has no inference routes (its upgrade drops them), so
        # a route a 0.0.x apply recorded is forgotten, in every prune mode.
        self.data["objects"] = [o for o in self.data["objects"] if o.get("kind") != "inference"]

    def save(self):
        if self.dry_run:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        write_json_atomic(self.path, self.data)

    def add(self, kind, workspace, name, profile, adopted=False):
        workspace = workspace or ""
        for obj in self.data["objects"]:
            if (obj["kind"], obj.get("workspace", ""), obj["name"]) == (kind, workspace, name):
                obj["profile"] = profile
                return
        self.data["objects"].append({
            "kind": kind, "workspace": workspace, "name": name, "profile": profile,
            "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "adopted": adopted,
        })

    def drop(self, kind, workspace, name):
        workspace = workspace or ""
        self.data["objects"] = [
            obj for obj in self.data["objects"]
            if (obj["kind"], obj.get("workspace", ""), obj["name"]) != (kind, workspace, name)]


class HarnessVolume:
    """A sandbox's podman named volume holding its harness bundle tree
    unchanged, plus a marker with the source and tree digest. An unchanged,
    intact volume is left alone; anything else is wiped and refilled in
    place, so a file dropped from the bundle does not linger and the volume
    keeps its identity (OpenShell stops a sandbox whose attached volume was
    recreated). Runs as the runtime user, next to the rootless podman
    OpenShell creates sandboxes with.
    """

    def __init__(self, shell, podman="podman"):
        self.sh = shell
        self.podman = podman

    def _podman(self, *args, **kw):
        return self.sh.run([self.podman, *args], **kw)

    @staticmethod
    def labels(workspace):
        return {ATTACHABLE_LABEL: "true", ATTACHABLE_WORKSPACE_LABEL: workspace,
                HARNESS_VOLUME_LABEL: "true"}

    def inspect(self, volume):
        """podman's view of the volume, or None when it does not exist.
        `volume exists` first, so a missing volume is not logged as an error."""
        if not self._podman("volume", "exists", volume, check=False, quiet=True).ok:
            return None
        got = self._podman("volume", "inspect", "--format", "json", volume, check=False, quiet=True)
        if not got.ok:
            return None
        try:
            doc = json.loads(got.out)
        except ValueError:
            raise InstallerError(f"podman volume inspect {volume} did not return JSON") from None
        doc = doc[0] if isinstance(doc, list) and doc else doc
        return doc if isinstance(doc, dict) else None

    def admitted(self, info, workspace):
        """True when the volume carries the labels OpenShell admits it with."""
        labels = (info or {}).get("Labels") or {}
        return all(labels.get(k) == v for k, v in self.labels(workspace).items())

    def ensure(self, volume, workspace):
        """Create the volume with its admission labels. Labels cannot be
        changed on an existing volume: one without them is reported, so the
        caller can free it (delete the sandbox that mounts it) and recreate
        it with remove(). Returns the host mountpoint, or None when the
        volume exists without the labels."""
        info = self.inspect(volume)
        if info is None:
            label_args = [a for k, v in self.labels(workspace).items() for a in ("--label", f"{k}={v}")]
            self._podman("volume", "create", *label_args, volume, quiet=True)
            info = self.inspect(volume)
        if info is None:
            raise InstallerError(f"podman did not create volume {volume}")
        if not self.admitted(info, workspace):
            return None
        mountpoint = info.get("Mountpoint") or ""
        if not mountpoint:
            raise InstallerError(f"podman gave no mountpoint for volume {volume}")
        return Path(mountpoint)

    def remove(self, volume):
        """True once the volume is gone (podman refuses while it is in use)."""
        return self._podman("volume", "rm", volume, check=False, quiet=True).ok

    def marker(self, mountpoint):
        """The marker the last fill wrote ({} when there is none)."""
        try:
            return json.loads((mountpoint / HARNESS_MARKER).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def current(self, mountpoint, source):
        """(tree, marker) if the volume holds exactly `source`, intact; else
        (None, marker)."""
        marker = self.marker(mountpoint)
        if marker.get("source") != source:
            return None, marker
        tree = read_volume_tree(mountpoint)
        if harness_tree_digest(tree) != marker.get("treeDigest"):
            return None, marker
        return tree, marker

    def fill(self, volume, mountpoint, source, tree):
        """Wipe the volume, then import `tree` unchanged plus the marker."""
        for child in list(mountpoint.iterdir()):
            try:
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            except PermissionError:
                # Content not written by this installer (other owner in the
                # user namespace): remove it from inside the namespace.
                self._podman("unshare", "rm", "-rf", str(child))
        marker = {"source": source, "treeDigest": harness_tree_digest(tree)}
        with tempfile.TemporaryDirectory(prefix="saw-harness-") as tmp:
            tarball = Path(tmp) / "bundle.tar"
            write_harness_tar(tarball, tree, marker)
            self._podman("volume", "import", volume, str(tarball))
        return marker

    def verify(self, volume, workspace, source):
        """Failures (list of text) unless the volume is admitted and holds
        `source` intact."""
        if self.sh.dry_run:
            return []
        info = self.inspect(volume)
        if info is None:
            return [f"volume {volume} does not exist"]
        if not self.admitted(info, workspace):
            return [f"volume {volume} lacks the openshell.ai/sandbox-attachable labels"]
        tree, marker = self.current(Path(info.get("Mountpoint") or ""), source)
        if tree is None:
            if marker.get("source") and marker.get("source") != source:
                return [f"volume {volume} holds {marker['source']}, not {source}"]
            return [f"volume {volume} does not hold an intact copy of {source}"]
        return []


class ProfileApplier:
    def __init__(self, shell, cfg, creds, provider_profile_docs=None, harness=None):
        self.sh = shell
        self.cfg = cfg
        self.creds = creds
        self.provider_profiles = provider_profile_docs or {}   # id -> profile YAML
        self.gateway = cfg["mtlsGateway"]
        self.skipped = set()          # (workspace, provider) the gateway had no profile for
        self.desired = {}             # (kind, workspace, name) -> profile name that wants it
        self.profile_name = ""
        prune = cfg.get("prune") or {}
        self.prune_mode = prune.get("mode", "off")
        self.prune_sandboxes = bool(prune.get("sandboxes", False))
        self.ledger = Ledger(prune["ledgerPath"], shell.dry_run) if prune.get("ledgerPath") else None
        self.harness = harness or {"bundles": {}}
        self.volumes = HarnessVolume(shell)
        self.catalogs = {}            # workspace -> {profile id: endpoint hosts}
        self.harness_info = {}        # (workspace, sandbox) -> describe_harness_tree()
        self.harness_volumes = set()  # volumes this apply wants to keep
        for workspace in creds.values():
            for value in workspace.values():
                shell.add_secret(value)

    def cli(self, *args, **kwargs):
        return self.sh.run(["openshell", *args], **kwargs)

    def usable(self, ws):
        """Enabled providers that exist on the gateway (not skipped)."""
        return [p for p in ws.providers if p.enabled and (ws.name, p.name) not in self.skipped]

    # -- gateway access ------------------------------------------------------

    def ensure_admin_client_cert(self):
        """The installer's own mTLS client certificate, CN=saw-installer,
        OU=openshell-admin, signed by the gateway's CA.

        The gateway takes an mTLS caller's roles from the certificate's OU.
        The client certificate the gateway generates for local use carries
        OU=openshell-user, which is enough while no RBAC applies but not once
        OIDC is on (found live: workspace create was refused). Kept in its own
        directory, in the layout `gateway add --local` imports via
        OPENSHELL_LOCAL_TLS_DIR; re-issued when missing, not signed by the
        current CA, or expiring within 30 days."""
        home = Path(os.environ.get("HOME", "/home/cloud-user"))
        gateway_tls = home / ".local" / "state" / "openshell" / "tls"
        out = home / ".local" / "state" / "saw-installer" / "tls"
        if self.sh.dry_run:
            log(f"[dry-run] admin client certificate in {out}")
            return out
        ca_crt, ca_key = gateway_tls / "ca.crt", gateway_tls / "ca.key"
        if not (ca_crt.is_file() and ca_key.is_file()):
            raise InstallerError(f"gateway CA not found in {gateway_tls}; the installer signs its "
                                 "admin client certificate with it (is the gateway set up?)")
        client = out / "client"
        client.mkdir(parents=True, exist_ok=True)
        for d in (out.parent, out, client):
            os.chmod(d, 0o700)
        shutil.copyfile(ca_crt, out / "ca.crt")
        crt, key = client / "tls.crt", client / "tls.key"
        current = (crt.is_file() and key.is_file()
                   and self.sh.run(["openssl", "verify", "-CAfile", str(ca_crt), str(crt)],
                                   check=False, quiet=True).ok
                   and self.sh.run(["openssl", "x509", "-checkend", str(30 * 86400), "-noout",
                                    "-in", str(crt)], check=False, quiet=True).ok)
        if current:
            return out
        log(f"Issuing the installer's admin client certificate ({ADMIN_CERT_SUBJECT})")
        with tempfile.TemporaryDirectory(prefix="saw-cert-") as tmp:
            csr, ext = Path(tmp) / "req.csr", Path(tmp) / "ext.cnf"
            ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                           "extendedKeyUsage=clientAuth\n", encoding="utf-8")
            self.sh.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt",
                         "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(key),
                         "-subj", ADMIN_CERT_SUBJECT, "-out", str(csr)], quiet=True)
            os.chmod(key, 0o600)
            self.sh.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt),
                         "-CAkey", str(ca_key), "-set_serial", "0x" + secrets.token_hex(16),
                         "-days", "365", "-extfile", str(ext), "-out", str(crt)], quiet=True)
        return out

    def register_gateway(self):
        """Point the CLI at the local gateway over mTLS as the installer's
        admin identity. The entry is replaced on every run so a stale entry
        never wins; the default `openshell` entry is left alone."""
        tls_dir = self.ensure_admin_client_cert()
        log(f"Registering local mTLS gateway '{self.gateway}' (OU=openshell-admin)")
        self.cli("gateway", "remove", self.gateway, check=False, quiet=True)
        self.cli("gateway", "add", f"https://127.0.0.1:{GATEWAY_PORT}",
                 "--name", self.gateway, "--local", env={"OPENSHELL_LOCAL_TLS_DIR": str(tls_dir)})
        self.cli("gateway", "select", self.gateway)
        result = self.cli("workspace", "list", check=False)
        if not result.ok:
            raise InstallerError(
                "the mTLS client cannot list workspaces; the installer needs the "
                "local mTLS identity to act as a platform admin (openshell-admin)")

    # -- workspaces and providers ------------------------------------------

    def remember(self, kind, workspace, name):
        """An object this apply still wants. Recorded so a later apply can
        prune it. The profile is captured here (per object), not read later
        off the shared self.profile_name, which would attribute every
        object to whichever profile happened to be processed last when more
        than one profile is in use (PR #54 review, 9)."""
        self.desired[(kind, workspace or "", name)] = self.profile_name

    def apply_workspace(self, ws):
        self.remember("workspace", "", ws.name)
        if ws.name != "default":
            result = self.cli("workspace", "create", "--name", ws.name,
                              "--label", MANAGED_LABEL,
                              check=False, ok_if_exists=True)
            if not result.ok:
                raise InstallerError(
                    f"could not create workspace '{ws.name}'. Creating workspaces needs "
                    "platform admin; check the mTLS identity has the openshell-admin role")
        owner = self.cfg.get("ownerSubject")
        if owner:
            self.cli("workspace", "member", "add", "--workspace", ws.name,
                     "--subject", owner, "--role", "admin", ok_if_exists=True)

    def apply_provider(self, ws, provider):
        """Create the provider; if it exists, push the current key to it.

        `--credential NAME` (no value) makes the CLI read the key from the
        environment variable NAME, so the key never appears in argv
        (/proc/<pid>/cmdline) or in logs."""
        credential = self.creds[ws.name][provider.name]
        env_name = PROVIDER_CRED_MAP[provider.type]
        env = {env_name: credential}
        # A custom endpoint is recorded on the provider; start_openclaw
        # points the agent at it.
        config = (("--config", f"{BASE_URL_CONFIG_KEYS[provider.type]}={provider.base_url}")
                  if provider.base_url else ())
        create = ("provider", "create", "--name", provider.name, "--type", provider.type,
                  *ws_args(ws.name), "--credential", env_name, *config)
        created = self.cli(*create, env=env, ok_if_exists=True, check=False)
        if (not created.ok and NO_PROFILE_RE.search(created.out + " " + created.err)
                and provider.type in self.provider_profiles):
            self.import_provider_profile(ws, provider.type)
            created = self.cli(*create, env=env, ok_if_exists=True, check=False)
        if not created.ok and NO_PROFILE_RE.search(created.out + " " + created.err):
            log(f"WARN: skipping provider '{provider.name}': the gateway has no '{provider.type}' "
                "provider profile (governed profiles come from the governance interceptor; "
                "is governance enabled?)")
            self.skipped.add((ws.name, provider.name))
            # Remembered even though it is unusable this run: a transient
            # catalog gap (governance restarting, a brief profile outage)
            # must not prune a provider that was working a moment ago
            # (PR #54 review, 6b). finish_prune() also refuses to prune at
            # all this run once anything lands in self.skipped.
            self.remember("provider", ws.name, provider.name)
            return
        if not created.ok:
            raise InstallerError(f"could not create provider '{provider.name}' in workspace "
                                 f"'{ws.name}' (openshell provider create failed)")
        if created.existed:
            updated = self.cli("provider", "update", provider.name, *ws_args(ws.name),
                               "--credential", env_name, *config, env=env, check=False)
            if not updated.ok:
                log(f"WARN: could not refresh the credential of existing provider '{provider.name}'")
        self.remember("provider", ws.name, provider.name)
        if provider.type in self.provider_profiles:
            # Keep an imported profile remembered on every run that still
            # uses it, not only the run that imported it. Before this fix,
            # the profile was only remembered when import_provider_profile
            # ran (i.e. the gateway didn't have it yet); the very next apply
            # (provider already exists) pruned the profile out from under
            # the provider still using it, and the run after that
            # re-imported it (PR #54 review, 6a).
            self.remember("profile", ws.name, provider.type)

    def import_provider_profile(self, ws, profile_id):
        """The gateway has no profile for this provider type (governed
        profiles come from the governance interceptor, which may be off).
        Import the copy shipped with the chart into the workspace."""
        log(f"Gateway has no '{profile_id}' provider profile; importing the shipped one "
            f"into workspace '{ws.name}'")
        with tempfile.TemporaryDirectory(prefix="saw-profile-") as tmp:
            path = Path(tmp) / f"{profile_id}.yaml"
            path.write_text(self.provider_profiles[profile_id], encoding="utf-8")
            result = self.cli("provider", "profile", "import", "-f", str(path), *ws_args(ws.name),
                              ok_if_exists=True, check=False)
        if not result.ok:
            raise InstallerError(f"could not import the '{profile_id}' provider profile into "
                                 f"workspace '{ws.name}'")
        self.remember("profile", ws.name, profile_id)

    # -- sandboxes -------------------------------------------------------

    def find_provider(self, ws, names):
        """The provider an agent sandbox is onboarded with: one of the
        sandbox's own providers, preferring one with a model. Never another
        provider of the workspace: found live, a skipped `custom` provider
        made OpenClaw onboard with `brave` and a default NVIDIA model."""
        usable = self.usable(ws)
        if names:
            usable = [p for n in names for p in usable if p.name == n]
        return next((p for p in usable if p.model), usable[0] if usable else None)

    def sandbox_state(self, ws, sb):
        """'running', 'broken' (Error/Completed) or 'missing'."""
        state = self.cli("sandbox", "get", sb.name, *ws_args(ws.name), check=False, quiet=True)
        if not state.ok:
            return "missing"
        clean = re.sub(r"\x1b\[[0-9;]*m", "", state.out)
        return "broken" if ("Error" in clean or "Phase: Completed" in clean) else "running"

    def harness_source(self, sb):
        """(source id, inline bundle) for a sandbox's harnessRef, or (None, None).

        The source id is the pinned image, or "bundle:<name>@<digest>" for an
        inline bundle from the saw-bom ConfigMap.
        """
        ref = sb.harness_ref or {}
        if not ref:
            return None, None
        image = harness_image(ref)
        if image:
            return image, None
        bundle = pinned_bundle(sb, self.harness["bundles"])
        return f"bundle:{bundle.name}@{bundle.digest}", bundle

    def desired_harness_mount(self, ws, sb):
        """The volume the sandbox should mount at HARNESS_MOUNT, or None."""
        return harness_volume_name(ws.name, sb.name) if sb.harness_ref else None

    def _podman(self, *args, **kw):
        return self.sh.run(["podman", *args], **kw)

    def image_tree(self, image):
        """The bundle tree of a harness image (with file modes). Pulled by
        digest when it is not present yet."""
        if not self._podman("image", "exists", image, check=False, quiet=True).ok:
            self._podman("pull", "--quiet", image, timeout=900)
        created = self._podman("create", image, "/harness.yaml")
        cid = created.out.strip().splitlines()[-1] if created.out.strip() else ""
        if not cid:
            raise InstallerError(f"podman create returned no container id for {image}")
        with tempfile.TemporaryDirectory(prefix="saw-harness-") as tmp:
            exported = Path(tmp) / "image.tar"
            try:
                self._podman("export", "-o", str(exported), cid)
            finally:
                self._podman("rm", "-f", cid, check=False, quiet=True)
            return read_harness_tar(exported)

    def sandbox_harness_mount(self, ws, sb):
        """(type, source) of what the sandbox's container mounts at
        HARNESS_MOUNT; None when it mounts nothing there; False when there
        is no container to look at.

        Read from podman, which OpenShell's podman driver runs the sandbox
        container in:
          - the container carries the labels openshell.ai/sandbox-name and
            openshell.ai/sandbox-workspace, so it is found without guessing
            its generated name (openshell-<ws>--<sandbox>-<uuid>);
          - 0.1.x runs each sandbox as two containers with those labels, the
            workload and its supervisor; only the workload
            (openshell.ai/isolation-role=sandbox) has the user's mounts;
          - `.Mounts` lists a named volume as {"Type": "volume", "Name":
            <volume>, ...} (checked live on 0.0.116; same labels in 0.1.2,
            driver_utils.rs).
        """
        names = self._podman("ps", "-a",
                             "--filter", f"label=openshell.ai/sandbox-name={sb.name}",
                             "--filter", f"label=openshell.ai/sandbox-workspace={ws.name}",
                             "--filter", f"label={WORKLOAD_ROLE_LABEL}",
                             "--format", "{{.Names}}", check=False, quiet=True)
        found = (names.out or "").split()
        if not names.ok or not found:
            return False
        if len(found) > 1:
            raise InstallerError(f"more than one workload container for sandbox '{sb.name}' in "
                                 f"workspace '{ws.name}': {', '.join(found)}")
        name = found
        got = self._podman("inspect", "--format", "{{json .Mounts}}", name[0],
                           check=False, quiet=True)
        try:
            mounts = json.loads(got.out) if got.ok else []
        except ValueError:
            mounts = []
        for mount in mounts or []:
            if mount.get("Destination") == HARNESS_MOUNT:
                kind = (mount.get("Type") or "").lower()
                source = mount.get("Name") if kind == "volume" else mount.get("Source")
                return (kind, source or "")
        return None

    def harness_mount_ok(self, ws, sb):
        """True when the sandbox mounts exactly its harness volume, or,
        without a harnessRef, mounts nothing at HARNESS_MOUNT (a harness
        that was removed must not stay mounted). A sandbox whose container
        cannot be found is left to the gateway."""
        seen = self.sandbox_harness_mount(ws, sb)
        if seen is False:
            log(f"WARN: no workload container found for sandbox '{sb.name}'; "
                "not checking its harness mount")
            return True
        want = self.desired_harness_mount(ws, sb)
        return seen == (("volume", want) if want else None)

    def governance_catalog(self, ws):
        """{profile id: endpoint hosts} the gateway serves in the workspace
        right now (from the governance interceptor, or profiles imported into
        the workspace). Read live, so there is no list to keep in sync. In
        0.1.x `provider list-profiles` lists one workspace's catalog, so it
        is read, and cached, per workspace."""
        if ws.name not in self.catalogs:
            listed = self.cli("provider", "list-profiles", *ws_args(ws.name), "-o", "json",
                              check=False, quiet=True)
            if not listed.ok:
                raise InstallerError("cannot read the gateway's provider profile catalog "
                                     f"for workspace '{ws.name}' (openshell provider "
                                     "list-profiles failed); refusing to fill a harness "
                                     "without a governance check")
            self.catalogs[ws.name] = parse_profile_catalog(listed.out)
        return self.catalogs[ws.name]

    def check_harness_governance(self, ws, sb, info):
        """Each governed item's profile must be served by the gateway in the
        sandbox's workspace, the sandbox must have a provider of that type
        (without one, neither the profile's endpoints nor its key reach the
        sandbox), and a remote MCP server's host must be one of that
        profile's endpoints."""
        if not info["governance"]:
            return
        catalog = self.governance_catalog(ws)
        attached = {p.type for p in self.usable(ws) if p.name in sb.providers}
        for item in info["governance"]:
            profile = item["governanceProfile"]
            what = f"harness '{info['name']}' {item['kind']} '{item['name']}'"
            if profile not in catalog:
                raise InstallerError(
                    f"{what} names governanceProfile '{profile}', which the gateway does not "
                    f"serve in workspace '{ws.name}'; refusing to fill the harness of sandbox "
                    f"'{sb.name}'")
            if profile not in attached:
                raise InstallerError(
                    f"{what} names governanceProfile '{profile}', but sandbox '{sb.name}' has no "
                    f"provider of type '{profile}'; add one to the workspace's providers.yaml and "
                    "to the sandbox's providers (its endpoints and key reach the sandbox only "
                    "through a provider)")
            for host in item["hosts"]:
                if host not in catalog[profile]:
                    allowed = ", ".join(sorted(catalog[profile])) or "none"
                    raise InstallerError(
                        f"{what} reaches {host}, which governanceProfile '{profile}' does not "
                        f"allow (allowed: {allowed}); refusing to fill the harness of "
                        f"sandbox '{sb.name}'")

    def prepare_harness(self, ws, sb):
        """Check the sandbox's harness and fill its volume.

        The bundle is read from the volume when it already holds this source
        intact (no pull), else from the image (pulled by digest) or the
        ConfigMap files. Governance is checked before anything is written:
        a bundle that fails it never reaches the volume.
        """
        source, bundle = self.harness_source(sb)
        if source is None:
            return None
        volume = harness_volume_name(ws.name, sb.name)
        self.harness_volumes.add(volume)
        if self.sh.dry_run:
            log(f"Harness {source} for sandbox '{sb.name}' in volume {volume} (dry run)")
            return None
        mountpoint = self.volumes.ensure(volume, ws.name)
        # None: the volume predates its admission labels, which cannot be
        # added later; it is replaced below, after governance passed.
        tree = self.volumes.current(mountpoint, source)[0] if mountpoint else None
        current = tree is not None
        if current:
            log(f"Harness volume {volume} already holds {source}")
        elif bundle is None:
            log(f"Harness image {source} for sandbox '{sb.name}'")
            tree = self.image_tree(source)
        else:
            tree = {rel: (base64.b64decode(b64), False) for rel, b64 in bundle.files.items()}
        info = describe_harness_tree(tree, inline=bundle is not None)
        if info["agent"] != "openclaw":
            raise InstallerError(f"harness {source} is for agent '{info['agent']}', "
                                 f"sandbox '{sb.name}' runs openclaw")
        self.check_harness_governance(ws, sb, info)
        if mountpoint is None:
            log(f"Harness volume {volume} lacks its admission labels; recreating it "
                f"(and sandbox '{sb.name}', which mounts it)")
            self.delete_sandbox_and_wait(ws, sb)
            self.remove_volume_and_wait(volume)
            mountpoint = self.volumes.ensure(volume, ws.name)
            if mountpoint is None:
                raise InstallerError(f"podman created volume {volume} without its labels")
        if not current:
            self.volumes.fill(volume, mountpoint, source, tree)
            log(f"Harness volume {volume} filled from {source}")
        self.harness_info[(ws.name, sb.name)] = info
        return info

    def delete_sandbox_and_wait(self, ws, sb, attempts=24, delay=5):
        """Delete a sandbox and wait until the gateway no longer has it and
        podman has removed its workload container: 0.1.x may accept the
        delete with cleanup still pending, and its container keeps the
        harness volume in use until it is gone."""
        self.cli("sandbox", "delete", sb.name, *ws_args(ws.name), check=False)
        if self.sh.dry_run:
            return
        for _ in range(attempts):
            if self.sandbox_state(ws, sb) == "missing" and self.sandbox_harness_mount(ws, sb) is False:
                return
            time.sleep(delay)
        raise InstallerError(f"sandbox '{sb.name}' in workspace '{ws.name}' was not removed")

    def remove_volume_and_wait(self, volume, attempts=12, delay=5):
        for _ in range(attempts):
            if self.volumes.remove(volume):
                return
            time.sleep(delay)
        raise InstallerError(f"could not remove harness volume {volume} to relabel it")

    def create_sandbox(self, ws, sb):
        self.prepare_harness(ws, sb)
        state = self.sandbox_state(ws, sb)
        if state == "running" and not self.sh.dry_run and not self.harness_mount_ok(ws, sb):
            # Mounts are fixed at create: a sandbox created before its
            # harnessRef, one that still mounts a harness it no longer has,
            # or one that mounts another volume there is created again.
            # /sandbox/persist and other data volumes are kept by OpenShell;
            # the rest is not.
            want = self.desired_harness_mount(ws, sb)
            log(f"Sandbox '{sb.name}' " + (f"does not mount its harness volume {want}"
                                           if want else "still mounts a removed harness")
                + "; recreating it")
            self.delete_sandbox_and_wait(ws, sb)
            state = "missing"
        if state == "broken":
            log(f"Sandbox '{sb.name}' is not running; recreating it")
            self.cli("sandbox", "delete", sb.name, *ws_args(ws.name), check=False)
        elif state == "running":
            log(f"Sandbox '{sb.name}' already exists")
            self.attach_missing_providers(ws, sb)
            self.remember("sandbox", ws.name, sb.name)
            return
        if sb.image and ("/" in sb.image or ":" in sb.image):
            self.sh.run(["podman", "pull", sb.image], check=False, timeout=900)
        args = ["sandbox", "create", "--name", sb.name, "--label", MANAGED_LABEL]
        if sb.image:
            args += ["--from", sb.image]
        args += ws_args(ws.name)
        volume = self.desired_harness_mount(ws, sb)
        if volume:
            args += ["--driver-config-json", harness_mounts_json(volume)]
        for prov in sb.providers:
            if (ws.name, prov) in self.skipped:
                log(f"WARN: sandbox '{sb.name}' created without skipped provider '{prov}'")
                continue
            args += ["--provider", prov]
        # Keep the sandbox Ready for the follow-up `sandbox exec` setup.
        args += ["--no-tty", "--detach", "--", "sh", "-c", "sleep infinity"]
        self.cli(*args, timeout=900)
        self.remember("sandbox", ws.name, sb.name)

    def attach_missing_providers(self, ws, sb):
        """A sandbox created while one of its providers was skipped (e.g. no
        provider profile yet) gets it once it exists. Found live: the
        sandbox kept running without `custom` after the profile arrived."""
        if not sb.providers:
            return
        listed = self.cli("sandbox", "provider", "list", sb.name, *ws_args(ws.name),
                          check=False, quiet=True)
        attached = set(re.sub(r"\x1b\[[0-9;]*m", "", listed.out).split())
        for prov in sb.providers:
            if prov in attached or (ws.name, prov) in self.skipped:
                continue
            log(f"Attaching provider '{prov}' to existing sandbox '{sb.name}'")
            self.cli("sandbox", "provider", "attach", sb.name, prov, *ws_args(ws.name), check=False)

    def onboard_nemoclaw(self, ws, sb, provider):
        home = Path(os.environ.get("HOME", "/home/cloud-user"))
        mgmt_path = home / "gateway-management.json"
        mgmt = {
            "version": 1, "mode": "externally-supervised",
            "endpoint": f"https://127.0.0.1:{GATEWAY_PORT}",
            "stateDir": str(home / ".local" / "state" / "openshell"),
            "supervisor": {"kind": "systemd-user", "serviceName": "openshell-gateway.service",
                           "execPath": "/usr/local/bin/openshell-gateway"},
        }
        if not self.sh.dry_run:
            mgmt_path.write_text(json.dumps(mgmt), encoding="utf-8")
        credential = self.creds[ws.name][provider.name]
        nc_provider = provider.nemoclaw_provider or provider.type
        env = {
            "NEMOCLAW_GATEWAY_MANAGEMENT": str(mgmt_path),
            "NEMOCLAW_GATEWAY_PORT": str(GATEWAY_PORT),
            "NEMOCLAW_IGNORE_RUNTIME_RESOURCES": "1",
            "NEMOCLAW_OPENSHELL_GATEWAY_BIN": "/usr/local/bin/openshell-gateway",
            "NEMOCLAW_OPENSHELL_SANDBOX_BIN": "/usr/local/bin/openshell-supervisor",
            "NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE": "1",
            "NEMOCLAW_PROVIDER": nc_provider,
            "NEMOCLAW_PROVIDER_KEY": credential,
        }
        if sb.model or provider.model:
            env["NEMOCLAW_MODEL"] = sb.model or provider.model
        if PROVIDER_CRED_MAP.get(nc_provider):
            env[PROVIDER_CRED_MAP[nc_provider]] = credential
        result = self.sh.run(["nemoclaw", "onboard", "--fresh", "--non-interactive",
                              "--name", sb.name, "--agent", sb.agent or "openclaw",
                              "--yes", "--yes-i-accept-third-party-software"],
                             env=env, check=False, timeout=900)
        return result.ok

    def start_openclaw(self, ws, sb, provider):
        """Onboard openclaw inside the sandbox and start its web gateway.
        These steps are best effort, as before; verification decides."""
        exec_cmd = ["sandbox", "exec", "-n", sb.name, *ws_args(ws.name), "--no-tty", "--"]
        if not self.sh.dry_run:
            for attempt in range(20):
                state = self.cli("sandbox", "get", sb.name, *ws_args(ws.name), check=False, quiet=True)
                clean = re.sub(r"\x1b\[[0-9;]*m", "", state.out)
                if "Ready" in clean and "Error" not in clean:
                    break
                log(f"  waiting for sandbox '{sb.name}' to be Ready ({attempt + 1}/20)")
                time.sleep(5)
        # No /sandbox chown: OpenShell 0.1.x runs the workload without
        # capabilities (root in the container cannot even read /sandbox) and
        # already gives /sandbox to the image's user.
        token = secrets.token_hex(16)
        self.sh.add_secret(token)
        model = sb.model or provider.model or "nvidia/nemotron-3-super-120b-a12b"
        oc_env = ("OPENCLAW_HOME=/sandbox SQLITE_TMPDIR=/sandbox/.openclaw/state "
                  "TMPDIR=/sandbox/.openclaw/state OPENCLAW_NIX_MODE=0")
        # OpenShell 0.1.x: no inference.local. OpenClaw calls the provider's
        # own endpoint with the placeholder key this exec receives in the
        # provider's env var (e.g. NVIDIA_API_KEY); the sandbox proxy puts in
        # the real key only for the profile's endpoints and binaries. The
        # placeholder is read inside the sandbox (\$), never by the installer.
        base_url = provider.base_url or NATIVE_BASE_URLS.get(provider.type, "")
        key_var = PROVIDER_CRED_MAP.get(provider.type, "")
        if not base_url or not key_var:
            log(f"WARN: no native endpoint known for provider type '{provider.type}'; "
                f"set baseUrl on provider '{provider.name}'. Skipping OpenClaw onboarding")
            # The sandbox still has to stay Ready after the installer exits.
            self.install_keepalive(ws, sb)
            return
        # key_var is a constant (PROVIDER_CRED_MAP); everything that comes from
        # the profile or a Secret is quoted for the sandbox's shell.
        onboarded = self.cli(*exec_cmd, "sh", "-c",
                 f"{oc_env} CUSTOM_API_KEY=\"${key_var}\" openclaw onboard --non-interactive "
                 "--accept-risk --mode local --auth-choice custom-api-key "
                 f"--custom-base-url {shlex.quote(base_url)} "
                 f"--custom-provider-id {shlex.quote(provider.type)} "
                 f"--custom-model-id {shlex.quote(model)} "
                 "--custom-compatibility openai --skip-channels --skip-health", check=False)
        # Re-onboarding an existing sandbox with a different provider or model
        # (e.g. after switching to a custom endpoint) makes OpenClaw save the
        # new credential but keep the old connection; activate the new one.
        profile_id = openclaw_replacement_profile(onboarded.out + "\n" + onboarded.err)
        if profile_id:
            log(f"Activating the new OpenClaw credential '{profile_id}'")
            self.cli(*exec_cmd, "sh", "-c",
                     f"{oc_env} openclaw models auth activate {shlex.quote(profile_id)} --agent main",
                     check=False)
        self.cli(*exec_cmd, "sh", "-c",
                 f"{oc_env} openclaw config set gateway.auth.token {shlex.quote(token)}",
                 check=False)
        self.configure_harness(ws, sb, exec_cmd, oc_env)
        route = self.cfg.get("sandboxDashboardRoute")
        if route:
            origins = shlex.quote(json.dumps([f"https://{route}"]))
            self.cli(*exec_cmd, "sh", "-c",
                     f"{oc_env} openclaw config set gateway.controlUi.allowedOrigins {origins}",
                     check=False)
        self.cli(*exec_cmd, "sh", "-c",
                 f"export OPENCLAW_GATEWAY_TOKEN={token} {oc_env} && "
                 "nohup openclaw gateway run --allow-unconfigured --bind lan --port 18789 "
                 "> /tmp/openclaw-gateway.log 2>&1 &",
                 check=False)
        self.install_keepalive(ws, sb)

    def configure_harness(self, ws, sb, exec_cmd, oc_env):
        """Point OpenClaw at the mounted bundle (openclaw_harness_config).

        Config only: the bundle's files reach the sandbox through the mount,
        never through exec, and no key is written: a governed plugin or MCP
        server gets its provider's placeholder from the sandbox environment.
        The values depend only on the bundle's shape (plugin.json, skills/,
        plugins/), so a refilled volume normally leaves them unchanged.
        """
        info = self.harness_info.get((ws.name, sb.name))
        if info is None:
            return
        for key, value in openclaw_harness_config(info).items():
            self.cli(*exec_cmd, "sh", "-c",
                     f"{oc_env} openclaw config set {key} {shlex.quote(json.dumps(value))}",
                     check=False)

    def verify_harness(self, ws, sb):
        """The sandbox mounts exactly its harness volume, the volume holds
        the pinned source intact, and the sandbox reads it through the mount
        (the marker file, which names the source and tree digest)."""
        if self.sh.dry_run:
            return []
        source, _ = self.harness_source(sb)
        if source is None:
            if not self.harness_mount_ok(ws, sb):
                return [f"{HARNESS_MOUNT} is still mounted although the sandbox has no "
                        "harnessRef; the next apply recreates the sandbox"]
            return []
        volume = harness_volume_name(ws.name, sb.name)
        failures = self.volumes.verify(volume, ws.name, source)
        if failures:
            return failures
        if not self.harness_mount_ok(ws, sb):
            return [f"{HARNESS_MOUNT} is not mounted from volume {volume}; "
                    "the next apply recreates the sandbox"]
        expected = (Path(self.volumes.inspect(volume)["Mountpoint"]) / HARNESS_MARKER).read_bytes()
        seen = self.cli("sandbox", "exec", "-n", sb.name, *ws_args(ws.name), "--no-tty", "--",
                        "cat", f"{HARNESS_MOUNT}/{HARNESS_MARKER}", check=False, quiet=True)
        if not seen.ok or seen.out.strip() != expected.decode("utf-8", "replace").strip():
            return [f"the sandbox does not see {source} at {HARNESS_MOUNT}"]
        return []

    def cleanup_harness_volumes(self):
        """Remove harness volumes that no enabled sandbox wants any more (a
        harnessRef removed, a sandbox disabled or pruned). podman refuses to
        remove a volume a container still uses, so one still mounted stays
        until that sandbox is gone."""
        if self.sh.dry_run:
            return
        listed = self._podman("volume", "ls", "--format", "{{.Name}}", check=False, quiet=True)
        if not listed.ok:
            return
        for volume in (listed.out or "").split():
            if volume.startswith(HARNESS_VOLUME_PREFIX) and volume not in self.harness_volumes:
                if self.volumes.remove(volume):
                    log(f"Removed harness volume {volume}; no sandbox uses it any more")

    def install_keepalive(self, ws, sb):
        """A system unit that keeps an exec session open so the sandbox stays
        Ready after the installer exits (same as the old setup Job)."""
        user = self.cfg["runtimeUser"]
        service = f"openshell-sandbox-{sb.name}"
        flags = " ".join(ws_args(ws.name))
        unit = (f"[Unit]\nDescription=OpenShell sandbox keep-alive for {sb.name}\n"
                f"After=network-online.target\n\n"
                f"[Service]\nType=simple\nUser={user}\n"
                f"ExecStart=/usr/local/bin/openshell sandbox exec -n {sb.name} {flags} "
                f"--no-tty -- sleep infinity\nRestart=always\nRestartSec=5\n\n"
                f"[Install]\nWantedBy=multi-user.target\n")
        self.sh.run(["sudo", "-n", "tee", f"/etc/systemd/system/{service}.service"],
                    input_text=unit, check=False, quiet=True)
        self.sh.run(["sudo", "-n", "systemctl", "daemon-reload"], check=False)
        self.sh.run(["sudo", "-n", "systemctl", "enable", "--now", service], check=False)

    def apply_sandbox(self, ws, sb):
        provider = self.find_provider(ws, sb.providers)
        if provider is None and sb.type in ("nemoclaw", "openclaw"):
            log(f"WARN: no usable provider for {sb.type} sandbox '{sb.name}'; "
                "creating it without agent onboarding")
            self.create_sandbox(ws, sb)
            return
        if sb.type == "nemoclaw":
            # Onboard once: on later boots the sandbox exists and nemoclaw
            # refuses to attach to the already running gateway.
            if self.sandbox_state(ws, sb) == "running":
                log(f"Sandbox '{sb.name}' already onboarded; skipping nemoclaw onboard")
            elif not self.onboard_nemoclaw(ws, sb, provider):
                log(f"nemoclaw onboard failed for '{sb.name}'; continuing with plain sandbox create")
            self.create_sandbox(ws, sb)
            self.start_openclaw(ws, sb, provider)
        elif sb.type == "openclaw":
            self.create_sandbox(ws, sb)
            self.start_openclaw(ws, sb, provider)
        else:
            self.create_sandbox(ws, sb)

    # -- orchestration ---------------------------------------------------

    def apply(self, profiles):
        if not any(True for _ in enabled_workspaces(profiles)):
            raise InstallerError(
                "profile ConfigMap is missing or empty; refusing to change the gateway")
        self.register_gateway()
        for profile, ws in enabled_workspaces(profiles):
            self.profile_name = profile.name
            banner(f"Profile {profile.name} / workspace {ws.name}")
            self.apply_workspace(ws)
            for provider in ws.providers:
                if provider.enabled:
                    self.apply_provider(ws, provider)
            for sb in ws.sandboxes:
                if sb.enabled:
                    self.apply_sandbox(ws, sb)
                else:
                    log(f"Sandbox '{sb.name}' disabled, skipping")
        self.finish_prune()
        self.cleanup_harness_volumes()

    def finish_prune(self):
        if self.ledger is None or self.prune_mode == "off":
            return
        if not self.ledger.data.get("adopted"):
            for (kind, workspace, name), profile in sorted(self.desired.items()):
                self.ledger.add(kind, workspace, name, profile, adopted=True)
            self.ledger.data["adopted"] = True
            self.ledger.data["lastPrune"] = {"pruned": [], "wouldPrune": []}
            self.ledger.save()
            log("adopted objects that match the current profiles; pruning nothing on the first run")
            return
        for (kind, workspace, name), profile in self.desired.items():
            self.ledger.add(kind, workspace, name, profile, adopted=False)
        if self.skipped:
            # A provider skipped this run (the gateway briefly had no
            # profile for its type) must not turn into deletions: the
            # desired state this run is incomplete, not smaller on purpose
            # (PR #54 review, 6b).
            log(f"WARN: not pruning this run: {len(self.skipped)} provider(s) were skipped "
                "(gateway briefly missing a provider profile for their type)")
            self.ledger.data["lastPrune"] = {"pruned": [], "wouldPrune": [],
                                             "skipped": "providers were skipped this run"}
            self.ledger.save()
            return
        self.prune()

    def managed_label_ok(self, kind, workspace, name, entry):
        """Workspaces and sandboxes also carry saw.redhat.com/managed=true.

        Adopted objects predate that label, so the ledger alone allows them.
        Providers cannot be labeled.
        """
        if entry.get("adopted") or kind not in ("workspace", "sandbox"):
            return True
        if kind == "sandbox":
            got = self.cli("sandbox", "get", name, *ws_args(workspace), check=False, quiet=True)
        else:
            got = self.cli("workspace", "get", name, check=False, quiet=True)
        return got.ok and MANAGED_LABEL in (got.out + got.err)

    def workspace_contents(self, name):
        """Sandboxes and providers still in the workspace, used to decide
        whether it is safe to delete. A failed listing must not look like
        'empty': fail safe by reporting an opaque marker so the caller keeps
        the workspace instead of silently deleting a non-empty one because a
        command errored (PR #54 review, 8). Providers are checked too, not
        only sandboxes: a hand-created provider with no sandbox otherwise
        made the workspace look empty."""
        contents = []
        sandboxes = self.cli("sandbox", "list", "--workspace", name, check=False, quiet=True)
        if not sandboxes.ok:
            contents.append("(sandbox listing failed)")
        else:
            for line in re.sub(r"\x1b\[[0-9;]*m", "", sandboxes.out).splitlines():
                line = line.strip()
                if not line or line.lower().startswith("name"):
                    continue
                contents.append(line.split()[0])
        providers = self.cli("provider", "list", "--workspace", name, check=False, quiet=True)
        if not providers.ok:
            contents.append("(provider listing failed)")
        else:
            for line in re.sub(r"\x1b\[[0-9;]*m", "", providers.out).splitlines():
                line = line.strip()
                if not line or line.lower().startswith("name"):
                    continue
                contents.append(f"provider {line.split()[0]}")
        return contents

    def delete_managed(self, kind, workspace, name):
        if kind == "sandbox":
            self.cli("sandbox", "delete", name, *ws_args(workspace), check=False)
        elif kind == "provider":
            self.cli("provider", "delete", name, *ws_args(workspace), check=False)
        elif kind == "profile":
            self.cli("provider", "profile", "delete", name, *ws_args(workspace), check=False)
        elif kind == "workspace":
            if name == "default":
                log("keeping workspace 'default'")
                return False
            left = self.workspace_contents(name)
            if left:
                log(f"WARN: keeping workspace '{name}'; it still contains: {', '.join(left)}")
                return False
            self.cli("workspace", "delete", name, check=False)
        return True

    def kept_sandbox_providers(self):
        """(workspace, provider-name) pairs, and workspaces, still needed by
        a sandbox this run is keeping (desired, or retained because
        prune.sandboxes is false). Removing a workspace from a profile must
        not delete the provider or inference route a kept sandbox in it
        still uses, even though the sandbox object itself is correctly left
        alone (PR #54 review, 6c)."""
        providers, workspaces = set(), set()
        for obj in self.ledger.data["objects"]:
            if obj["kind"] != "sandbox":
                continue
            workspace, name = obj.get("workspace", ""), obj["name"]
            identity = ("sandbox", workspace, name)
            if identity not in self.desired and self.prune_sandboxes:
                continue    # this sandbox is actually going to be deleted
            workspaces.add(workspace)
            listed = self.cli("sandbox", "provider", "list", name, *ws_args(workspace),
                              check=False, quiet=True)
            if listed.ok:
                for provider_name in re.sub(r"\x1b\[[0-9;]*m", "", listed.out).split():
                    providers.add((workspace, provider_name))
            else:
                # Fail safe like workspace_contents: a failed listing must
                # not look like "this sandbox uses nothing", or every
                # provider in its workspace becomes prunable (PR #54
                # review round 2, 3). Protect everything the ledger knows
                # about in that workspace instead of guessing.
                for other in self.ledger.data["objects"]:
                    if other["kind"] == "provider" and other.get("workspace", "") == workspace:
                        providers.add((workspace, other["name"]))
        return providers, workspaces

    def prune(self):
        """Ledger entries that this apply did not want."""
        kept_providers, _ = self.kept_sandbox_providers()
        pruned, would = [], []
        for kind in PRUNE_ORDER:
            for obj in list(self.ledger.data["objects"]):
                if obj["kind"] != kind:
                    continue
                workspace, name = obj.get("workspace", ""), obj["name"]
                identity = (obj["kind"], workspace, name)
                if identity in self.desired:
                    continue
                if kind == "sandbox" and not self.prune_sandboxes:
                    log(f"keeping sandbox '{name}' in '{workspace}' "
                        "(prune.sandboxes is false)")
                    continue
                if kind == "provider" and (workspace, name) in kept_providers:
                    log(f"keeping provider '{name}' in '{workspace}': a sandbox this apply "
                        "is keeping still uses it")
                    continue
                if not self.managed_label_ok(kind, workspace, name, obj):
                    log(f"keeping {kind} '{name}': not labeled {MANAGED_LABEL}")
                    continue
                label = f"{kind} {workspace or '-'}/{name}"
                if self.prune_mode == "report":
                    log(f"would delete {label}")
                    would.append(label)
                    continue
                if self.prune_mode != "on":
                    continue
                if self.delete_managed(kind, workspace, name):
                    log(f"deleted {label}")
                    pruned.append(label)
                    self.ledger.drop(kind, workspace, name)
        self.ledger.data["lastPrune"] = {"pruned": pruned, "wouldPrune": would}
        self.ledger.save()

    def verify(self, profiles):
        banner("Verification")
        failures = []
        listed = self.cli("workspace", "list", check=False, quiet=True)
        for profile, ws in enabled_workspaces(profiles):
            if ws.name != "default" and not re.search(rf"(^|\s){re.escape(ws.name)}(\s|$)", listed.out, re.M):
                failures.append(f"workspace '{ws.name}' is missing")
            for p in self.usable(ws):
                if not self.cli("provider", "get", p.name, *ws_args(ws.name),
                                              check=False, quiet=True).ok:
                    failures.append(f"provider '{p.name}' in '{ws.name}' is missing")
            for sb in ws.sandboxes:
                if not sb.enabled:
                    continue
                if not self.cli("sandbox", "get", sb.name, *ws_args(ws.name), check=False, quiet=True).ok:
                    failures.append(f"sandbox '{sb.name}' in '{ws.name}' is missing")
                    continue
                if sb.type in ("openclaw", "nemoclaw"):
                    # The agent setup steps are best effort; this is what
                    # catches an image whose OpenClaw cannot run under the
                    # sandbox policy (found live: /opt/openclaw was denied).
                    ran = self.cli("sandbox", "exec", "-n", sb.name, *ws_args(ws.name), "--no-tty",
                                   "--", "sh", "-c", "openclaw --version", check=False, quiet=True)
                    if not ran.ok:
                        detail = (ran.err or ran.out).strip().splitlines()[-1:] or [f"exit {ran.rc}"]
                        failures.append(f"openclaw cannot run in sandbox '{sb.name}': {detail[0]}")
                if sb.type in ("openclaw", "nemoclaw") and sb.providers and \
                        self.find_provider(ws, sb.providers) is None:
                    # All of the agent's providers were skipped (e.g. no
                    # provider profile for their type): it has no model.
                    skipped = ", ".join(f"{p.name} ({p.type})" for p in ws.providers
                                        if p.name in sb.providers)
                    failures.append(f"{sb.type} sandbox '{sb.name}' in '{ws.name}' has no usable "
                                    f"provider: skipped {skipped}; the gateway has no profile for that type")
                failures += [f"harness in sandbox '{sb.name}': {f}"
                             for f in self.verify_harness(ws, sb)]
                if sb.providers:
                    attached = self.cli("sandbox", "provider", "list", sb.name, *ws_args(ws.name),
                                        check=False, quiet=True).out
                    for name in sb.providers:
                        if (ws.name, name) not in self.skipped and name not in attached:
                            failures.append(f"sandbox '{sb.name}' is missing provider '{name}'")
        for ws_name, name in sorted(self.skipped):
            log(f"SKIP  provider '{name}' in '{ws_name}': no provider profile on the gateway")
        for failure in failures:
            log(f"FAIL  {failure}")
        if not failures:
            log("PASS  all workspaces, providers and sandboxes present")
        return failures


def setup_dashboard(shell, cfg, script, home):
    """Run the dashboard setup script as the runtime user.

    The oauth2-proxy cookie secret is created once and kept, so re-running
    the installer does not log everyone out."""
    dash = cfg.get("dashboard") or {}
    if not dash.get("enabled"):
        return
    if not cfg.get("oidcIssuer") or not dash.get("redirectUrl"):
        log("Dashboard skipped: needs oidcIssuer and a webui route host (set global.clusterDomain or route.webuiHost)")
        return
    cookie_file = Path(home) / ".config" / "openshell" / "dashboard-cookie-secret"
    if shell.dry_run:
        cookie = "dry-run"
    elif cookie_file.exists():
        cookie = cookie_file.read_text(encoding="utf-8").strip()
    else:
        cookie_file.parent.mkdir(parents=True, exist_ok=True)
        cookie = secrets.token_hex(16)
        cookie_file.write_text(cookie, encoding="utf-8")
        os.chmod(cookie_file, 0o600)
    shell.add_secret(cookie)
    result = shell.run(["bash", str(script)], check=False, timeout=600, env={
        "RUNTIME": "podman",
        "DASHBOARD_ENABLED": "true",
        "DASHBOARD_IMAGE": dash["image"],
        "DASHBOARD_PROXY_IMAGE": dash["proxyImage"],
        "DASHBOARD_CLIENT_ID": dash["clientId"],
        "DASHBOARD_COOKIE_SECRET": cookie,
        "DASHBOARD_REDIRECT_URL": dash["redirectUrl"],
        "DASHBOARD_INSECURE_SKIP_TLS": str(bool(dash.get("insecureSkipTlsVerify"))).lower(),
        "OIDC_ISSUER": cfg["oidcIssuer"],
    })
    if not result.ok:
        log("WARN: dashboard setup failed (the workspaces are still usable)")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

class Inputs:
    def __init__(self, root, installer_dir=None):
        """installer_dir overrides where the BOM/config/apply_bom.py/dashboard
        script are read from: the golden image's verify-bundle stages and
        verifies them outside the live mount before install/apply/reconcile
        ever runs, and always execs apply_bom.py from that staged copy
        (/var/lib/saw/verified/installer by default). profiles/secrets are
        intentionally still read live from root: they are not part of the
        signed bundle and are meant to change without a restart
        (PR #54 review, 2)."""
        self.root = Path(root)
        self.installer = Path(installer_dir) if installer_dir else self.root / "installer"
        self.bom = self.installer / "installer-bom.yaml"
        self.config = self.installer / "config.json"
        self.dashboard_script = self.installer / "setup-dashboard.sh"
        self.profiles = self.root / "profiles"
        self.secrets = self.root / "secrets"

    def load(self):
        """Load and validate everything. Nothing is changed."""
        bom = load_bom(self.bom)
        cfg = load_config(self.config)
        profile_files, harness_files, index = read_profile_files(self.profiles)
        profiles = parse_profiles(profile_files)
        validate_profiles(profiles)
        check_profiles_against_bom(profiles, bom)
        creds = resolve_credentials(profiles, self.secrets)
        bundles = parse_harness_files(harness_files)
        check_harness_index(bundles, index)
        revisions = validate_harness(profiles, bundles)
        if revisions:
            check_driver_config_allowed(self.installer / "gateway.toml")
        harness = {"bundles": bundles, "revisions": revisions}
        return bom, cfg, profiles, creds, harness


class Status:
    """status.json has one section per step, so `install` and `apply` can be
    run and inspected separately. The `ready` marker (used by the optional
    VM readiness probe) exists only when both steps succeeded for the same
    BOM."""

    def __init__(self, state_dir, step, dry_run=False):
        self.path = Path(state_dir) / "status.json"
        self.ready = Path(state_dir) / "ready"
        self.step = step
        self.dry_run = dry_run

    def read(self):
        return read_json(self.path, {})

    def set(self, phase, bom=None, message="", signature=None, pruned=None, would_prune=None, extra=None):
        log(f"{self.step}: {phase}{' - ' + message if message else ''}")
        if self.dry_run:
            return
        data = self.read()
        section = {
            "phase": phase, "bom": bom, "message": message,
            "installerVersion": INSTALLER_VERSION,
            "updatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **(extra or {}),
        }
        if signature:
            section["signature"] = signature
        if pruned is not None:
            section["pruned"] = pruned
        if would_prune is not None:
            section["wouldPrune"] = would_prune
        data[self.step] = section
        write_json_atomic(self.path, data)
        install, apply = data.get("install", {}), data.get("apply", {})
        is_ready = (install.get("phase") == "Done" and apply.get("phase") == "Done"
                    and install.get("bom") == apply.get("bom"))
        if is_ready:
            self.ready.write_text(f"{bom}\n", encoding="utf-8")
        elif self.ready.exists():
            self.ready.unlink()


def cmd_validate(args):
    bom, cfg, profiles, creds, harness = Inputs(args.inputs).load()
    workspaces = [ws.name for _, ws in enabled_workspaces(profiles)]
    log(f"BOM {bom['metadata']['name']}: " + ", ".join(
        f"{c} {e['version']}" for c, e in bom["spec"]["openshell"].items()))
    log(f"VM {cfg['vmName']}: {len(workspaces)} workspace(s) {workspaces}, "
        f"{sum(len(v) for v in creds.values())} credential(s) resolved")
    if harness["bundles"]:
        log(f"harness: {len(harness['bundles'])} bundle(s), revisions "
            f"{harness['revisions']}")
    log("inputs are valid")
    return 0


def runtime_user(cfg, as_current_user):
    """Return (env, wrap) for running things as the runtime user."""
    if as_current_user:
        return dict(os.environ), (lambda argv: argv)
    user = cfg["runtimeUser"]
    _, env = user_env(user)
    return env, (lambda argv: as_user(user, env, argv))


def runtime_home(cfg, as_current_user):
    """(home, (uid, gid)) of the runtime user."""
    if as_current_user:
        return Path(os.environ.get("HOME", str(Path.home()))), None
    import pwd
    info = pwd.getpwnam(cfg["runtimeUser"])
    return Path(info.pw_dir), (info.pw_uid, info.pw_gid)


def cmd_install(args):
    """Step 1 (root): install the BOM's components and start the gateway.

    Needs only the BOM and config; profiles and credentials are not read,
    so a profile mistake can never block a software install."""
    inputs = Inputs(args.inputs, getattr(args, "installer_dir", None))
    state_dir = Path(args.state_dir)
    status = Status(state_dir, "install", dry_run=args.dry_run)
    shell = Shell(dry_run=args.dry_run)
    bom_name = None
    try:
        status.set("Running")
        bom = load_bom(inputs.bom)
        cfg = load_config(inputs.config)
        bom_name = bom["metadata"]["name"]
        installer = ComponentInstaller(shell, args.bin_dir, state_dir / "installed.json",
                                       podman=args.podman, opt_dir=args.opt_dir,
                                       signing_mode=cfg.get("signing", {}).get("mode", "off"))
        state_file = state_dir / "installed.json"
        # A move to a new release series must reset the gateway state even if
        # this run dies after the new binaries are recorded: the pending reset
        # is saved first and cleared only once it is done, so a retry (the
        # recorded version is already the new one) still performs it.
        state = installer.load_state()
        previous = state.get("components", {}).get("gateway", {}).get("version")
        new_version = bom["spec"]["openshell"]["gateway"]["version"]
        if needs_state_reset(previous, new_version) and not state.get("gatewayStateResetPending"):
            state["gatewayStateResetPending"] = {"from": previous, "to": new_version}
            if not args.dry_run:
                write_json_atomic(state_file, state)
        changed = installer.install(bom)
        log(f"changed components: {', '.join(changed) or 'none'}")

        env, wrap = runtime_user(cfg, args.as_current_user)
        home, owner = runtime_home(cfg, args.as_current_user)
        pending = read_json(state_file, {}).get("gatewayStateResetPending") or \
            state.get("gatewayStateResetPending")
        if pending:
            reset_gateway_state(shell, wrap, home, pending["from"], pending["to"],
                                dry_run=args.dry_run)
            done = read_json(state_file, {"components": {}})
            done.pop("gatewayStateResetPending", None)
            done["gatewayRestartPending"] = True
            if not args.dry_run:
                write_json_atomic(state_file, done)
        config_changed = sync_gateway_config(inputs, cfg, args.etc_dir, home, owner,
                                             dry_run=args.dry_run)
        allow_guest_agent_ssh_keys(shell)
        # Remember that a restart is owed until it has actually happened, so
        # a failure between here and the restart cannot leave the old
        # gateway running on a retry.
        state = read_json(state_file, {"components": {}})
        if {"gateway", "supervisor"} & set(changed) or config_changed:
            state["gatewayRestartPending"] = True
            if not args.dry_run:
                write_json_atomic(state_file, state)
        if not args.skip_gateway:
            ensure_gateway(shell, cfg["runtimeUser"], env,
                           restart=bool(state.get("gatewayRestartPending")))
        if state.pop("gatewayRestartPending", None) and not args.dry_run:
            write_json_atomic(state_file, state)
        status.set("Done", bom_name, signature=installer.signatures)
        return 0
    except InstallerError as exc:
        log(f"ERROR: {exc}")
        signature = installer.signatures if "installer" in locals() else None
        status.set("Failed", bom_name, str(exc).splitlines()[0], signature=signature)
        return 1


def provider_profiles(installer_dir):
    """Provider profiles shipped on the installer disk, by profile id
    (provider-profile-<id>.yaml)."""
    found = {}
    for path in sorted(Path(installer_dir).glob("provider-profile-*.yaml")):
        found[path.name[len("provider-profile-"):-len(".yaml")]] = path.read_text(encoding="utf-8")
    return found


def plan_for_user(cfg, profiles, creds, dashboard_script,
                  provider_profile_docs=None, harness=None):
    harness = harness or {}
    return {"config": cfg, "profiles": [asdict(p) for p in profiles],
            "credentials": creds, "dashboardScript": str(dashboard_script),
            "providerProfiles": provider_profile_docs or {},
            "harness": {"bundles": {k: asdict(v) for k, v
                                    in (harness.get("bundles") or {}).items()}}}


def harness_from_plan(data):
    raw = data.get("harness") or {}
    bundles = {}
    for name, b in (raw.get("bundles") or {}).items():
        bundles[name] = HarnessBundle(
            name=b["name"], agent=b["agent"], digest=b["digest"], files=b["files"])
    return {"bundles": bundles}


def profiles_from_plan(data):
    profiles = []
    for p in data["profiles"]:
        workspaces = []
        for w in p["workspaces"]:
            workspaces.append(Workspace(
                name=w["name"], enabled=w["enabled"], description=w["description"],
                providers=[Provider(**x) for x in w["providers"]],
                sandboxes=[Sandbox(**x) for x in w["sandboxes"]]))
        profiles.append(Profile(name=p["name"], workspaces=workspaces))
    return profiles


def cmd_apply(args):
    """Step 2 (root entry): apply the SAW-BOM profiles.

    Refuses to run until `install` has installed this exact BOM. Reads the
    mounted profiles and Secrets as root, then hands the plan to a child
    process running as the runtime user on stdin, so that user never needs
    access to /run/saw."""
    inputs = Inputs(args.inputs, getattr(args, "installer_dir", None))
    state_dir = Path(args.state_dir)
    status = Status(state_dir, "apply", dry_run=args.dry_run)
    bom_name = None
    try:
        status.set("Running")
        bom, cfg, profiles, creds, harness = inputs.load()
        bom_name = bom["metadata"]["name"]
        install = status.read().get("install", {})
        if not args.dry_run and (install.get("phase") != "Done" or install.get("bom") != bom_name):
            raise InstallerError(
                f"install has not finished for BOM {bom_name} "
                f"(install: {install.get('phase') or 'never ran'}"
                f"{' for ' + install['bom'] if install.get('bom') else ''}); run `install` first")

        cfg = dict(cfg)
        prune = dict(cfg.get("prune") or {})
        # The child runs as the runtime user. /var/lib/saw itself stays
        # root-owned (status.json); the ledger lives in a directory that user
        # can write, or the first apply dies with PermissionError.
        _, owner = runtime_home(cfg, args.as_current_user)
        ledger_dir = state_dir / "user"
        if not args.dry_run:
            ledger_dir.mkdir(parents=True, exist_ok=True)
            if owner:
                os.chown(ledger_dir, *owner)
            os.chmod(ledger_dir, 0o700)
        prune["ledgerPath"] = str(ledger_dir / "managed.json")
        cfg["prune"] = prune
        if args.dry_run:
            # Nothing runs in a dry run, so no user switch is needed (the
            # runtime user could not read /run/saw anyway).
            apply_plan(json.loads(json.dumps(plan_for_user(
                cfg, profiles, creds, inputs.dashboard_script,
                provider_profiles(inputs.installer), harness))), True)
            return 0
        else:
            # A root-owned, world-readable copy the runtime user can execute.
            copy_dir = state_dir / "installer"
            copy_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(copy_dir, 0o755)
            script = copy_dir / "apply_bom.py"
            shutil.copyfile(Path(__file__).resolve(), script)
            os.chmod(script, 0o644)
            dash_copy = copy_dir / "setup-dashboard.sh"
            if inputs.dashboard_script.is_file():
                shutil.copyfile(inputs.dashboard_script, dash_copy)
                os.chmod(dash_copy, 0o644)

        _, wrap = runtime_user(cfg, args.as_current_user)
        argv = [sys.executable, str(script), "apply-profiles"]
        plan = json.dumps(plan_for_user(cfg, profiles, creds, dash_copy,
                                        provider_profiles(inputs.installer), harness))
        result = subprocess.run(wrap(argv), input=plan, text=True, check=False)
        if result.returncode != 0:
            raise InstallerError("applying profiles failed; see the log above")
        report = {}
        ledger_path = state_dir / "user" / "managed.json"
        if ledger_path.is_file():
            report = json.loads(ledger_path.read_text(encoding="utf-8")).get("lastPrune") or {}
        status.set("Done", bom_name, pruned=report.get("pruned"),
                   would_prune=report.get("wouldPrune"),
                   extra={"appliedRevision": harness["revisions"]})
        return 0
    except InstallerError as exc:
        log(f"ERROR: {exc}")
        status.set("Failed", bom_name, str(exc).splitlines()[0])
        return 1


def cmd_apply_profiles(args):
    """Runs as the runtime user with the plan on stdin."""
    return apply_plan(json.loads(sys.stdin.read()), args.dry_run)


def apply_plan(data, dry_run):
    cfg = data["config"]
    profiles = profiles_from_plan(data)
    shell = Shell(dry_run=dry_run)
    applier = ProfileApplier(shell, cfg, data["credentials"], data.get("providerProfiles"),
                             harness_from_plan(data))
    if not list(enabled_workspaces(profiles)):
        log("No enabled workspaces in the SAW-BOM profiles; only the gateway entry is configured")
        applier.register_gateway()
    else:
        applier.apply(profiles)
    setup_dashboard(shell, cfg, data["dashboardScript"], os.environ.get("HOME", "~"))
    if dry_run:
        return 0
    failures = applier.verify(profiles)
    if failures:
        raise InstallerError(f"verification failed: {len(failures)} problem(s)")
    return 0


def tree_hash(path):
    """Stable hash of a mounted input tree.

    ConfigMap virtiofs mounts expose keys as symlinks into a ..data directory.
    Names starting with '..' are that implementation and are not hashed.
    """
    path = Path(path)
    digest = hashlib.sha256()
    if not path.is_dir():
        digest.update(b"missing")
        return digest.hexdigest()
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames
                             if not name.startswith("..") and name != "__pycache__")
        for filename in sorted(filenames):
            if filename.startswith("..") or filename.endswith(".pyc"):
                continue
            file_path = Path(dirpath) / filename
            target = file_path.resolve() if file_path.is_symlink() else file_path
            if not target.is_file():
                continue
            digest.update(file_path.relative_to(path).as_posix().encode())
            digest.update(b"\0")
            digest.update(target.read_bytes())
            digest.update(b"\0")
    return digest.hexdigest()


def input_hashes(inputs):
    return {
        "installer": tree_hash(inputs.installer),
        "profiles": tree_hash(inputs.profiles),
        "secrets": tree_hash(inputs.secrets),
    }


def reconcile_actions(current, applied, install_done, apply_done):
    """What reconcile should run.

    An empty applied record after a successful boot is adopted: those inputs
    are already installed. A later change runs install for the installer
    tree and apply for profiles or Secrets.
    """
    if not applied:
        if install_done and apply_done:
            return []
        return ["install", "apply"]
    actions = []
    installer_changed = current.get("installer") != applied.get("installer")
    rest_changed = (current.get("profiles") != applied.get("profiles")
                    or current.get("secrets") != applied.get("secrets"))
    if installer_changed:
        actions.append("install")
    # A BOM or installer-file change is followed by apply, so the new
    # binaries are what the profile step uses. Profile or Secret changes
    # run apply only.
    if installer_changed or rest_changed:
        actions.append("apply")
    return actions


def write_inputs_status(state_dir, current, applied, message):
    path = Path(state_dir) / "status.json"
    data = read_json(path, {})
    data["inputs"] = {
        "applied": applied,
        "current": current,
        "upToDate": current == applied,
        "message": message,
    }
    write_json_atomic(path, data)


# Without a backoff, a reconcile that fails (e.g. a component image is
# briefly unreachable) never updates "applied", so the next timer tick --
# about a minute later, per saw-inputs.timer -- immediately retries the same
# failing, possibly 900s-timeout install or apply, while holding
# /run/saw/lock the whole time (PR #54 review, 10).
RECONCILE_BACKOFF_SECONDS = int(os.environ.get("SAW_RECONCILE_BACKOFF", "300"))


def write_inputs_failure(state_dir, current, message):
    path = Path(state_dir) / "status.json"
    data = read_json(path, {})
    inputs = dict(data.get("inputs") or {})
    inputs.update({
        "current": current,
        "upToDate": False,
        "message": message,
        "lastFailedHash": current,
        "lastFailedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    data["inputs"] = inputs
    write_json_atomic(path, data)


def reconcile_backoff_remaining(data, current):
    """Seconds left in the backoff for this exact input hash, or 0."""
    inputs = data.get("inputs") or {}
    if inputs.get("lastFailedHash") != current or not inputs.get("lastFailedAt"):
        return 0
    try:
        failed_at = datetime.fromisoformat(inputs["lastFailedAt"])
    except ValueError:
        return 0
    elapsed = (datetime.now(timezone.utc) - failed_at).total_seconds()
    return max(0, RECONCILE_BACKOFF_SECONDS - elapsed)


def cmd_reconcile(args):
    """Re-apply virtiofs inputs that changed since the last successful run.

    Like install/apply, reads the installer tree (BOM, config, apply_bom.py
    itself) from the staged, verified copy when --installer-dir is set, not
    the live virtiofs mount -- the golden image's verify-bundle staged and
    checked it moments earlier, in the same systemd unit's ExecStartPre.
    Before this, reconcile ran apply_bom.py straight off the live mount with
    no verification at all (PR #54 review, 2)."""
    inputs = Inputs(args.inputs, getattr(args, "installer_dir", None))
    state_dir = Path(args.state_dir)
    current = input_hashes(inputs)
    data = read_json(state_dir / "status.json", {})
    applied = (data.get("inputs") or {}).get("applied") or {}
    install_done = data.get("install", {}).get("phase") == "Done"
    apply_done = data.get("apply", {}).get("phase") == "Done"
    actions = reconcile_actions(current, applied, install_done, apply_done)
    if not actions:
        record = current if (install_done and apply_done) else applied
        if install_done and apply_done and not applied:
            record = current
        write_inputs_status(state_dir, current, record or current,
                            "inputs are up to date")
        log("reconcile: inputs are up to date")
        return 0
    remaining = reconcile_backoff_remaining(data, current)
    if remaining > 0:
        log(f"reconcile: {', '.join(actions)} failed on this exact input before; "
            f"waiting {int(remaining)}s more (or a further change) before retrying")
        return 0
    log(f"reconcile: running {', '.join(actions)}")
    if "install" in actions and cmd_install(args) != 0:
        write_inputs_failure(state_dir, current, "install failed; see status.install for details")
        return 1
    if "apply" in actions and cmd_apply(args) != 0:
        write_inputs_failure(state_dir, current, "apply failed; see status.apply for details")
        return 1
    write_inputs_status(state_dir, current, current, "applied changed inputs")
    log("reconcile: applied changed inputs")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="In-guest SAW installer (Stage 1)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="check all inputs; changes nothing")
    p_validate.add_argument("--inputs", default=str(DEFAULT_INPUTS))

    for name, help_text in (("install", "step 1 (root): install BOM components, start the gateway"),
                            ("apply", "step 2 (root): apply SAW-BOM profiles as the runtime user"),
                            ("reconcile", "re-run install and/or apply when inputs changed")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--inputs", default=str(DEFAULT_INPUTS))
        p.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
        # Where the BOM/config/apply_bom.py/dashboard script are actually
        # read from. Defaults to <inputs>/installer (the live mount) for
        # backward compatibility; the systemd units point this at the
        # golden image's verify-bundle staging area instead.
        p.add_argument("--installer-dir", default=None)
        p.add_argument("--dry-run", action="store_true")
        # Test hook: run the user part as the current user instead of runuser.
        p.add_argument("--as-current-user", action="store_true", help=argparse.SUPPRESS)
        if name in ("install", "reconcile"):
            p.add_argument("--bin-dir", default="/usr/local/bin")
            p.add_argument("--opt-dir", default="/opt")
            p.add_argument("--podman", default="podman")
            p.add_argument("--etc-dir", default="/etc/openshell")
            p.add_argument("--skip-gateway", action="store_true", help=argparse.SUPPRESS)

    p_apply = sub.add_parser("apply-profiles", help=argparse.SUPPRESS)
    p_apply.add_argument("--dry-run", action="store_true")

    args = parser.parse_args(argv)
    commands = {"validate": cmd_validate, "install": cmd_install,
                "apply": cmd_apply, "reconcile": cmd_reconcile,
                "apply-profiles": cmd_apply_profiles}
    try:
        return commands[args.command](args)
    except InstallerError as exc:
        log(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
