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
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
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
    "sandboxUi": [],
    "sandboxUiProxy": {},
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
    merged["sandboxUi"], merged["sandboxUiProxy"] = check_sandbox_ui(
        merged.get("sandboxUi"), merged.get("sandboxUiProxy"))
    return merged


HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9./:_@-]*$")
USER_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,255}$")


def check_sandbox_ui(entries, proxy):
    """sandboxUi and sandboxUiProxy go into unit files and command lines,
    so everything is checked against a strict pattern."""
    if not isinstance(entries or [], list) or not isinstance(proxy or {}, dict):
        raise InstallerError("installer config: sandboxUi must be a list, sandboxUiProxy an object")
    proxy = dict(proxy or {})
    ports, out = set(), []
    for e in entries or []:
        what = f"installer config: sandboxUi entry {e!r}"
        if not isinstance(e, dict) or not all(NAME_RE.match(str(e.get(k, ""))) for k in ("workspace", "sandbox")):
            raise InstallerError(f"{what}: workspace and sandbox must be DNS labels")
        if not HOST_RE.match(str(e.get("host", ""))):
            raise InstallerError(f"{what}: needs a route host (set global.clusterDomain)")
        for key in ("proxyPort", "forwardPort"):
            if not isinstance(e.get(key), int) or not 1024 <= e[key] <= 65535 or e[key] in ports:
                raise InstallerError(f"{what}: {key} must be a free port from 1024 to 65535")
            ports.add(e[key])
        internal = e["forwardPort"] + FORWARD_INTERNAL_OFFSET
        if internal > 65535 or internal in ports:
            raise InstallerError(f"{what}: forwardPort + {FORWARD_INTERNAL_OFFSET} must be a free port "
                                 "(the relay in front of the forward uses forwardPort)")
        ports.add(internal)
        out.append({k: e[k] for k in ("workspace", "sandbox", "host", "proxyPort", "forwardPort")})
    if out:
        users = proxy.get("allowedUsers") or []
        if not users or not all(isinstance(u, str) and USER_RE.match(u) for u in users):
            raise InstallerError("installer config: sandboxUiProxy.allowedUsers must name the owner "
                                 "(accessControl.owner) and be plain user names")
        if not IMAGE_RE.match(str(proxy.get("image", ""))) or not NAME_RE.match(str(proxy.get("clientId", ""))):
            raise InstallerError("installer config: sandboxUiProxy needs a valid image and clientId")
        target = proxy.get("targetPort", 18789)
        if not isinstance(target, int) or not 1 <= target <= 65535:
            raise InstallerError("installer config: sandboxUiProxy.targetPort must be a port")
    proxy["trustedProxy"] = check_trusted_proxy(proxy.get("trustedProxy"))
    return out, proxy


def check_trusted_proxy(tp):
    """sandboxUiProxy.trustedProxy: OpenClaw trusts the oauth2-proxy's
    X-Forwarded-User instead of asking for its gateway token. Off when absent
    (configs from before this setting)."""
    if tp is None:
        return {"enabled": False}
    if not isinstance(tp, dict) or not isinstance(tp.get("enabled", False), bool) \
            or not isinstance(tp.get("deviceAutoApprove", True), bool):
        raise InstallerError("installer config: sandboxUiProxy.trustedProxy must be "
                             "{enabled: bool, cidrs: [...], deviceAutoApprove: bool}")
    cidrs = tp.get("cidrs", TRUSTED_PROXY_CIDRS)
    if not isinstance(cidrs, list) or not cidrs:
        raise InstallerError("installer config: sandboxUiProxy.trustedProxy.cidrs must be a list of CIDRs")
    for c in cidrs:
        try:
            ipaddress.ip_network(str(c), strict=False)
        except ValueError:
            raise InstallerError(f"installer config: sandboxUiProxy.trustedProxy.cidrs: {c!r} is not a CIDR")
    return {"enabled": tp.get("enabled", False), "cidrs": [str(c) for c in cidrs],
            "deviceAutoApprove": tp.get("deviceAutoApprove", True)}


# Where the proxied requests reach the sandbox's gateway from: `openshell
# forward service` connects to the port inside the sandbox, over loopback.
TRUSTED_PROXY_CIDRS = ["127.0.0.1/32", "::1/128"]
# What a signed-in owner's Control UI device gets without manual pairing.
# The header OpenClaw reads the user from: oauth2-proxy's X-Forwarded-Email
# carries the preferred_username it admitted (see openclaw_gateway_script).
TRUSTED_PROXY_USER_HEADER = "x-forwarded-email"
TRUSTED_PROXY_SCOPES = ["operator.read", "operator.write", "operator.approvals", "operator.questions"]


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


def read_profile_files(directory):
    """Read the flattened saw-bom ConfigMap: profiles__<profile>__<ws>__<file>."""
    directory = Path(directory)
    if not directory.is_dir():
        return {}
    files = {}
    for entry in sorted(directory.iterdir()):
        if entry.name.startswith(".") or not entry.is_file():
            continue  # kubelet/ISO housekeeping entries
        if not (entry.name.startswith("profiles__") and entry.name.endswith(".yaml")):
            # A wrong key layout must not look like "no profiles".
            raise InstallerError(f"unexpected file in the profiles ConfigMap: {entry.name}")
        files[entry.name] = entry.read_text(encoding="utf-8")
    return files


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
                        model=s.get("model", "")))
            profile.workspaces.append(ws)
        profiles.append(profile)
    return profiles


def enabled_workspaces(profiles):
    for profile in profiles:
        for ws in profile.workspaces:
            if ws.enabled:
                yield profile, ws


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
MANAGED_LABEL_KEY = "saw.redhat.com/managed"
# OpenShell 0.0.116 and 0.1.2 print the two kinds differently (confirmed on
# a 0.0.116 guest, and the same in the 0.1.2 CLI): `sandbox get` human text
# is one `key: value` line per label and `--output json` has
# labels[key] == "true"; `workspace get` has no `--output` flag and prints
# `Labels: key=value, ...`.
_MANAGED_LABEL_RE = re.compile(
    r"(?:^|[\s,])saw\.redhat\.com/managed\s*[:=]\s*true\b")
PRUNE_ORDER = ("sandbox", "provider", "profile", "workspace")


def _strip_ansi(text):
    return re.sub(r"\x1b\[[0-9;]*m", "", text or "")


def _managed_label_in_text(text):
    return _MANAGED_LABEL_RE.search(_strip_ansi(text)) is not None


def _managed_label_from_json(text):
    """True or False when `text` is a JSON object, None when it is not JSON."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict):
        return False
    labels = doc.get("labels") or {}
    if not isinstance(labels, dict):
        return False
    return str(labels.get(MANAGED_LABEL_KEY, "")).lower() == "true"


def _cli_rejected_output_flag(text):
    low = _strip_ansi(text).lower()
    return "output" in low and (
        "unexpected argument" in low or "unrecognized" in low or "unknown argument" in low)


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


class ProfileApplier:
    def __init__(self, shell, cfg, creds, provider_profile_docs=None):
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
        """'running', 'broken' (Error/Completed), 'deleting' or 'missing'."""
        state = self.cli("sandbox", "get", sb.name, *ws_args(ws.name), check=False, quiet=True)
        if not state.ok:
            return "missing"
        clean = re.sub(r"\x1b\[[0-9;]*m", "", state.out)
        if re.search(r"Phase:\s*Deleting", clean):
            return "deleting"
        return "broken" if ("Error" in clean or "Phase: Completed" in clean) else "running"

    # Found live after a VM restart: a sandbox reports an error for a while
    # as its supervisor reconnects, then recovers. Recreating it would lose
    # /sandbox, so a broken sandbox gets this long to come back first.
    BROKEN_GRACE_SECONDS = 90
    # `sandbox delete` only accepts the deletion; creating the same name
    # before the cleanup finishes fails with "already exists".
    DELETE_WAIT_SECONDS = 300
    POLL_SECONDS = 5

    def wait_sandbox(self, ws, sb, until, seconds):
        """Poll sandbox_state until until(state) or the time is up; the last state."""
        state = self.sandbox_state(ws, sb)
        deadline = time.monotonic() + (0 if self.sh.dry_run else seconds)
        while not until(state) and time.monotonic() < deadline:
            time.sleep(self.POLL_SECONDS)
            state = self.sandbox_state(ws, sb)
        return state

    def create_sandbox(self, ws, sb):
        state = self.sandbox_state(ws, sb)
        if state == "broken":
            log(f"Sandbox '{sb.name}' reports an error; waiting up to "
                f"{self.BROKEN_GRACE_SECONDS}s for it to recover")
            state = self.wait_sandbox(ws, sb, lambda s: s != "broken", self.BROKEN_GRACE_SECONDS)
        if state == "broken":
            log(f"Sandbox '{sb.name}' is not running; recreating it")
            self.cli("sandbox", "delete", sb.name, *ws_args(ws.name), check=False)
            state = "deleting"
        if state == "deleting":
            # Also a deletion an earlier run started (found live: that run
            # failed on "already exists" and left the sandbox Deleting).
            log(f"Waiting for sandbox '{sb.name}' to be deleted")
            state = self.wait_sandbox(ws, sb, lambda s: s == "missing", self.DELETE_WAIT_SECONDS)
            if state != "missing":
                raise InstallerError(f"sandbox '{sb.name}' was still being deleted after "
                                     f"{self.DELETE_WAIT_SECONDS}s; the next apply recreates it")
        if state == "running":
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

    EXEC_READY_SECONDS = 300

    def wait_exec_ready(self, ws, sb):
        """Wait until `sandbox exec` works. Found live after a VM restart:
        `sandbox get` already mentioned Ready while the phase was still
        Provisioning, every exec failed with "not ready", and the OpenClaw
        gateway was never started."""
        if self.sh.dry_run:
            return True
        deadline = time.monotonic() + self.EXEC_READY_SECONDS
        attempt = 0
        while True:
            probe = self.cli("sandbox", "exec", "-n", sb.name, *ws_args(ws.name), "--no-tty", "--",
                             "true", check=False, quiet=True)
            if probe.ok:
                return True
            if time.monotonic() >= deadline:
                log(f"WARN: sandbox '{sb.name}' did not accept exec within {self.EXEC_READY_SECONDS}s")
                return False
            attempt += 1
            if attempt % 6 == 1:
                log(f"  waiting for sandbox '{sb.name}' to be ready")
            time.sleep(self.POLL_SECONDS)

    def start_openclaw(self, ws, sb, provider):
        """Onboard openclaw inside the sandbox and start its web gateway.
        These steps are best effort, as before; verification decides."""
        exec_cmd = ["sandbox", "exec", "-n", sb.name, *ws_args(ws.name), "--no-tty", "--"]
        self.wait_exec_ready(ws, sb)
        # No /sandbox chown: OpenShell 0.1.x runs the workload without
        # capabilities (root in the container cannot even read /sandbox) and
        # already gives /sandbox to the image's user.
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
                     f"{oc_env} openclaw models auth activate {profile_id} --agent main", check=False)
        # One script: the gateway secret is made and kept inside the sandbox
        # (the installer never sees it), and the gateway is restarted so a
        # changed auth mode or origin list takes effect.
        self.cli(*exec_cmd, "sh", "-c", openclaw_gateway_script(self.cfg, ws.name, sb.name, oc_env),
                 check=False)
        self.install_keepalive(ws, sb)

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
        Providers cannot be labeled. A missing object or a get that fails
        for any other reason stays unlabeled: prune keeps it rather than
        deleting something it could not identify.
        """
        if entry.get("adopted") or kind not in ("workspace", "sandbox"):
            return True
        if kind == "sandbox":
            return self._sandbox_labeled(workspace, name)
        got = self.cli("workspace", "get", name, check=False, quiet=True)
        return got.ok and _managed_label_in_text(got.out + "\n" + got.err)

    def _sandbox_labeled(self, workspace, name):
        got = self.cli("sandbox", "get", name, *ws_args(workspace),
                       "--output", "json", check=False, quiet=True)
        if got.ok:
            parsed = _managed_label_from_json(got.out)
            if parsed is None:
                return _managed_label_in_text(got.out + "\n" + got.err)
            return parsed
        # A CLI that predates `--output` rejects the flag. Retry the human
        # text, which is `key: value`. Any other failure (not found, auth)
        # is unlabeled.
        blob = got.out + "\n" + got.err
        if not _cli_rejected_output_flag(blob):
            return False
        got = self.cli("sandbox", "get", name, *ws_args(workspace), check=False, quiet=True)
        return got.ok and _managed_label_in_text(got.out + "\n" + got.err)

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
        """Delete one ledger object. False leaves it in the ledger.

        A failed CLI delete must not look like success: prune() would log
        `deleted`, record it in lastPrune (and therefore status.json), and
        drop the ledger entry while the object is still on the gateway.
        """
        if kind == "sandbox":
            result = self.cli("sandbox", "delete", name, *ws_args(workspace), check=False)
        elif kind == "provider":
            result = self.cli("provider", "delete", name, *ws_args(workspace), check=False)
        elif kind == "profile":
            result = self.cli("provider", "profile", "delete", name, *ws_args(workspace), check=False)
        elif kind == "workspace":
            if name == "default":
                log("keeping workspace 'default'")
                return False
            left = self.workspace_contents(name)
            if left:
                log(f"WARN: keeping workspace '{name}'; it still contains: {', '.join(left)}")
                return False
            result = self.cli("workspace", "delete", name, check=False)
        else:
            log(f"WARN: keeping {kind} '{name}': unknown kind; leaving it in the ledger")
            return False
        if not result.ok:
            where = f" in '{workspace}'" if workspace else ""
            log(f"WARN: keeping {kind} '{name}'{where}: delete failed; leaving it in the ledger")
            return False
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


def sandbox_ui_origins(cfg, workspace, sandbox):
    """https origins the sandbox's OpenClaw control UI is opened from: the
    legacy dashboard route, and the sandbox's own UI route (sandboxUi)."""
    origins = []
    if cfg.get("sandboxDashboardRoute"):
        origins.append(f"https://{cfg['sandboxDashboardRoute']}")
    for e in cfg.get("sandboxUi") or []:
        if e.get("workspace") == workspace and e.get("sandbox") == sandbox and e.get("host"):
            origins.append(f"https://{e['host']}")
    return origins


def sandbox_ui_trusted_users(cfg, workspace, sandbox):
    """The users OpenClaw takes from the oauth2-proxy's X-Forwarded-User, or
    None when the sandbox keeps token auth: it has no UI route, or
    sandboxUiProxy.trustedProxy is off."""
    proxy = cfg.get("sandboxUiProxy") or {}
    if not (proxy.get("trustedProxy") or {}).get("enabled"):
        return None
    if not any(e.get("workspace") == workspace and e.get("sandbox") == sandbox
               for e in cfg.get("sandboxUi") or []):
        return None
    return list(proxy.get("allowedUsers") or [])


# The gateway's config file (OPENCLAW_HOME=/sandbox). `openclaw config get`
# redacts secrets, so the existing one is read from the file.
OPENCLAW_CONFIG = "/sandbox/.openclaw/openclaw.json"
_READ_SECRET_JS = ('try{const a=(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).gateway||{}).auth||{};'
                   'const t=[a.password,a.token].find(v=>typeof v==="string"&&/^[A-Za-z0-9_-]{16,}$/.test(v));'
                   'if(t)process.stdout.write(t)}catch(e){}')
# Writes gateway.auth.password ($SAW_GATEWAY_SECRET) into the config file.
# Found live (OpenClaw 2026.9.x, openclaw/openclaw#162216): `config set`
# removes the password as "inactive" in trusted-proxy mode, although the
# gateway accepts it from local clients that send no forwarded headers
# (openclaw/openclaw#82607). Without it the CLI got "device-required".
_WRITE_PASSWORD_JS = ('const fs=require("fs"),f=process.argv[1];const c=JSON.parse(fs.readFileSync(f,"utf8"));'
                      'c.gateway=c.gateway||{};c.gateway.auth=c.gateway.auth||{};'
                      'c.gateway.auth.password=process.env.SAW_GATEWAY_SECRET;'
                      'fs.writeFileSync(f,JSON.stringify(c,null,2)+"\\n",{mode:0o600})')
_NEW_SECRET_JS = 'process.stdout.write(require("crypto").randomBytes(24).toString("hex"))'
# Stops a running gateway (a re-run must apply the new config). /proc, not
# pkill: the sandbox image need not have procps. Shells are skipped: this
# script's own `sh -c` (and any wrapper running it) contains the pattern.
_STOP_GATEWAY_SH = (
    'for d in /proc/[0-9]*; do c=$(tr "\\000" " " < "$d/cmdline" 2>/dev/null) || continue; '
    'case "$c" in *"sh -c "*) continue;; esac; '
    'case "$c" in *"openclaw gateway run"*|openclaw-gateway*) kill "${d#/proc/}" 2>/dev/null;; esac; '
    'done; sleep 2')


def openclaw_gateway_script(cfg, workspace, sandbox, oc_env):
    """The sandbox shell script that configures and (re)starts OpenClaw's
    gateway on 0.0.0.0:18789.

    The gateway secret is kept across runs (read from the config file, made
    once), so the CLI, the TUI and a saved UI session keep working.

    Token mode (no UI route, or trustedProxy off): clients present the secret
    as gateway.auth.token.

    Trusted-proxy mode (a UI route behind the owner-only oauth2-proxy): the
    Control UI needs no token. OpenClaw accepts a request only from the
    trusted CIDRs (the forward arrives over loopback) and takes the user from
    X-Forwarded-Email: oauth2-proxy sets it to the Keycloak
    preferred_username it admitted (OIDC_EMAIL_CLAIM), overwriting any value
    the browser sent. (Found live: its X-Forwarded-User is the Keycloak
    subject, a UUID.) allowUsers is the same list the proxy admits, and their
    UI devices are approved without pairing. Local clients (the CLI, the TUI,
    `openclaw agent`) use the same secret as gateway.auth.password."""
    q = shlex.quote
    users = sandbox_ui_trusted_users(cfg, workspace, sandbox)
    run = ("nohup openclaw gateway run --allow-unconfigured "
           "--bind lan --port 18789 > /tmp/openclaw-gateway.log 2>&1 &")
    token_auth = [
        # JSON-quoted: `config set` parses values as JSON5, and a bare hex
        # secret of digits only would become a number.
        "openclaw config set gateway.auth.mode '\"token\"'",
        'openclaw config set gateway.auth.token "\\"$secret\\""',
        "openclaw config unset gateway.auth.trustedProxy >/dev/null 2>&1 || true",
        "openclaw config unset gateway.trustedProxies >/dev/null 2>&1 || true",
    ]
    lines = [
        "set -u",
        f"export {oc_env}",
        f"secret=$(node -e {q(_READ_SECRET_JS)} {OPENCLAW_CONFIG} 2>/dev/null)",
        f'[ -n "$secret" ] || secret=$(node -e {q(_NEW_SECRET_JS)})',
    ]
    if users is None:
        lines += token_auth
    else:
        tp = cfg["sandboxUiProxy"]["trustedProxy"]
        cidrs = tp.get("cidrs") or TRUSTED_PROXY_CIDRS
        basic = {"userHeader": TRUSTED_PROXY_USER_HEADER, "allowUsers": users}
        loopback = {**basic, "allowLoopback": any(ipaddress.ip_network(c, strict=False).is_loopback
                                                  for c in cidrs)}
        full = {**loopback, "deviceAutoApprove": {"enabled": bool(tp.get("deviceAutoApprove", True)),
                                                  "scopes": TRUSTED_PROXY_SCOPES}}
        # Older OpenClaw releases (found live: the NemoClaw image's 2026.7.1)
        # refuse the newer keys, and a refused `config set` left the mode
        # trusted-proxy without its settings: the gateway did not start. So
        # each smaller form is tried in turn, and the mode is switched only
        # once one was saved; otherwise the sandbox keeps token auth.
        lines += [
            f"openclaw config set gateway.trustedProxies {q(json.dumps(cidrs))}",
            "trusted=0",
            f"openclaw config set gateway.auth.trustedProxy {q(json.dumps(full))} && trusted=1",
        ]
        for what, value in (("deviceAutoApprove", loopback), ("allowLoopback", basic)):
            lines += [
                'if [ "$trusted" = 0 ]; then',
                f'echo "WARN: this OpenClaw refused the trusted-proxy settings; trying without {what}"',
                f"openclaw config set gateway.auth.trustedProxy {q(json.dumps(value))} && trusted=1",
                "fi",
            ]
        lines += [
            # The mode after its settings: it is only valid once they are there.
            'if [ "$trusted" = 1 ]; then',
            "openclaw config set gateway.auth.mode '\"trusted-proxy\"'",
            "else",
            'echo "WARN: this OpenClaw refused every trusted-proxy form; the UI keeps token auth"',
            *token_auth,
            "fi",
        ]
    # NemoClaw's image sets OpenClaw's managed proxy to 10.200.0.1:3128,
    # the explicit egress proxy of OpenShell 0.0.x. OpenShell 0.1.x proxies
    # transparently and refuses that address (found live: connect EACCES, so
    # every LLM call failed with "network connection error"). Unset, OpenClaw
    # connects directly and the sandbox's own proxy applies the policy.
    lines.append("openclaw config unset proxy >/dev/null 2>&1 || true")
    origins = sandbox_ui_origins(cfg, workspace, sandbox)
    if origins:
        # The control UI is reached through a route, so the browser's Origin
        # is the route's https URL.
        lines.append(f"openclaw config set gateway.controlUi.allowedOrigins {q(json.dumps(origins))}")
    lines.append(_STOP_GATEWAY_SH)
    if users is None:
        lines.append(f'OPENCLAW_GATEWAY_TOKEN="$secret" {run}')
    else:
        lines += [
            'if [ "$trusted" = 1 ]; then',
            # After the last `config set`, which would remove it again.
            f'SAW_GATEWAY_SECRET="$secret" node -e {q(_WRITE_PASSWORD_JS)} {OPENCLAW_CONFIG} '
            '|| echo "WARN: could not set gateway.auth.password; the CLI needs a paired device"',
            f'OPENCLAW_GATEWAY_PASSWORD="$secret" {run}',
            "else",
            f'OPENCLAW_GATEWAY_TOKEN="$secret" {run}',
            "fi",
        ]
    return "\n".join(lines) + "\n"


SANDBOX_UI_UNIT_RE = re.compile(r"^saw-ui-(forward|limit|proxy)-[a-z0-9-]+\.service$")
# The forward listens on forwardPort + this (VM loopback only); the relay that
# caps its connections listens on forwardPort, where oauth2-proxy sends.
FORWARD_INTERNAL_OFFSET = 10000
# At most this many connections reach `openshell forward service` per UI
# (OpenShell allows 20 per sandbox; the rest are left for exec sessions).
FORWARD_MAX_CONNECTIONS = 16
SANDBOX_UI_LIMIT_PY = r'''"""Caps the connections to `openshell forward service` (SAW sandbox UI).

OpenShell allows 20 concurrent forward connections per sandbox and closes
the rest (RESOURCE_EXHAUSTED, "sandbox SSH connection limit reached",
NVIDIA/OpenShell#3494). A browser loading the OpenClaw control UI through
the route opens more than that at once, and the requests that lost came
back as 502/504 after 30 s. This TCP relay sits between oauth2-proxy and the
forward:

- at most MAX connections reach the forward; the others wait for a free one;
- while some wait, an HTTP keep-alive connection that has been idle for
  IDLE_PREEMPT seconds after an answer is closed to make room (an HTTP
  client opens a new one); WebSocket connections are never closed;
- a connection the forward closes or resets before answering is retried;
- a GET that gets no answer at all within ANSWER_WAIT is sent again on new
  connections, and the first answer wins.

  python3 saw_ui_limit.py LISTEN_PORT UPSTREAM_PORT [MAX]
"""
import asyncio
import sys
import time


def log(message):
    print(message, file=sys.stderr, flush=True)

RETRIES = 8
BUFFER_LIMIT = 1 << 20
ANSWER_WAIT = 2.0       # seconds to wait for a first answer byte before giving up retries
IDLE_PREEMPT = 2.0      # seconds an answered keep-alive connection may hold a slot others wait for
HEDGES = 2              # extra connections for a repeatable request that gets no answer
HEDGE_TOTAL = 25.0      # seconds before giving up on such a request (the router allows 30)


class Conn:
    """One client connection holding (or waiting for) a slot."""

    def __init__(self, websocket):
        self.websocket = websocket
        self.last = time.monotonic()
        self.answered = False       # the forward spoke last: no request in flight
        self.writers = []

    def touch(self, answered):
        self.last = time.monotonic()
        self.answered = answered

    def idle_for(self):
        return time.monotonic() - self.last

    def close(self):
        for w in self.writers:
            try:
                w.transport.abort()
            except Exception:
                pass


class Slots:
    """MAX connections at a time; idle keep-alive ones give way."""

    def __init__(self, limit):
        self.limit = limit
        self.active = set()
        self.cond = asyncio.Condition()

    def victim(self):
        idle = [c for c in self.active
                if not c.websocket and c.answered and c.idle_for() >= IDLE_PREEMPT]
        return min(idle, key=lambda c: c.last) if idle else None

    def describe(self):
        ws = sum(1 for c in self.active if c.websocket)
        busy = sum(1 for c in self.active if not c.websocket and not c.answered)
        idle = sorted(round(c.idle_for(), 1) for c in self.active if not c.websocket and c.answered)
        return (f"{len(self.active)}/{self.limit} in use: {ws} websocket, {busy} awaiting an answer, "
                f"{len(idle)} answered (idle s: {idle})")

    async def acquire(self, conn):
        start = time.monotonic()
        logged = 0.0
        async with self.cond:
            while len(self.active) >= self.limit:
                v = self.victim()
                if v is not None:
                    log(f"closing a keep-alive connection idle {v.idle_for():.1f}s to make room")
                    self.active.discard(v)
                    v.close()
                    break
                waited = time.monotonic() - start
                if waited - logged >= 5:
                    logged = waited
                    log(f"waiting {waited:.0f}s for a slot; {self.describe()}")
                try:
                    await asyncio.wait_for(self.cond.wait(), 0.25)
                except asyncio.TimeoutError:
                    pass
            self.active.add(conn)
        if time.monotonic() - start >= 1:
            log(f"got a slot after {time.monotonic() - start:.1f}s; {self.describe()}")

    async def release(self, conn):
        async with self.cond:
            if conn in self.active:
                self.active.discard(conn)
                self.cond.notify()


async def relay(reader, writer, conn, answered):
    """Copy until EOF, then half-close the other side."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            conn.touch(answered)
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
    except (ConnectionError, OSError):
        pass


async def open_answering(upstream, sent):
    """Connect to the forward and send the client's first bytes; retry when
    the forward closes or resets the connection without answering."""
    for attempt in range(RETRIES + 1):
        try:
            ureader, uwriter = await asyncio.open_connection("127.0.0.1", upstream)
        except OSError:
            await asyncio.sleep(min(1.0, 0.2 * (attempt + 1)))
            continue
        try:
            uwriter.write(sent)
            await uwriter.drain()
            # A refused forward connection closes (or resets) at once. A
            # request still being sent (a large body) gets no answer yet:
            # relay it.
            first = await asyncio.wait_for(ureader.read(65536), ANSWER_WAIT)
        except asyncio.TimeoutError:
            if not hedgeable(sent):
                log(f"no answer within {ANSWER_WAIT:.0f}s ({sent[:60]!r}); relaying without retries")
                return ureader, uwriter, b""
            return await hedge(upstream, sent, ureader, uwriter)
        except (ConnectionError, OSError):
            first = b""
        if first:
            return ureader, uwriter, first
        uwriter.close()
        await asyncio.sleep(min(1.0, 0.2 * (attempt + 1)))
    return None, None, b""


def hedgeable(sent):
    """A complete GET/HEAD request without a body, not a WebSocket upgrade:
    safe to send again on another connection."""
    head = sent.split(b"\r\n\r\n", 1)
    return (len(head) == 2 and not head[1] and sent.split(b" ", 1)[0] in (b"GET", b"HEAD")
            and b"upgrade: websocket" not in sent.lower())


async def hedge(upstream, sent, ureader, uwriter):
    """Found live: a request through the forward sometimes got no answer at
    all (no error, nothing in the forward's log) and the browser saw a 504.
    For a request that is safe to repeat, send it again on new connections
    and keep whichever answers first."""
    pending = {asyncio.ensure_future(ureader.read(65536)): (ureader, uwriter)}
    deadline = time.monotonic() + HEDGE_TOTAL
    for extra in range(HEDGES + 1):
        if extra < HEDGES:
            log(f"no answer within {ANSWER_WAIT:.0f}s ({sent[:60]!r}); sending it again ({extra + 1})")
            try:
                r, w = await asyncio.open_connection("127.0.0.1", upstream)
                w.write(sent)
                await w.drain()
                pending[asyncio.ensure_future(r.read(65536))] = (r, w)
            except (ConnectionError, OSError):
                pass
        wait = ANSWER_WAIT * 2 if extra < HEDGES else max(0.0, deadline - time.monotonic())
        done, _ = await asyncio.wait(pending, timeout=wait, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            r, w = pending.pop(task)
            try:
                data = task.result()
            except (ConnectionError, OSError):
                data = b""
            if data:
                for other, (_, ow) in pending.items():
                    other.cancel()
                    ow.close()
                return r, w, data
            w.close()
    for other, (_, ow) in pending.items():
        other.cancel()
        ow.close()
    log(f"no answer on {HEDGES + 1} connections ({sent[:60]!r})")
    return None, None, b""


def handler(upstream, slots):
    async def handle(creader, cwriter):
        conn = None
        try:
            # The first bytes tell an HTTP request from a WebSocket upgrade,
            # and are what a retry resends.
            sent = await creader.read(65536)
            if not sent:
                return
            conn = Conn(b"upgrade: websocket" in sent.lower())
            conn.writers.append(cwriter)
            await slots.acquire(conn)
            ureader, uwriter, first = await open_answering(upstream, sent)
            if ureader is None:
                log("the forward refused the connection on every retry")
                return
            conn.writers.append(uwriter)
            conn.touch(bool(first))
            if first:
                cwriter.write(first)
                await cwriter.drain()
            await asyncio.gather(relay(creader, uwriter, conn, False),
                                 relay(ureader, cwriter, conn, True))
            uwriter.close()
        except (ConnectionError, OSError):
            pass
        finally:
            if conn is not None:
                await slots.release(conn)
            cwriter.close()
    return handle


async def main(listen, upstream, limit):
    server = await asyncio.start_server(handler(upstream, Slots(limit)), "127.0.0.1", listen,
                                        limit=BUFFER_LIMIT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    listen_port, upstream_port = int(sys.argv[1]), int(sys.argv[2])
    max_conns = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    asyncio.run(main(listen_port, upstream_port, max_conns))
'''



def sandbox_ui_units(cfg, home, cookie, gateway):
    """{unit file name: content} plus {file: content} for every sandbox UI.

    Per entry of cfg["sandboxUi"] (rendered by the openshell-saw chart):
      saw-ui-forward-<ws>-<sb>  `openshell forward service`: VM
                                127.0.0.1:<forwardPort + 10000> to the
                                sandbox's 127.0.0.1:<targetPort> (OpenClaw,
                                listening on 0.0.0.0 in the sandbox)
      saw-ui-limit-<ws>-<sb>    a TCP relay on 127.0.0.1:<forwardPort> that
                                lets at most FORWARD_MAX_CONNECTIONS through
                                to the forward and queues the rest (OpenShell
                                refuses more than 20 per sandbox)
      saw-ui-proxy-<ws>-<sb>    oauth2-proxy on 0.0.0.0:<proxyPort> (what the
                                route reaches) in front of the relay. It
                                signs in with Keycloak (PKCE, the dashboard's
                                public client) and admits only the users in
                                sandbox-ui-users (preferred_username): the
                                workspace owner and sandboxUiProxy.allowedUsers
                                (saw-ui-<ws>-<sb>.users).
    """
    proxy = cfg.get("sandboxUiProxy") or {}
    config_dir = Path(home) / ".config" / "openshell"
    users = "".join(f"{u}\n" for u in proxy.get("allowedUsers") or [])
    units, files = {}, {}
    limiter = config_dir / "saw-ui-limit.py"
    if cfg.get("sandboxUi"):
        files[limiter] = SANDBOX_UI_LIMIT_PY
    for e in cfg.get("sandboxUi") or []:
        tag = f"{e['workspace']}-{e['sandbox']}"
        forward, proxy_unit = f"saw-ui-forward-{tag}.service", f"saw-ui-proxy-{tag}.service"
        env_file = config_dir / f"saw-ui-{tag}.env"
        # One users file per proxy: each container relabels its mount
        # privately (:Z), which a shared file would not survive.
        users_file = config_dir / f"saw-ui-{tag}.users"
        files[users_file] = users
        files[env_file] = "".join(f"{k}={v}\n" for k, v in {
            "OAUTH2_PROXY_HTTP_ADDRESS": f"0.0.0.0:{e['proxyPort']}",
            "OAUTH2_PROXY_UPSTREAMS": f"http://127.0.0.1:{e['forwardPort']}",
            "OAUTH2_PROXY_PROVIDER": "oidc",
            "OAUTH2_PROXY_OIDC_ISSUER_URL": cfg["oidcIssuer"],
            "OAUTH2_PROXY_CLIENT_ID": proxy.get("clientId", "openshell-dashboard"),
            "OAUTH2_PROXY_CLIENT_SECRET_FILE": "/dev/null",
            "OAUTH2_PROXY_CODE_CHALLENGE_METHOD": "S256",
            "OAUTH2_PROXY_REDIRECT_URL": f"https://{e['host']}/oauth2/callback",
            "OAUTH2_PROXY_COOKIE_SECRET": cookie,
            "OAUTH2_PROXY_COOKIE_NAME": f"_saw_ui_{e['proxyPort']}",
            "OAUTH2_PROXY_COOKIE_SECURE": "true",
            "OAUTH2_PROXY_COOKIE_REFRESH": "60s",
            "OAUTH2_PROXY_SCOPE": "openid email profile",
            # Who gets in: the Keycloak username, matched against the file.
            "OAUTH2_PROXY_OIDC_EMAIL_CLAIM": "preferred_username",
            # X-Forwarded-Email (= that username), which OpenClaw's
            # trusted-proxy mode reads; oauth2-proxy overwrites any value the
            # browser sent.
            "OAUTH2_PROXY_PASS_USER_HEADERS": "true",
            "OAUTH2_PROXY_AUTHENTICATED_EMAILS_FILE": "/etc/saw/sandbox-ui-users",
            "OAUTH2_PROXY_INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL": "true",
            "OAUTH2_PROXY_SKIP_PROVIDER_BUTTON": "true",
            "OAUTH2_PROXY_REVERSE_PROXY": "true",
            "OAUTH2_PROXY_SSL_INSECURE_SKIP_VERIFY": str(bool(proxy.get("insecureSkipTlsVerify"))).lower(),
        }.items())
        internal = e["forwardPort"] + FORWARD_INTERNAL_OFFSET
        limit_unit = f"saw-ui-limit-{tag}.service"
        units[forward] = (
            f"[Unit]\nDescription=SAW sandbox UI: forward {e['sandbox']} ({e['workspace']}) port "
            f"{proxy.get('targetPort', 18789)} to 127.0.0.1:{internal}\n\n"
            f"[Service]\nType=simple\n"
            f"ExecStart=/usr/local/bin/openshell --gateway {gateway} forward service {e['sandbox']} "
            f"--workspace {e['workspace']} --target-port {proxy.get('targetPort', 18789)} "
            f"--local 127.0.0.1:{internal}\n"
            f"Restart=always\nRestartSec=5s\n\n[Install]\nWantedBy=default.target\n")
        # Found live: the control UI's burst of requests went past OpenShell's
        # 20 forward connections per sandbox; the refused ones came back as
        # 502/504 after 30 s. The relay queues them instead.
        units[limit_unit] = (
            f"[Unit]\nDescription=SAW sandbox UI: at most {FORWARD_MAX_CONNECTIONS} connections "
            f"from 127.0.0.1:{e['forwardPort']} to the forward of {e['sandbox']} ({e['workspace']})\n"
            f"After={forward}\nWants={forward}\n\n"
            f"[Service]\nType=simple\n"
            f"ExecStart=/usr/bin/python3 {limiter} {e['forwardPort']} {internal} {FORWARD_MAX_CONNECTIONS}\n"
            f"Restart=always\nRestartSec=2s\n\n[Install]\nWantedBy=default.target\n")
        units[proxy_unit] = (
            f"[Unit]\nDescription=SAW sandbox UI: oauth2-proxy for {e['sandbox']} ({e['workspace']}) "
            f"on port {e['proxyPort']}\nAfter={limit_unit}\nWants={limit_unit}\n\n"
            f"[Service]\nType=simple\n"
            f"ExecStartPre=-/usr/bin/podman rm -f saw-ui-proxy-{tag}\n"
            f"ExecStart=/usr/bin/podman run --rm --name saw-ui-proxy-{tag} --network host "
            f"--env-file={env_file} -v {users_file}:/etc/saw/sandbox-ui-users:ro,Z "
            f"{proxy.get('image', 'quay.io/oauth2-proxy/oauth2-proxy:v7.9.0')}\n"
            f"ExecStop=/usr/bin/podman stop -t 5 saw-ui-proxy-{tag}\n"
            f"Restart=on-failure\nRestartSec=5s\n\n[Install]\nWantedBy=default.target\n")
    return units, files


def setup_sandbox_ui(shell, cfg, home):
    """Run a forward and an owner-only oauth2-proxy per sandbox web UI, as
    `systemctl --user` units of the runtime user; remove the units of
    sandboxes that no longer have a UI route. Best effort: a failure here
    leaves the workspaces usable, and verify reports it."""
    entries = cfg.get("sandboxUi") or []
    unit_dir = Path(home) / ".config" / "systemd" / "user"
    existing = set() if shell.dry_run or not unit_dir.is_dir() else {
        p.name for p in unit_dir.iterdir() if SANDBOX_UI_UNIT_RE.match(p.name)}
    units, files = {}, {}
    if entries:
        if not cfg.get("oidcIssuer"):
            log("WARN: sandbox UI routes need oidcIssuer (Keycloak); not starting their proxies")
            entries = []
        else:
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
            units, files = sandbox_ui_units(cfg, home, cookie, cfg.get("mtlsGateway", "saw-installer"))
    stale = sorted(existing - set(units))
    for name in stale:
        log(f"Removing sandbox UI unit {name}; its sandbox no longer has a UI route")
        shell.run(["systemctl", "--user", "disable", "--now", name], check=False)
        if not shell.dry_run:
            (unit_dir / name).unlink(missing_ok=True)
    if not units:
        if stale:
            shell.run(["systemctl", "--user", "daemon-reload"], check=False)
        return
    if not shell.dry_run:
        unit_dir.mkdir(parents=True, exist_ok=True)
        for path, text in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            os.chmod(path, 0o600 if path.suffix == ".env" else 0o644)
        for name, text in units.items():
            (unit_dir / name).write_text(text, encoding="utf-8")
    for e in entries:
        log(f"Sandbox UI: https://{e['host']} -> {e['sandbox']} ({e['workspace']})")
    shell.run(["systemctl", "--user", "daemon-reload"], check=False)
    shell.run(["systemctl", "--user", "enable", *sorted(units)], check=False)
    # restart, not `enable --now`: a running proxy keeps its old env file.
    shell.run(["systemctl", "--user", "restart", *sorted(units)], check=False)


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
        profiles = parse_profiles(read_profile_files(self.profiles))
        validate_profiles(profiles)
        check_profiles_against_bom(profiles, bom)
        creds = resolve_credentials(profiles, self.secrets)
        return bom, cfg, profiles, creds


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

    def set(self, phase, bom=None, message="", signature=None, pruned=None, would_prune=None):
        log(f"{self.step}: {phase}{' - ' + message if message else ''}")
        if self.dry_run:
            return
        data = self.read()
        section = {
            "phase": phase, "bom": bom, "message": message,
            "installerVersion": INSTALLER_VERSION,
            "updatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
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
    bom, cfg, profiles, creds = Inputs(args.inputs).load()
    workspaces = [ws.name for _, ws in enabled_workspaces(profiles)]
    log(f"BOM {bom['metadata']['name']}: " + ", ".join(
        f"{c} {e['version']}" for c, e in bom["spec"]["openshell"].items()))
    log(f"VM {cfg['vmName']}: {len(workspaces)} workspace(s) {workspaces}, "
        f"{sum(len(v) for v in creds.values())} credential(s) resolved")
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


def plan_for_user(cfg, profiles, creds, dashboard_script, provider_profile_docs=None):
    return {"config": cfg, "profiles": [asdict(p) for p in profiles],
            "credentials": creds, "dashboardScript": str(dashboard_script),
            "providerProfiles": provider_profile_docs or {}}


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
        bom, cfg, profiles, creds = inputs.load()
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
                provider_profiles(inputs.installer)))), True)
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
                                        provider_profiles(inputs.installer)))
        result = subprocess.run(wrap(argv), input=plan, text=True, check=False)
        if result.returncode != 0:
            raise InstallerError("applying profiles failed; see the log above")
        report = {}
        ledger_path = state_dir / "user" / "managed.json"
        if ledger_path.is_file():
            report = json.loads(ledger_path.read_text(encoding="utf-8")).get("lastPrune") or {}
        status.set("Done", bom_name, pruned=report.get("pruned"),
                   would_prune=report.get("wouldPrune"))
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
    applier = ProfileApplier(shell, cfg, data["credentials"], data.get("providerProfiles"))
    if not list(enabled_workspaces(profiles)):
        log("No enabled workspaces in the SAW-BOM profiles; only the gateway entry is configured")
        applier.register_gateway()
    else:
        applier.apply(profiles)
    setup_dashboard(shell, cfg, data["dashboardScript"], os.environ.get("HOME", "~"))
    setup_sandbox_ui(shell, cfg, os.environ.get("HOME", "~"))
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
