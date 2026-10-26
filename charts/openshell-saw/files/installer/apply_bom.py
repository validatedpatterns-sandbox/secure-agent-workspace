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
    /run/saw/installer/tool-actions.yaml    consequential-tool policy
    /run/saw/installer/tool-gate.mjs        tool-call decision engine
    /run/saw/installer/tool-gate-plugin.mjs OpenClaw before_tool_call hook
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
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import traceback
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import urlopen

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

# NemoClaw names the NVIDIA API Catalog `build`, OpenShell's profile for it
# is `nvidia`. The BOM uses OpenShell's name; the installer translates for
# `nemoclaw onboard`. `nemoclawProvider` on a provider overrides this.
NEMOCLAW_PROVIDER_MAP = {
    "nvidia": "build",
}


def nemoclaw_provider(provider):
    return provider.nemoclaw_provider or NEMOCLAW_PROVIDER_MAP.get(provider.type, provider.type)


def profile_credential_envs(profile_text):
    """The first env var of each credential a provider profile declares, in
    order (credentials[i].env_vars[0]); "" for a credential without one."""
    try:
        doc = yaml.safe_load(profile_text) if profile_text else None
    except yaml.YAMLError:
        return []
    out = []
    for cred in (doc or {}).get("credentials") or []:
        envs = (cred.get("env_vars") or []) if isinstance(cred, dict) else []
        out.append(envs[0] if envs else "")
    return out


def profile_credentials(profile_text):
    """A provider profile's credentials: [(name, [env vars])], in order."""
    try:
        doc = yaml.safe_load(profile_text) if profile_text else None
    except yaml.YAMLError:
        return []
    out = []
    for cred in (doc or {}).get("credentials") or []:
        if isinstance(cred, dict) and cred.get("name"):
            out.append((str(cred["name"]), [str(e) for e in cred.get("env_vars") or []]))
    return out


def profile_all_credential_envs(profile_text):
    """Every env var any credential of a provider profile is exposed under
    (all of credentials[].env_vars, e.g. GITHUB_TOKEN and GH_TOKEN)."""
    try:
        doc = yaml.safe_load(profile_text) if profile_text else None
    except yaml.YAMLError:
        return set()
    return {env for cred in (doc or {}).get("credentials") or [] if isinstance(cred, dict)
            for env in (cred.get("env_vars") or [])}


def profile_credential_env(profile_text):
    """The primary credential env var a provider profile declares
    (credentials[0].env_vars[0]), or "" when it declares none."""
    envs = profile_credential_envs(profile_text)
    return envs[0] if envs else ""


def credential_env_name(provider_type, profiles):
    """Env var the installer passes a provider's credential through: the one
    the provider's own profile declares, else the built-in default. This lets
    a profile-backed type (github, slack, gmail, ...) work as a provider with
    no PROVIDER_CRED_MAP edit; for the shipped built-ins the two agree."""
    return (profile_credential_env((profiles or {}).get(provider_type, ""))
            or PROVIDER_CRED_MAP.get(provider_type, ""))


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

OPENCLAW_AUTH_CHOICES = {"openai": "openai-api-key", "anthropic": "apiKey"}
# By protocol: the official API an agent talks to when no endpoint is given.
PROTOCOL_NATIVE_BASE_URLS = {"openai": "https://api.openai.com/v1",
                             "anthropic": "https://api.anthropic.com"}


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
            timeout=300, input_text=None, quiet=False, force=False):
        display = self.mask(" ".join(str(c) for c in cmd))
        # force=True: still run this during --dry-run (catalog reads, and the
        # harness image pull/export needed to check it) so governance cannot
        # pass dry-run and fail apply. The image pull is the one exception to
        # "read-only": pulling by digest is deterministic and safe to repeat,
        # but it does write to the local image store.
        if self.dry_run and not force:
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
                  {"installerVersion", "openshell", "nemoclaw", "spireAgent"}, "InstallerBOM spec")
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
    # Helm null / omitted both mean "no nemoclaw component".
    if spec.get("nemoclaw") is not None:
        _require_keys(spec["nemoclaw"], {"cliImage"}, {"cliImage"}, "spec.nemoclaw")
        image = spec["nemoclaw"]["cliImage"]
        # Optional add-on: a tag is accepted (no digest is published for it
        # yet), but only the OpenShell components are guaranteed pinned.
        if not isinstance(image, str) or not IMAGE_RE.match(image):
            raise InstallerError("spec.nemoclaw.cliImage is not a valid image reference")
        if not DIGEST_IMAGE_RE.match(image):
            log(f"WARN: spec.nemoclaw.cliImage {image} is not pinned by digest")
    else:
        spec.pop("nemoclaw", None)
    if spec.get("spireAgent") is not None:
        entry = spec["spireAgent"]
        _require_keys(entry, {"image", "version", "path"}, {"image", "version", "path"}, "spec.spireAgent")
        _check_digest_image(entry["image"], "spec.spireAgent.image")
        if not VERSION_RE.match(entry["version"]) or not entry["path"].startswith("/"):
            raise InstallerError("spec.spireAgent needs a version and absolute binary path")
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
    "ownerSubjectSource": "",
    "sandboxDashboardRoute": "",
    "sandboxUi": [],
    "sandboxUiProxy": {},
    "dashboard": {"enabled": False},
    "signing": {"mode": "off"},
    "prune": {"mode": "off", "sandboxes": False},
    "registry": {"host": "", "caBundle": "", "authSecret": ""},
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
    source = merged["ownerSubjectSource"]
    if source not in ("", "resolved"):
        raise InstallerError("installer config: ownerSubjectSource must be empty or resolved")
    if source == "resolved" and merged["ownerSubject"]:
        raise InstallerError("installer config: resolved owner cannot also have ownerSubject")
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
    registry = merged.get("registry") or {}
    if not isinstance(registry, dict) or set(registry) - {"host", "caBundle", "authSecret"}:
        raise InstallerError("installer config: registry must have host, caBundle, and authSecret only")
    registry = {**CONFIG_DEFAULTS["registry"], **registry}
    host, ca_bundle, auth_secret = (registry[key] for key in ("host", "caBundle", "authSecret"))
    if not all(isinstance(value, str) for value in (host, ca_bundle, auth_secret)):
        raise InstallerError("installer config: registry settings must be strings")
    name, separator, port = host.rpartition(":")
    if host and (not separator or not HOST_RE.fullmatch(name) or not port.isdigit()
                 or not 1 <= int(port) <= 65535):
        raise InstallerError("installer config: registry.host must be a DNS name and port")
    if (ca_bundle or auth_secret) and not host:
        raise InstallerError("installer config: registry.host is required for CA or authentication")
    if auth_secret and not SECRET_NAME_RE.fullmatch(auth_secret):
        raise InstallerError("installer config: registry.authSecret is invalid")
    merged["registry"] = registry
    dash = merged.get("dashboard") or {}
    if dash.get("enabled"):
        for key in ("image", "proxyImage", "clientId"):
            if not dash.get(key):
                raise InstallerError(f"installer config: dashboard.{key} is required when the dashboard is enabled")
        owner = dash.get("owner")
        users = dash.get("allowedUsers")
        if not isinstance(owner, str) or not USER_RE.match(owner):
            raise InstallerError("installer config: dashboard owner must be a valid user name")
        if not isinstance(users, list) or owner not in users or not all(
                isinstance(user, str) and USER_RE.match(user) for user in users):
            raise InstallerError("installer config: dashboard allowedUsers must include the owner")
    merged["sandboxUi"], merged["sandboxUiProxy"] = check_sandbox_ui(
        merged.get("sandboxUi"), merged.get("sandboxUiProxy"))
    harness_signature_cache_ttl(merged)
    return merged


def harness_signature_cache_ttl(cfg):
    """Bound the grace period for an already verified digest to five minutes."""
    harness = cfg.get("harness") or {}
    sig = (harness.get("cosign") or {}) if isinstance(harness, dict) else None
    if not isinstance(sig, dict):
        raise InstallerError("installer config: harness.cosign must be an object")
    ttl = sig.get("cacheTtlSeconds", 300)
    if type(ttl) is not int or not 0 <= ttl <= 300:
        raise InstallerError("installer config: harness.cosign.cacheTtlSeconds must be an integer from 0 to 300")
    return ttl


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
    runtime_credentials: bool = False
    externally_managed: bool = False
    credential_free: bool = False
    # Optional `credentials:` mapping, keyed by the profile's credential name
    # ({api_key: {secretKey: ...}, app_secret: {secretKey: ...}}): one value
    # per credential, from the same Secret, each passed as its own
    # `--credential ENV` with the env var that credential declares. The
    # single-credential shorthand credentialSecretKey is one entry for the
    # profile's first credential.
    credentials_spec: dict = field(default_factory=dict)
    credential_values: dict = field(default_factory=dict)   # credential name -> value


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
    # `env:` -- the workload's environment (`sandbox create --env`; changing
    # it recreates the sandbox). {NAME: {value, title?}}: literals only, so
    # env_values (below) is derived, never a resolved copy that could go
    # stale (found in CI: freshly parsed profiles compared an empty copy
    # with the sandbox's env label and recreated it). Never for credentials
    # (the agent, and argv, can read these): those stay on providers.
    env: dict = field(default_factory=dict)
    # `inference:` -- how the agent reaches its model: {providerRef, protocol,
    # baseUrl?, model, timeoutSeconds?}. Each of baseUrl/model/timeoutSeconds
    # is a literal or an input ({secretKeyRef: {name, key}, default?,
    # required?, title?}); inference_values is it resolved. The installer onboards the
    # agent from it (by protocol, so any profile-backed provider type works).
    inference: dict = field(default_factory=dict)
    inference_values: dict = field(default_factory=dict)

    @property
    def env_values(self):
        """NAME -> value for the sandbox's env (literal entries; anything
        else is refused by validation)."""
        if not isinstance(self.env, dict):
            return {}
        return {str(name): str(src["value"]) for name, src in sorted(self.env.items())
                if isinstance(src, dict) and "value" in src}


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
GATE_MOUNT = "/sandbox/.saw/trusted"
AUDIT_MOUNT = "/sandbox/.saw/audit"
GATE_VOLUME_PREFIX = "saw-gate-"
AUDIT_VOLUME_PREFIX = "saw-audit-"
AUDIT_FILE = "tool-actions.jsonl"
# A harness image is read fully into memory (tree_digest, the volume import
# tarball); an unbounded one can exhaust the VM. 512 MiB comfortably covers a
# real bundle (skills, a few native plugins) with headroom to spare.
HARNESS_IMAGE_MAX_BYTES = 512 * 1024 * 1024
# Keys configure_harness may set; a shape change must unset the ones it
# no longer wants, not leave them stale.
HARNESS_CONFIG_KEYS = ("plugins.load.paths", "skills.load.extraDirs")
OPENCLAW_EXEC_ENV = ("OPENCLAW_HOME=/sandbox SQLITE_TMPDIR=/sandbox/.openclaw/state "
                     "TMPDIR=/sandbox/.openclaw/state OPENCLAW_NIX_MODE=0")
# mcp.json env/header value: exactly ${VAR}, or Authorization-style
# "Bearer ${VAR}". Any other prefix could smuggle a literal secret.
MCP_PLACEHOLDER_ONLY = re.compile(
    r"^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|Bearer \$\{[A-Za-z_][A-Za-z0-9_]*\})$",
    re.IGNORECASE)
# A stdio arg naming a credential-ish flag with a literal value, e.g.
# "--api-key=sk-live-...". The "--flag value" two-token form is not covered.
MCP_ARG_CREDENTIAL_RE = re.compile(
    r"^--?[\w-]*(?:key|token|secret|password|passwd|auth)[\w-]*=(?P<value>.*)$",
    re.IGNORECASE)
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


def sandbox_volume_name(prefix, workspace, sandbox):
    tag = hashlib.sha256(f"{workspace}/{sandbox}".encode()).hexdigest()[:8]
    return f"{prefix}{workspace}-{sandbox}-{tag}"


def sandbox_mounts(ws, sb):
    """The exact podman volume mounts required by this sandbox."""
    mounts = []
    if sb.harness_ref:
        mounts.append({"type": "volume", "source": harness_volume_name(ws.name, sb.name),
                       "target": HARNESS_MOUNT, "read_only": True})
    if sb.type in ("openclaw", "nemoclaw"):
        mounts += [
            {"type": "volume", "source": sandbox_volume_name(GATE_VOLUME_PREFIX, ws.name, sb.name),
             "target": GATE_MOUNT, "read_only": True},
            {"type": "volume", "source": sandbox_volume_name(AUDIT_VOLUME_PREFIX, ws.name, sb.name),
             "target": AUDIT_MOUNT, "read_only": False},
        ]
    return mounts


def sandbox_mounts_json(ws, sb):
    """--driver-config-json for the podman driver and APF allowlist."""
    return json.dumps({"podman": {"mounts": sandbox_mounts(ws, sb)}}, separators=(",", ":"))


def safe_rel_path(rel, where):
    """A bundle-relative POSIX path: no absolute, no empty or '.'/'..' segment."""
    parts = rel.split("/")
    if not rel or rel.startswith("/") or any(part in ("", ".", "..") for part in parts):
        raise InstallerError(f"{where}: unsafe path {rel!r}")
    return rel


def read_harness_tar(path):
    """{relpath: (bytes, executable)} from `podman export` of a harness image.

    The bundle tree is the image root (FROM scratch, COPY . /). Directories and
    macOS AppleDouble files are skipped; links, devices and paths that escape
    the tree are refused. The tree (with each file's executable bit) is what
    goes into the sandbox's harness volume.
    """
    files = {}
    total = 0
    with tarfile.open(path) as tar:
        for member in tar.getmembers():
            rel = member.name
            while rel.startswith("./"):
                rel = rel[2:]
            rel = rel.lstrip("/")
            if not rel or member.isdir() or rel.rsplit("/", 1)[-1].startswith("._"):
                continue
            safe_rel_path(rel, "harness image")
            if not member.isfile():
                raise InstallerError(f"harness image: {member.name!r} is not a regular file")
            total += member.size
            if total > HARNESS_IMAGE_MAX_BYTES:
                raise InstallerError(
                    f"harness image exceeds {HARNESS_IMAGE_MAX_BYTES} bytes uncompressed; refusing it")
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


class VolumeDrift(Exception):
    """A harness volume holds a symlink or other non-regular entry.

    A writable mount from a second sandbox (or anything else with access to
    the volume) can plant a symlink without changing the tree digest, since
    it carries no file content; silently skipping it would leave `current()`
    reporting the volume intact while OpenClaw loads whatever it points at.
    """


def read_volume_tree(root):
    """{relpath: (bytes, executable)} of a filled volume, without the marker.

    Raises VolumeDrift on a symlink or other non-regular entry.
    """
    root = Path(root)
    files = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise VolumeDrift(f"{rel!r} is a symlink")
        if not path.is_file() and not path.is_dir():
            raise VolumeDrift(f"{rel!r} is not a regular file or directory")
        if path.is_file() and rel != HARNESS_MARKER:
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
       mcpServers           server names declared in mcp.json
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
    mcp_server_names = []
    mcp_configs = {}
    if "mcp.json" in files and "plugin.json" not in files:
        raise InstallerError(
            f"harness '{name}': mcp.json with no plugin.json at the bundle root; OpenClaw only "
            "reads a bundle's mcp.json when the bundle root is on plugins.load.paths, which "
            "openclaw_harness_config only sets for an Agent Plugins bundle. Add a plugin.json "
            "at the bundle root")
    plugin_dirs = sorted({rel.split("/")[1] for rel in files
                          if rel.startswith("plugins/") and rel.count("/") >= 2})
    declared_plugins = {item.get("name") for item in spec.get("plugins") or []}
    for plugin in plugin_dirs:
        if plugin not in declared_plugins:
            log(f"WARN: harness '{name}': plugin '{plugin}' has no entry in harness.yaml "
                "spec.plugins; its egress, if any, is enforced at runtime by the sandbox "
                "proxy, not checked here")
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
        mcp_server_names = sorted(servers)
        mcp_configs = {k: v for k, v in servers.items() if isinstance(v, dict)}
        for server, conf in sorted(servers.items()):
            if not isinstance(conf, dict) or conf.get("type") not in ("stdio", "streamable-http", "sse"):
                raise InstallerError(
                    f"harness '{name}': mcp.json server '{server}' needs \"type\": \"stdio\", "
                    "\"streamable-http\" or \"sse\" (OpenClaw ignores it otherwise)")
            for field in ("env", "headers"):
                for key, value in (conf.get(field) or {}).items():
                    if not isinstance(value, str) or not MCP_PLACEHOLDER_ONLY.match(value):
                        raise InstallerError(
                            f"harness '{name}': mcp.json server '{server}' {field} '{key}' is not "
                            "a bare ${VAR} placeholder (e.g. \"Bearer ${VAR}\"); a literal secret "
                            "must not ship in a bundle's mcp.json, the ConfigMap or the image")
            for arg in conf.get("args") or []:
                match = isinstance(arg, str) and MCP_ARG_CREDENTIAL_RE.match(arg)
                if match and not MCP_PLACEHOLDER_ONLY.match(match.group("value")):
                    raise InstallerError(
                        f"harness '{name}': mcp.json server '{server}' arg {arg!r} looks like a "
                        "credential flag with a literal value; use --flag=${VAR} instead")
            if isinstance(conf.get("url"), str):
                creds = urlsplit(conf["url"])
                if creds.username or creds.password:
                    raise InstallerError(
                        f"harness '{name}': mcp.json server '{server}' url has a literal "
                        "credential in it (user:pass@host); a literal secret must not ship "
                        "in a bundle's mcp.json, the ConfigMap or the image")
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
                else:
                    log(f"WARN: harness '{name}': stdio MCP server '{server}' has no "
                        "governanceProfile; its egress, if any, is enforced at runtime by "
                        "the sandbox proxy, not checked here")
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
    bundle_id = name
    if "plugin.json" in files:
        try:
            bundle_id = json.loads(files["plugin.json"][0].decode("utf-8")).get("name") or name
        except (ValueError, AttributeError):
            pass
    return {
        "name": name,
        "bundleId": bundle_id,
        "agent": spec.get("agent", "openclaw"),
        "skills": any(rel.startswith("skills/") for rel in files),
        "agentPluginsBundle": "plugin.json" in files,
        "mcp": "mcp.json" in files,
        "mcpServers": mcp_server_names,
        "mcpConfigs": mcp_configs,
        "pluginDirs": plugin_dirs,
        "governance": governance,
    }


def parse_provider_profile_catalog(output):
    """{profile id: profile record} from
    `openshell provider list-profiles -o json` (checked on OpenShell 0.0.116).
    A malformed entry is skipped, not fatal: one bad profile in the gateway
    must not stop an apply that does not use it. What a profile is used for
    (credentials, enforcement) is checked where it is used."""
    try:
        doc = json.loads(output or "")
    except ValueError:
        raise InstallerError("openshell provider list-profiles -o json did not return JSON") from None
    if isinstance(doc, dict):
        doc = doc.get("profiles") or doc.get("items") or []
    doc = doc if isinstance(doc, list) else []
    return {item["id"]: item for item in doc
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]}


def parse_profile_catalog(profiles):
    """{profile id: set of endpoint hosts} from parse_provider_profile_catalog()."""
    return {pid: {e.get("host") for e in item.get("endpoints") or []
                  if isinstance(e, dict) and e.get("host")}
            for pid, item in profiles.items()}


def in_cluster_host(host):
    """A Kubernetes Service name: <svc>.<ns>.svc[.cluster.local]. The VM
    reaches these through networkPolicy.extraEgress, never the EgressFirewall."""
    labels = host.lower().rstrip(".").split(".")
    return len(labels) >= 3 and (labels[2:3] == ["svc"] and labels[3:] in ([], ["cluster", "local"]))


def host_allowed(host, patterns):
    """A profile endpoint host may be a glob (*-aiplatform.googleapis.com);
    ports are not part of the match. Each `*` is one DNS label (no dots)."""
    host = (host or "").split(":")[0].lower()
    for pattern in patterns:
        regex = re.escape((pattern or "").split(":")[0].lower()).replace(r"\*", r"[^.]*")
        if re.fullmatch(regex, host):
            return True
    return False


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


# OpenClaw (2026.9.x) expands only ${PLUGIN_ROOT}, ${PLUGIN_DATA} and
# ${CLAUDE_PLUGIN_ROOT} in a bundle's mcp.json; any other ${VAR} reaches the
# server as literal text, and a stdio server inherits only HOME, LOGNAME,
# PATH, SHELL, TERM and USER. So a bundle server never sees its provider's
# placeholder (Slack answers invalid_auth) or the sandbox's CA settings (TLS
# through the egress proxy fails). openclaw.json does expand ${VAR} from the
# gateway's environment, which has both, and a server defined under
# mcp.servers replaces the bundle's server of the same name (found live: the
# daily-briefing Slack reader works only this way).
BUNDLE_ROOT_PLACEHOLDERS = ("${CLAUDE_PLUGIN_ROOT}", "${PLUGIN_ROOT}")
# The CA settings OpenShell gives a sandbox's processes when it has the proxy
# CA (openshell-sandbox child_env::tls_env_vars). Only the ones the sandbox
# really has are passed on: OpenClaw leaves an unset ${VAR} as literal text,
# and REQUESTS_CA_BUNDLE='${REQUESTS_CA_BUNDLE}' breaks every HTTPS call.
MCP_TRUST_ENV = ("NODE_EXTRA_CA_CERTS", "DENO_CERT", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                 "CURL_CA_BUNDLE", "GIT_SSL_CAINFO")
MCP_SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
SAW_MCP_STATE = "/sandbox/.openclaw/saw-mcp-servers.json"


def harness_mcp_servers(info, trust_env=()):
    """{name: mcp.servers entry} re-declaring the bundle's MCP servers in
    openclaw.json, where OpenClaw expands ${VAR}. Stdio servers also get the
    CA settings named in trust_env (the ones the sandbox has), so they trust
    the egress proxy. Paths resolve as OpenClaw resolves them for a bundle
    (root: the harness mount)."""
    if info is None or not info.get("agentPluginsBundle"):
        return {}
    root = HARNESS_MOUNT
    data = f"/sandbox/.openclaw/saw-plugin-data/{info['bundleId']}"

    def expand(value):
        if not isinstance(value, str):
            return value
        for placeholder in BUNDLE_ROOT_PLACEHOLDERS:
            value = value.replace(placeholder, root)
        return value.replace("${PLUGIN_DATA}", data)

    out = {}
    for name, conf in sorted((info.get("mcpConfigs") or {}).items()):
        if not MCP_SERVER_NAME_RE.match(name):
            log(f"WARN: harness '{info['name']}': MCP server name {name!r} cannot be "
                "re-declared in openclaw.json; it keeps the bundle's literal env")
            continue
        kind = conf.get("type")
        if kind == "stdio":
            command = conf.get("command")
            if isinstance(command, str) and command.startswith("./"):
                command = f"{root}/{command[2:]}"
            entry = {"command": expand(command),
                     "args": [expand(a) for a in conf.get("args") or []],
                     "env": {"PLUGIN_ROOT": root, "PLUGIN_DATA": data,
                             **{var: f"${{{var}}}" for var in trust_env},
                             **{k: expand(v) for k, v in (conf.get("env") or {}).items()}}}
            if conf.get("cwd"):
                entry["cwd"] = expand(conf["cwd"])
        elif kind in ("streamable-http", "sse"):
            if not conf.get("headers"):
                continue        # nothing for OpenClaw to expand: the bundle's own entry works
            entry = {"url": expand(conf.get("url")), "transport": kind,
                     "headers": {k: expand(v) for k, v in conf["headers"].items()}}
        else:
            continue
        out[name] = entry
    return out


def mcp_trust_env_probe():
    """Shell that prints the names (never the values) of the MCP_TRUST_ENV
    settings the sandbox has."""
    names = " ".join(MCP_TRUST_ENV)
    return f'for v in {names}; do [ -n "$(printenv "$v")" ] && echo "$v"; done; true'


def harness_plugin_ids(info):
    """The OpenClaw plugin ids the harness brings: the bundle's (plugin.json
    name) and each native plugin under plugins/."""
    ids = [info["bundleId"]] if info["agentPluginsBundle"] else []
    return ids + list(info["pluginDirs"])


def mcp_registration_failures(output, declared):
    """Inspect reports configuration registration, never MCP process readiness.

    Kept pure so the E2E script can apply the same checks to inspection JSON.
    Names in descriptions or diagnostics are not evidence of registration.
    """
    try:
        report = json.loads(output)
        plugin = report["plugin"]
        servers = report["mcpServers"]
        diagnostics = report.get("diagnostics") or []
        if not isinstance(plugin, dict) or not isinstance(servers, list) or not isinstance(diagnostics, list):
            raise ValueError("invalid inspection shape")
        if plugin.get("status") != "loaded" or plugin.get("enabled") is False or plugin.get("error"):
            return ["OpenClaw bundle runtime inspection reports an error or disabled bundle"]
        if any(isinstance(d, dict) and d.get("level") == "error" for d in diagnostics):
            return ["OpenClaw bundle runtime inspection reports error diagnostics"]
        registered = {entry["name"] for entry in servers
                      if isinstance(entry, dict) and isinstance(entry.get("name"), str)
                      and not entry.get("unsupported")}
    except (ValueError, TypeError, KeyError):
        return ["could not parse OpenClaw MCP registration inspection JSON"]
    missing = sorted(set(declared) - registered)
    return ([f"OpenClaw does not list MCP server(s) {', '.join(missing)} as registered"]
            if missing else [])


def parse_harness_files(files):
    """Build bundles from flat ConfigMap keys harness__<bundle>__<hash>, plus
    one harness__<bundle>__map key per bundle mapping each hash to its
    relpath (content-addressed: the key no longer encodes the path, so it
    never hits the iso9660/Joliet 64-character filename limit regardless of
    how deep or long a bundle's paths are; see templates/configmap-bom.yaml).

    The digest is computed, never authored here: the pin lives in
    sandbox.yaml harnessRef, outside the hashed tree. Relpaths from the map
    get the same .. / empty / absolute checks as read_harness_tar.
    """
    raw_by_bundle, maps = {}, {}
    for key, raw in files.items():
        parts = key.split("__")
        if len(parts) != 3 or parts[0] != "harness":
            raise InstallerError(f"unexpected harness file name: {key}")
        bundle, token = parts[1], parts[2]
        if token == "map":
            try:
                maps[bundle] = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise InstallerError(
                    f"harness bundle {bundle!r}: map is not valid JSON ({exc})") from None
        else:
            raw_by_bundle.setdefault(bundle, {})[token] = raw
    bundles = {}
    for name in sorted(raw_by_bundle):
        path_map = maps.get(name)
        if path_map is None:
            raise InstallerError(f"harness bundle {name!r} has no path map (harness__{name}__map)")
        tree = {}
        for hash_, raw in raw_by_bundle[name].items():
            rel = path_map.get(hash_)
            if rel is None:
                raise InstallerError(
                    f"harness bundle {name!r}: key 'harness__{name}__{hash_}' is not in its path map")
            tree[safe_rel_path(rel, f"harness bundle {name!r} path map")] = raw
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
    harness__<bundle>__<hash-or-"map"> and hold base64 (see the digest
    contract in templates/configmap-bom.yaml and parse_harness_files).
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
                    cred_spec = p.get("credentials")
                    if cred_spec is not None and "credentialSecretKey" in p:
                        raise InstallerError(f"{key}: provider '{p['name']}' sets both "
                                             "credentials and credentialSecretKey; use one")
                    primary_key = p.get("credentialSecretKey", "api_key")
                    ws.providers.append(Provider(
                        name=p["name"], type=p["type"],
                        enabled=p.get("enabled", True),
                        credential_free=p.get("credentialFree", False),
                        nemoclaw_provider=p.get("nemoclawProvider", ""),
                        credential_secret=p.get("credentialSecret", ""),
                        credential_secret_key=primary_key,
                        model=p.get("model", ""),
                        base_url_secret_key=p.get("baseUrlSecretKey", ""),
                        model_secret_key=p.get("modelSecretKey", ""),
                        inference_timeout=int(p.get("inferenceTimeout", 0) or 0),
                        runtime_credentials=p.get("runtimeCredentials", False),
                        externally_managed=p.get("externallyManaged", False),
                        credentials_spec=cred_spec if cred_spec is not None else {}))
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
                        harness_ref=dict(s.get("harnessRef") or {}),
                        env=s.get("env") if s.get("env") is not None else {},
                        inference=s.get("inference") if s.get("inference") is not None else {}))
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


def agent_mounts_planned(profiles):
    return any(sb.enabled and sb.type in ("openclaw", "nemoclaw")
               for _profile, ws in enabled_workspaces(profiles) for sb in ws.sandboxes)


def governance_enabled(toml_path):
    """Whether gateway.toml takes provider profiles from the governance
    interceptor (openshell.gateway.provider_profile_sources has an
    interceptor entry). False when the file is unreadable: the shipped
    profiles are then the only catalog the installer can rely on."""
    try:
        gateway = tomllib.loads(Path(toml_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return False
    sources = gateway.get("openshell", {}).get("gateway", {}).get("provider_profile_sources")
    return any(isinstance(src, dict) and src.get("type") == "interceptor"
               for src in (sources or []))


def check_driver_config_allowed(toml_path):
    """Agent trust volumes require caller driver config before any mutation."""
    try:
        gateway = tomllib.loads(Path(toml_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise InstallerError(f"cannot read gateway.toml for agent mounts: {exc}") from None
    podman = gateway.get("openshell", {}).get("drivers", {}).get("podman", {})
    if not isinstance(podman, dict) or podman.get("allow_driver_config") is not True:
        raise InstallerError(
            "an agent sandbox is planned, but gateway.toml does not set "
            "allow_driver_config = true, so OpenShell would refuse its trusted mounts")


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


def validate_profiles(profiles, known_profiles=(), governed=False):
    """Catch mistakes before anything touches the gateway.

    governed: the gateway takes its provider profiles from the governance
    interceptor, which may serve profiles the installer does not ship
    (overrides/governance-profiles). A type that is neither built-in nor
    shipped is then checked against the live catalog at apply time
    (ProfileApplier.adopt_governed_profiles) instead of refused here."""
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
        provider_types = {p.name: p.type for p in ws.providers if p.enabled}
        if len(provider_names) != len(set(provider_names)):
            errors.append(f"{where}: duplicate provider names")
        for p in ws.providers:
            if not p.enabled:
                continue
            if not isinstance(p.runtime_credentials, bool) or not isinstance(p.externally_managed, bool):
                errors.append(f"{where}: dynamic provider flags must be booleans")
            if p.runtime_credentials and p.externally_managed:
                errors.append(f"{where}: provider '{p.name}' cannot be both runtime and externally managed")
            if p.runtime_credentials or p.externally_managed:
                if not isinstance(p.credential_free, bool):
                    errors.append(f"{where}: provider '{p.name}' credentialFree must be a boolean")
                if p.credential_free:
                    errors.append(f"{where}: dynamic provider '{p.name}' cannot be credentialFree")
                if p.credential_secret:
                    errors.append(f"{where}: dynamic provider '{p.name}' cannot use credentialSecret")
                if p.credentials_spec:
                    errors.append(f"{where}: dynamic provider '{p.name}' cannot use credentials")
                if (p.model or p.nemoclaw_provider or p.model_secret_key or p.base_url_secret_key
                        or p.base_url or p.inference_timeout):
                    errors.append(f"{where}: dynamic provider '{p.name}' cannot use static provider settings")
                if not NAME_RE.match(p.type or "") or len(p.type) > OPENSHELL_NAME_LIMIT:
                    errors.append(f"{where}: dynamic provider profile type must be a DNS label of at most "
                                  f"{OPENSHELL_NAME_LIMIT} characters")
                continue
            if not isinstance(p.credential_free, bool):
                errors.append(f"{where}: provider '{p.name}' credentialFree must be a boolean")
            elif p.credential_free:
                # A keyless provider is an attachment to a governed service
                # (an in-cluster MCP Service): no key, no model, and a type
                # that is a live governance profile, not a built-in type.
                for label, value in (("name", p.name), ("type", p.type)):
                    if not NAME_RE.match(value or "") or len(value) > OPENSHELL_NAME_LIMIT:
                        errors.append(f"{where}: keyless provider {label} must be a "
                                      f"DNS label of at most {OPENSHELL_NAME_LIMIT} characters")
                if p.type in PROVIDER_CRED_MAP:
                    errors.append(f"{where}: provider '{p.name}' credentialFree cannot disable "
                                  f"the credential requirement of built-in type '{p.type}'")
                if p.credential_secret:
                    errors.append(f"{where}: provider '{p.name}' credentialFree cannot be "
                                  "combined with credentialSecret")
                if (p.model or p.nemoclaw_provider or p.model_secret_key or p.base_url_secret_key
                        or p.base_url or p.inference_timeout):
                    errors.append(f"{where}: keyless provider '{p.name}' cannot be combined "
                                  "with model/inference settings")
            if governed and p.name != p.type:
                # OpenShell 0.1.2's governance interceptor validates a new
                # sandbox's providers by comparing each provider *name* with
                # the vended profile ids (examples/governance-interceptor,
                # providers_are_managed): a provider named differently from
                # its type is refused at sandbox create with "sandbox
                # providers may only use vended provider profiles". Found
                # live; refuse it here, with the reason, instead.
                errors.append(f"{where}: provider '{p.name}' must be named after its type "
                              f"'{p.type}' (the governance interceptor checks sandbox providers "
                              "by profile id, so name and type must match)")
            if (not p.credential_free and p.type not in PROVIDER_CRED_MAP
                    and p.type not in known_profiles):
                if not governed:
                    errors.append(f"{where}: provider '{p.name}' has unsupported type '{p.type}' "
                                  "(no built-in type and no shipped provider profile)")
                elif not NAME_RE.match(p.type or "") or len(p.type) > OPENSHELL_NAME_LIMIT:
                    errors.append(f"{where}: provider '{p.name}' type must be a DNS label of at "
                                  f"most {OPENSHELL_NAME_LIMIT} characters (a governance profile id)")
            if not p.credential_secret and not p.credential_free:
                errors.append(f"{where}: provider '{p.name}' has no credentialSecret")
            elif p.credential_secret and not SECRET_NAME_RE.match(p.credential_secret):
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
            if p.credentials_spec:
                if not isinstance(p.credentials_spec, dict):
                    errors.append(f"{where}: provider '{p.name}' credentials must be a mapping of "
                                  "the profile's credential name to {secretKey[, title]}")
                elif p.credential_free:
                    errors.append(f"{where}: keyless provider '{p.name}' cannot have credentials")
                else:
                    for cname, entry in p.credentials_spec.items():
                        if not CREDENTIAL_NAME_RE.match(str(cname)):
                            errors.append(f"{where}: provider '{p.name}' credential '{cname}' is "
                                          "not a valid credential name")
                        if not isinstance(entry, dict) or not SECRET_KEY_RE.match(
                                str(entry.get("secretKey", ""))):
                            errors.append(f"{where}: provider '{p.name}' credential '{cname}' "
                                          "needs a valid secretKey")
                        elif set(entry) - {"secretKey", "title"}:
                            errors.append(f"{where}: provider '{p.name}' credential '{cname}' has "
                                          "unknown keys "
                                          f"{', '.join(sorted(set(entry) - {'secretKey', 'title'}))}")
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
            if s.inference:
                errors += [f"{where}: sandbox '{s.name}' {p}"
                           for p in sandbox_inference_problems(s, provider_types)]
            if not isinstance(s.env, dict):
                errors.append(f"{where}: sandbox '{s.name}' env must be a mapping of NAME to "
                              "{value} or {secret, secretKey}")
            else:
                for name, src in s.env.items():
                    errors += [f"{where}: sandbox '{s.name}' env '{name}' {problem}"
                               for problem in sandbox_env_problems(name, src)]
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
    valid = {provider.type, nemoclaw_provider(provider)}
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
            if p.runtime_credentials or p.externally_managed or p.credential_free:
                continue
            base = secrets_dir / p.credential_secret
            if p.credentials_spec:
                # The primary credential is the mapping's first entry.
                p.credential_secret_key = next(iter(p.credentials_spec.values()))["secretKey"]
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
            # Every named credential, from the same Secret.
            p.credential_values = {}
            for cname, entry in p.credentials_spec.items():
                cvalue = read_secret_value(base, entry["secretKey"])
                if not cvalue:
                    raise InstallerError(
                        f"credential '{cname}' of provider '{p.name}' in workspace '{ws.name}' "
                        f"not found: Secret '{p.credential_secret}' key '{entry['secretKey']}'")
                p.credential_values[cname] = cvalue
            creds.setdefault(ws.name, {})[p.name] = value
        for sb in ws.sandboxes:
            if not sb.enabled:
                continue
            # Always set (a re-resolve after the profile changed must not
            # keep an earlier value). env needs no resolving: literals only.
            sb.inference_values = (resolve_sandbox_inference(ws, sb, secrets_dir)
                                   if sb.inference else {})
    return creds


def read_secret_value(base, key):
    try:
        return (Path(base) / key).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


# Characters a base URL never needs and a shell would interpret; the URL ends
# up in an OpenClaw command line inside the sandbox.
SHELL_UNSAFE = set("\"'`$\\;|&<>(){}")

# Environment variable names (a credential's `env`, a sandbox `env:` key);
# OpenShell's own rule for `sandbox create --env`.
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# A profile credential name (`credentials[].name`).
CREDENTIAL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
# OpenShell's limit for one `--env` value.
ENV_VALUE_LIMIT = 8192
# A value read from a Secret, as Kubernetes spells it:
#   secretKeyRef: {name: <Secret>, key: <key>}
# with an optional default (used when the key is absent), required (defaults
# to "no default given") and title (the RHDH form's label).
SANDBOX_ENV_KEYS = {"value", "title"}
INPUT_KEYS = {"secretKeyRef", "default", "required", "title"}


def secret_ref(src):
    """(name, key) of a {secretKeyRef: {name, key}} input, or None."""
    ref = src.get("secretKeyRef") if isinstance(src, dict) else None
    if not isinstance(ref, dict):
        return None
    return str(ref.get("name", "")), str(ref.get("key", ""))


def secret_ref_problems(src):
    ref = secret_ref(src)
    if ref is None:
        return ["needs secretKeyRef: {name, key}"]
    out = []
    if not SECRET_NAME_RE.match(ref[0]):
        out.append("secretKeyRef.name must be a valid Secret name")
    if not SECRET_KEY_RE.match(ref[1]):
        out.append("secretKeyRef.key must be a valid Secret key")
    if set(src["secretKeyRef"]) - {"name", "key"}:
        out.append("secretKeyRef takes only name and key")
    return out
INFERENCE_KEYS = {"providerRef", "protocol", "baseUrl", "model", "timeoutSeconds"}
# The API protocols the installer can onboard an agent with. A provider's
# *profile* (type) says which hosts a credential may reach; the protocol says
# how the agent talks to them, so a governed profile for another host (e.g.
# vllm-prod) works with protocol openai.
INFERENCE_PROTOCOLS = {"openai", "anthropic"}
# The protocol a built-in provider type speaks (the legacy path, no
# `inference:` block, and the default when a sandbox names a provider of
# such a type).
PROVIDER_PROTOCOLS = {"openai": "openai", "codex": "openai", "nvidia": "openai",
                      "build": "openai", "anthropic": "anthropic", "claude-code": "anthropic"}


def check_env_value(value):
    """A value OpenShell accepts for `--env`: one line, at most 8 KiB. The
    value is not echoed (it may come from a Secret)."""
    if "\n" in value or "\r" in value or "\0" in value:
        raise ValueError("value must be a single line")
    if len(value.encode()) > ENV_VALUE_LIMIT:
        raise ValueError(f"value is longer than {ENV_VALUE_LIMIT} bytes")
    return value


def sandbox_env_problems(name, src):
    """What is wrong with one `env:` entry of a sandbox ([] when fine)."""
    out = []
    if not ENV_NAME_RE.match(str(name)):
        out.append("is not a valid variable name ([A-Za-z_][A-Za-z0-9_]*)")
    elif str(name).startswith("OPENSHELL_"):
        out.append("is reserved by OpenShell (OPENSHELL_*)")
    elif name in set(PROVIDER_CRED_MAP.values()):
        out.append("is a provider credential variable; credentials go on a provider, "
                   "the agent can read sandbox env")
    elif name in set(BASE_URL_CONFIG_KEYS.values()) or name in ("MODEL", "OPENCLAW_MODEL",
                                                               "NEMOCLAW_MODEL"):
        out.append("is an inference setting; set it in the sandbox's inference: block")
    if isinstance(src, dict) and ("secretKeyRef" in src or "default" in src):
        # A value from a Secret would travel in `sandbox create --env`'s argv
        # and be readable by every process in the sandbox (review, P1):
        # secrets go on a provider, whose profile the gateway injects.
        return out + ["must be a literal ({value: ...}); a value from a Secret belongs on a "
                      "provider, not in sandbox env (the agent and argv could read it)"]
    if not isinstance(src, dict) or "value" not in src:
        return out + ["needs {value: ...}"]
    unknown = sorted(set(src) - SANDBOX_ENV_KEYS)
    if unknown:
        out.append(f"has unknown keys {', '.join(unknown)}")
    if isinstance(src["value"], bool) or not isinstance(src["value"], (str, int, float)):
        out.append("value must be a string (quote it)")
    else:
        try:
            check_env_value(str(src["value"]))
        except ValueError as exc:
            out.append(f"value: {exc}")
    return out


def same_sandbox(seen, recorded):
    """Is the running sandbox the one the record describes?

    Strict matching on the strong identity signals only -- the instance
    label this installer stamps at create, and the gateway's own id when
    the CLI prints one. EVERY signal known on both sides is compared before
    any conclusion: one that differs is a veto, whatever the others say
    (matching instance labels never hide a conflicting native id). A match
    needs at least one agreeing strong signal. An env label never
    establishes identity: it describes configuration, which can be rolled
    back or copied, and it was behind two data-loss findings."""
    agreed = False
    for key in ("instance", "native"):
        a, b = seen.get(key) or "", recorded.get(key) or ""
        if a and b:
            if a != b:
                return False
            agreed = True
        elif key == "instance" and (a or b):
            return False                # one side labelled, the other not: different creates
    return agreed


def env_label(values):
    """The digest of a sandbox env kept in its `saw.redhat.com/env` label:
    "none" for no env (a label, not "", so a sandbox created before this
    label existed is told apart from one with no env)."""
    if not values:
        return "none"
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()[:16]


def env_flags(values):
    """`--env NAME=VALUE` for each value (argv, not a shell: no quoting)."""
    return [part for name, value in sorted(values.items())
            for part in ("--env", f"{name}={value}")]


def input_problems(src, kinds=(str,)):
    """What is wrong with one typed input (a literal or {secret, secretKey,
    default?, required?, title?}); [] when fine."""
    if not isinstance(src, dict):
        return [] if isinstance(src, kinds) and not isinstance(src, bool) else [
            "must be a string or {secretKeyRef: {name, key}, ...}"]
    out = []
    unknown = sorted(set(src) - INPUT_KEYS)
    if unknown:
        out.append(f"has unknown keys {', '.join(unknown)}")
    out += secret_ref_problems(src)
    if "required" in src and not isinstance(src["required"], bool):
        out.append("required must be true or false")
    if "default" in src and (isinstance(src["default"], bool)
                             or not isinstance(src["default"], kinds)):
        out.append("default must be a string")
    return out


def resolve_input(src, secrets_dir, what):
    """A typed input's value: the literal, or the Secret key it refers to
    (secretKeyRef), else its default; "" when optional and absent."""
    if not isinstance(src, dict):
        return str(src)
    sname, skey = secret_ref(src)
    value = read_secret_value(Path(secrets_dir) / sname, skey)
    if value:
        return value
    if "default" in src:
        return str(src["default"])
    if src.get("required", "default" not in src):
        raise InstallerError(f"{what} not found: Secret '{sname}' key '{skey}'. List the "
                             "Secret in openshell-saw additionalProviderSecrets and make sure "
                             "it exists.")
    return ""


def inference_protocol(spec, provider_type):
    """The protocol an `inference:` block uses: its own `protocol`, else the
    one the provider's type implies ("" when neither says)."""
    return spec.get("protocol") or PROVIDER_PROTOCOLS.get(provider_type or "", "")


def sandbox_inference_problems(sb, provider_types):
    """What is wrong with a sandbox's `inference:` block ([] when fine).
    `provider_types` maps the workspace's enabled provider names to their
    types."""
    spec = sb.inference
    provider_names = provider_types
    if not isinstance(spec, dict):
        return ["inference must be a mapping"]
    out = []
    unknown = sorted(set(spec) - INFERENCE_KEYS)
    if unknown:
        out.append(f"inference has unknown keys {', '.join(unknown)}")
    ref = spec.get("providerRef")
    if not ref:
        out.append("inference needs providerRef (the provider whose credential it uses)")
    elif ref not in provider_names:
        out.append(f"inference providerRef '{ref}' is not an enabled provider in this workspace")
    elif ref not in sb.providers:
        out.append(f"inference providerRef '{ref}' is not in the sandbox's providers")
    protocol = inference_protocol(spec, provider_types.get(ref or ""))
    if "protocol" in spec and spec["protocol"] not in INFERENCE_PROTOCOLS:
        out.append(f"inference protocol must be one of {', '.join(sorted(INFERENCE_PROTOCOLS))}")
    elif not protocol and ref in provider_names:
        out.append(f"inference needs protocol ({' | '.join(sorted(INFERENCE_PROTOCOLS))}): "
                   f"provider type '{provider_types[ref]}' does not imply one")
    if "model" not in spec:
        out.append("inference needs model")
    for key in ("baseUrl", "model"):
        if key in spec:
            out += [f"inference {key} {p}" for p in input_problems(spec[key])]
    if "timeoutSeconds" in spec:
        out += [f"inference timeoutSeconds {p}"
                for p in input_problems(spec["timeoutSeconds"], (str, int))]
    return out


def resolve_sandbox_inference(ws, sb, secrets_dir):
    """A sandbox's `inference:` resolved: providerRef, protocol, baseUrl
    (validated, "" = the protocol's native API), model, timeoutSeconds."""
    spec = sb.inference
    where = f"sandbox '{sb.name}' in workspace '{ws.name}'"
    provider = next((p for p in ws.providers if p.enabled and p.name == spec["providerRef"]), None)
    out = {"providerRef": spec["providerRef"],
           "protocol": inference_protocol(spec, provider.type if provider else "")}
    out["model"] = resolve_input(spec["model"], secrets_dir, f"{where}: inference model")
    if not out["model"]:
        raise InstallerError(f"{where}: inference model is empty")
    url = resolve_input(spec["baseUrl"], secrets_dir, f"{where}: inference baseUrl") \
        if "baseUrl" in spec else ""
    if url:
        try:
            url = check_base_url(url)
        except ValueError as exc:
            raise InstallerError(f"{where}: inference baseUrl: {exc}") from None
    out["baseUrl"] = url
    timeout = resolve_input(spec["timeoutSeconds"], secrets_dir,
                            f"{where}: inference timeoutSeconds") if "timeoutSeconds" in spec else ""
    if timeout and (not str(timeout).isdigit() or int(timeout) < 0):
        raise InstallerError(f"{where}: inference timeoutSeconds must be a non-negative integer")
    out["timeoutSeconds"] = int(timeout) if timeout else 0
    for key in ("model", "baseUrl"):
        try:
            check_env_value(out[key])
        except ValueError as exc:
            raise InstallerError(f"{where}: inference {key}: {exc}") from None
    return out


def sandbox_protocol(sb, provider):
    """How the agent talks to its inference endpoint."""
    if sb.inference_values:
        return sb.inference_values["protocol"]
    return PROVIDER_PROTOCOLS.get(provider.type, "") if provider else ""


def sandbox_model(sb, provider, default=""):
    """The model the agent runs: `inference.model`, else the legacy sandbox
    `model`, the provider's `model`/`modelSecretKey`, the built-in default."""
    if sb.inference_values:
        return sb.inference_values["model"]
    return sb.model or (provider.model if provider else "") or default


def sandbox_endpoint(sb, provider):
    """The endpoint the agent is onboarded against: `inference.baseUrl`, else
    the provider's own base URL ("" = the protocol's native API)."""
    if sb.inference_values:
        return sb.inference_values["baseUrl"]
    return provider.base_url if provider else ""


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
        components = dict(bom["spec"]["openshell"])
        if "spireAgent" in bom["spec"]:
            components["spireAgent"] = bom["spec"]["spireAgent"]
        for comp, entry in components.items():
            layout = COMPONENTS.get(comp, {"dest": "spire-agent", "image_path": "/opt/spire/bin/spire-agent"})
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
            dest = self.bin_dir / layout["dest"]
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
                self._extract(image, entry.get("path", layout["image_path"]), staged)
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


# Where releases before the trust was scoped put the issuer CA: the VM's
# system trust store, trusted by every TLS client on the VM (podman pulls
# included). Removed when found.
LEGACY_CA_ANCHOR = Path(os.environ.get("SAW_CA_ANCHOR",
                                       "/etc/pki/ca-trust/source/anchors/saw-ca-bundle.crt"))
# The public CAs Fedora ships; the gateway's private trust file starts from it.
SYSTEM_CA_BUNDLE = Path(os.environ.get("SAW_SYSTEM_CA_BUNDLE",
                                       "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"))
# The issuer CA is trusted only by the gateway and the oauth2-proxies, never
# by the system store: the cluster's ingress CA has no name constraints, and
# a certificate it signed for quay.io must not verify for podman.
#   issuer-ca.pem     the CA certificates alone: the oauth2-proxies'
#                     OAUTH2_PROXY_PROVIDER_CA_FILES (issuer calls only)
#   issuer-trust.pem  the public CAs plus those: the gateway's SSL_CERT_FILE
# Both in the runtime user's config dir (owned by it, like the dashboard's
# gateway CA), so rootless podman can mount issuer-ca.pem with :z.
ISSUER_CA_NAME = "issuer-ca.pem"
ISSUER_TRUST_NAME = "issuer-trust.pem"
TRUST_DROPIN = Path(".config/systemd/user/openshell-gateway.service.d/issuer-ca.conf")
PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----\s.*?-----END CERTIFICATE-----", re.S)


def cert_is_ca(pem):
    """True when the certificate says it is a CA (basicConstraints CA:TRUE)."""
    try:
        out = subprocess.run(["openssl", "x509", "-noout", "-ext", "basicConstraints"],
                             input=pem, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallerError(f"caBundle: cannot inspect a certificate: {exc}") from None
    if out.returncode != 0:
        raise InstallerError("caBundle: a certificate in it cannot be parsed")
    return re.search(r"\bCA:TRUE\b", out.stdout) is not None


def issuer_ca_certs(pem, is_ca=cert_is_ca):
    """The CA certificates of a caBundle, as PEM, or "" for none. Refuses a
    bundle with a private key in it (someone pasted the TLS Secret instead of
    its ca-bundle.crt: config.json and the VM would expose the key) and one
    without a CA. Leaf certificates are dropped: only a CA can sign the
    issuer's certificate, so a leaf adds nothing but a pinned name."""
    pem = (pem or "").strip()
    if not pem:
        return ""
    if "PRIVATE KEY-----" in pem:
        raise InstallerError(
            "caBundle contains a private key; give only the CA certificate(s), "
            "e.g. the ca-bundle.crt of default-ingress-cert, never a TLS Secret")
    certs = PEM_CERT_RE.findall(pem)
    if not certs:
        raise InstallerError("caBundle is not a PEM certificate bundle")
    cas = [c for c in certs if is_ca(c)]
    if not cas:
        raise InstallerError("caBundle has no CA certificate (basicConstraints CA:TRUE)")
    if len(cas) < len(certs):
        log(f"caBundle: ignoring {len(certs) - len(cas)} certificate(s) that are not a CA")
    return "\n".join(cas) + "\n"


REGISTRY_CERTS_DIR = Path(os.environ.get("SAW_REGISTRY_CERTS_DIR", "/etc/containers/certs.d"))
REGISTRY_CA_NAME = "saw-registry-ca.crt"
REGISTRY_AUTH_NAME = "registry-auth.json"


def registry_auth_path(home):
    return Path(home) / ".config" / "openshell" / REGISTRY_AUTH_NAME


def configure_registry_access(shell, cfg, secrets_dir, home, owner=None,
                              dry_run=False, is_ca=cert_is_ca):
    """Set Podman's registry-scoped CA and private auth file before pulls.

    The public CA stays under containers/certs.d/<host:port>. The bearer
    token comes only from a mounted Secret, never from config.json or argv.
    """
    registry = cfg["registry"]
    host = registry["host"]
    try:
        ca = issuer_ca_certs(registry["caBundle"], is_ca)
    except InstallerError as exc:
        raise InstallerError(f"registry.{exc}") from None
    changed = False
    if host:
        ca_file = REGISTRY_CERTS_DIR / host / REGISTRY_CA_NAME
        if ca:
            if dry_run:
                log(f"[dry-run] would trust registry CA for {host}")
            else:
                changed = write_if_changed(ca_file, ca, 0o644) or changed
        elif ca_file.exists():
            if not dry_run:
                ca_file.unlink()
            changed = True
    auth_file = registry_auth_path(home)
    if registry["authSecret"]:
        token_file = Path(secrets_dir) / registry["authSecret"] / "token"
        try:
            token = token_file.read_text(encoding="utf-8").strip()
        except OSError:
            raise InstallerError("registry pull token Secret is not mounted") from None
        if not token or any(char.isspace() for char in token):
            raise InstallerError("registry pull token Secret has no valid token")
        shell.add_secret(token)
        encoded = base64.b64encode(f"serviceaccount:{token}".encode()).decode()
        shell.add_secret(encoded)
        auth = json.dumps({"auths": {host: {"auth": encoded}}}, separators=(",", ":")) + "\n"
        if dry_run:
            log(f"[dry-run] would update private registry auth file {auth_file}")
        else:
            changed = write_if_changed(auth_file, auth, 0o600, owner) or changed
            os.chmod(auth_file, 0o600)
            if owner and os.geteuid() == 0:
                os.chown(auth_file, *owner)
        shell.env["REGISTRY_AUTH_FILE"] = str(auth_file)
    elif auth_file.exists():
        if not dry_run:
            auth_file.unlink()
        changed = True
    return changed


def issuer_trust_paths(home):
    config = Path(home) / ".config" / "openshell"
    return config / ISSUER_CA_NAME, config / ISSUER_TRUST_NAME


def trust_dropin(trust_file):
    return f"[Service]\nEnvironment=SSL_CERT_FILE={trust_file}\n"


def trust_issuer_ca(shell, pem, home, owner=None, dry_run=False, is_ca=cert_is_ca):
    """Let the gateway and the oauth2-proxies (and nothing else on the VM)
    trust the issuer's CA (configured_ca_bundle): for example the cluster's
    ingress CA when its *.apps certificate is not from a public CA. The
    gateway fetches the issuer at startup with rustls' native roots and
    exits when it cannot verify it; SSL_CERT_FILE in a drop-in points those
    at the public CAs plus the issuer CA. Written on every run (cloud-init
    runs once per VM), so an emptied setting removes it. Also removes what
    older releases put in the system trust store. True when anything
    changed (the gateway must restart)."""
    cas = issuer_ca_certs(pem, is_ca)
    home = Path(home)
    ca_file, trust_file = issuer_trust_paths(home)
    dropin = home / TRUST_DROPIN
    changed = False
    if LEGACY_CA_ANCHOR.exists():
        if dry_run:
            log(f"would remove {LEGACY_CA_ANCHOR} from the system trust store")
        else:
            LEGACY_CA_ANCHOR.unlink()
            shell.run(["update-ca-trust", "extract"])
            log(f"Removed {LEGACY_CA_ANCHOR}: the issuer CA is no longer trusted system-wide")
        changed = True
    if not cas:
        for path in (ca_file, trust_file, dropin):
            if path.exists():
                if not dry_run:
                    path.unlink()
                changed = True
        if changed and not dry_run:
            log("No issuer CA configured; the gateway and the proxies use the public CAs")
        return changed
    try:
        public = SYSTEM_CA_BUNDLE.read_text(encoding="utf-8")
    except OSError:
        public = ""
    if public and not public.endswith("\n"):
        public += "\n"
    wanted = {ca_file: cas, trust_file: public + cas, dropin: trust_dropin(trust_file)}
    if dry_run:
        stale = [str(p) for p, text in wanted.items()
                 if not p.is_file() or p.read_text(encoding="utf-8") != text]
        if stale:
            log(f"[dry-run] issuer trust files to update: {stale}")
        return changed or bool(stale)
    wrote_ca = False
    for path, text in wanted.items():
        if write_if_changed(path, text, 0o644, owner):
            changed = True
            wrote_ca = wrote_ca or path == ca_file
    if owner and os.geteuid() == 0:
        for directory in (dropin.parent.parent, dropin.parent):
            if directory.is_dir():
                os.chown(directory, *owner)
    if wrote_ca:
        log(f"Trusting the issuer CA ({cas.count('BEGIN CERTIFICATE')} certificate(s)) "
            f"for the gateway and the oauth2-proxies only: {ca_file}")
    return changed


CA_BUNDLE_HELP = (
    "set oidc.caBundle to the issuer's CA (PEM) and restart the VM. For the "
    "in-cluster Keycloak the validated pattern does this itself (saw-users "
    "clusterCaSecret, the saw-ingress-ca imperative job); with the quickstart: "
    "oc get cm default-ingress-cert -n openshift-config-managed "
    "-o jsonpath='{.data.ca-bundle\\.crt}'. See docs/deployment-guide.md, "
    "\"The issuer's certificate\"")


def probe_issuer(issuer, cafile=None, timeout=10, opener=urlopen):
    """Fetch the issuer's OIDC configuration, verifying its certificate with
    cafile alone (None: the VM's public CAs). Returns ("ok", ""),
    ("untrusted", reason) or ("unreachable", reason)."""
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        context = ssl.create_default_context(cafile=str(cafile)) if cafile else None
    except (OSError, ssl.SSLError) as exc:
        return "untrusted", f"cannot load the CA file: {exc}"
    try:
        with opener(url, timeout=timeout, context=context) as resp:
            resp.read(1)
        return "ok", ""
    except ssl.SSLCertVerificationError as exc:
        return "untrusted", exc.verify_message or str(exc)
    except URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            return "untrusted", exc.reason.verify_message or str(exc.reason)
        return "unreachable", str(exc.reason)
    except (OSError, ValueError) as exc:
        return "unreachable", str(exc)


def select_issuer_ca(issuer, cas, timeout=10, opener=urlopen, public_cafile=None):
    """The issuer CA to install: cas when it signs the issuer's certificate,
    "" when the issuer is publicly trusted anyway (an extra CA would only
    widen the gateway's trust: the automatic cluster CA on a cluster whose
    *.apps certificate is public), and an error when neither verifies it.
    Verified with the extra CA alone, so a bundle that signs nothing is
    never installed. Unreachable issuer: keep cas, the gateway reports it."""
    if not issuer or not cas:
        return cas
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as tmp:
        tmp.write(cas)
    try:
        verdict, reason = probe_issuer(issuer, tmp.name, timeout, opener)
    finally:
        os.unlink(tmp.name)
    if verdict == "ok":
        return cas
    if verdict == "unreachable":
        log(f"WARN: cannot reach the OIDC issuer {url} to check the issuer CA: {reason}")
        return cas
    public, _ = probe_issuer(issuer, public_cafile, timeout, opener)
    if public == "ok":
        log(f"The OIDC issuer {url} is publicly trusted; not installing the configured "
            "issuer CA, which does not sign its certificate")
        return ""
    raise InstallerError(
        f"the configured issuer CA does not sign the OIDC issuer's certificate "
        f"({url}: {reason}); {CA_BUNDLE_HELP}")


def check_issuer_trusted(issuer, timeout=10, opener=urlopen, cafile=None):
    """Fetch the issuer's OIDC configuration with the gateway's trust (the
    public CAs, plus the issuer CA when one is installed), as the gateway
    does at startup, before starting it. The gateway only says
    "OIDC discovery request failed" and exits, and install then times out
    waiting for its port; an untrusted certificate is the usual cause and
    oidc.caBundle the fix, so say that. Other failures (DNS, timeouts) are
    only warned about: the gateway reports them itself."""
    if not issuer:
        return
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    verdict, reason = probe_issuer(issuer, cafile, timeout, opener)
    if verdict == "untrusted":
        raise InstallerError(
            f"cannot verify the OIDC issuer's certificate ({url}: {reason}); {CA_BUNDLE_HELP}")
    if verdict == "unreachable":
        log(f"WARN: cannot reach the OIDC issuer {url}: {reason}")


def configured_ca_bundle(cfg, secrets_dir):
    """The PEM the VM should trust for the issuer: config.json's caBundle, or
    else the cluster's ingress CA from the caBundleSecret Secret (key
    ca-bundle.crt, mounted under secrets_dir like the provider Secrets), or
    "". The chart only sets caBundleSecret for the in-cluster Keycloak."""
    pem = (cfg.get("caBundle") or "").strip()
    name = cfg.get("caBundleSecret") or ""
    if pem or not name:
        return pem
    if not NAME_RE.match(name):
        raise InstallerError(f"installer config: invalid caBundleSecret {name!r}")
    path = Path(secrets_dir) / name / "ca-bundle.crt"
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        raise InstallerError(
            f"the cluster CA Secret {name} is not mounted ({path}); it is "
            "filled from Vault by the saw-ingress-ca imperative job") from None


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


# The chart emits this only while identity is enabled. Opt-out must not keep
# a copy that the golden image or an earlier boot appended.
IDENTITY_ENV_KEYS = {"OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET"}
# Keys an earlier chart wrote that must not survive as "extra" keys.
# OPENSHELL_DRIVERS became OPENSHELL_COMPUTE_DRIVER in OpenShell 0.1.x; the
# old name is only a deprecated alias there.
RETIRED_ENV_KEYS = {"OPENSHELL_DRIVERS", "OPENSHELL_CONFIG_FILE", "OPENSHELL_SSH_GATEWAY_PORT"}


def merge_user_env(chart_env, current):
    """The chart's gateway.env wins; keys only the golden image's first-boot
    setup adds (runtime bridge endpoint, podman socket) are kept.

    The Workload API socket is not one of those keys. When the chart omits
    it, the merged file omits it too.
    """
    chart_keys = _env_keys(chart_env)
    extra = [line for key, line in _env_keys(current).items()
             if key not in chart_keys and key not in IDENTITY_ENV_KEYS | RETIRED_ENV_KEYS]
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


_TOOL_GATE_PACKAGE = """\
{
  "name": "saw-tool-gate",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "openclaw": {
    "extensions": ["./index.js"],
    "runtimeExtensions": ["./index.js"]
  }
}
"""

_TOOL_GATE_MANIFEST = """\
{
  "id": "saw-tool-gate",
  "name": "SAW tool gate",
  "description": "Audit every tool call with the signed-in user and current task, and require approval before consequential tools run.",
  "activation": {"onStartup": true},
  "configSchema": {"type": "object", "additionalProperties": false}
}
"""

# CJS so `node -e` can update OpenClaw's writable configuration. All trusted
# code, policy and identity are already on the read-only volume.
_TOOL_GATE_CONFIG = """\
const fs = require("fs");
const file = "/sandbox/.openclaw/openclaw.json";
const cfg = JSON.parse(fs.readFileSync(file, "utf8"));
cfg.plugins = cfg.plugins || {};
cfg.plugins.load = cfg.plugins.load || {};
const paths = Array.isArray(cfg.plugins.load.paths) ? cfg.plugins.load.paths : [];
cfg.plugins.load.paths = [...new Set([...paths, "/sandbox/.saw/trusted/plugin"])];
if (Array.isArray(cfg.plugins.allow) && cfg.plugins.allow.length) {
  cfg.plugins.allow = [...new Set([...cfg.plugins.allow, "saw-tool-gate"])];
}
cfg.plugins.entries = cfg.plugins.entries || {};
cfg.plugins.entries["saw-tool-gate"] = {
  ...cfg.plugins.entries["saw-tool-gate"], enabled: true,
};
fs.writeFileSync(file, JSON.stringify(cfg, null, 2) + "\\n");
"""

MANAGED_LABEL = "saw.redhat.com/managed=true"
MANAGED_LABEL_KEY = "saw.redhat.com/managed"
# A sandbox's environment is fixed at `sandbox create`; its digest is kept
# as a label so a later apply can tell the sandbox no longer matches its
# profile and recreate it (OpenShell 0.1.x has no way to change it).
ENV_LABEL_KEY = "saw.redhat.com/env"
# Each `sandbox create` gets a random instance id as a label. It is the
# sandbox's identity across a recreation: the env label says what a sandbox
# was created *with*, which the desired configuration can be rolled back to,
# so it can never say *which* sandbox this is.
INSTANCE_LABEL_KEY = "saw.redhat.com/instance"
# OpenShell 0.0.116 and 0.1.2 print the two kinds differently (confirmed on
# a 0.0.116 guest, and the same in the 0.1.2 CLI): `sandbox get` human text
# is one `key: value` line per label and `--output json` has
# labels[key] == "true"; `workspace get` has no `--output` flag and prints
# `Labels: key=value, ...`.
_MANAGED_LABEL_RE = re.compile(
    r"(?:^|[\s,])saw\.redhat\.com/managed\s*[:=]\s*true\b")
# A missing sandbox, workspace, or provider. Matches the short CLI line
# (`sandbox 'name' not found`) and tonic's `status: NotFound, message: "..."`.
# "provider profile 'x' was not found" is a catalog miss, not a missing object.
_RESOURCE_NOT_FOUND_RE = re.compile(
    r"status:\s*notfound\b"
    r"|\b(?:sandbox|workspace|provider)\s+(?:'[^']*'\s+)?(?:was\s+)?not\s+found\b",
    re.IGNORECASE)
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
    # Top-level `labels` is the OpenShell 0.1.2 `sandbox get --output json`
    # shape (labels["saw.redhat.com/managed"] == "true"). Read that key on
    # purpose so a later CLI that nests labels elsewhere is an explicit change.
    labels = doc.get("labels") or {}
    if not isinstance(labels, dict):
        return False
    return str(labels.get(MANAGED_LABEL_KEY, "")).lower() == "true"


def _label_from_json(text, key):
    """A label's value from `sandbox get --output json`, "" when unset, None
    when `text` is not JSON."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return None
    labels = doc.get("labels") if isinstance(doc, dict) else None
    return str((labels or {}).get(key, "")) if isinstance(labels, dict) else ""


def _label_from_text(text, key):
    match = re.search(rf"(?m)^\s*{re.escape(key)}\s*[:=]\s*(\S+)", _strip_ansi(text))
    return match.group(1).rstrip(",") if match else ""


def _cli_rejected_output_flag(text):
    """True only for Clap's `unexpected argument '--output'` rejection.

    A broader match (any error that mentions "output") would treat an
    unrelated CLI failure as a missing `--output` flag and fall back to text.
    """
    low = _strip_ansi(text).lower()
    return "unexpected argument '--output'" in low


def _resource_not_found(text):
    """True when the CLI says this sandbox, workspace, or provider is gone."""
    return _RESOURCE_NOT_FOUND_RE.search(_strip_ansi(text)) is not None


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


# The OpenClaw gateways running in a sandbox, one pid per line. A pattern
# (`pgrep -f`, `pkill -f`) is not usable here: the `sh -c` script that runs
# this check also contains the text `openclaw gateway run` (it starts the
# gateway), so the pattern matched the script's own shell, which then killed
# itself, or concluded a gateway was already running. This walks /proc and
# skips any `sh -c` process; it also matches the gateway once it has renamed
# itself `openclaw-gateway`.
_GATEWAY_PIDS_SH = (
    'gateway_pids() { for d in /proc/[0-9]*; do '
    'c=$(tr "\\000" " " < "$d/cmdline" 2>/dev/null) || continue; '
    'case "$c" in *"sh -c "*) continue;; esac; '
    'case "$c" in *"openclaw gateway run"*|openclaw-gateway*) echo "${d#/proc/}";; esac; '
    'done; }')

# sup_pids(): the gateway supervisors (saw-gateway-supervise.sh), found the
# same way as gateway_pids but matched by the supervisor's script path. The
# supervisor runs as `sh <path>` (not `sh -c`), so the transient config shell
# that writes and launches it is still skipped.
_SUP_PIDS_SH = _GATEWAY_PIDS_SH.replace("gateway_pids()", "sup_pids()").replace(
    '*"openclaw gateway run"*|openclaw-gateway*', "*saw-gateway-supervise.sh*")


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

    def current(self, mountpoint, source, expected_digest):
        """(tree, marker) if the volume holds exactly `source`, intact; else
        (None, marker).

        `expected_digest` comes from outside the volume (ConfigMap digest for
        an inline bundle, installer ledger for an image). The marker's own
        treeDigest is not trusted: a workspace user who can mount the volume
        writable could edit the tree, recompute the digest and rewrite the
        marker to match.
        """
        marker = self.marker(mountpoint)
        if marker.get("source") != source:
            return None, marker
        if expected_digest is None:
            # No trusted digest yet (image bundle, no ledger): refill.
            return None, marker
        try:
            tree = read_volume_tree(mountpoint)
        except VolumeDrift as exc:
            log(f"WARN: harness volume drift ({exc}); refilling")
            return None, marker
        except OSError as exc:
            # A planted file unreadable by our uid (other owner in the user
            # namespace) must not crash the apply: refill, same as drift.
            log(f"WARN: harness volume unreadable ({exc}); refilling")
            return None, marker
        if harness_tree_digest(tree) != expected_digest:
            return None, marker
        return tree, marker

    def fill(self, volume, mountpoint, source, tree):
        """Wipe the volume, then import `tree` unchanged plus the marker.

        A previous tree is tarred first so a failed import can restore it
        instead of leaving the volume empty.
        """
        marker = {"source": source, "treeDigest": harness_tree_digest(tree)}
        with tempfile.TemporaryDirectory(prefix="saw-harness-") as tmp:
            backup = Path(tmp) / "prev.tar"
            had = any(mountpoint.iterdir())
            if had:
                with tarfile.open(backup, "w") as tar:
                    for child in mountpoint.iterdir():
                        try:
                            tar.add(child, arcname=child.name)
                        except OSError as exc:
                            # Content not readable by our uid (other owner in
                            # the user namespace) cannot be backed up; proceed
                            # without it rather than blocking the refill.
                            log(f"WARN: could not back up {child.name} before refill ({exc})")
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
            tarball = Path(tmp) / "bundle.tar"
            write_harness_tar(tarball, tree, marker)
            try:
                self._podman("volume", "import", volume, str(tarball))
            except InstallerError:
                if had:
                    with tarfile.open(backup) as tar:
                        tar.extractall(mountpoint, filter="data")
                raise
        return marker

    def verify(self, volume, workspace, source, expected_digest):
        """Failures (list of text) unless the volume is admitted and holds
        `source` intact against `expected_digest`."""
        if self.sh.dry_run:
            return []
        info = self.inspect(volume)
        if info is None:
            return [f"volume {volume} does not exist"]
        if not self.admitted(info, workspace):
            return [f"volume {volume} lacks the openshell.ai/sandbox-attachable labels"]
        tree, marker = self.current(
            Path(info.get("Mountpoint") or ""), source, expected_digest)
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
        self.owner_state_path = (Path(prune["ledgerPath"]).with_name("owner-memberships.json")
                                 if prune.get("ledgerPath") else None)
        # Sandbox recreations in progress (env change): the archive of the
        # old /sandbox and its checksum, kept until the restore is verified.
        self.migrations_path = (Path(prune["ledgerPath"]).with_name("sandbox-migrations.json")
                                if prune.get("ledgerPath") else None)
        self.migrations = (read_json(self.migrations_path, {})
                           if self.migrations_path and not shell.dry_run else {})
        if not isinstance(self.migrations, dict):
            self.migrations = {}
        self.owner_memberships = (read_json(self.owner_state_path, {})
                                  if self.owner_state_path and not shell.dry_run else {})
        if not isinstance(self.owner_memberships, dict):
            raise InstallerError("owner membership state is not an object")
        self.harness = harness or {"bundles": {}}
        self.volumes = HarnessVolume(shell)
        self.catalogs = {}            # workspace -> {profile id: endpoint hosts}
        self.catalog_details = {}     # workspace -> {profile id: profile record}
        self.harness_info = {}        # (workspace, sandbox) -> describe_harness_tree()
        self.harness_refilled = {}    # (workspace, sandbox) -> volume was (re)filled this apply
        self.harness_volumes = set()  # volumes this apply wants to keep
        self.harness_images = set()   # harnessRef.image refs this apply wants to keep
        self.harness_digests = {}     # volume -> trusted tree digest, this apply
        self.gate_expected = {}       # (workspace, sandbox) -> (source, digest, policy hash)
        self.gate_refilled = {}       # (workspace, sandbox) -> gate bytes changed
        self.sandbox_failures = []    # "sandbox '<name>': <error>" kept for the raise at end
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
            self.owner_memberships[ws.name] = owner
            if self.owner_state_path and not self.sh.dry_run:
                write_json_atomic(self.owner_state_path, self.owner_memberships, mode=0o600)

    def reconcile_owner_memberships(self):
        """Revoke an old subject in every recorded workspace, even if its
        profile is now disabled or removed and pruning retains the workspace."""
        owner = self.cfg.get("ownerSubject")
        for workspace, previous in list(self.owner_memberships.items()):
            if not previous or previous == owner:
                continue
            removed = self.cli("workspace", "member", "remove", "--workspace", workspace,
                               "--subject", previous, check=False)
            if not removed.ok and "not found" not in (removed.out + removed.err).lower():
                raise InstallerError(f"could not remove previous owner from workspace '{workspace}'")
            self.owner_memberships.pop(workspace, None)
            if self.owner_state_path and not self.sh.dry_run:
                write_json_atomic(self.owner_state_path, self.owner_memberships, mode=0o600)

    def preflight(self, profiles):
        """Checks that need the provider profiles, for every enabled
        workspace, before anything on the gateway changes -- so an existing
        sandbox is held to the same rules as a new one.

        - a provider's named credentials exist in its profile (and each
          declares an env var to pass the value through);
        - no sandbox env variable shadows a credential variable of a
          provider the sandbox has: the agent would read the plain value."""
        errors = []
        for profile, ws in enabled_workspaces(profiles):
            where = f"{profile.name}/{ws.name}"
            for prov in ws.providers:
                if not prov.enabled or not prov.credentials_spec:
                    continue
                declared = dict(profile_credentials(self.provider_profiles.get(prov.type, "")))
                for cname in prov.credentials_spec:
                    if cname not in declared:
                        errors.append(
                            f"{where}: provider '{prov.name}' credential '{cname}' is not one the "
                            f"'{prov.type}' profile declares ({', '.join(declared) or 'none shipped'})")
                    elif not declared[cname]:
                        errors.append(f"{where}: provider '{prov.name}' credential '{cname}' "
                                      f"declares no env var in the '{prov.type}' profile")
            for sb in ws.sandboxes:
                if not sb.enabled or not sb.env_values:
                    continue
                for prov in ws.providers:
                    if prov.name not in sb.providers:
                        continue
                    names = profile_all_credential_envs(self.provider_profiles.get(prov.type, ""))
                    names.add(credential_env_name(prov.type, self.provider_profiles))
                    names.discard("")
                    clash = sorted(names & set(sb.env_values))
                    if clash:
                        errors.append(
                            f"{where}: sandbox '{sb.name}' env {', '.join(clash)} is the credential "
                            f"variable of provider '{prov.name}'; keep credentials on the provider "
                            "(the agent can read sandbox env)")
        if errors:
            raise InstallerError("invalid profiles:\n  - " + "\n  - ".join(errors))

    def adopt_governed_profiles(self, ws, catalog_ws=None):
        """Provider types the installer neither knows built-in nor ships must
        be profiles the gateway's governance catalog serves (a deployment's
        own, from overrides/governance-profiles). Their catalog records become
        the profile docs, so the credential env var and credential names come
        from the governed profile exactly as from a shipped one. A type the
        catalog does not serve is an error here, before anything is created:
        skipping it would leave a sandbox whose `inference.providerRef` names
        a provider that does not exist.

        catalog_ws: the workspace whose catalog to read (the interceptor's
        catalog is gateway-wide; before the workspaces exist, preflight reads
        it through the default workspace)."""
        catalog_ws = catalog_ws or ws
        for prov in ws.providers:
            if (not prov.enabled or prov.credential_free or prov.type in PROVIDER_CRED_MAP
                    or prov.type in self.provider_profiles):
                continue
            self.governance_catalog(catalog_ws)
            record = (self.catalog_details.get(catalog_ws.name) or {}).get(prov.type)
            if not record:
                raise InstallerError(
                    f"provider '{prov.name}' in workspace '{ws.name}' has type '{prov.type}', "
                    "which is neither a built-in type, a shipped provider profile, nor a profile "
                    "the gateway's governance catalog serves; add the profile under "
                    "overrides/governance-profiles (see docs/custom-inference.md) or fix the type")
            self.provider_profiles[prov.type] = yaml.safe_dump(record, sort_keys=False)
            if not credential_env_name(prov.type, self.provider_profiles):
                raise InstallerError(
                    f"provider '{prov.name}': governance profile '{prov.type}' declares no "
                    "credential env var (credentials[].env_vars), so no key can be passed to it")
            log(f"Provider '{prov.name}': type '{prov.type}' is a governance-catalog profile "
                f"(credential via {credential_env_name(prov.type, self.provider_profiles)})")

    def apply_provider(self, ws, provider):
        """Create the provider; if it exists, push the current key to it.

        `--credential NAME` (no value) makes the CLI read the key from the
        environment variable NAME, so the key never appears in argv
        (/proc/<pid>/cmdline) or in logs."""
        if provider.runtime_credentials or provider.externally_managed:
            if not (self.cfg.get("spiffe") or {}).get("enabled"):
                raise InstallerError("dynamic token-grant providers require spiffe.enabled")
            if provider.type not in self.provider_profiles:
                raise InstallerError(f"dynamic provider '{provider.type}' has no approved shipped profile")
            doc = _yaml(self.provider_profiles[provider.type], provider.type)
            grants = [c.get("token_grant") for c in doc.get("credentials", []) if c.get("token_grant")]
            if provider.externally_managed:
                if not grants or any(g.get("grant_type") != "token_exchange" for g in grants):
                    raise InstallerError("externally managed providers require a token_exchange profile")
                self.reconcile_dynamic_profile(ws, provider.type)
                if not self.cli("provider", "get", provider.name, *ws_args(ws.name), check=False, quiet=True).ok:
                    raise InstallerError(f"provider '{provider.name}' must be created with openshell-saw-token-provider")
                return
            if not grants or any(g.get("grant_type", "client_credentials") != "client_credentials" for g in grants):
                raise InstallerError("runtime providers require a client_credentials token-grant profile")
            self.reconcile_dynamic_profile(ws, provider.type)
            result = self.cli("provider", "create", "--name", provider.name, "--type", provider.type,
                              *ws_args(ws.name), "--runtime-credentials", ok_if_exists=True, check=False)
            if not result.ok:
                raise InstallerError(f"could not create runtime provider '{provider.name}'")
            return
        env, credential_args = {}, ()
        env_name = credential_env_name(provider.type, self.provider_profiles)
        if provider.credential_free:
            self.check_keyless_profile(ws, provider)
        elif provider.credentials_spec:
            # Named credentials: each bound to the env var its profile
            # credential declares (preflight checked the names exist).
            by_name = dict(profile_credentials(self.provider_profiles.get(provider.type, "")))
            for cname, value in provider.credential_values.items():
                envs = by_name.get(cname) or []
                if not envs:
                    raise InstallerError(
                        f"provider '{provider.name}': credential '{cname}' is not declared by "
                        f"the '{provider.type}' profile, or declares no env var")
                self.sh.add_secret(value)
                env[envs[0]] = value
                credential_args += ("--credential", envs[0])
        else:
            env = {env_name: self.creds[ws.name][provider.name]}
            credential_args = ("--credential", env_name)
        # A custom endpoint is recorded on the provider; start_openclaw
        # points the agent at it.
        config = (("--config", f"{BASE_URL_CONFIG_KEYS[provider.type]}={provider.base_url}")
                  if provider.base_url else ())
        create = ("provider", "create", "--name", provider.name, "--type", provider.type,
                  *ws_args(ws.name), *credential_args, *config)
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
        if created.existed and provider.credential_free:
            # An existing provider of this name may be a keyed one from an
            # earlier BOM. Reusing it would leave its key in the sandbox
            # with nothing in the BOM that says so.
            existing = self.cli("provider", "get", provider.name, *ws_args(ws.name),
                                check=False, quiet=True)
            plain = re.sub(r"\x1b\[[0-9;]*m", "", existing.out)
            current_type = re.search(r"(?m)^\s*Type:\s*(\S+)\s*$", plain)
            credential_keys = re.search(r"(?m)^\s*Credential keys:[ \t]*([^\n]*)$", plain)
            if not existing.ok or not current_type or current_type[1] != provider.type:
                raise InstallerError(f"keyless provider '{provider.name}' has an unverified or "
                                     "mismatched existing type; refusing to reuse it")
            if not credential_keys or credential_keys[1].strip() != "<none>":
                raise InstallerError(f"keyless provider '{provider.name}' already has credentials "
                                     "or their absence cannot be verified; remove them explicitly first")
        if created.existed and not provider.credential_free:
            updated = self.cli("provider", "update", provider.name, *ws_args(ws.name),
                               *credential_args, *config, env=env, check=False)
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

    def check_keyless_profile(self, ws, provider):
        """A keyless provider carries no key, so the governance profile is
        the only thing between the sandbox and the service: it must exist,
        declare no required credential, and enforce its endpoints."""
        self.governance_catalog(ws)
        profile = self.catalog_details[ws.name].get(provider.type)
        if profile is None:
            raise InstallerError(f"keyless provider '{provider.name}' needs live profile "
                                 f"'{provider.type}' in workspace '{ws.name}'")
        # A profile with no key omits `credentials` entirely (the shape of the
        # shipped web-search profile); an empty list means the same.
        declarations = profile.get("credentials")
        if declarations is None:
            declarations = []
        if not isinstance(declarations, list) or any(
                not isinstance(d, dict) or d.get("required", True) is not False
                for d in declarations):
            raise InstallerError(f"keyless provider '{provider.name}' cannot use profile "
                                 f"'{provider.type}': credentials are required or their "
                                 "declarations are malformed")
        # Without a key the endpoints are the only control, so each one must
        # say it is enforced. An endpoint that does not declare enforcement is
        # refused rather than assumed enforcing: this check is what the key
        # would otherwise be.
        endpoints = profile.get("endpoints")
        if not isinstance(endpoints, list) or not endpoints:
            raise InstallerError(f"keyless provider '{provider.name}' cannot use profile "
                                 f"'{provider.type}': it declares no endpoints")
        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or endpoint.get("enforcement") != "enforce":
                raise InstallerError(f"keyless provider '{provider.name}' cannot use profile "
                                     f"'{provider.type}': endpoint "
                                     f"'{endpoint.get('host') if isinstance(endpoint, dict) else endpoint}' "
                                     "is not enforced")
            # Keyless exists for in-cluster Services, where the cluster's own
            # network is part of the control. An outside host reached with no
            # key would widen the sandbox's egress with nothing in the BOM
            # naming a Secret; shipped web-search declares no credential and
            # would otherwise qualify.
            if not in_cluster_host(endpoint.get("host") or ""):
                raise InstallerError(f"keyless provider '{provider.name}' cannot use profile "
                                     f"'{provider.type}': endpoint "
                                     f"'{endpoint.get('host')}' is not an in-cluster Service "
                                     "(credentialFree is for .svc hosts)")

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
        # Earlier custom providers may have cached the catalog before this import.
        self.catalogs.pop(ws.name, None)
        self.catalog_details.pop(ws.name, None)
        self.remember("profile", ws.name, profile_id)

    @staticmethod
    def profile_contains(current, desired):
        """Compare shipped fields with an export that includes server defaults."""
        if isinstance(desired, dict):
            return isinstance(current, dict) and all(
                key in current and ProfileApplier.profile_contains(current[key], value)
                for key, value in desired.items())
        if isinstance(desired, list):
            return isinstance(current, list) and len(current) == len(desired) and all(
                ProfileApplier.profile_contains(actual, value)
                for actual, value in zip(current, desired))
        return current == desired

    def reconcile_dynamic_profile(self, ws, profile_id):
        """Keep an approved custom profile aligned with the installer disk.

        OpenShell import accepts an existing profile without changing it.
        Updates need the resource_version from the gateway export.
        """
        desired = _yaml(self.provider_profiles[profile_id], profile_id)
        current = self.cli("provider", "profile", "export", profile_id,
                           *ws_args(ws.name), check=False, quiet=True, force=True)
        if not current.ok:
            detail = current.out + " " + current.err
            if not ("provider profile" in detail.lower() and "not found" in detail.lower()):
                raise InstallerError(f"could not export the '{profile_id}' provider profile")
            self.import_provider_profile(ws, profile_id)
            return
        try:
            exported = _yaml(current.out, f"exported {profile_id}")
        except InstallerError as exc:
            raise InstallerError(f"could not parse the '{profile_id}' provider profile export") from exc
        if not isinstance(exported, dict):
            raise InstallerError(f"invalid '{profile_id}' provider profile export")

        # OpenShell exports the default grant type without a grant_type key
        # and turns cache_ttl_seconds into a duration string.
        for credential in desired.get("credentials", []):
            grant = credential.get("token_grant")
            if not isinstance(grant, dict):
                continue
            grant_type = grant.pop("grant_type", None)
            if grant_type not in ("client_credentials", "token_exchange"):
                raise InstallerError(f"unsupported grant type in '{profile_id}' provider profile")
            seconds = grant.pop("cache_ttl_seconds", None)
            if seconds is not None:
                grant["cache_ttl"] = f"{seconds}s"
        if self.profile_contains(exported, desired):
            self.remember("profile", ws.name, profile_id)
            return
        if exported.get("scope") != "workspace" or exported.get("source") != "user":
            raise InstallerError(f"'{profile_id}' provider profile differs from the approved "
                                 "profile and is not a workspace custom profile")
        version = exported.get("resource_version")
        if not isinstance(version, int) or version <= 0:
            raise InstallerError(f"'{profile_id}' provider profile has no resource version")
        replacement = _yaml(self.provider_profiles[profile_id], profile_id)
        replacement["resource_version"] = version
        with tempfile.TemporaryDirectory(prefix="saw-profile-") as tmp:
            path = Path(tmp) / f"{profile_id}.yaml"
            path.write_text(yaml.safe_dump(replacement), encoding="utf-8")
            result = self.cli("provider", "profile", "update", profile_id,
                              "-f", str(path), *ws_args(ws.name), check=False)
        if not result.ok:
            raise InstallerError(f"could not update the '{profile_id}' provider profile")
        self.remember("profile", ws.name, profile_id)

    # -- sandboxes -------------------------------------------------------

    def find_provider(self, ws, names, sb=None):
        """The provider an agent sandbox is onboarded with: the sandbox's
        `inference.providerRef`, else one of the sandbox's own providers,
        preferring one with a model. Never another provider of the
        workspace: found live, a skipped `custom` provider made OpenClaw
        onboard with `brave` and a default NVIDIA model."""
        usable = [p for p in self.usable(ws) if not p.credential_free]
        if sb is not None and sb.inference_values:
            ref = sb.inference_values["providerRef"]
            return next((p for p in usable if p.name == ref), None)
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

    def workload_api_mount_must_go(self, ws, sb):
        """Identity opt-out has to recreate a sandbox that still bind-mounts the Workload API."""
        if (self.cfg.get("spiffe") or {}).get("enabled"):
            return False
        listed = self.sh.run(
            ["podman", "ps", "-a",
             "--filter", f"label=openshell.ai/sandbox-name={sb.name}",
             "--filter", f"label=openshell.ai/sandbox-workspace={ws.name}",
             "--filter", f"label={WORKLOAD_ROLE_LABEL}",
             "--format", "{{.Names}}"], check=False, quiet=True)
        if not listed.ok:
            return False
        for name in listed.out.split():
            inspected = self.sh.run(
                ["podman", "inspect", "--format", "{{json .HostConfig.Binds}}", name],
                check=False, quiet=True)
            if inspected.ok and "/spiffe-workload-api" in (inspected.out or ""):
                return True
        return False

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

    def tool_gate_identity(self, ws, sb):
        dashboard = self.cfg.get("dashboard") or {}
        owner = dashboard.get("owner") if isinstance(dashboard, dict) else ""
        subject = self.cfg.get("ownerSubject") or ""
        if not isinstance(owner, str) or not owner.strip():
            raise InstallerError(f"sandbox '{sb.name}': dashboard.owner is required for the tool gate")
        if not isinstance(subject, str) or not subject.strip():
            raise InstallerError(f"sandbox '{sb.name}': ownerSubject is required for the tool gate")
        return {"username": owner, "subject": subject,
                "sandbox": sb.name, "workspace": ws.name}

    def tool_gate_bundle(self, ws, sb):
        """Derive the trusted tree and expected digest without mutating a volume."""
        identity = self.tool_gate_identity(ws, sb)
        here = Path(__file__).resolve().parent
        names = ("tool-actions.yaml", "tool-gate.mjs", "tool-gate-plugin.mjs")
        missing = [name for name in names if not (here / name).is_file()]
        if missing:
            raise InstallerError("tool gate files missing from the installer disk: " + ", ".join(missing))
        policy = (here / "tool-actions.yaml").read_bytes()
        policy_hash = "sha256:" + hashlib.sha256(policy).hexdigest()
        plugin = (here / "tool-gate-plugin.mjs").read_bytes().replace(
            b"__SAW_POLICY_HASH__", policy_hash.encode())
        tree = {
            "tool-actions.yaml": (policy, False),
            "identity.json": ((json.dumps(identity, sort_keys=True) + "\n").encode(), False),
            "plugin/package.json": (_TOOL_GATE_PACKAGE.encode(), False),
            "plugin/openclaw.plugin.json": (_TOOL_GATE_MANIFEST.encode(), False),
            "plugin/index.js": (plugin, False),
            "plugin/tool-gate.mjs": ((here / "tool-gate.mjs").read_bytes(), False),
        }
        digest = harness_tree_digest(tree)
        source = f"gate:{digest}"
        return tree, source, digest, policy_hash

    def prepare_tool_gate(self, ws, sb):
        """Fill trusted plugin, policy and identity from the host, before create."""
        if sb.type not in ("openclaw", "nemoclaw"):
            return
        tree, source, digest, policy_hash = self.tool_gate_bundle(ws, sb)
        key = (ws.name, sb.name)
        self.gate_expected[key] = (source, digest, policy_hash)
        if self.sh.dry_run:
            self.gate_refilled[key] = False
            return
        volume = sandbox_volume_name(GATE_VOLUME_PREFIX, *key)
        mountpoint = self.volumes.ensure(volume, ws.name)
        if mountpoint is None:
            raise InstallerError(f"gate volume {volume} lacks sandbox admission labels")
        current, _marker = self.volumes.current(mountpoint, source, digest)
        self.gate_refilled[key] = current is None
        if current is None:
            self.volumes.fill(volume, mountpoint, source, tree)
            log(f"Gate volume {volume} filled with policy {policy_hash}")
        audit_volume = sandbox_volume_name(AUDIT_VOLUME_PREFIX, *key)
        audit_dir = self.volumes.ensure(audit_volume, ws.name)
        if audit_dir is None:
            raise InstallerError(f"audit volume {audit_volume} lacks sandbox admission labels")
        # A running rootless sandbox may remap the volume owner to a subordinate
        # UID, so host-side chmod fails even though podman owns the volume.
        self._podman("unshare", "chmod", "555", str(audit_dir))

    def finalize_tool_audit(self, ws, sb):
        """Make the sandbox user's log append-only, with an unwritable parent."""
        if self.sh.dry_run:
            return
        volume = sandbox_volume_name(AUDIT_VOLUME_PREFIX, ws.name, sb.name)
        info = self.volumes.inspect(volume)
        if info is None or not self.volumes.admitted(info, ws.name):
            raise InstallerError(f"audit volume {volume} is missing or lacks admission labels")
        root = Path(info["Mountpoint"])
        log_file = root / AUDIT_FILE
        if log_file.is_symlink() or (log_file.exists() and not stat.S_ISREG(log_file.stat().st_mode)):
            raise InstallerError(f"audit path {log_file} is not a regular file")
        if not log_file.exists():
            exec_cmd = ("sandbox", "exec", "-n", sb.name, *ws_args(ws.name), "--no-tty", "--")
            uid = self.cli(*exec_cmd, "id", "-u", quiet=True).out.strip()
            gid = self.cli(*exec_cmd, "id", "-g", quiet=True).out.strip()
            if not uid.isdigit() or not gid.isdigit():
                raise InstallerError(f"sandbox '{sb.name}': cannot determine the audit writer's uid/gid")
            self._podman("unshare", "chmod", "755", str(root))
            try:
                self._podman("unshare", "touch", str(log_file))
                self._podman("unshare", "chmod", "600", str(log_file))
                self._podman("unshare", "chown", f"{uid}:{gid}", str(log_file))
            finally:
                self._podman("unshare", "chmod", "555", str(root))
        self.sh.run(["sudo", "-n", "chattr", "+a", str(log_file)])

    def _podman(self, *args, **kw):
        return self.sh.run(["podman", *args], **kw)

    def verify_harness_image(self, image):
        """Fail closed, with bounded reuse of successful digest verification."""
        sig = (self.cfg.get("harness") or {}).get("cosign") or {}
        identity, issuer = sig.get("identity") or "", sig.get("issuer") or ""
        ttl = harness_signature_cache_ttl(self.cfg)
        if not identity or not issuer:
            raise InstallerError(
                f"harness image {image} has no cosign identity/issuer configured; "
                "refusing to use it")
        policy = {"identity": identity, "issuer": issuer}
        now = time.time()
        cache = self.ledger.data.get("harnessSignatures", {}) if self.ledger is not None else {}
        if not isinstance(cache, dict):
            cache = {}
        entry = cache.get(image)
        if ttl and isinstance(entry, dict) and entry.get("policy") == policy:
            verified_at = entry.get("verifiedAt")
            if type(verified_at) in (int, float) and 0 <= now - verified_at < ttl:
                log(f"Harness signature for {image}: using verified digest cache "
                    f"(age {int(now - verified_at)}s, maximum {ttl}s)")
                return
        result = self.sh.run(
            ["cosign", "verify", "--certificate-identity", identity,
             "--certificate-oidc-issuer", issuer, image],
            check=False, quiet=True, force=True, timeout=120)
        if not result.ok:
            if self.ledger is not None and not self.sh.dry_run:
                cache.pop(image, None)
                self.ledger.data["harnessSignatures"] = cache
                self.ledger.save()
            raise InstallerError(f"harness image {image} is not signed by {identity}")
        if self.ledger is not None and not self.sh.dry_run and ttl:
            cache[image] = {"policy": policy, "verifiedAt": now}
            self.ledger.data["harnessSignatures"] = cache
            self.ledger.save()

    def image_tree(self, image):
        """The bundle tree of a harness image (with file modes). Pulled by
        digest when it is not present yet.

        The signature is checked by the caller (prepare_harness), on every
        apply rather than only on the one that reaches here.

        Runs even under --dry-run (force): dry-run must refuse a bad image the
        same way a real apply would, before it claims success.
        """
        if not self._podman("image", "exists", image, check=False, quiet=True, force=True).ok:
            self._podman("pull", "--quiet", image, timeout=900, force=True)
        created = self._podman("create", image, "/harness.yaml", force=True)
        cid = created.out.strip().splitlines()[-1] if created.out.strip() else ""
        if not cid:
            raise InstallerError(f"podman create returned no container id for {image}")
        with tempfile.TemporaryDirectory(prefix="saw-harness-") as tmp:
            exported = Path(tmp) / "image.tar"
            try:
                self._podman("export", "-o", str(exported), cid, force=True)
            finally:
                self._podman("rm", "-f", cid, check=False, quiet=True, force=True)
            return read_harness_tar(exported)

    def sandbox_mount_map(self, ws, sb):
        """Relevant workload mounts keyed by destination; False if uninspectable.

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
        if not got.ok:
            return False
        try:
            mounts = json.loads(got.out)
        except ValueError:
            return False
        if not isinstance(mounts, list) or any(not isinstance(m, dict) for m in mounts):
            return False
        found = {}
        for mount in mounts:
            target = mount.get("Destination")
            if target in (HARNESS_MOUNT, GATE_MOUNT, AUDIT_MOUNT):
                kind = (mount.get("Type") or "").lower()
                source = mount.get("Name") if kind == "volume" else mount.get("Source")
                # Missing RW: treat as writable (not OK).
                if target in found:
                    return False
                found[target] = (kind, source or "", bool(mount.get("RW", True)))
        return found

    def sandbox_harness_mount(self, ws, sb):
        seen = self.sandbox_mount_map(ws, sb)
        return False if seen is False else seen.get(HARNESS_MOUNT)

    def sandbox_mounts_ok(self, ws, sb):
        seen = self.sandbox_mount_map(ws, sb)
        if seen is False:
            if sb.type in ("openclaw", "nemoclaw"):
                raise InstallerError(f"cannot inspect trusted mounts in sandbox '{sb.name}'")
            return True
        desired = {mount["target"]: ("volume", mount["source"], not mount["read_only"])
                   for mount in sandbox_mounts(ws, sb)}
        return seen == desired

    def harness_mount_ok(self, ws, sb):
        """True when the sandbox mounts exactly its harness volume read-only,
        or, without a harnessRef, mounts nothing at HARNESS_MOUNT (a harness
        that was removed must not stay mounted). A sandbox whose container
        cannot be found is left to the gateway."""
        seen = self.sandbox_harness_mount(ws, sb)
        if seen is False:
            log(f"WARN: no workload container found for sandbox '{sb.name}'; "
                "not checking its harness mount")
            return True
        want = self.desired_harness_mount(ws, sb)
        return seen == (("volume", want, False) if want else None)

    def governance_catalog(self, ws):
        """{profile id: endpoint hosts} the gateway serves in the workspace
        right now (from the governance interceptor, or profiles imported into
        the workspace). Read live, so there is no list to keep in sync. In
        0.1.x `provider list-profiles` lists one workspace's catalog, so it
        is read, and cached, per workspace."""
        if ws.name not in self.catalogs:
            # force: dry-run must still see the live catalog (see prepare_harness).
            listed = self.cli("provider", "list-profiles", *ws_args(ws.name), "-o", "json",
                              check=False, quiet=True, force=True)
            if not listed.ok:
                raise InstallerError("cannot read the gateway's provider profile catalog "
                                     f"for workspace '{ws.name}' (openshell provider "
                                     "list-profiles failed); refusing to apply "
                                     "without a governance check")
            self.catalog_details[ws.name] = parse_provider_profile_catalog(listed.out)
            self.catalogs[ws.name] = parse_profile_catalog(self.catalog_details[ws.name])
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
                if not host_allowed(host, catalog[profile]):
                    allowed = ", ".join(sorted(catalog[profile])) or "none"
                    raise InstallerError(
                        f"{what} reaches {host}, which governanceProfile '{profile}' does not "
                        f"allow (allowed: {allowed}); refusing to fill the harness of "
                        f"sandbox '{sb.name}'")

    def expected_harness_digest(self, volume, bundle, source):
        """Trusted tree digest for `volume`, or None when none is known yet.

        Inline: the ConfigMap digest. Image: this apply's confirmed digest,
        else the ledger entry written after a previous fill, if it is for
        this same `source` (a changed harnessRef makes a stale entry's digest
        describe the wrong tree; a forged on-volume marker could otherwise
        pair that stale-but-valid digest with a source string it does not
        belong to and pass as intact). No ledger and no in-apply confirmation
        means the volume is always refilled.
        """
        if bundle is not None:
            return bundle.digest
        if volume in self.harness_digests:
            return self.harness_digests[volume]
        if self.ledger is None:
            return None
        entry = self.ledger.data.get("harness", {}).get(volume, {})
        return entry.get("treeDigest") if entry.get("source") == source else None

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
        if bundle is None:
            # Check trust before using a cached tree or pulling an image.
            # A successful signature may be reused for the bounded cache
            # period; changed signing policy invalidates it immediately.
            # Verified before it joins harness_images: an
            # image that fails here must not be kept, or cleanup_harness_images
            # (previous - self.harness_images) would never remove it.
            try:
                self.verify_harness_image(source)
            except InstallerError:
                # Refusing a new apply is insufficient when revoked code is
                # still mounted in an existing sandbox. Recreate without it;
                # keep the requested source refused so a later apply must
                # pass verification before restoring the mount.
                seen = None if self.sh.dry_run else self.sandbox_harness_mount(ws, sb)
                # False means the container inspection was inconclusive;
                # an existing sandbox cannot keep running untrusted code
                # merely because podman inspection failed.
                if seen is not None and (seen is not False or self.sandbox_state(ws, sb) != "missing"):
                    log(f"Removing untrusted harness from sandbox '{sb.name}'")
                    self.delete_sandbox_and_wait(ws, sb)
                    self.harness_info.pop((ws.name, sb.name), None)
                    self.harness_refilled.pop((ws.name, sb.name), None)
                    self.apply_sandbox(ws, replace(sb, harness_ref={}))
                raise
            self.harness_images.add(source)
        volume = harness_volume_name(ws.name, sb.name)
        self.harness_volumes.add(volume)
        # Dry-run still resolves the tree and runs governance (so a bundle
        # that would fail apply cannot pass --dry-run); it skips volume I/O.
        mountpoint = None if self.sh.dry_run else self.volumes.ensure(volume, ws.name)
        expected_digest = self.expected_harness_digest(volume, bundle, source)
        # None: the volume predates its admission labels, which cannot be
        # added later; it is replaced below, after governance passed.
        tree = (self.volumes.current(mountpoint, source, expected_digest)[0]
                if mountpoint else None)
        current = tree is not None
        if current:
            log(f"Harness volume {volume} already holds {source}")
        elif bundle is None:
            log(f"Harness image {source} for sandbox '{sb.name}'")
            tree = self.image_tree(source)
        else:
            tree = {rel: (base64.b64decode(b64), False) for rel, b64 in bundle.files.items()}
        if bundle is None:
            # Confirmed for this apply so verify can trust it even with no ledger.
            self.harness_digests[volume] = (
                expected_digest if current else harness_tree_digest(tree))
        info = describe_harness_tree(tree, inline=bundle is not None)
        if info["agent"] != "openclaw":
            raise InstallerError(f"harness {source} is for agent '{info['agent']}', "
                                 f"sandbox '{sb.name}' runs openclaw")
        self.check_harness_governance(ws, sb, info)
        self.harness_info[(ws.name, sb.name)] = info
        self.harness_refilled[(ws.name, sb.name)] = not current
        if self.sh.dry_run:
            log(f"Harness {source} for sandbox '{sb.name}' in volume {volume} (dry run)")
            return info
        if mountpoint is None:
            log(f"Harness volume {volume} lacks its admission labels; recreating it "
                f"(and sandbox '{sb.name}', which mounts it)")
            self.delete_sandbox_and_wait(ws, sb)
            self.remove_volume_and_wait(volume)
            mountpoint = self.volumes.ensure(volume, ws.name)
            if mountpoint is None:
                raise InstallerError(f"podman created volume {volume} without its labels")
        if not current:
            marker = self.volumes.fill(volume, mountpoint, source, tree)
            if bundle is None and self.ledger is not None:
                self.ledger.data.setdefault("harness", {})[volume] = {
                    "source": source, "treeDigest": marker["treeDigest"]}
                self.ledger.save()
            log(f"Harness volume {volume} filled from {source}")
        return info

    def delete_sandbox_and_wait(self, ws, sb, attempts=24, delay=None):
        """Delete a sandbox and wait until the gateway no longer has it and
        podman has removed its workload container: 0.1.x may accept the
        delete with cleanup still pending, and its container keeps the
        harness volume in use until it is gone."""
        self.cli("sandbox", "delete", sb.name, *ws_args(ws.name), check=False)
        if self.sh.dry_run:
            return
        delay = self.POLL_SECONDS if delay is None else delay
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

    def create_sandbox(self, ws, sb, configure_harness=True):
        """configure_harness=False: the caller runs start_openclaw right
        after this, which configures the harness itself; skip the redundant
        round trip here."""
        self.prepare_tool_gate(ws, sb)
        self.prepare_harness(ws, sb)
        state = self.sandbox_state(ws, sb)
        if state == "broken":
            log(f"Sandbox '{sb.name}' reports an error; waiting up to "
                f"{self.BROKEN_GRACE_SECONDS}s for it to recover")
            state = self.wait_sandbox(ws, sb, lambda s: s != "broken", self.BROKEN_GRACE_SECONDS)
        if state == "running" and self.workload_api_mount_must_go(ws, sb):
            log(f"Sandbox '{sb.name}' still mounts the Workload API; recreating it")
            self.delete_sandbox_and_wait(ws, sb)
            state = "missing"
        if state == "running" and not self.sh.dry_run and not self.harness_mount_ok(ws, sb):
            # Mounts are fixed at create: a sandbox created before its
            # harnessRef, one that still mounts a harness it no longer has,
            # or one that mounts another volume there is created again.
            # OpenShell 0.1.x deletes the per-sandbox /sandbox workspace
            # volume, including /sandbox/persist. Preserve needed files
            # separately before a recreation; the harness volume is distinct.
            want = self.desired_harness_mount(ws, sb)
            log(f"Sandbox '{sb.name}' " + (f"does not mount its harness volume {want}"
                                           if want else "still mounts a removed harness")
                + "; recreating it")
            self.delete_sandbox_and_wait(ws, sb)
            state = "missing"
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
        # The sandbox is now either running (recovered included) or missing:
        # only now look at what it is, so a recovering sandbox is reconciled
        # like any other.
        key = self.migration_key(ws, sb)
        labels = None
        if state == "running" and not self.sh.dry_run:
            labels = self.sandbox_labels(ws, sb)
        if key in self.migrations:
            state = self.recover_migration(ws, sb, state, labels)
            if state == "running":
                labels = self.sandbox_labels(ws, sb) if not self.sh.dry_run else labels
        if state == "running" and labels is not None and key not in self.migrations:
            have = labels[0] or "none"             # created before the label: had no env
            if have != env_label(sb.env_values):
                self.begin_migration(ws, sb, labels)
                state = "missing"
        if state == "running" and not self.sh.dry_run and not self.sandbox_mounts_ok(ws, sb):
            # Mounts are fixed at create: a sandbox created before its
            # harnessRef, one that still mounts a harness it no longer has,
            # or one that mounts another volume there is created again.
            # OpenShell 0.1.x deletes the per-sandbox /sandbox workspace
            # volume, including /sandbox/persist. Preserve needed files
            # separately before a recreation; the harness volume is distinct.
            log(f"Sandbox '{sb.name}' has stale or missing trusted mounts; recreating it")
            self.delete_sandbox_and_wait(ws, sb)
            state = "missing"
        if state == "running":
            log(f"Sandbox '{sb.name}' already exists")
            self.attach_missing_providers(ws, sb)
            if sb.harness_ref and configure_harness:
                exec_cmd = ["sandbox", "exec", "-n", sb.name, *ws_args(ws.name),
                            "--no-tty", "--"]
                self.configure_harness(ws, sb, exec_cmd, OPENCLAW_EXEC_ENV)
            self.remember("sandbox", ws.name, sb.name)
            return
        if sb.image and ("/" in sb.image or ":" in sb.image):
            self.sh.run(["podman", "pull", sb.image], check=False, timeout=900)
        # The replacement of a pending recreation is created with the env
        # the profile wants NOW (identity does not depend on the env, so
        # there is no reason to materialise an intermediate one); the record
        # is updated to say so, and its instance token identifies the
        # replacement for the restore.
        pending = self.migrations.get(self.migration_key(ws, sb))
        if pending and pending.get("env") != sb.env_values:
            pending["env"] = dict(sb.env_values)
            self.save_migrations()
        instance = pending["toInstance"] if pending else secrets.token_hex(8)
        args = ["sandbox", "create", "--name", sb.name, "--label", MANAGED_LABEL,
                "--label", f"{ENV_LABEL_KEY}={env_label(sb.env_values)}",
                "--label", f"{INSTANCE_LABEL_KEY}={instance}"]
        if sb.image:
            args += ["--from", sb.image]
        args += ws_args(ws.name)
        # The workload's environment, for every process in the sandbox:
        # literals from the profile (never Secret values: `--env` puts them
        # in argv and every sandbox process could read them; a Secret value
        # goes on a provider).
        args += env_flags(sb.env_values)
        if sandbox_mounts(ws, sb):
            args += ["--driver-config-json", sandbox_mounts_json(ws, sb)]
        for prov in sb.providers:
            if (ws.name, prov) in self.skipped:
                log(f"WARN: sandbox '{sb.name}' created without skipped provider '{prov}'")
                continue
            args += ["--provider", prov]
        # Keep the sandbox Ready for the follow-up `sandbox exec` setup.
        args += ["--no-tty", "--detach", "--", "sh", "-c", "sleep infinity"]
        self.cli(*args, timeout=900)
        self.remember("sandbox", ws.name, sb.name)
        if pending:
            # The replacement exists now: restore into it (by its token).
            self.recover_migration(ws, sb, "running",
                                   (env_label(sb.env_values), instance, ""))

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
            keyless = any(p.name == prov and p.credential_free for p in self.usable(ws))
            # A keyless provider is the sandbox's permission to reach its
            # governed service, and the attachment installs the policy for
            # processes started after it: wait for it, and restart OpenClaw
            # so the running gateway is covered too.
            self.cli("sandbox", "provider", "attach", sb.name, prov, *ws_args(ws.name),
                     *(("--wait",) if keyless else ()), check=keyless)
            if keyless:
                self.harness_refilled[(ws.name, sb.name)] = True

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
        nc_provider = nemoclaw_provider(provider)
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
        model = sandbox_model(sb, provider)
        if model:
            env["NEMOCLAW_MODEL"] = model
        if (sb.inference_values or {}).get("timeoutSeconds"):
            # NemoClaw's onboarding has no request-timeout setting; the
            # OpenClaw gateway it runs gets it in start_openclaw.
            log(f"NOTE: inference.timeoutSeconds of '{sb.name}' applies to its OpenClaw gateway, "
                "not to nemoclaw onboard (no such setting)")
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
        self.finalize_tool_audit(ws, sb)
        # No /sandbox chown: OpenShell 0.1.x runs the workload without
        # capabilities (root in the container cannot even read /sandbox) and
        # already gives /sandbox to the image's user.
        model = sandbox_model(sb, provider, "nvidia/nemotron-3.5-lightning-30b-a3b")
        oc_env = OPENCLAW_EXEC_ENV
        # OpenShell 0.1.x: no inference.local. OpenClaw calls the provider's
        # own endpoint with the placeholder key this exec receives in the
        # provider's env var (e.g. NVIDIA_API_KEY); the sandbox proxy puts in
        # the real key only for the profile's endpoints and binaries. The
        # placeholder is read inside the sandbox (\$), never by the installer.
        # The endpoint and protocol are the sandbox's inference settings
        # (`inference:`), else the provider type's (legacy). The provider
        # only names the credential: its profile decides which hosts the
        # key may reach; the protocol decides how the agent talks to them.
        endpoint = sandbox_endpoint(sb, provider)
        protocol = sandbox_protocol(sb, provider)
        if sb.inference_values:
            # No baseUrl: the provider type's own API (NVIDIA's, say), else
            # the protocol's official one. An official API (openai,
            # anthropic) is onboarded natively (OpenClaw's own catalog) when
            # the provider is that API; anything else as a custom endpoint.
            base_url = (endpoint or NATIVE_BASE_URLS.get(provider.type, "")
                        or PROTOCOL_NATIVE_BASE_URLS.get(protocol, ""))
            native = (not endpoint and provider.type in OPENCLAW_AUTH_CHOICES
                      and PROVIDER_PROTOCOLS.get(provider.type) == protocol)
        else:
            base_url = endpoint or NATIVE_BASE_URLS.get(provider.type, "")
            native = not (endpoint or provider.base_url_secret_key)
        key_var = credential_env_name(provider.type, self.provider_profiles)
        auth_choice = OPENCLAW_AUTH_CHOICES.get(provider.type) if native else None
        if (not base_url and not auth_choice) or not key_var:
            log(f"WARN: no endpoint for provider '{provider.name}' (type '{provider.type}'); "
                f"set the sandbox's inference.baseUrl. Skipping OpenClaw onboarding")
            # No openclaw.json yet, so the plugin entry is not enabled. The
            # files are still in place for a later onboard.
            self.install_tool_gate(ws, sb, enable=False)
            # The sandbox still has to stay Ready after the installer exits.
            self.install_keepalive(ws, sb)
            return
        # An official OpenAI provider the sandbox has (onboarded or attached
        # for API-key chats) uses OpenClaw's own runtime, not the Codex plugin.
        if auth_choice == "openai-api-key" or any(
                p.enabled and p.name in sb.providers and p.type == "openai"
                and not (p.base_url or p.base_url_secret_key) for p in ws.providers):
            # API-key chats use OpenClaw without the optional Codex plugin.
            self.cli(*exec_cmd, "sh", "-c",
                     f"{oc_env} openclaw config set 'agents.defaults.models.openai/*.agentRuntime' "
                     + shlex.quote(json.dumps({"id": "openclaw"})), check=False)
        if auth_choice:
            # Native onboarding keeps an old custom endpoint unless it is removed.
            self.cli(*exec_cmd, "sh", "-c",
                     f"{oc_env} openclaw config unset models.providers.{provider.type}",
                     check=False)
            auth_args = f"--auth-choice {auth_choice}"
            key_env = ""
        else:
            auth_args = ("--auth-choice custom-api-key "
                         f"--custom-base-url {shlex.quote(base_url)} "
                         f"--custom-provider-id {shlex.quote(provider.type)} "
                         f"--custom-model-id {shlex.quote(model)} "
                         f"--custom-compatibility {shlex.quote(protocol or 'openai')}")
            key_env = f'CUSTOM_API_KEY="${key_var}" '
        onboarded = self.cli(*exec_cmd, "sh", "-c",
                 f"{oc_env} {key_env}openclaw onboard --non-interactive "
                 f"--accept-risk --mode local {auth_args} --skip-channels --skip-health", check=False)
        # Re-onboarding an existing sandbox with a different provider or model
        # (e.g. after switching to a custom endpoint) makes OpenClaw save the
        # new credential but keep the old connection; activate the new one.
        profile_id = openclaw_replacement_profile(onboarded.out + "\n" + onboarded.err)
        if profile_id:
            log(f"Activating the new OpenClaw credential '{profile_id}'")
            self.cli(*exec_cmd, "sh", "-c",
                     f"{oc_env} openclaw models auth activate {shlex.quote(profile_id)} --agent main",
                     check=False)
        if auth_choice:
            model_id = model if model.startswith(f"{provider.type}/") else f"{provider.type}/{model}"
            self.cli(*exec_cmd, "sh", "-c",
                     f"{oc_env} openclaw models set {shlex.quote(model_id)}", check=False)
        # The request timeout: OpenClaw's per-provider HTTP timeout
        # (models.providers.<id>.timeoutSeconds; the custom provider's id is
        # the --custom-provider-id above, a native one's its type).
        # Set when given, unset otherwise: OpenClaw's onboarding keeps an
        # existing provider's settings, so a removed value would stay. The
        # unset is conditional: `config unset` of an absent path logs an
        # error (found live).
        timeout = (sb.inference_values or {}).get("timeoutSeconds", 0)
        key = f"models.providers.{shlex.quote(provider.type)}.timeoutSeconds"
        self.cli(*exec_cmd, "sh", "-c",
                 f"{oc_env} openclaw config set {key} {int(timeout)}" if timeout
                 else f"{oc_env} openclaw config get {key} >/dev/null 2>&1 && "
                      f"{oc_env} openclaw config unset {key} || true", check=False)
        self.configure_harness(ws, sb, exec_cmd, oc_env)
        # Before the gateway process starts, so this boot loads the hook.
        # openclaw_gateway_script restarts only on a harness refill, when none
        # is running, or when its settings changed; the files are in place either way.
        self.install_tool_gate(ws, sb, enable=True)
        # One script: the gateway secret is made and kept inside the sandbox
        # (the installer never sees it). The gateway is restarted only when
        # the harness was refilled, none is running, or its settings (auth
        # mode, users, origins) changed: a restart cuts live sessions.
        refilled = (self.harness_refilled.get((ws.name, sb.name), False)
                    or self.gate_refilled.get((ws.name, sb.name), False))
        self.cli(*exec_cmd, "sh", "-c",
                 openclaw_gateway_script(self.cfg, ws.name, sb.name, oc_env, refilled=refilled),
                 check=False)
        self.install_keepalive(ws, sb)

    def configure_harness(self, ws, sb, exec_cmd, oc_env):
        """Point OpenClaw at the mounted bundle (openclaw_harness_config).

        Config only: the bundle's files reach the sandbox through the mount,
        never through exec, and no key is written: a governed plugin or MCP
        server gets its provider's placeholder from the sandbox environment.
        """
        info = self.harness_info.get((ws.name, sb.name))
        desired = openclaw_harness_config(info) if info is not None else {}
        if sb.type in ("openclaw", "nemoclaw"):
            desired["plugins.load.paths"] = [
                *desired.get("plugins.load.paths", []), f"{GATE_MOUNT}/plugin"]
        for key, value in desired.items():
            self.cli(*exec_cmd, "sh", "-c",
                     f"{oc_env} openclaw config set {key} {shlex.quote(json.dumps(value))}",
                     check=False)
        for key in HARNESS_CONFIG_KEYS:
            if key not in desired:
                # Conditional: `config unset` of an absent path logs an
                # error on every apply (found live).
                self.cli(*exec_cmd, "sh", "-c",
                         f"{oc_env} openclaw config get {key} >/dev/null 2>&1 && "
                         f"{oc_env} openclaw config unset {key} || true", check=False)
        # OpenClaw 2026.9.x keeps a plugin found on plugins.load.paths
        # disabled until it is enabled with capability consent, and a
        # restrictive plugins.allow (NemoClaw ships one) blocks it outright;
        # `plugins enable` does both. Older releases load it anyway and may
        # not know --accept-capabilities, hence the plain retry.
        ids = harness_plugin_ids(info) if info is not None else []
        if ids:
            script = "; ".join(
                f"{oc_env} openclaw plugins enable {shlex.quote(i)} --accept-capabilities "
                f"|| {oc_env} openclaw plugins enable {shlex.quote(i)}" for i in ids)
            self.cli(*exec_cmd, "sh", "-c", script, check=False)
        self.configure_harness_mcp(ws, sb, exec_cmd, oc_env, info)

    def configure_harness_mcp(self, ws, sb, exec_cmd, oc_env, info):
        """Re-declare the bundle's MCP servers under mcp.servers
        (harness_mcp_servers), and remove the ones an earlier apply added
        that the bundle no longer has. A change restarts the gateway, which
        starts MCP servers."""
        trust_env = ()
        if info is not None and info.get("mcpConfigs"):
            probe = self.cli(*exec_cmd, "sh", "-c", mcp_trust_env_probe(), check=False, quiet=True)
            if not probe.ok:
                log(f"WARN: sandbox '{sb.name}': could not read its CA settings; "
                    "MCP server declarations left unchanged until the next apply")
                return
            have = set(probe.out.split())
            trust_env = tuple(var for var in MCP_TRUST_ENV if var in have)
        desired = harness_mcp_servers(info, trust_env)
        state = json.dumps(desired, sort_keys=True)
        # Absent on a sandbox's first apply: not an error worth logging.
        seen = self.cli(*exec_cmd, "sh", "-c", f"cat {SAW_MCP_STATE} 2>/dev/null || true",
                        check=False, quiet=True)
        try:
            previous = json.loads(seen.out) if seen.ok and seen.out.strip() else {}
        except ValueError:
            previous = {}
        if not isinstance(previous, dict):
            previous = {}
        if json.dumps(previous, sort_keys=True) == state:
            return
        # set -e: the record is written only when every declaration took,
        # so a failed one is retried by the next apply instead of being
        # recorded as done (verify would then fail on every apply).
        lines = ["set -e"]
        lines += [f"{oc_env} openclaw config unset mcp.servers.{shlex.quote(name)} >/dev/null 2>&1 || true"
                 for name in sorted(set(previous) - set(desired)) if MCP_SERVER_NAME_RE.match(name)]
        for name, entry in desired.items():
            data = (entry.get("env") or {}).get("PLUGIN_DATA")
            if data:
                lines.append(f"mkdir -p {shlex.quote(data)}")
            lines.append(f"{oc_env} openclaw config set mcp.servers.{name} "
                         f"{shlex.quote(json.dumps(entry))}")
        lines.append(f"printf '%s\\n' {shlex.quote(state)} > {SAW_MCP_STATE}")
        done = self.cli(*exec_cmd, "sh", "-c", "\n".join(lines), check=False)
        # Restart even after a partial failure: some declarations may have
        # changed, and the gateway reads them only when it starts.
        self.harness_refilled[(ws.name, sb.name)] = True
        if not done.ok:
            log(f"WARN: sandbox '{sb.name}': declaring the harness MCP servers in "
                "openclaw.json failed; the next apply retries")
            return
        if desired:
            log(f"Sandbox '{sb.name}': MCP server(s) {', '.join(desired)} declared in "
                "openclaw.json (provider placeholders and the proxy CA reach them)")

    def verify_harness(self, ws, sb):
        """The sandbox mounts exactly its harness volume, the volume holds
        the pinned source intact, and the sandbox reads it through the mount
        (the marker file, which names the source and tree digest)."""
        if self.sh.dry_run:
            return []
        source, bundle = self.harness_source(sb)
        if source is None:
            if not self.harness_mount_ok(ws, sb):
                return [f"{HARNESS_MOUNT} is still mounted although the sandbox has no "
                        "harnessRef; the next apply recreates the sandbox"]
            return []
        volume = harness_volume_name(ws.name, sb.name)
        expected_digest = self.expected_harness_digest(volume, bundle, source)
        failures = self.volumes.verify(volume, ws.name, source, expected_digest)
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
        info = self.harness_info.get((ws.name, sb.name))
        if info is None:
            return []
        exec_cmd = ["sandbox", "exec", "-n", sb.name, *ws_args(ws.name), "--no-tty", "--"]
        # `mcp list` never shows bundle servers; verify the bundle row of
        # `plugins list --json` instead (mount row loaded, caps when present,
        # native ids enabled).
        plugin_json = self.cli(*exec_cmd, "sh", "-c",
                               f"{OPENCLAW_EXEC_ENV} openclaw plugins list --json",
                               check=False, quiet=True)
        if not plugin_json.ok:
            return [f"could not list OpenClaw plugins for sandbox '{sb.name}'"]
        try:
            parsed = json.loads(plugin_json.out)
            rows = [p for p in (parsed.get("plugins") or []) if isinstance(p, dict)]
        except (ValueError, AttributeError, TypeError):
            return [f"could not parse `openclaw plugins list --json` for sandbox '{sb.name}'"]
        by_id = {p.get("id") or p.get("name"): p for p in rows}
        # Match the mount row first: a stock plugin could reuse the bundle name.
        # rootDir only: Source may be an origin string ($OPENCLAW_HOME/...),
        # not a path.
        bundle = next((p for p in rows
                       if p.get("format") == "bundle" and p.get("rootDir") == HARNESS_MOUNT),
                      None)
        if bundle is None:
            bundle = by_id.get(info["name"])
        if (not isinstance(bundle, dict) or not bundle.get("enabled")
                or bundle.get("status") != "loaded"):
            why = ""
            if isinstance(bundle, dict):
                why = f"; status {bundle.get('status') or 'unknown'}"
                if bundle.get("error"):
                    why += f": {bundle['error']}"
            return [f"OpenClaw does not load the harness bundle '{info['name']}' "
                    f"from {HARNESS_MOUNT} ({source}){why}"]
        caps = bundle.get("bundleCapabilities") or []
        if caps:
            need_caps = set()
            if info["mcp"]:
                need_caps.add("mcpServers")
            if info["skills"]:
                need_caps.add("skills")
            missing_caps = sorted(need_caps - set(caps))
            if missing_caps:
                return [f"OpenClaw bundle '{info['name']}' lacks capability(ies) "
                        f"{', '.join(missing_caps)} from {source}"]
        missing = [p for p in info["pluginDirs"]
                   if not by_id.get(p, {}).get("enabled", False)]
        if missing:
            return [f"OpenClaw does not list enabled plugin(s) {', '.join(missing)} "
                    f"from {source}"]
        if info["mcpServers"]:
            plugin_id = bundle.get("id") or bundle.get("name") or info["name"]
            listed = self.cli(*exec_cmd, "sh", "-c",
                              f"{OPENCLAW_EXEC_ENV} openclaw plugins inspect "
                              f"{shlex.quote(plugin_id)} --runtime --json",
                              check=False, quiet=True)
            detail = (listed.err + "\n" + listed.out).lower()
            unsupported = (not listed.ok and any(marker in detail for marker in (
                "unknown command", "unknown option", "unexpected argument")))
            if unsupported:
                log(f"WARN: harness {info['name']!r}: sandbox {sb.name!r} "
                    "does not support runtime plugin inspection; MCP registration is unverified "
                    "and MCP process readiness is not checked")
            elif not listed.ok:
                return ["could not inspect OpenClaw MCP registration"]
            else:
                failures = mcp_registration_failures(listed.out, info["mcpServers"])
                if failures:
                    return [f"{failure} from {source}" for failure in failures]
        for name, entry in harness_mcp_servers(info, MCP_TRUST_ENV).items():
            got = self.cli(*exec_cmd, "sh", "-c",
                           f"{OPENCLAW_EXEC_ENV} openclaw config get mcp.servers.{name}",
                           check=False, quiet=True)
            try:
                seen_entry = json.loads(got.out) if got.ok else None
            except ValueError:
                seen_entry = None
            key = "command" if "command" in entry else "url"
            # The bundle's own env keys must all be there (OpenClaw redacts
            # the values); the CA settings are only the ones the sandbox has.
            want_env = set(entry.get("env") or {}) - set(MCP_TRUST_ENV)
            seen_env = (seen_entry.get("env") or {}) if isinstance(seen_entry, dict) else {}
            if (not isinstance(seen_entry, dict) or seen_entry.get(key) != entry[key]
                    or not isinstance(seen_env, dict) or not want_env <= set(seen_env)):
                return [f"OpenClaw does not declare MCP server '{name}' in openclaw.json; "
                        "the bundle's own entry cannot pass it its provider placeholder "
                        f"or the proxy CA ({source})"]
        desired = openclaw_harness_config(info)
        if sb.type in ("openclaw", "nemoclaw"):
            desired["plugins.load.paths"] = [
                *desired.get("plugins.load.paths", []), f"{GATE_MOUNT}/plugin"]
        for key in HARNESS_CONFIG_KEYS:
            got = self.cli(*exec_cmd, "sh", "-c",
                           f"{OPENCLAW_EXEC_ENV} openclaw config get {key}",
                           check=False, quiet=True)
            if key not in desired:
                if got.ok and got.out.strip() and got.out.strip() not in ("null", "undefined"):
                    return [f"OpenClaw still has {key} although the harness does not need it"]
                continue
            try:
                seen = json.loads(got.out) if got.ok else None
            except ValueError:
                seen = None
            if seen != desired[key]:
                return [f"OpenClaw {key} does not match the harness ({got.out.strip() or 'unset'})"]
        return []

    def verify_tool_gate(self, ws, sb):
        """Check the trusted mounts, their content and the loaded plugin."""
        if sb.type not in ("openclaw", "nemoclaw") or self.sh.dry_run:
            return []
        key = (ws.name, sb.name)
        if key in self.gate_expected:
            source, digest, policy_hash = self.gate_expected[key]
        else:
            _tree, source, digest, policy_hash = self.tool_gate_bundle(ws, sb)
        gate_volume = sandbox_volume_name(GATE_VOLUME_PREFIX, *key)
        audit_volume = sandbox_volume_name(AUDIT_VOLUME_PREFIX, *key)
        failures = self.volumes.verify(gate_volume, ws.name, source, digest)
        audit_info = self.volumes.inspect(audit_volume)
        if audit_info is None or not self.volumes.admitted(audit_info, ws.name):
            failures.append(f"audit volume {audit_volume} is missing or lacks admission labels")
        elif not (Path(audit_info["Mountpoint"]) / AUDIT_FILE).is_file():
            failures.append(f"audit volume {audit_volume} has no {AUDIT_FILE}")
        seen = self.sandbox_mount_map(ws, sb)
        if seen is False:
            failures.append("could not inspect the sandbox's trusted mounts")
        else:
            if seen.get(GATE_MOUNT) != ("volume", gate_volume, False):
                failures.append(f"{GATE_MOUNT} is not the read-only gate volume")
            if seen.get(AUDIT_MOUNT) != ("volume", audit_volume, True):
                failures.append(f"{AUDIT_MOUNT} is not the audit volume")
        exec_cmd = ("sandbox", "exec", "-n", sb.name, *ws_args(ws.name), "--no-tty", "--")
        policy = self.cli(*exec_cmd, "sha256sum", f"{GATE_MOUNT}/tool-actions.yaml",
                          check=False, quiet=True)
        if not policy.ok or policy.out.split()[:1] != [policy_hash.removeprefix("sha256:")]:
            failures.append("the sandbox's mounted tool-action policy hash does not match")
        identity = self.cli(*exec_cmd, "cat", f"{GATE_MOUNT}/identity.json",
                            check=False, quiet=True)
        try:
            actual = json.loads(identity.out) if identity.ok else None
        except ValueError:
            actual = None
        if actual != self.tool_gate_identity(ws, sb):
            failures.append("the sandbox's mounted tool-gate identity does not match the owner")
        listed = self.cli(*exec_cmd, "sh", "-c",
                          f"{OPENCLAW_EXEC_ENV} openclaw plugins list --json",
                          check=False, quiet=True)
        try:
            plugins = (json.loads(listed.out).get("plugins") or []) if listed.ok else []
        except (ValueError, AttributeError):
            plugins = []
        gate = next((row for row in plugins if isinstance(row, dict)
                     and row.get("id") == "saw-tool-gate"), None)
        if (not gate or not gate.get("enabled") or gate.get("status") != "loaded"
                or gate.get("rootDir") != f"{GATE_MOUNT}/plugin"):
            failures.append("OpenClaw has not loaded saw-tool-gate from the trusted mount")
        return failures

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

    def cleanup_harness_images(self):
        """Remove previously-pulled harness images no sandbox wants any more.

        Unlike volumes, a stray podman image carries no marker of its own, so
        "previously pulled for a harness" has to be tracked across applies;
        the ledger (already the trust anchor for prune) is where that lives.
        No ledger configured: images just accumulate, as before.
        """
        if self.sh.dry_run or self.ledger is None:
            return
        previous = set(self.ledger.data.get("harnessImages", []))
        for image in previous - self.harness_images:
            if self._podman("rmi", image, check=False, quiet=True).ok:
                log(f"Removed harness image {image}; no sandbox uses it any more")
        self.ledger.data["harnessImages"] = sorted(self.harness_images)
        cache = self.ledger.data.get("harnessSignatures", {})
        if isinstance(cache, dict):
            self.ledger.data["harnessSignatures"] = {
                image: entry for image, entry in cache.items() if image in self.harness_images}
        self.ledger.save()

    def install_tool_gate(self, ws, sb, enable=True):
        """Configure OpenClaw to load the trusted plugin after harness setup."""
        self.tool_gate_identity(ws, sb)
        if not enable:
            return
        exec_cmd = ("sandbox", "exec", "-n", sb.name, *ws_args(ws.name), "--no-tty", "--")
        if not self.cli(*exec_cmd, "node", "-e", _TOOL_GATE_CONFIG,
                        check=False, quiet=True).ok:
            raise InstallerError(f"could not configure saw-tool-gate in sandbox '{sb.name}'")
        oc_env = OPENCLAW_EXEC_ENV
        enabled = self.cli(*exec_cmd, "sh", "-c",
                           f"{oc_env} openclaw plugins enable saw-tool-gate --accept-capabilities "
                           f"|| {oc_env} openclaw plugins enable saw-tool-gate",
                           check=False, quiet=True)
        if not enabled.ok:
            raise InstallerError(f"could not enable saw-tool-gate in sandbox '{sb.name}'")

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
        provider = self.find_provider(ws, sb.providers, sb)
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
            self.create_sandbox(ws, sb, configure_harness=False)
            self.start_openclaw(ws, sb, provider)
        elif sb.type == "openclaw":
            self.create_sandbox(ws, sb, configure_harness=False)
            self.start_openclaw(ws, sb, provider)
        else:
            self.create_sandbox(ws, sb)

    # -- orchestration ---------------------------------------------------

    def apply(self, profiles):
        if not any(True for _ in enabled_workspaces(profiles)):
            raise InstallerError(
                "profile ConfigMap is missing or empty; refusing to change the gateway")
        # The local mTLS gateway entry first: everything below, the catalog
        # read included, must talk to this VM's gateway (found in review: a
        # fresh VM has no selected gateway, a reused one may select another).
        # register_gateway only writes the CLI's local gateway entry.
        self.register_gateway()
        # Governance-only provider types are resolved before preflight, so
        # the credential checks there see those profiles too (found in
        # review: preflight ran first and called their credentials "none
        # shipped"). The catalog is gateway-wide; read through the default
        # workspace, which exists before any profile workspace does.
        default_ws = Workspace(name="default")
        for _, ws in enabled_workspaces(profiles):
            self.adopt_governed_profiles(ws, catalog_ws=default_ws)
        self.preflight(profiles)
        self.reconcile_owner_memberships()
        for profile, ws in enabled_workspaces(profiles):
            self.profile_name = profile.name
            banner(f"Profile {profile.name} / workspace {ws.name}")
            self.apply_workspace(ws)
            self.adopt_governed_profiles(ws)
            for provider in ws.providers:
                if provider.enabled:
                    self.apply_provider(ws, provider)
            for sb in ws.sandboxes:
                if sb.enabled:
                    try:
                        self.apply_sandbox(ws, sb)
                    except InstallerError as exc:
                        log(f"ERROR: sandbox '{sb.name}': {exc}")
                        self.sandbox_failures.append(f"sandbox '{sb.name}': {exc}")
                    except Exception as exc:
                        log(f"ERROR: sandbox '{sb.name}': {exc}\n{traceback.format_exc()}")
                        self.sandbox_failures.append(f"sandbox '{sb.name}': {exc}")
                else:
                    log(f"Sandbox '{sb.name}' disabled, skipping")
        self.finish_prune()
        self.cleanup_harness_volumes()
        self.cleanup_harness_images()
        if self.sandbox_failures:
            raise InstallerError(
                f"{len(self.sandbox_failures)} sandbox(es) failed to apply:\n" +
                "\n".join(self.sandbox_failures))

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
        if self.sandbox_failures:
            # A sandbox that failed this run (governance refusal, transient
            # registry/cosign error) was never remember()ed: the desired
            # state this run is incomplete, not smaller on purpose.
            log(f"WARN: not pruning this run: {len(self.sandbox_failures)} sandbox(es) failed to apply")
            self.ledger.data["lastPrune"] = {"pruned": [], "wouldPrune": [],
                                             "skipped": "sandboxes failed this run"}
            self.ledger.save()
            return
        self.prune()

    def managed_label_ok(self, kind, workspace, name, entry):
        """True when the object may be pruned, False when it must be kept.

        None means get reported the object already gone, so the caller drops
        the ledger entry instead of logging "not labeled" forever.

        Adopted objects predate the managed label, so the ledger alone allows
        them. Providers cannot be labeled. A get that fails for any other
        reason (auth, a gateway error) stays unlabeled: prune keeps it rather
        than deleting something it could not identify.
        """
        if entry.get("adopted") or kind not in ("workspace", "sandbox"):
            return True
        if kind == "sandbox":
            return self._sandbox_labeled(workspace, name)
        got = self.cli("workspace", "get", name, check=False, quiet=True)
        blob = got.out + "\n" + got.err
        if not got.ok and _resource_not_found(blob):
            return None
        return got.ok and _managed_label_in_text(blob)

    def sandbox_labels(self, ws, sb):
        """What identifies a running sandbox: (env digest, instance id, native
        id) -- the two labels it was created with ("" when unset) and the
        gateway's own id for it when the CLI prints one ("" otherwise).
        None when none of it can be read."""
        keys = (ENV_LABEL_KEY, INSTANCE_LABEL_KEY)
        got = self.cli("sandbox", "get", sb.name, *ws_args(ws.name),
                       "--output", "json", check=False, quiet=True)
        if got.ok:
            values = [_label_from_json(got.out, k) for k in keys]
            if values[0] is None:
                return (*(_label_from_text(got.out, k) for k in keys), "")
            try:
                native = json.loads(got.out).get("id") or ""
            except (json.JSONDecodeError, AttributeError):
                native = ""
            return (*values, str(native))
        if not _cli_rejected_output_flag(got.out + "\n" + got.err):
            return None
        got = self.cli("sandbox", "get", sb.name, *ws_args(ws.name), check=False, quiet=True)
        return (*(_label_from_text(got.out, k) for k in keys), "") if got.ok else None

    def sandbox_env_label(self, ws, sb):
        labels = self.sandbox_labels(ws, sb)
        return None if labels is None else labels[0]

    # /sandbox is the sandbox's workspace volume, which OpenShell 0.1.x
    # deletes with the sandbox. What the installer mounts there itself is
    # excluded (it is refilled on create); the rest is carried across a
    # recreation as a tar archive, kept on the VM until the restore is
    # verified, so an interrupted or failed restore is finished on a later
    # apply and the old sandbox is only ever deleted once its files are
    # safely out.
    # Inside /sandbox: `sandbox download`/`upload` only serve paths within the
    # sandbox's working directory (a path outside it, /tmp say, is refused
    # before any data moves -- found live). The archive excludes itself.
    # gzip: OpenClaw's state (sqlite, caches) made a 92 MB archive live,
    # and the sandbox SSH proxy broke the upload more than once at that
    # size; compressed it is a fraction of that.
    PRESERVE_ARCHIVE = "/sandbox/.saw-preserve.tar.gz"
    PRESERVE_SUM = "/sandbox/.saw-preserve.sha256"

    def migration_key(self, ws, sb):
        return f"{ws.name}/{sb.name}"

    def save_migrations(self):
        if self.migrations_path and not self.sh.dry_run:
            write_json_atomic(self.migrations_path, self.migrations, mode=0o600)

    def archive_dir(self):
        base = (self.migrations_path.with_name("sandbox-archives") if self.migrations_path
                else Path(tempfile.gettempdir()) / "saw-sandbox-archives")
        base.mkdir(parents=True, exist_ok=True)
        return base

    def preserve_sandbox(self, ws, sb):
        """Archive the sandbox's own files (under /sandbox, minus the
        installer's mounts), checksum them in the sandbox, download the
        archive and verify it. Returns {"archive", "sha256"}; raises when
        anything fails: the caller must not delete the sandbox then."""
        # Everything under /sandbox except the installer's own paths: the
        # mounts (`./harness`, `./.saw/trusted`, ...) and `./.saw` itself,
        # each pruned at its exact path (a bare `harness` would also drop a
        # user's project/harness/). Directories are archived too (empty ones
        # and their permissions come back), listed by find with
        # --no-recursion so nothing is added twice; `./.saw` is pruned
        # because restoring its entry onto the root-owned mount directory
        # failed ("Cannot utime", found live). The archive excludes itself.
        pruned = {"./.saw", *("./" + m["target"][len("/sandbox/"):]
                             for m in sandbox_mounts(ws, sb) if m["target"].startswith("/sandbox/"))}
        prune = " ".join(f"-path {shlex.quote(p)} -prune -o" for p in sorted(pruned))
        own = shlex.quote("./" + Path(self.PRESERVE_ARCHIVE).name)
        script = (f"cd /sandbox || exit 3; rm -f {self.PRESERVE_ARCHIVE}; "
                  f"find . {prune} ! -path . ! -path {own} -print0 | "
                  f"tar -czf {self.PRESERVE_ARCHIVE} --null --no-recursion -T - && "
                  f"sha256sum {self.PRESERVE_ARCHIVE} | cut -d' ' -f1")
        packed = self.cli("sandbox", "exec", "-n", sb.name, *ws_args(ws.name), "--no-tty", "--",
                          "sh", "-c", script, check=False)
        digest = (packed.out or "").strip().split()[-1] if packed.ok and packed.out.strip() else ""
        if not packed.ok or (not self.sh.dry_run and not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise InstallerError(
                f"could not archive /sandbox of '{sb.name}' (exit {packed.rc}); the sandbox is "
                "left as it is. Fix the sandbox (or set its env back) and apply again")
        local = self.archive_dir() / f"{ws.name}-{sb.name}-{int(time.time())}.tar.gz"
        got = self.cli("sandbox", "download", sb.name, *ws_args(ws.name),
                       self.PRESERVE_ARCHIVE, str(local), check=False)
        if self.sh.dry_run:
            return {"archive": str(local), "sha256": digest or "dry-run"}
        if not got.ok or not local.is_file():
            raise InstallerError(f"could not download the archive of '{sb.name}'; the sandbox "
                                 "is left as it is")
        if sha256_file(local) != digest:
            local.unlink(missing_ok=True)
            raise InstallerError(f"the downloaded archive of '{sb.name}' does not match its "
                                 "checksum; the sandbox is left as it is")
        return {"archive": str(local), "sha256": digest}

    def restore_sandbox(self, ws, sb, record):
        """Upload the archive into the (new) sandbox, verify it there, unpack
        it over /sandbox and verify what was unpacked. Raises on failure; the
        migration record stays so the next apply tries again."""
        local = Path(record["archive"])
        if not self.sh.dry_run and not local.is_file():
            raise InstallerError(f"the archive to restore into '{sb.name}' is missing: {local}")
        # A leftover archive from an earlier attempt (a restore that failed
        # after the upload) makes the next upload fail ("failed to add
        # .saw-preserve.tar to tar archive", found live): remove it first.
        self.cli("sandbox", "exec", "-n", sb.name, *ws_args(ws.name), "--no-tty", "--",
                 "rm", "-f", self.PRESERVE_ARCHIVE, check=False, quiet=True)
        # --no-git-ignore: `sandbox upload` filters by .gitignore rules by
        # default and stops when the file is filtered (found live: the
        # archive was refused and the restore never ran).
        put = self.cli("sandbox", "upload", sb.name, *ws_args(ws.name), "--no-git-ignore",
                       str(local), self.PRESERVE_ARCHIVE, check=False)
        if not put.ok:
            raise InstallerError(f"could not upload the archive into '{sb.name}'; the restore "
                                 "is retried on the next apply")
        q = shlex.quote
        script = (f"[ \"$(sha256sum {self.PRESERVE_ARCHIVE} | cut -d' ' -f1)\" = "
                  f"{q(record['sha256'])} ] || exit 4; cd /sandbox || exit 3; "
                  # --no-overwrite-dir: an existing directory (the image's
                  # .openclaw, say) keeps its metadata; a new one gets the
                  # archived mode. The diff covers the non-directory members:
                  # directory mtimes drift as soon as anything is written.
                  f"tar -xzf {self.PRESERVE_ARCHIVE} --no-overwrite-dir && "
                  f"tar -tzf {self.PRESERVE_ARCHIVE} | grep -v '/$' | "
                  f"tar -dzf {self.PRESERVE_ARCHIVE} -T - && rm -f {self.PRESERVE_ARCHIVE}")
        done = self.cli("sandbox", "exec", "-n", sb.name, *ws_args(ws.name), "--no-tty", "--",
                        "sh", "-c", script, check=False)
        if not done.ok:
            why = {3: "no /sandbox", 4: "the uploaded archive does not match its checksum"}.get(
                done.rc, f"exit {done.rc}")
            raise InstallerError(f"could not restore the files of '{sb.name}' ({why}); the "
                                 "restore is retried on the next apply")

    def complete_migration(self, ws, sb):
        """The restore verified: forget the record and the archive. The only
        place the archive is ever deleted."""
        record = self.migrations.pop(self.migration_key(ws, sb), None)
        self.save_migrations()
        if record:
            try:
                Path(record["archive"]).unlink()
            except OSError:
                pass

    def begin_migration(self, ws, sb, labels):
        """Start recreating a running sandbox whose env differs from the
        profile's: archive and verify its /sandbox, persist the record (the
        original's identity, the replacement's instance token and the env
        it will be created with), then delete it. The record exists before
        anything is destroyed, so every later apply can finish the job."""
        log(f"Sandbox '{sb.name}' was created with a different environment; recreating it "
            "(its /sandbox files are carried over, open sessions end)")
        self.wait_exec_ready(ws, sb)
        record = self.preserve_sandbox(ws, sb)
        record.update({"fromInstance": labels[1] or "", "fromNative": labels[2] or "",
                       "env": dict(sb.env_values), "toInstance": secrets.token_hex(8)})
        self.migrations[self.migration_key(ws, sb)] = record
        self.save_migrations()
        self.delete_sandbox_and_wait(ws, sb)

    def recover_migration(self, ws, sb, state, labels):
        """One pending recreation, one decision. Given the sandbox's state and
        (when running) its identity, returns the state create_sandbox should
        continue from:

        - replacement running  -> restore and verify into it; "running"
        - original running     -> refresh its archive (replacing the old one
                                  only once the new one verified), delete it;
                                  "missing"
        - nothing running      -> "missing" (create the replacement, restore)
        - identity differs or cannot be read -> InstallerError; nothing is
                                  changed, the service retries

        Identity is decided by same_sandbox() on the strong signals only."""
        key = self.migration_key(ws, sb)
        record = self.migrations[key]
        if state != "running":
            return "missing"
        if labels is None:
            raise InstallerError(
                f"sandbox '{sb.name}' in workspace '{ws.name}' has a pending restore but its "
                "labels cannot be read (`sandbox get` failed); nothing was changed, the apply "
                "is retried")
        env_now, instance, native = labels
        seen = {"instance": instance, "native": native}
        if same_sandbox(seen, {"instance": record.get("toInstance", ""), "native": ""}):
            log(f"Finishing the recreation of sandbox '{sb.name}': restoring its files")
            self.wait_exec_ready(ws, sb)
            self.restore_sandbox(ws, sb, record)
            self.complete_migration(ws, sb)
            log(f"Sandbox '{sb.name}': files restored")
            return "running"
        if same_sandbox(seen, {"instance": record.get("fromInstance", ""),
                               "native": record.get("fromNative", "")}):
            log(f"Sandbox '{sb.name}' is still the original (an earlier recreation did not get "
                "to delete it); archiving it again and retrying")
            fresh = self.preserve_sandbox(ws, sb)       # verified before anything changes
            old_archive = record["archive"]
            record.update(fresh)
            self.save_migrations()
            if old_archive != fresh["archive"]:
                try:
                    Path(old_archive).unlink()
                except OSError:
                    pass
            self.delete_sandbox_and_wait(ws, sb)
            return "missing"
        raise InstallerError(
            f"sandbox '{sb.name}' in workspace '{ws.name}' has a pending restore but is neither "
            f"the sandbox it was taken from nor its replacement (instance "
            f"{instance or 'unlabelled'}, gateway id {native or 'unknown'}). Its files are in "
            f"{record['archive']}. Delete the sandbox to let the installer recreate and restore "
            f"it, or remove the entry from {self.migrations_path} to keep the sandbox as it is")

    def _sandbox_labeled(self, workspace, name):
        got = self.cli("sandbox", "get", name, *ws_args(workspace),
                       "--output", "json", check=False, quiet=True)
        if got.ok:
            parsed = _managed_label_from_json(got.out)
            if parsed is None:
                return _managed_label_in_text(got.out + "\n" + got.err)
            return parsed
        blob = got.out + "\n" + got.err
        # Gone already. Do not confuse that with Clap rejecting `--output`.
        if _resource_not_found(blob):
            return None
        # A CLI that predates `--output` rejects the flag. Retry the human
        # text, which is `key: value`. Any other failure stays unlabeled.
        if not _cli_rejected_output_flag(blob):
            return False
        got = self.cli("sandbox", "get", name, *ws_args(workspace), check=False, quiet=True)
        blob = got.out + "\n" + got.err
        if not got.ok and _resource_not_found(blob):
            return None
        return got.ok and _managed_label_in_text(blob)

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
        """Delete one ledger object.

        True: the CLI deleted it. ``"missing"``: the CLI says it is already
        gone. False: leave it in the ledger.

        A failed CLI delete must not look like success: prune() would log
        `deleted`, record it in lastPrune (and therefore status.json), and
        drop the ledger entry while the object is still on the gateway.
        A not-found result is the exception: the object is already gone, so
        the caller drops the ledger entry and logs ``not found``.
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
            # sandbox/provider delete pass allow_missing on OpenShell 0.1.2, so
            # they succeed when the object is already gone. workspace delete
            # does not: a workspace removed by hand fails here. That is gone,
            # not a referential-integrity failure, so the caller drops it.
            if _resource_not_found(result.out + "\n" + result.err):
                return "missing"
            where = f" in '{workspace}'" if workspace else ""
            log(f"WARN: keeping {kind} '{name}'{where}: delete failed; leaving it in the ledger")
            return False
        return True

    def _forget_missing(self, kind, workspace, name, label, pruned, would):
        """Drop a ledger entry the gateway no longer has.

        `on` removes it so the next reconcile does not retry. `report` only
        records the would-be cleanup.
        """
        if self.prune_mode == "report":
            log(f"would delete {label}: not found")
            would.append(label)
            return
        if self.prune_mode != "on":
            return
        where = f" in '{workspace}'" if workspace else ""
        log(f"{kind} '{name}'{where}: not found; removing it from the ledger")
        pruned.append(label)
        self.ledger.drop(kind, workspace, name)

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
                label = f"{kind} {workspace or '-'}/{name}"
                labeled = self.managed_label_ok(kind, workspace, name, obj)
                if labeled is None:
                    self._forget_missing(kind, workspace, name, label, pruned, would)
                    continue
                if not labeled:
                    log(f"keeping {kind} '{name}': not labeled {MANAGED_LABEL}")
                    continue
                if self.prune_mode == "report":
                    log(f"would delete {label}")
                    would.append(label)
                    continue
                if self.prune_mode != "on":
                    continue
                outcome = self.delete_managed(kind, workspace, name)
                if outcome == "missing":
                    self._forget_missing(kind, workspace, name, label, pruned, would)
                elif outcome:
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
                        self.find_provider(ws, sb.providers, sb) is None:
                    # All of the agent's providers were skipped (e.g. no
                    # provider profile for their type): it has no model.
                    skipped = ", ".join(f"{p.name} ({p.type})" for p in ws.providers
                                        if p.name in sb.providers)
                    failures.append(f"{sb.type} sandbox '{sb.name}' in '{ws.name}' has no usable "
                                    f"provider: skipped {skipped}; the gateway has no profile for that type")
                failures += [f"harness in sandbox '{sb.name}': {f}"
                             for f in self.verify_harness(ws, sb)]
                failures += [f"tool gate in sandbox '{sb.name}': {f}"
                             for f in self.verify_tool_gate(ws, sb)]
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


def openclaw_gateway_script(cfg, workspace, sandbox, oc_env, refilled=False):
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
    `openclaw agent`) use the same secret as gateway.auth.password.

    The settings are written on every run (the secret is the kept one, so a
    running gateway and its config never disagree on it). The gateway is
    restarted only when the harness was refilled, none is running, or the
    settings differ from the ones it was started with (a fingerprint kept
    next to the config): a restart cuts live UI and CLI sessions."""
    q = shlex.quote
    users = sandbox_ui_trusted_users(cfg, workspace, sandbox)
    # The gateway is supervised by a small keep-alive script written into the
    # sandbox (saw-gateway-supervise.sh): it relaunches the gateway if it
    # exits, so a crash no longer 502s the *-ui route until a manual restart.
    # The gateway logs to a file, not /proc/1/fd/2 directly: a broken PID 1
    # stderr pipe used to take the gateway down with it. A disposable tail in
    # the supervisor mirrors that file to PID 1 so podman logs still keeps an
    # outside copy; if that pipe breaks, only the tail dies, never the gateway.
    run = 'nohup sh "$SUP" >/dev/null 2>&1 &'
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
    # Every setting above is fixed text (the secret stays "$secret"), so
    # their digest says whether the running gateway has them.
    fingerprint = hashlib.sha256("\n".join(lines).encode()).hexdigest()
    fp_file = '"${OPENCLAW_HOME:-/sandbox}/.openclaw/saw-gateway.sha256"'
    if users is not None:
        lines += [
            'if [ "$trusted" = 1 ]; then',
            # After the last `config set`, which would remove it again; on
            # every run, as every run does `config set`.
            f'SAW_GATEWAY_SECRET="$secret" node -e {q(_WRITE_PASSWORD_JS)} {OPENCLAW_CONFIG} '
            '|| echo "WARN: could not set gateway.auth.password; the CLI needs a paired device"',
            "fi",
        ]
    lines += [
        _GATEWAY_PIDS_SH,
        _SUP_PIDS_SH,
        "SAW_STATE=${OPENCLAW_HOME:-/sandbox}/.openclaw/state",
        "SUP=$SAW_STATE/saw-gateway-supervise.sh",
        'mkdir -p "$SAW_STATE" 2>/dev/null || true',
        "cat > \"$SUP\" <<'SAWSUP'",
        "#!/bin/sh",
        "# SAW: keep the OpenClaw control-UI gateway (:18789) alive; relaunch it",
        "# if it exits. Output goes to a file so a broken PID 1 stderr pipe can",
        "# never take the gateway down; a disposable tail mirrors it to PID 1.",
        "log=${OPENCLAW_HOME:-/sandbox}/.openclaw/state/openclaw-gateway.log",
        'mkdir -p "${OPENCLAW_HOME:-/sandbox}/.openclaw/state" 2>/dev/null || true',
        ': >> "$log" 2>/dev/null || true',
        'cleanup() { kill "$mpid" 2>/dev/null; exit 0; }',
        "trap cleanup INT TERM",
        '( tail -n 0 -f "$log" >> /proc/1/fd/2 2>/dev/null ) & mpid=$!',
        "while :; do",
        '  openclaw gateway run --allow-unconfigured --bind lan --port 18789 >> "$log" 2>&1',
        '  echo "saw: openclaw-gateway exited ($?); relaunching in 2s" >> "$log"',
        "  sleep 2",
        "done",
        "SAWSUP",
        'chmod +x "$SUP" 2>/dev/null || true',
        '[ -s "$SUP" ] || echo "saw: WARNING could not write $SUP; the control-UI gateway is not supervised" >> /proc/1/fd/2 2>/dev/null',
        # Restart into the supervised gateway when none is supervised yet (first
        # start, or an old unsupervised gateway from before this), on a harness
        # refill, or when the settings changed. Killing the supervisor (TERM)
        # stops it relaunching and reaps its tail; its live gateway child is
        # orphaned, so kill that too.
        f'if [ {"1" if refilled else "0"} = 1 ] || [ -z "$(sup_pids)" ] || '
        f'[ "$(cat {fp_file} 2>/dev/null)" != {fingerprint} ]; then',
        '  for p in $(sup_pids); do kill "$p" 2>/dev/null; done',
        '  for p in $(gateway_pids); do kill "$p" 2>/dev/null; done',
        "  sleep 1",
        *([f'  OPENCLAW_GATEWAY_TOKEN="$secret" {run}'] if users is None else [
            '  if [ "$trusted" = 1 ]; then',
            f'  OPENCLAW_GATEWAY_PASSWORD="$secret" {run}',
            "  else",
            f'  OPENCLAW_GATEWAY_TOKEN="$secret" {run}',
            "  fi"]),
        f"  echo {fingerprint} 2>/dev/null > {fp_file} || true",
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
# For a request that is not safe to send again and lost its answer.
_AMBIGUOUS_BODY = b"The sandbox closed the connection; the request may have been processed.\n"
AMBIGUOUS_ANSWER = (b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(_AMBIGUOUS_BODY)) + _AMBIGUOUS_BODY


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
    """MAX upstream connections at a time; idle keep-alive ones give way.

    A client connection holds one slot for its upstream connection. A hedge
    (an extra connection for a repeatable request that got no answer) takes
    a slot of its own, only when one is free, and gives it back as soon as
    it is closed or becomes the connection that answered."""

    def __init__(self, limit):
        self.limit = limit
        self.active = set()
        self.extra = 0          # hedge connections open now
        self.cond = asyncio.Condition()

    def in_use(self):
        return len(self.active) + self.extra

    def try_extra(self):
        """Take a slot for a hedge connection if one is free; never waits.
        (No await: atomic within the event loop.)"""
        if self.in_use() >= self.limit:
            return False
        self.extra += 1
        return True

    async def release_extra(self, count=1):
        if count <= 0:
            return
        async with self.cond:
            self.extra = max(0, self.extra - count)
            self.cond.notify(count)

    def victim(self):
        idle = [c for c in self.active
                if not c.websocket and c.answered and c.idle_for() >= IDLE_PREEMPT]
        return min(idle, key=lambda c: c.last) if idle else None

    def describe(self):
        ws = sum(1 for c in self.active if c.websocket)
        busy = sum(1 for c in self.active if not c.websocket and not c.answered)
        idle = sorted(round(c.idle_for(), 1) for c in self.active if not c.websocket and c.answered)
        return (f"{self.in_use()}/{self.limit} in use: {ws} websocket, {busy} awaiting an answer, "
                f"{len(idle)} answered (idle s: {idle}), {self.extra} hedge")

    async def acquire(self, conn):
        start = time.monotonic()
        logged = 0.0
        async with self.cond:
            while self.in_use() >= self.limit:
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


class Ambiguous(Exception):
    """The request reached the forward, but no answer came back: it may or
    may not have been processed, so it is not sent again."""


async def open_answering(upstream, sent, slots):
    """Connect to the forward and send the client's first bytes.

    Retries when nothing was sent (the connection failed), and, for a
    request that is safe to send again (replayable), when the forward
    closes or resets the connection without answering: that is how it
    refuses a connection past its limit. Any other request may already
    have been processed by then, so it is not sent again: Ambiguous."""
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
            return await hedge(upstream, sent, ureader, uwriter, slots)
        except (ConnectionError, OSError):
            first = b""
        if first:
            return ureader, uwriter, first
        uwriter.close()
        if not replayable(sent):
            raise Ambiguous()
        await asyncio.sleep(min(1.0, 0.2 * (attempt + 1)))
    return None, None, b""


def replayable(sent):
    """A complete GET/HEAD/OPTIONS request without a body (a WebSocket
    upgrade included: no answer means no upgrade): sending it again cannot
    repeat a change."""
    head = sent.split(b"\r\n\r\n", 1)
    return len(head) == 2 and not head[1] and sent.split(b" ", 1)[0] in (b"GET", b"HEAD", b"OPTIONS")


def hedgeable(sent):
    """A replayable request that is not a WebSocket upgrade: safe to send
    again on another connection while the first is still open."""
    return replayable(sent) and b"upgrade: websocket" not in sent.lower()


async def hedge(upstream, sent, ureader, uwriter, slots):
    """Found live: a request through the forward sometimes got no answer at
    all (no error, nothing in the forward's log) and the browser saw a 504.
    For a request that is safe to repeat, send it again on new connections
    and keep whichever answers first. Each extra connection needs a free
    slot (Slots.try_extra); without one, the request just keeps waiting on
    the connections it has."""
    pending = {asyncio.ensure_future(ureader.read(65536)): (ureader, uwriter)}
    extras = 0
    deadline = time.monotonic() + HEDGE_TOTAL
    try:
        for extra in range(HEDGES + 1):
            if extra < HEDGES:
                if slots.try_extra():
                    extras += 1
                    log(f"no answer within {ANSWER_WAIT:.0f}s ({sent[:60]!r}); "
                        f"sending it again ({extra + 1})")
                    try:
                        r, w = await asyncio.open_connection("127.0.0.1", upstream)
                        w.write(sent)
                        await w.drain()
                        pending[asyncio.ensure_future(r.read(65536))] = (r, w)
                    except (ConnectionError, OSError):
                        pass
                else:
                    log(f"no answer within {ANSWER_WAIT:.0f}s ({sent[:60]!r}); "
                        "no free slot to send it again")
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
                    pending.clear()
                    return r, w, data
                w.close()
            if not pending:
                break
        for other, (_, ow) in pending.items():
            other.cancel()
            ow.close()
        log(f"no answer on {extras + 1} connections ({sent[:60]!r})")
        return None, None, b""
    finally:
        # The connection that answered (if any) runs on the client's own
        # slot; every extra one taken here is closed by now.
        await slots.release_extra(extras)


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
            try:
                ureader, uwriter, first = await open_answering(upstream, sent, slots)
            except Ambiguous:
                log(f"the forward closed without an answer ({sent[:60]!r}); "
                    "not sending it again, it may have been processed")
                cwriter.write(AMBIGUOUS_ANSWER)
                await cwriter.drain()
                return
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



def sandbox_ui_units(cfg, home, cookie, gateway, issuer_ca=None):
    """{unit file name: content} plus {file: content} for every sandbox UI.
    issuer_ca: the issuer CA file (issuer_trust_paths), when one is
    configured; each proxy then verifies the issuer against it alone.

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
    # Only the proxy's calls to the issuer use the CA (provider CA files),
    # not its system store. :z, not :Z: every proxy mounts the same file.
    ca_mount = f"-v {issuer_ca}:/etc/saw/issuer-ca.pem:ro,z " if issuer_ca else ""
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
            **({"OAUTH2_PROXY_PROVIDER_CA_FILES": "/etc/saw/issuer-ca.pem"} if issuer_ca else {}),
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
            f"{ca_mount}"
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
            issuer_ca = issuer_trust_paths(home)[0]
            units, files = sandbox_ui_units(cfg, home, cookie, cfg.get("mtlsGateway", "saw-installer"),
                                            issuer_ca if issuer_ca.is_file() else None)
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
    elif cookie_file.exists() and (cookie_file.with_suffix(".users-hash").exists()
                                  and cookie_file.with_suffix(".users-hash").read_text() ==
                                  hashlib.sha256("\n".join(sorted(dash["allowedUsers"])).encode()).hexdigest()):
        cookie = cookie_file.read_text(encoding="utf-8").strip()
    else:
        cookie_file.parent.mkdir(parents=True, exist_ok=True)
        cookie = secrets.token_hex(16)
        cookie_file.write_text(cookie, encoding="utf-8")
        os.chmod(cookie_file, 0o600)
        hash_file = cookie_file.with_suffix(".users-hash")
        hash_file.write_text(hashlib.sha256("\n".join(sorted(dash["allowedUsers"])).encode()).hexdigest())
        os.chmod(hash_file, 0o600)
    shell.add_secret(cookie)
    issuer_ca = issuer_trust_paths(home)[0]
    result = shell.run(["bash", str(script)], check=False, timeout=600, env={
        "RUNTIME": "podman",
        "DASHBOARD_ENABLED": "true",
        "DASHBOARD_IMAGE": dash["image"],
        "DASHBOARD_PROXY_IMAGE": dash["proxyImage"],
        "DASHBOARD_CLIENT_ID": dash["clientId"],
        "DASHBOARD_COOKIE_SECRET": cookie,
        "DASHBOARD_REDIRECT_URL": dash["redirectUrl"],
        "DASHBOARD_ALLOWED_USERS": ",".join(dash["allowedUsers"]),
        "DASHBOARD_INSECURE_SKIP_TLS": str(bool(dash.get("insecureSkipTlsVerify"))).lower(),
        "OIDC_ISSUER": cfg["oidcIssuer"],
        "DASHBOARD_ISSUER_CA": str(issuer_ca) if issuer_ca.is_file() else "",
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
        self.owner = self.root / "owner"

    def load(self, check_agent_mounts=True):
        """Load and validate everything. Nothing is changed."""
        bom = load_bom(self.bom)
        cfg = load_config(self.config)
        if cfg["ownerSubjectSource"] == "resolved":
            subject_file = self.owner / "subject"
            subject = subject_file.read_text(encoding="utf-8").strip() if subject_file.is_file() else ""
            if subject and not re.fullmatch(r"[A-Za-z0-9._:@/-]{1,255}", subject):
                raise InstallerError("resolved owner subject has invalid characters")
            cfg["ownerSubject"] = subject
        profile_files, harness_files, index = read_profile_files(self.profiles)
        profiles = parse_profiles(profile_files)
        validate_profiles(profiles, set(provider_profiles(self.installer)),
                          governed=governance_enabled(self.installer / "gateway.toml"))
        check_profiles_against_bom(profiles, bom)
        creds = resolve_credentials(profiles, self.secrets)
        bundles = parse_harness_files(harness_files)
        check_harness_index(bundles, index)
        revisions = validate_harness(profiles, bundles)
        if check_agent_mounts and agent_mounts_planned(profiles):
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
        env = dict(os.environ)
        if cfg["registry"]["authSecret"]:
            env["REGISTRY_AUTH_FILE"] = str(registry_auth_path(runtime_home(cfg, True)[0]))
        return env, (lambda argv: argv)
    user = cfg["runtimeUser"]
    _, env = user_env(user)
    if cfg["registry"]["authSecret"]:
        env["REGISTRY_AUTH_FILE"] = str(registry_auth_path(runtime_home(cfg, False)[0]))
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
        home, owner = runtime_home(cfg, args.as_current_user)
        registry_changed = configure_registry_access(
            shell, cfg, inputs.secrets, home, owner, dry_run=args.dry_run)
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
        issuer_ca = issuer_ca_certs(configured_ca_bundle(cfg, inputs.secrets))
        if not args.dry_run:
            issuer_ca = select_issuer_ca(cfg.get("oidcIssuer", ""), issuer_ca)
        trust_changed = trust_issuer_ca(shell, issuer_ca, home, owner, dry_run=args.dry_run)
        identity_script = str(inputs.installer / "identity.py")
        if (cfg.get("spiffe") or {}).get("enabled"):
            if "spireAgent" not in bom["spec"]:
                raise InstallerError("identity requires a pinned spireAgent BOM component")
            shell.run([sys.executable, identity_script, str(inputs.config)], timeout=600)
        else:
            shell.run([sys.executable, identity_script, "disable"], timeout=120)
        if (cfg.get("spiffe") or {}).get("testMode"):
            shell.run([sys.executable, identity_script, "test-helper"], timeout=300)
        # Remember that a restart is owed until it has actually happened, so
        # a failure between here and the restart cannot leave the old
        # gateway running on a retry.
        state = read_json(state_file, {"components": {}})
        if ({"gateway", "supervisor"} & set(changed) or config_changed or
                trust_changed or registry_changed):
            state["gatewayRestartPending"] = True
            if not args.dry_run:
                write_json_atomic(state_file, state)
        if not args.skip_gateway:
            if not args.dry_run:
                trust_file = issuer_trust_paths(home)[1]
                check_issuer_trusted(cfg.get("oidcIssuer", ""),
                                     cafile=trust_file if trust_file.is_file() else None)
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
        bom, cfg, profiles, creds, harness = inputs.load(check_agent_mounts=False)
        bom_name = bom["metadata"]["name"]
        install = status.read().get("install", {})
        if not args.dry_run and (install.get("phase") != "Done" or install.get("bom") != bom_name):
            raise InstallerError(
                f"install has not finished for BOM {bom_name} "
                f"(install: {install.get('phase') or 'never ran'}"
                f"{' for ' + install['bom'] if install.get('bom') else ''}); run `install` first")
        if agent_mounts_planned(profiles):
            check_driver_config_allowed(inputs.installer / "gateway.toml")

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
            # The runtime user executes this copy, so the tool-gate files it
            # reads from next to itself have to come along. They are part of
            # the installer disk (inputs.installer), not only the source tree.
            for name in ("tool-actions.yaml", "tool-gate.mjs", "tool-gate-plugin.mjs"):
                src = inputs.installer / name
                if not src.is_file():
                    raise InstallerError(f"tool gate file missing from the installer disk: {name}")
                dest = copy_dir / name
                shutil.copyfile(src, dest)
                os.chmod(dest, 0o644)
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
    apply_error = None
    if not list(enabled_workspaces(profiles)):
        log("No enabled workspaces in the SAW-BOM profiles; reconciling owner access")
        applier.register_gateway()
        applier.reconcile_owner_memberships()
    else:
        try:
            applier.apply(profiles)
        except InstallerError as exc:
            # Partial apply still reaches verify so successful siblings are checked.
            apply_error = exc
    if dry_run:
        if apply_error:
            raise apply_error
        return 0
    if apply_error is None:
        setup_dashboard(shell, cfg, data["dashboardScript"], os.environ.get("HOME", "~"))
    # Also after a partial apply: the UI routes of the sandboxes that did
    # apply keep working (a route to the failed one just does not answer).
    setup_sandbox_ui(shell, cfg, os.environ.get("HOME", "~"))
    failures = applier.verify(profiles)
    if apply_error:
        raise apply_error
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
    result = {
        "installer": tree_hash(inputs.installer),
        "profiles": tree_hash(inputs.profiles),
        "secrets": tree_hash(inputs.secrets),
    }
    if inputs.owner.is_dir():
        result["owner"] = tree_hash(inputs.owner)
    return result


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
                    or current.get("secrets") != applied.get("secrets")
                    or current.get("owner") != applied.get("owner"))
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


def check_bundle(directory):
    """Validate a harness-bundles/<name>/ tree with the same rules apply uses.

    Used by CI and scripts/harness-bundle.sh so a broken bundle fails once,
    before every SAW.
    """
    root = Path(directory)
    if not (root / "harness.yaml").is_file():
        raise InstallerError(f"{root}: has no harness.yaml")
    files = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            if path.is_symlink():
                raise InstallerError(f"{root}: contains symbolic link {path.relative_to(root)}")
            continue
        rel = path.relative_to(root).as_posix()
        if rel.rsplit("/", 1)[-1].startswith("._"):
            continue
        files[rel] = (path.read_bytes(), bool(path.stat().st_mode & 0o111))
    describe_harness_tree(files, inline=False)
    log(f"{root.name}: bundle is valid")


def cmd_check_bundle(args):
    check_bundle(args.directory)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="In-guest SAW installer (Stage 1)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="check all inputs; changes nothing")
    p_validate.add_argument("--inputs", default=str(DEFAULT_INPUTS))

    p_check = sub.add_parser("check-bundle",
                             help="validate a harness-bundles/<name>/ tree; changes nothing")
    p_check.add_argument("directory")

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
                "apply-profiles": cmd_apply_profiles,
                "check-bundle": cmd_check_bundle}
    try:
        return commands[args.command](args)
    except InstallerError as exc:
        log(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
