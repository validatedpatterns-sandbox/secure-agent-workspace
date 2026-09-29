#!/usr/bin/env python3
"""
apply_bom.py - in-guest SAW installer (Stage 1).

Runs INSIDE the gateway VM. saw-install.service runs `install` and then
saw-apply.service runs `apply`, on every boot.
There is no SSH and no setup Job: the chart attaches everything this script
needs as read-only disks, which saw-mount-inputs mounts under /run/saw:

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
    apply-profiles  (runtime user) internal; reads its plan from stdin

Stage 1 scope: images are pinned by digest, which gives integrity without
signing. Package/bundle signing is intentionally left for a later stage.

The installer talks to the gateway only through a local mTLS gateway entry.
End users log in with their own OIDC token; this script never performs an
OIDC login and never configures the CLI for OAuth.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
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
    "supervisor": {"image_path": "/openshell-sandbox",
                   "dest": "openshell-supervisor"},
    "cli": {"image_path": "/usr/local/bin/openshell",
            "dest": "openshell"},
}
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
# The gateway resolves the system inference route's provider in this workspace.
SYSTEM_WORKSPACE = "default"
ALREADY_RE = re.compile(r"already (exists|a member)", re.IGNORECASE)
# The gateway has no profile for this provider type. Profiles such as brave
# come from the governance interceptor, so they are missing when it is off.
NO_PROFILE_RE = re.compile(r"provider profile '[^']*' not\s+found|unsupported provider type",
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
# Provider config key that holds the upstream base URL for OpenShell's
# inference router (openshell-core inference profiles). An `openai` provider
# with OPENAI_BASE_URL reaches any OpenAI-compatible server (vLLM, Ollama, ...).
BASE_URL_CONFIG_KEYS = {
    "openai": "OPENAI_BASE_URL",
    "anthropic": "ANTHROPIC_BASE_URL",
    "nvidia": "NVIDIA_BASE_URL",
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
                  {"installerVersion", "openshell", "nemoclaw", "spireAgent"}, "InstallerBOM spec")
    if spec["installerVersion"] != INSTALLER_VERSION:
        raise InstallerError(
            f"InstallerBOM targets installer {spec['installerVersion']}, "
            f"this installer is {INSTALLER_VERSION}")
    _require_keys(spec["openshell"], set(COMPONENTS), set(COMPONENTS), "spec.openshell")
    for comp, entry in spec["openshell"].items():
        where = f"spec.openshell.{comp}"
        _require_keys(entry, {"version", "image"}, {"version", "image", "path"}, where)
        if not isinstance(entry["version"], str) or not VERSION_RE.match(entry["version"]):
            raise InstallerError(f"{where}.version is not a version string")
        _check_digest_image(entry["image"], f"{where}.image")
        if "path" in entry and (not isinstance(entry["path"], str) or not entry["path"].startswith("/")):
            raise InstallerError(f"{where}.path must be an absolute path")
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
}


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
    runtime_credentials: bool = False
    externally_managed: bool = False


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
                        inference_timeout=int(p.get("inferenceTimeout", 0) or 0),
                        runtime_credentials=p.get("runtimeCredentials", False),
                        externally_managed=p.get("externallyManaged", False)))
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
            if not isinstance(p.runtime_credentials, bool) or not isinstance(p.externally_managed, bool):
                errors.append(f"{where}: dynamic provider flags must be booleans")
            if p.runtime_credentials and p.externally_managed:
                errors.append(f"{where}: provider '{p.name}' cannot be both runtime and externally managed")
            if p.runtime_credentials or p.externally_managed:
                if p.credential_secret:
                    errors.append(f"{where}: dynamic provider '{p.name}' cannot use credentialSecret")
                if not NAME_RE.match(p.type):
                    errors.append(f"{where}: invalid dynamic provider profile type")
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
            if p.runtime_credentials or p.externally_managed:
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


def check_base_url(url):
    """An http(s) base URL without credentials, query or fragment. The value
    is not echoed in errors: a pasted URL may contain a token."""
    try:
        parts = urlsplit(url)
        ok = (parts.scheme in ("http", "https") and parts.hostname
              and parts.username is None and parts.password is None
              and not parts.query and not parts.fragment
              and not any(c.isspace() for c in url))
        if ok:
            parts.port  # raises ValueError on a bad port
    except ValueError:
        ok = False
    if not ok:
        raise ValueError("base URL must be http(s)://host[:port][/path] without credentials, "
                         "query or fragment")
    host = parts.hostname
    if host in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("base URL must not be localhost: the gateway, not the sandbox, "
                         "calls it (use a cluster Service or Route host)")
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

    def __init__(self, shell, bin_dir, state_file, podman="podman", opt_dir="/opt"):
        self.sh = shell
        self.bin_dir = Path(bin_dir)
        self.state_file = Path(state_file)
        self.podman = podman
        self.opt_dir = Path(opt_dir)

    def load_state(self):
        return read_json(self.state_file, {"components": {}})

    def _is_current(self, state_entry, image, dest):
        return (state_entry
                and state_entry.get("image") == image
                and dest.exists()
                and state_entry.get("sha256") == sha256_file(dest))

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

    def install(self, bom):
        """Install every component. Returns the names of changed components."""
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
            dest = self.bin_dir / layout["dest"]
            image = entry["image"]
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
                               "sha256": sha256_file(dest)}
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


def merge_user_env(chart_env, current):
    """The chart's gateway.env wins; keys only the golden image's first-boot
    setup adds (runtime bridge endpoint, podman socket) are kept."""
    chart_keys = _env_keys(chart_env)
    extra = [line for key, line in _env_keys(current).items() if key not in chart_keys]
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


class ProfileApplier:
    def __init__(self, shell, cfg, creds, provider_profile_docs=None):
        self.sh = shell
        self.cfg = cfg
        self.creds = creds
        self.provider_profiles = provider_profile_docs or {}   # id -> profile YAML
        self.gateway = cfg["mtlsGateway"]
        self.skipped = set()          # (workspace, provider) the gateway had no profile for
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

    def apply_workspace(self, ws):
        if ws.name != "default":
            result = self.cli("workspace", "create", "--name", ws.name,
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
                self.import_provider_profile(ws, provider.type)
                if not self.cli("provider", "get", provider.name, *ws_args(ws.name), check=False, quiet=True).ok:
                    raise InstallerError(f"provider '{provider.name}' must be created with openshell-saw-token-provider")
                return
            if not grants or any(g.get("grant_type", "client_credentials") != "client_credentials" for g in grants):
                raise InstallerError("runtime providers require a client_credentials token-grant profile")
            self.import_provider_profile(ws, provider.type)
            result = self.cli("provider", "create", "--name", provider.name, "--type", provider.type,
                              *ws_args(ws.name), "--runtime-credentials", ok_if_exists=True, check=False)
            if not result.ok:
                raise InstallerError(f"could not create runtime provider '{provider.name}'")
            return
        credential = self.creds[ws.name][provider.name]
        env_name = PROVIDER_CRED_MAP[provider.type]
        env = {env_name: credential}
        # OpenAI-compatible (and other) endpoints: the inference router reads
        # the upstream base URL from the provider config.
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
            return
        if not created.ok:
            raise InstallerError(f"could not create provider '{provider.name}' in workspace "
                                 f"'{ws.name}' (openshell provider create failed)")
        if created.existed:
            updated = self.cli("provider", "update", provider.name, *ws_args(ws.name),
                               "--credential", env_name, *config, env=env, check=False)
            if not updated.ok:
                log(f"WARN: could not refresh the credential of existing provider '{provider.name}'")

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

    def apply_inference(self, ws):
        chosen = next((p for p in self.usable(ws) if p.model), None)
        if not chosen:
            return
        log(f"Inference for '{ws.name}': {chosen.name} / {chosen.model}")
        timeout = ("--timeout", str(chosen.inference_timeout)) if chosen.inference_timeout else ()
        self.cli("inference", "set", "--provider", chosen.name, "--model", chosen.model,
                 "--workspace", ws.name, *timeout, "--no-verify")
        # The system route must point at a provider in the 'default'
        # workspace (the gateway looks it up there), so only that workspace
        # sets it.
        if ws.name == SYSTEM_WORKSPACE:
            self.cli("inference", "set", "--system", "--provider", chosen.name,
                     "--model", chosen.model, *timeout, "--no-verify")

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

    def create_sandbox(self, ws, sb):
        state = self.sandbox_state(ws, sb)
        if state == "broken":
            log(f"Sandbox '{sb.name}' is not running; recreating it")
            self.cli("sandbox", "delete", sb.name, *ws_args(ws.name), check=False)
        elif state == "running":
            log(f"Sandbox '{sb.name}' already exists")
            self.attach_missing_providers(ws, sb)
            return
        if sb.image and ("/" in sb.image or ":" in sb.image):
            self.sh.run(["podman", "pull", sb.image], check=False, timeout=900)
        args = ["sandbox", "create", "--name", sb.name]
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
        # The supervisor rewrites passwd; match /sandbox ownership to it.
        self.sh.run(["bash", "-c",
                     "CNAME=$(podman ps -a --filter 'name=openshell.*" + sb.name +
                     "' --format '{{.Names}}' | head -1) && [ -n \"$CNAME\" ] && "
                     "podman exec -u 0 \"$CNAME\" chown -R sandbox:sandbox /sandbox"],
                    check=False)
        token = secrets.token_hex(16)
        self.sh.add_secret(token)
        model = sb.model or provider.model or "nvidia/nemotron-3-super-120b-a12b"
        oc_env = ("OPENCLAW_HOME=/sandbox SQLITE_TMPDIR=/sandbox/.openclaw/state "
                  "TMPDIR=/sandbox/.openclaw/state OPENCLAW_NIX_MODE=0")
        onboarded = self.cli(*exec_cmd, "sh", "-c",
                 f"{oc_env} CUSTOM_API_KEY=proxy-managed openclaw onboard --non-interactive "
                 "--accept-risk --mode local --auth-choice custom-api-key "
                 '--custom-base-url "https://inference.local/v1" '
                 f"--custom-provider-id {provider.type} --custom-model-id \"{model}\" "
                 "--custom-compatibility openai --skip-channels --skip-health", check=False)
        # Re-onboarding an existing sandbox with a different provider or model
        # (e.g. after switching to a custom endpoint) makes OpenClaw save the
        # new credential but keep the old connection; activate the new one.
        profile_id = openclaw_replacement_profile(onboarded.out + "\n" + onboarded.err)
        if profile_id:
            log(f"Activating the new OpenClaw credential '{profile_id}'")
            self.cli(*exec_cmd, "sh", "-c",
                     f"{oc_env} openclaw models auth activate {profile_id} --agent main", check=False)
        self.cli(*exec_cmd, "sh", "-c", f"{oc_env} openclaw config set gateway.auth.token '{token}'",
                 check=False)
        route = self.cfg.get("sandboxDashboardRoute")
        if route:
            self.cli(*exec_cmd, "sh", "-c",
                     f"{oc_env} openclaw config set gateway.controlUi.allowedOrigins "
                     f"'[\"https://{route}\"]'", check=False)
        self.cli(*exec_cmd, "sh", "-c",
                 f"export OPENCLAW_GATEWAY_TOKEN={token} {oc_env} && nohup openclaw gateway run "
                 "--allow-unconfigured --bind lan --port 18789 > /tmp/openclaw-gateway.log 2>&1 &",
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
        self.register_gateway()
        system_set = False
        for profile, ws in enabled_workspaces(profiles):
            banner(f"Profile {profile.name} / workspace {ws.name}")
            self.apply_workspace(ws)
            for provider in ws.providers:
                if provider.enabled:
                    self.apply_provider(ws, provider)
            self.apply_inference(ws)
            system_set = system_set or (ws.name == SYSTEM_WORKSPACE and any(
                p.model for p in self.usable(ws)))
            for sb in ws.sandboxes:
                if sb.enabled:
                    self.apply_sandbox(ws, sb)
                else:
                    log(f"Sandbox '{sb.name}' disabled, skipping")
        if not system_set:
            log(f"No provider with a model in workspace '{SYSTEM_WORKSPACE}': "
                "system inference route left unchanged")

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
    def __init__(self, root):
        self.root = Path(root)
        self.installer = self.root / "installer"
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

    def set(self, phase, bom=None, message=""):
        log(f"{self.step}: {phase}{' - ' + message if message else ''}")
        if self.dry_run:
            return
        data = self.read()
        data[self.step] = {
            "phase": phase, "bom": bom, "message": message,
            "installerVersion": INSTALLER_VERSION,
            "updatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
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
    inputs = Inputs(args.inputs)
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
                                       podman=args.podman, opt_dir=args.opt_dir)
        changed = installer.install(bom)
        log(f"changed components: {', '.join(changed) or 'none'}")

        env, _ = runtime_user(cfg, args.as_current_user)
        home, owner = runtime_home(cfg, args.as_current_user)
        config_changed = sync_gateway_config(inputs, cfg, args.etc_dir, home, owner,
                                             dry_run=args.dry_run)
        allow_guest_agent_ssh_keys(shell)
        if (cfg.get("spiffe") or {}).get("enabled"):
            if "spireAgent" not in bom["spec"]:
                raise InstallerError("identity requires a pinned spireAgent BOM component")
            shell.run([sys.executable, str(inputs.installer / "identity.py"), str(inputs.config)], timeout=600)
        # Remember that a restart is owed until it has actually happened, so
        # a failure between here and the restart cannot leave the old
        # gateway running on a retry.
        state_file = state_dir / "installed.json"
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
        status.set("Done", bom_name)
        return 0
    except InstallerError as exc:
        log(f"ERROR: {exc}")
        status.set("Failed", bom_name, str(exc).splitlines()[0])
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
    inputs = Inputs(args.inputs)
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
        status.set("Done", bom_name)
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
    if dry_run:
        return 0
    failures = applier.verify(profiles)
    if failures:
        raise InstallerError(f"verification failed: {len(failures)} problem(s)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="In-guest SAW installer (Stage 1)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_validate = sub.add_parser("validate", help="check all inputs; changes nothing")
    p_validate.add_argument("--inputs", default=str(DEFAULT_INPUTS))

    for name, help_text in (("install", "step 1 (root): install BOM components, start the gateway"),
                            ("apply", "step 2 (root): apply SAW-BOM profiles as the runtime user")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--inputs", default=str(DEFAULT_INPUTS))
        p.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
        p.add_argument("--dry-run", action="store_true")
        # Test hook: run the user part as the current user instead of runuser.
        p.add_argument("--as-current-user", action="store_true", help=argparse.SUPPRESS)
        if name == "install":
            p.add_argument("--bin-dir", default="/usr/local/bin")
            p.add_argument("--opt-dir", default="/opt")
            p.add_argument("--podman", default="podman")
            p.add_argument("--etc-dir", default="/etc/openshell")
            p.add_argument("--skip-gateway", action="store_true", help=argparse.SUPPRESS)

    p_apply = sub.add_parser("apply-profiles", help=argparse.SUPPRESS)
    p_apply.add_argument("--dry-run", action="store_true")

    args = parser.parse_args(argv)
    commands = {"validate": cmd_validate, "install": cmd_install,
                "apply": cmd_apply, "apply-profiles": cmd_apply_profiles}
    try:
        return commands[args.command](args)
    except InstallerError as exc:
        log(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
