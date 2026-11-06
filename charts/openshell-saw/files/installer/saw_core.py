"""Shared SAW profile models, validation and workspace dependency ordering.

This is the canonical source for VM and Kubernetes integrations. It owns no
subprocess, cluster, credential-resolution or installation operations; effectful
ordering callbacks belong to backend adapters. Runtime
credential fields on legacy dataclasses remain for compatibility; parsing only
populates declarative references, never credential material. Backend capability
checks and mutation adapters are separate from this common profile language.

The VM chart embeds these exact bytes into its signed installer at render time.
Do not maintain a second copy or import this module from untrusted input paths.
"""

import base64
import hashlib
import json
import re
import shlex
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from pathlib import Path

import yaml

API_VERSION = "saw.redhat.com/v1alpha1"


NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


SECRET_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


SECRET_KEY_RE = re.compile(r"^[-._a-zA-Z0-9]+$")


OPENSHELL_NAME_LIMIT = 19


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


# NemoClaw calls the NVIDIA API Catalog "build"; OpenShell calls it "nvidia".
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


def credential_marker(prefix, secret_name, key):
    """Opaque value that the trusted proxy replaces for an approved endpoint."""
    return f"{prefix}.{secret_name}.{key}"


def credential_env_name(provider_type, profiles):
    """Env var the installer passes a provider's credential through: the one
    the provider's own profile declares, else the built-in default. This lets
    a profile-backed type (github, slack, gmail, ...) work as a provider with
    no PROVIDER_CRED_MAP edit; for the shipped built-ins the two agree."""
    return (profile_credential_env((profiles or {}).get(provider_type, ""))
            or PROVIDER_CRED_MAP.get(provider_type, ""))


SANDBOX_TYPES = {"generic", "openclaw", "nemoclaw"}


BASE_URL_CONFIG_KEYS = {
    "openai": "OPENAI_BASE_URL",
    "anthropic": "ANTHROPIC_BASE_URL",
    "nvidia": "NVIDIA_BASE_URL",
}


# OpenShell 0.1.x has no inference router: the agent calls the endpoint
# itself, and the provider profile must name that endpoint's host.
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
    credential_free: bool = False
    # Optional `credentials:` mapping, keyed by the profile's credential name
    # ({api_key: {secretKey: ...}, app_secret: {secretKey: ...}}): one value
    # per credential, from the same Secret, each passed as its own
    # `--credential ENV` with the env var that credential declares. The
    # single-credential shorthand credentialSecretKey is one entry for the
    # profile's first credential.
    refresh_strategy: str = ""
    refresh_material: dict = field(default_factory=dict)
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
    ui: dict = field(default_factory=dict)
    # `env:` -- the workload's environment (`sandbox create --env`; changing
    # it recreates the sandbox). {NAME: {value, title?}}: literals only, so
    # env_values (below) is derived, never a resolved copy that could go
    # stale (found in CI: freshly parsed profiles compared an empty copy
    # with the sandbox's env label and recreated it). Never for credentials
    # (the agent, and argv, can read these): those stay on providers.
    env: dict = field(default_factory=dict)
    # `inference:` -- how the agent reaches its model: {providerRef, protocol,
    # baseUrl?, model, models?, timeoutSeconds?}. models maps optional native
    # provider names to additional chat model inputs. baseUrl/model/timeoutSeconds
    # is a literal or an input ({secretKeyRef: {name, key}, default?,
    # required?, title?}); inference_values is it resolved. The installer onboards the
    # agent from it (by protocol, so any profile-backed provider type works).
    inference: dict = field(default_factory=dict)
    inference_values: dict = field(default_factory=dict)
    # Container-level GPU request (`openshell sandbox create --gpu`).
    # Independent of the gateway VM's vm.gpu.enabled (KubeVirt hostDevices).
    # Off unless the BOM sandbox sets gpu.enabled. See docs/gpu-passthrough.md.
    gpu_enabled: bool = False
    gpu_count: int = 1

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
    return split_bom_files({p.name: p.read_text(encoding="utf-8") for p in sorted(directory.iterdir())
                            if not p.name.startswith(".") and p.is_file()})


def split_bom_files(data):
    """Decode one flat saw-bom ConfigMap from either VM disk or Kubernetes API."""
    files, harness, index = {}, {}, {}
    for key, value in data.items():
        if key.startswith("profiles__") and key.endswith(".yaml"):
            files[key] = value
        elif key.startswith("harness__"):
            try:
                harness[key] = base64.b64decode(
                    value, validate=True)
            except (ValueError, UnicodeDecodeError) as exc:
                raise InstallerError(
                    f"harness file {key} is not valid base64 ({exc}); "
                    "the chart must b64enc every harness key") from None
        elif key == "harness-index.yaml":
            index = _yaml(value, key)
        else:
            # A wrong key layout must not look like "no profiles".
            raise InstallerError(f"unexpected file in the profiles ConfigMap: {key}")
    return files, harness, index


def _yaml(text, where):
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise InstallerError(f"{where}: invalid YAML ({exc})") from None


PROFILE_DOCUMENT_KINDS = {
    "workspace.yaml": "Workspace", "providers.yaml": "Providers", "sandbox.yaml": "Sandboxes",
}
PROFILE_PROVIDER_FIELDS = {
    "name", "type", "enabled", "credentialFree", "nemoclawProvider", "credentialSecret",
    "credentialSecretKey", "model", "baseUrlSecretKey", "modelSecretKey", "inferenceTimeout",
    "refresh", "credentials",
}
PROFILE_SANDBOX_FIELDS = {
    "name", "type", "enabled", "agent", "image", "providers", "model", "harnessRef", "env", "inference",
    "harnessRequired", "ui",
}


def _profile_mapping(value, allowed, required, where):
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise InstallerError(f"{where}: expected a mapping with string keys")
    missing, unknown = set(required) - set(value), set(value) - set(allowed)
    if missing or unknown:
        raise InstallerError(f"{where}: unknown or missing profile fields")
    return value


def _profile_input(value, kinds, where):
    if isinstance(value, dict):
        _profile_mapping(value, INPUT_KEYS, {"secretKeyRef"}, where)
        reference = _profile_mapping(value["secretKeyRef"], {"name", "key"}, {"name", "key"}, where)
        if any(not isinstance(item, str) for item in reference.values()):
            raise InstallerError(f"{where}: input references must be strings")
        if "title" in value and not isinstance(value["title"], str):
            raise InstallerError(f"{where}: input title must be a string")
    if input_problems(value, kinds):
        raise InstallerError(f"{where}: invalid inference input")


def validate_profile_document(doc, kind, where="profile"):
    """Strict common document schema, independent of backend capabilities.

    Legacy VM parsing remains compatible by default; new adapters call
    ``parse_profiles(..., strict=True)`` before capability checks so unknown
    fields cannot be silently discarded while constructing dataclasses.
    ``validate_profiles`` still validates cross-object semantics afterward.
    """
    _profile_mapping(doc, {"apiVersion", "kind", "metadata", "spec"}, {"apiVersion", "kind"}, where)
    if kind not in PROFILE_DOCUMENT_KINDS.values() or doc["apiVersion"] != API_VERSION or doc["kind"] != kind:
        raise InstallerError(f"{where}: unsupported profile apiVersion or kind")
    metadata = _profile_mapping(doc.get("metadata", {}), {"name", "description", "profile"}, set(), where)
    if any(not isinstance(value, str) for value in metadata.values()):
        raise InstallerError(f"{where}: metadata fields must be strings")
    fields = {"Workspace": {"enabled"}, "Providers": {"providers"}, "Sandboxes": {"sandboxes"}}[kind]
    spec = _profile_mapping(doc.get("spec", {}), fields, set(), where)
    if kind == "Workspace":
        if "enabled" in spec and type(spec["enabled"]) is not bool:
            raise InstallerError(f"{where}: enabled must be boolean")
        return doc
    list_key = "providers" if kind == "Providers" else "sandboxes"
    entries = spec.get(list_key, [])
    if not isinstance(entries, list):
        raise InstallerError(f"{where}: {list_key} must be a list")
    allowed = PROFILE_PROVIDER_FIELDS if kind == "Providers" else PROFILE_SANDBOX_FIELDS
    required = {"name", "type"} if kind == "Providers" else {"name"}
    for entry in entries:
        _profile_mapping(entry, allowed, required, where)
        booleans = {"enabled", "credentialFree"} if kind == "Providers" else {"enabled", "harnessRequired"}
        objects = {"refresh", "credentials"} if kind == "Providers" else {"harnessRef", "env", "inference", "ui"}
        for field_name, value in entry.items():
            if field_name in booleans:
                if type(value) is not bool:
                    raise InstallerError(f"{where}: {field_name} must be boolean")
            elif field_name in objects:
                if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
                    raise InstallerError(f"{where}: {field_name} must be a mapping with string keys")
            elif field_name == "inferenceTimeout":
                if type(value) is not int or value < 0:
                    raise InstallerError(f"{where}: inferenceTimeout must be a nonnegative integer")
            elif field_name == "providers":
                if not isinstance(value, list) or any(not isinstance(ref, str) for ref in value):
                    raise InstallerError(f"{where}: providers must be a list of names")
            elif not isinstance(value, str):
                raise InstallerError(f"{where}: {field_name} must be a string")
        if kind == "Providers":
            if "refresh" in entry:
                refresh = _profile_mapping(entry["refresh"], {"strategy"}, {"strategy"}, where)
                if not isinstance(refresh["strategy"], str):
                    raise InstallerError(f"{where}: refresh.strategy must be a string")
            if "credentials" in entry:
                for credential in entry["credentials"].values():
                    _profile_mapping(credential, {"secretKey", "title"}, {"secretKey"}, where)
                    if any(not isinstance(value, str) for value in credential.values()):
                        raise InstallerError(f"{where}: credential references must be strings")
        else:
            if "ui" in entry:
                ui = _profile_mapping(entry["ui"], {"route"}, set(), where)
                if "route" in ui and type(ui["route"]) is not bool:
                    raise InstallerError(f"{where}: ui.route must be boolean")
            if "harnessRef" in entry:
                harness = _profile_mapping(entry["harnessRef"], {"name", "image", "digest"}, set(), where)
                if any(not isinstance(value, str) for value in harness.values()):
                    raise InstallerError(f"{where}: harness references must be strings")
            for name, value in entry.get("env", {}).items():
                _profile_mapping(value, SANDBOX_ENV_KEYS, {"value"}, where)
                if "title" in value and not isinstance(value["title"], str):
                    raise InstallerError(f"{where}: environment title must be a string")
                if sandbox_env_problems(name, value):
                    raise InstallerError(f"{where}: invalid sandbox environment entry")
            inference = entry.get("inference", {})
            _profile_mapping(inference, INFERENCE_KEYS, set(), where)
            if "providerRef" in inference and not isinstance(inference["providerRef"], str):
                raise InstallerError(f"{where}: inference.providerRef must be a string")
            if "protocol" in inference and not isinstance(inference["protocol"], str):
                raise InstallerError(f"{where}: inference.protocol must be a string")
            for field_name in ("model", "baseUrl", "timeoutSeconds"):
                kinds = (str, int) if field_name == "timeoutSeconds" else (str,)
                if field_name in inference:
                    _profile_input(inference[field_name], kinds, where)
            if "models" in inference:
                models = inference["models"]
                if not isinstance(models, dict) or any(not isinstance(key, str) for key in models):
                    raise InstallerError(f"{where}: inference.models must be a mapping of names to inputs")
                for value in models.values():
                    _profile_input(value, (str,), where)
    return doc


def parse_profiles(files, *, strict=False, document_check=None):
    """Build profiles from {flat key: yaml text}.

    Only keys of the form profiles__<profile>__<workspace>__<file>.yaml are
    used, where <file> is workspace, providers or sandbox. Strict mode validates
    the common document shape before normalization; backend capabilities remain
    a separate check, so all backends use the same profile language. An optional
    ``document_check(doc, kind)`` can reject backend-unsupported chart directives
    before normalization (for example UI routes managed outside the VM parser).
    It receives a schema-validated document whenever strict mode is enabled.
    """
    grouped = {}
    for key, text in files.items():
        parts = key.split("__")
        if len(parts) != 4 or parts[0] != "profiles":
            raise InstallerError(f"unexpected profile file name: {key}")
        _, profile, ws_dir, filename = parts
        if filename not in ("workspace.yaml", "providers.yaml", "sandbox.yaml"):
            raise InstallerError(f"unexpected profile file: {key}")
        if strict or document_check is not None:
            doc, kind = _yaml(text, key), PROFILE_DOCUMENT_KINDS[filename]
            if strict:
                validate_profile_document(doc, kind, key)
            if document_check is not None:
                document_check(doc, kind)
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
                        refresh_strategy=str((p.get("refresh") or {}).get("strategy", "")),
                        credentials_spec=cred_spec if cred_spec is not None else {}))
            if "sandbox.yaml" in docs:
                key, text = docs["sandbox.yaml"]
                for s in (_yaml(text, key).get("spec") or {}).get("sandboxes") or []:
                    if "name" not in s:
                        raise InstallerError(f"{key}: every sandbox needs a name")
                    gpu = s.get("gpu", {})
                    if not isinstance(gpu, dict):
                        raise InstallerError(f"{key}: sandbox '{s['name']}' gpu must be a mapping")
                    unknown = sorted(set(gpu) - {"enabled", "count"})
                    if unknown:
                        raise InstallerError(f"{key}: sandbox '{s['name']}' gpu has unknown keys {', '.join(unknown)}")
                    if not isinstance(gpu.get("enabled", False), bool):
                        raise InstallerError(f"{key}: sandbox '{s['name']}' gpu.enabled must be true or false")
                    gpu_count = gpu.get("count", 1)
                    if isinstance(gpu_count, bool) or not isinstance(gpu_count, int):
                        raise InstallerError(f"{key}: sandbox '{s['name']}' gpu.count must be an integer")
                    ws.sandboxes.append(Sandbox(
                        name=s["name"], type=s.get("type", "generic"),
                        enabled=s.get("enabled", True),
                        agent=s.get("agent", "openclaw"),
                        image=s.get("image", ""),
                        providers=list(s.get("providers") or []),
                        model=s.get("model", ""),
                        harness_ref=dict(s.get("harnessRef") or {}),
                        ui=dict(s.get("ui") or {}),
                        env=s.get("env") if s.get("env") is not None else {},
                        inference=s.get("inference") if s.get("inference") is not None else {},
                        gpu_enabled=gpu.get("enabled", False), gpu_count=gpu_count))
            profile.workspaces.append(ws)
        profiles.append(profile)
    return profiles


def enabled_workspaces(profiles):
    for profile in profiles:
        for ws in profile.workspaces:
            if ws.enabled:
                yield profile, ws


def apply_workspace_sequence(workspace, providers, sandboxes, adapter):
    """Shared dependency ordering for one bounded workspace apply pass.

    The backend supplies ``prepare_workspace``, ``apply_provider`` and
    ``apply_sandbox`` methods returning readiness booleans. Observe/apply all
    providers before the barrier; a pending workspace or provider prevents
    sandbox creation. Backends retain authentication, ownership, capability
    validation, retry/deletion policy and error handling. No backend exception
    is swallowed here, and this function does not turn readiness into agent
    health. Callers select enabled entries or implement explicit skip behavior.
    """
    if not adapter.prepare_workspace(workspace):
        return False
    providers_ready = True
    for provider in providers:
        if not adapter.apply_provider(workspace, provider):
            providers_ready = False
    if not providers_ready:
        return False
    sandboxes_ready = True
    for sandbox in sandboxes:
        if not adapter.apply_sandbox(workspace, sandbox):
            sandboxes_ready = False
    return sandboxes_ready


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
            if p.refresh_strategy and p.refresh_strategy != "oauth2_refresh_token":
                errors.append(f"{where}: provider '{p.name}' has unsupported refresh strategy '{p.refresh_strategy}'")
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
            if s.gpu_enabled and s.gpu_count < 1:
                errors.append(f"{where}: sandbox '{s.name}' gpu.count must be at least 1")
            if s.type not in SANDBOX_TYPES:
                errors.append(f"{where}: sandbox '{s.name}' has unsupported type '{s.type}'")
            for ref in s.providers:
                if ref not in provider_names:
                    errors.append(f"{where}: sandbox '{s.name}' uses provider '{ref}' which is not an enabled provider in this workspace")
            if s.type in ("openclaw", "nemoclaw") and not provider_names:
                errors.append(f"{where}: {s.type} sandbox '{s.name}' needs at least one provider")
            if s.inference:
                errors += [f"{where}: sandbox '{s.name}' {p}"
                           for p in sandbox_inference_problems(
                               s, provider_types, {p.name: p.type for p in ws.providers})]
            if not isinstance(s.env, dict):
                errors.append(f"{where}: sandbox '{s.name}' env must be a mapping of NAME to "
                              "{value} or {secret, secretKey}")
            else:
                for name, src in s.env.items():
                    errors += [f"{where}: sandbox '{s.name}' env '{name}' {problem}"
                               for problem in sandbox_env_problems(name, src)]
    if errors:
        raise InstallerError("invalid profiles:\n  - " + "\n  - ".join(errors))


# Match OpenShell's environment-name and per-value size constraints.
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


CREDENTIAL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


ENV_VALUE_LIMIT = 8192


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


INFERENCE_KEYS = {"providerRef", "protocol", "baseUrl", "model", "models", "timeoutSeconds"}


# A profile controls allowed credential destinations; the protocol controls
# agent onboarding independently of a governed provider's custom profile name.
INFERENCE_PROTOCOLS = {"openai", "anthropic"}


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


def inference_protocol(spec, provider_type):
    """The protocol an `inference:` block uses: its own `protocol`, else the
    one the provider's type implies ("" when neither says)."""
    return spec.get("protocol") or PROVIDER_PROTOCOLS.get(provider_type or "", "")


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


def resolve_bom_input(src, read_value, what, forbidden=()):
    """A typed input's value: the literal, or the Secret key it refers to
    (secretKeyRef), else its default; "" when optional and absent."""
    if not isinstance(src, dict):
        return str(src)
    sname, skey = secret_ref(src)
    if (sname, skey) in forbidden:
        raise InstallerError(f"{what}: secretKeyRef names a provider credential or refresh material; refusing to expose it")
    value = read_value(sname, skey)
    if value:
        return value
    if "default" in src:
        return str(src["default"])
    if src.get("required", "default" not in src):
        raise InstallerError(f"{what} not found: Secret '{sname}' key '{skey}'. List the "
                             "Secret in openshell-saw additionalProviderSecrets and make sure "
                             "it exists.")
    return ""


def select_inference_provider(providers, names, *, inference_ref=None):
    """Select an agent provider from the adapter's available candidates.

    Disabled and credential-free providers cannot onboard an agent. An explicit
    inference reference never falls back to a different provider. Otherwise use
    attachment order, preferring a candidate with a model. The legacy empty
    attachment list retains candidate order; strict adapters must validate
    attachment requirements before calling. Availability and governance remain
    adapter checks, so a skipped provider must be absent from ``providers``.
    """
    usable = [p for p in providers if p.enabled and not p.credential_free]
    if inference_ref is not None:
        return next((p for p in usable if p.name == inference_ref), None)
    if names:
        usable = [p for name in names for p in usable if p.name == name]
    return next((p for p in usable if p.model), usable[0] if usable else None)


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


def openclaw_inference_settings(sb, provider):
    """Pure onboarding choices; transports and endpoint approval stay in adapters.

    Resolved inference inputs take precedence over legacy fields. An explicit
    endpoint uses custom onboarding even when its URL is a native API. A legacy
    base URL reference also keeps custom onboarding when its resolved value is
    absent, preserving the VM installer's compatibility behavior.
    """
    model = sandbox_model(sb, provider, "nvidia/nemotron-3.5-lightning-30b-a3b")
    endpoint = sandbox_endpoint(sb, provider)
    protocol = sandbox_protocol(sb, provider)
    if sb.inference_values:
        base_url = (endpoint or NATIVE_BASE_URLS.get(provider.type, "")
                    or PROTOCOL_NATIVE_BASE_URLS.get(protocol, ""))
        native = (not endpoint and provider.type in OPENCLAW_AUTH_CHOICES
                  and PROVIDER_PROTOCOLS.get(provider.type) == protocol)
    else:
        base_url = endpoint or NATIVE_BASE_URLS.get(provider.type, "")
        native = not (endpoint or provider.base_url_secret_key)
    return {"model": model, "base_url": base_url, "protocol": protocol,
            "auth_choice": OPENCLAW_AUTH_CHOICES.get(provider.type) if native else None}


def openclaw_managed_provider_id(kind):
    """Namespace explicit model catalogs away from stock catalog migrations.

    This is an OpenClaw configuration ID only. The BOM provider type, approved
    endpoint/protocol and OpenShell credential binding retain their identity.
    Native onboarding in the VM adapter remains unchanged.
    """
    if kind not in {"openai", "anthropic", "nvidia", "custom-inference"}:
        raise InstallerError("unsupported managed OpenClaw provider")
    return "saw-" + kind


def resolve_inference(ws, sb, read_value, validate_endpoint, forbidden=()):
    """A sandbox's `inference:` resolved: providerRef, protocol, baseUrl
    (validated, "" = the protocol's native API), model, timeoutSeconds."""
    spec = sb.inference
    where = f"sandbox '{sb.name}' in workspace '{ws.name}'"
    provider = next((p for p in ws.providers if p.enabled and p.name == spec["providerRef"]), None)
    out = {"providerRef": spec["providerRef"],
           "protocol": inference_protocol(spec, provider.type if provider else "")}
    out["model"] = resolve_bom_input(spec["model"], read_value, f"{where}: inference model", forbidden)
    if not out["model"]:
        raise InstallerError(f"{where}: inference model is empty")
    url = resolve_bom_input(spec["baseUrl"], read_value, f"{where}: inference baseUrl", forbidden) \
        if "baseUrl" in spec else ""
    if url:
        try:
            url = check_base_url(url)
        except ValueError as exc:
            raise InstallerError(f"{where}: inference baseUrl: {exc}") from None
    validate_endpoint(url, spec, provider, where)
    out["baseUrl"] = url
    timeout = resolve_bom_input(spec["timeoutSeconds"], read_value,
                            f"{where}: inference timeoutSeconds", forbidden) if "timeoutSeconds" in spec else ""
    if timeout and (not str(timeout).isdigit() or int(timeout) < 0):
        raise InstallerError(f"{where}: inference timeoutSeconds must be a non-negative integer")
    out["timeoutSeconds"] = int(timeout) if timeout else 0
    if "models" in spec:
        out["models"] = {}
        for name, src in spec["models"].items():
            attached = next((p for p in ws.providers if p.enabled and p.name == name
                             and name in sb.providers), None)
            if attached is None:
                continue
            if attached.base_url or attached.base_url_secret_key:
                raise InstallerError(f"{where}: inference models '{name}' needs a native API")
            model = resolve_bom_input(src, read_value, f"{where}: inference models '{name}'", forbidden)
            if not model:
                raise InstallerError(f"{where}: inference models '{name}' is empty")
            try:
                check_env_value(model)
            except ValueError as exc:
                raise InstallerError(f"{where}: inference models '{name}': {exc}") from None
            out["models"][name] = model
    for key in ("model", "baseUrl"):
        try:
            check_env_value(out[key])
        except ValueError as exc:
            raise InstallerError(f"{where}: inference {key}: {exc}") from None
    return out


def sandbox_inference_problems(sb, provider_types, declared_provider_types=None):
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
    model = spec.get("model")
    if model == "" or (isinstance(model, dict) and not model.get("default")
                       and not model.get("required", "default" not in model)):
        out.append("inference model must be non-empty: use a non-empty default or required: true")
    for key in ("baseUrl", "model"):
        if key in spec:
            out += [f"inference {key} {p}" for p in input_problems(spec[key])]
    models = spec.get("models", {})
    if not isinstance(models, dict):
        out.append("inference models must be a mapping of provider names to model inputs")
    else:
        declared = declared_provider_types if declared_provider_types is not None else provider_types
        if models and sb.type != "openclaw":
            out.append("inference models is supported only for openclaw sandboxes")
        for name, model in models.items():
            if name not in declared:
                out.append(f"inference models names unknown provider '{name}'")
            elif declared[name] not in ("openai", "anthropic"):
                out.append(f"inference models '{name}' needs a native OpenAI or Anthropic provider")
            out += [f"inference models '{name}' {p}" for p in input_problems(model)]
            if model == "" or (isinstance(model, dict) and not model.get("default")
                              and not model.get("required", "default" not in model)):
                out.append(f"inference models '{name}' must be non-empty")
    if "timeoutSeconds" in spec:
        out += [f"inference timeoutSeconds {p}"
                for p in input_problems(spec["timeoutSeconds"], (str, int))]
    return out


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


__all__ = (
    'API_VERSION', 'NAME_RE', 'SECRET_NAME_RE', 'SECRET_KEY_RE', 'OPENSHELL_NAME_LIMIT',
    'PROVIDER_CRED_MAP', 'NEMOCLAW_PROVIDER_MAP', 'nemoclaw_provider', 'profile_credential_envs',
    'profile_credentials', 'profile_all_credential_envs', 'profile_credential_env', 'credential_env_name',
    'SANDBOX_TYPES', 'BASE_URL_CONFIG_KEYS', 'InstallerError', 'Provider', 'Sandbox', 'Workspace',
    'Profile', 'HarnessBundle', 'read_profile_files', '_yaml', 'parse_profiles', 'enabled_workspaces',
    'validate_profiles', 'ENV_NAME_RE', 'CREDENTIAL_NAME_RE', 'ENV_VALUE_LIMIT', 'SANDBOX_ENV_KEYS',
    'INPUT_KEYS', 'secret_ref', 'secret_ref_problems', 'INFERENCE_KEYS', 'INFERENCE_PROTOCOLS',
    'PROVIDER_PROTOCOLS', 'check_env_value', 'sandbox_env_problems', 'input_problems',
    'check_base_url', 'resolve_bom_input', 'resolve_inference', 'inference_protocol', 'sandbox_inference_problems', 'harness_from_plan', 'profiles_from_plan',
    'validate_profile_document', 'apply_workspace_sequence', 'select_inference_provider',
    'NATIVE_BASE_URLS', 'OPENCLAW_AUTH_CHOICES', 'PROTOCOL_NATIVE_BASE_URLS',
    'sandbox_protocol', 'sandbox_model', 'sandbox_endpoint', 'openclaw_inference_settings',
    'openclaw_managed_provider_id',
)


def tree_digest(files):
    """Shared contract: sha256 over sorted "<relpath>\\0<sha256_hex>\\n" lines.

    `files` maps a POSIX relative path to file bytes. Helm computes the same
    value at render time; templates/configmap-bom.yaml must agree.
    """
    digest = hashlib.sha256()
    for rel in sorted(files):
        digest.update(f"{rel}\x00{hashlib.sha256(files[rel]).hexdigest()}\n".encode())
    return "sha256:" + digest.hexdigest()


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


def tool_gate_identity(owner, subject, workspace, sandbox):
    if not isinstance(owner, str) or not owner.strip():
        raise InstallerError(f"sandbox '{sandbox}': dashboard.owner is required for the tool gate")
    if not isinstance(subject, str) or not subject.strip():
        raise InstallerError(f"sandbox '{sandbox}': ownerSubject is required for the tool gate")
    return {"username": owner, "subject": subject,
            "sandbox": sandbox, "workspace": workspace}


def tool_gate_bundle(here, identity, receipt_key=None):
    """Build the identical policy, identity and OpenClaw extension for both runtimes."""
    names = ("tool-actions.yaml", "tool-gate.mjs", "tool-gate-plugin.mjs")
    missing = [name for name in names if not (here / name).is_file()]
    if missing:
        raise InstallerError("tool gate files missing from the installer disk: " + ", ".join(missing))
    policy = (here / "tool-actions.yaml").read_bytes()
    policy_hash = "sha256:" + hashlib.sha256(policy).hexdigest()
    plugin = (here / "tool-gate-plugin.mjs").read_bytes().replace(
        b"__SAW_POLICY_HASH__", policy_hash.encode())
    if receipt_key is not None:
        if not isinstance(receipt_key, str) or not re.fullmatch(r"MCowBQYDK2VwAyEA[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=", receipt_key):
            raise InstallerError("audit writer requires a canonical Ed25519 public key")
        plugin = plugin.replace(b"__SAW_AUDIT_KEY__", receipt_key.encode("ascii"))
    tree = {
        "tool-actions.yaml": (policy, False),
        "identity.json": ((json.dumps(identity, sort_keys=True) + "\n").encode(), False),
        "plugin/package.json": (_TOOL_GATE_PACKAGE.encode(), False),
        "plugin/openclaw.plugin.json": (_TOOL_GATE_MANIFEST.encode(), False),
        "plugin/index.js": (plugin, False),
        "plugin/tool-gate.mjs": ((here / "tool-gate.mjs").read_bytes(), False),
    }
    digest = tree_digest({key: data for key, (data, _) in tree.items()})
    source = f"gate:{digest}"
    return tree, source, digest, policy_hash


# Inline harness parsing and OpenClaw registration are shared by both installers.
HARNESS_MOUNT = "/sandbox/harness"


# mcp.json env/header value: exactly ${VAR}, or Authorization-style
# "Bearer ${VAR}". Any other prefix could smuggle a literal secret.
# A stdio arg naming a credential-ish flag with a literal value, e.g.
# "--api-key=sk-live-...". The "--flag value" two-token form is not covered.
MCP_PLACEHOLDER_ONLY = re.compile(
    r"^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|Bearer \$\{[A-Za-z_][A-Za-z0-9_]*\})$",
    re.IGNORECASE)


MCP_ARG_CREDENTIAL_RE = re.compile(
    r"^--?[\w-]*(?:key|token|secret|password|passwd|auth)[\w-]*=(?P<value>.*)$",
    re.IGNORECASE)


def safe_rel_path(rel, where):
    """A bundle-relative POSIX path: no absolute, no empty or '.'/'..' segment."""
    parts = rel.split("/")
    if not rel or rel.startswith("/") or any(part in ("", ".", "..") for part in parts):
        raise InstallerError(f"{where}: unsafe path {rel!r}")
    return rel


def describe_harness_tree(files, inline=False, *, warn=lambda _: None):
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
            warn(f"WARN: harness '{name}': plugin '{plugin}' has no entry in harness.yaml "
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
                    warn(f"WARN: harness '{name}': stdio MCP server '{server}' has no "
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


BUNDLE_ROOT_PLACEHOLDERS = ("${CLAUDE_PLUGIN_ROOT}", "${PLUGIN_ROOT}")


MCP_SERVER_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


# OpenClaw (2026.9.x) expands only ${PLUGIN_ROOT}, ${PLUGIN_DATA} and
# ${CLAUDE_PLUGIN_ROOT} in a bundle's mcp.json; any other ${VAR} reaches the
# server as literal text, and a stdio server inherits only HOME, LOGNAME,
# PATH, SHELL, TERM and USER. So a bundle server never sees its provider's
# placeholder (Slack answers invalid_auth) or the sandbox's CA settings (TLS
# through the egress proxy fails). openclaw.json does expand ${VAR} from the
# gateway's environment, which has both, and a server defined under
# mcp.servers replaces the bundle's server of the same name (found live: the
# daily-briefing Slack reader works only this way).
# The CA settings OpenShell gives a sandbox's processes when it has the proxy
# CA (openshell-sandbox child_env::tls_env_vars). Only the ones the sandbox
# really has are passed on: OpenClaw leaves an unset ${VAR} as literal text,
# and REQUESTS_CA_BUNDLE='${REQUESTS_CA_BUNDLE}' breaks every HTTPS call.
MCP_TRUST_ENV = ("NODE_EXTRA_CA_CERTS", "DENO_CERT", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                 "CURL_CA_BUNDLE", "GIT_SSL_CAINFO")


def harness_mcp_servers(info, trust_env=(), *, warn=lambda _: None):
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
            warn(f"WARN: harness '{info['name']}': MCP server name {name!r} cannot be "
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


def harness_plugin_ids(info):
    """The OpenClaw plugin ids the harness brings: the bundle's (plugin.json
    name) and each native plugin under plugins/."""
    ids = [info["bundleId"]] if info["agentPluginsBundle"] else []
    return ids + list(info["pluginDirs"])


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

__all__ += ('BUNDLE_ROOT_PLACEHOLDERS', 'HARNESS_MOUNT', 'MCP_ARG_CREDENTIAL_RE', 'MCP_PLACEHOLDER_ONLY', 'MCP_SERVER_NAME_RE', 'check_harness_index', 'harness_plugin_ids', 'openclaw_harness_config', 'parse_harness_files', 'pinned_bundle', 'safe_rel_path')


def host_allowed(host, patterns):
    """A profile endpoint host may be a glob (*-aiplatform.googleapis.com);
    ports are not part of the match. Each `*` is one DNS label (no dots)."""
    host = (host or "").split(":")[0].lower()
    for pattern in patterns:
        regex = re.escape((pattern or "").split(":")[0].lower()).replace(r"\*", r"[^.]*")
        if re.fullmatch(regex, host):
            return True
    return False


def check_harness_governance(ws, sb, info, catalog, attached):
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


def enable_harness_plugin(plugin_id, environment=""):
    """Grant bundle capability consent using the stock CLI, including older versions."""
    command = (environment + " openclaw plugins enable " + shlex.quote(plugin_id)).lstrip()
    return f"{command} --accept-capabilities || {command}"
