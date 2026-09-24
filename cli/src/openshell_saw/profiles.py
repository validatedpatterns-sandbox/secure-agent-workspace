"""Pure SAW-BOM profile expansion and namespace-local credential bindings.

This is a preflight contract, not an apply engine: it neither reads Secret
values nor creates providers. The guest reconciler consumes its
validated output instead of inheriting the legacy runner's implicit defaults.
"""

import hashlib
import json
import re
from copy import deepcopy

from .blueprints import API_VERSION, KEY, ValidationError, fields, load_document, name, string


def _list(value, path):
    if not isinstance(value, list):
        raise ValidationError(f"{path} must be an array")
    return value


def _secret_ref(value):
    fields(value, {"name", "key"}, {"name", "key"}, "secretRef")
    name(value["name"], "secretRef.name")
    string(value["key"], "secretRef.key", KEY)
    return deepcopy(value)


def _document(raw, kind, spec_fields):
    doc = load_document(raw)
    fields(doc, {"apiVersion", "kind", "metadata", "spec"},
           {"apiVersion", "kind", "metadata"}, "profile document")
    if doc["apiVersion"] != API_VERSION or doc["kind"] != kind:
        raise ValidationError("unsupported profile apiVersion/kind")
    fields(doc["metadata"], {"name", "description", "profile"}, set(), "profile metadata")
    fields(doc.get("spec", {}), spec_fields, set(), "profile spec")
    return doc


def _enabled(item):
    value = item.get("enabled", True)
    if type(value) is not bool:
        raise ValidationError("enabled must be boolean")
    return value


def resolve_profiles(selections, configmaps, namespace):
    """Expand selected local profile trees; return references, never secrets.

    `configmaps` is a Kubernetes List's items array, or an equivalent list of
    snapshots. The guest captures mounted input files before invoking this resolver.
    """
    name(namespace, "namespace")
    index = {}
    for cm in _list(configmaps, "configmaps"):
        if not isinstance(cm, dict) or cm.get("kind") != "ConfigMap" or cm.get("apiVersion") != "v1":
            raise ValidationError("profile inputs must be v1 ConfigMaps")
        meta = cm.get("metadata", {})
        if not isinstance(meta, dict) or meta.get("namespace") != namespace:
            raise ValidationError("profile ConfigMaps must belong to the requested namespace")
        cm_name = name(meta.get("name"), "ConfigMap name")
        if cm_name in index:
            raise ValidationError("duplicate profile ConfigMap")
        data = cm.get("data")
        if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str)
                                               for k, v in data.items()):
            raise ValidationError("profile ConfigMap data must contain string values")
        if len(json.dumps(data).encode()) > 512 * 1024:
            raise ValidationError("profile ConfigMap exceeds 512 KiB")
        index[cm_name] = data

    result, selected, workspace_names = [], set(), set()
    for entry in _list(selections, "workspaces"):
        fields(entry, {"profileRef", "credentialBindings"}, {"profileRef"}, "profile selection")
        ref = fields(entry["profileRef"], {"name", "configMapRef"},
                     {"name", "configMapRef"}, "profileRef")
        profile = name(ref["name"], "profile name")
        cm_ref = fields(ref["configMapRef"], {"name"}, {"name"}, "configMapRef")
        cm_name = name(cm_ref["name"], "configMapRef.name")
        if (cm_name, profile) in selected:
            raise ValidationError("duplicate profile selection")
        selected.add((cm_name, profile))
        if cm_name not in index:
            raise ValidationError("referenced profile ConfigMap is missing")
        bindings = entry.get("credentialBindings", {})
        if not isinstance(bindings, dict):
            raise ValidationError("credentialBindings must be a mapping")
        for slot, binding in bindings.items():
            name(slot, "credential slot")
            fields(binding, {"secretRef"}, {"secretRef"}, "credential binding")
            _secret_ref(binding["secretRef"])
        trees = {}
        prefix = f"profiles__{profile}__"
        for key, raw in index[cm_name].items():
            if not key.startswith(prefix):
                continue
            parts = key.split("__")
            if len(parts) != 4 or parts[3] not in {"workspace.yaml", "providers.yaml", "sandbox.yaml"}:
                raise ValidationError("invalid selected profile file key")
            workspace = name(parts[2], "workspace directory")
            trees.setdefault(workspace, {})[parts[3]] = raw
        if not trees:
            raise ValidationError("selected profile is missing or empty")
        used_bindings = set()
        for directory, files in sorted(trees.items()):
            if set(files) != {"workspace.yaml", "providers.yaml", "sandbox.yaml"}:
                raise ValidationError("selected workspace has incomplete profile documents")
            workspace = _document(files["workspace.yaml"], "Workspace",
                                  {"enabled", "members", "inference"})
            ws_name = name(workspace["metadata"].get("name"), "workspace name")
            if ws_name != directory or ws_name in workspace_names:
                raise ValidationError("workspace name mismatch or overlapping selected workspaces")
            workspace_names.add(ws_name)
            spec = workspace.get("spec", {})
            _enabled(spec)
            for member in _list(spec.get("members", []), "members"):
                fields(member, {"subject", "subjectRef", "role"}, {"role"}, "member")
                if ("subject" in member) == ("subjectRef" in member):
                    raise ValidationError("member must select exactly one subject form")
                if "subject" in member:
                    string(member["subject"], "member subject", limit=512)
                elif member["subjectRef"] != "instanceOwner":
                    raise ValidationError("unsupported member subjectRef")
                if member["role"] not in ("admin", "member"):
                    raise ValidationError("unsupported member role")
            providers_doc = _document(files["providers.yaml"], "Providers", {"providers"})
            providers, provider_names = [], set()
            for item in _list(providers_doc.get("spec", {}).get("providers", []), "providers"):
                fields(item, {"name", "type", "enabled", "nemoclawProvider", "model",
                              "credentialRef", "credentialSecret", "credentialSecretKey"},
                       {"name", "type"}, "provider")
                provider_name = name(item["name"], "provider name")
                name(item["type"], "provider type")
                if provider_name in provider_names:
                    raise ValidationError("duplicate provider name")
                provider_names.add(provider_name)
                enabled = _enabled(item)
                resolved = deepcopy(item)
                slot = item.get("credentialRef")
                legacy = "credentialSecret" in item or "credentialSecretKey" in item
                if "credentialRef" in item:
                    name(slot, "credentialRef")
                    if legacy or slot not in bindings:
                        raise ValidationError("ambiguous or missing provider credential binding")
                    used_bindings.add(slot)
                    resolved["secretRef"] = _secret_ref(bindings[slot]["secretRef"])
                elif legacy:
                    resolved["secretRef"] = _secret_ref({"name": item.get("credentialSecret"),
                                                        "key": item.get("credentialSecretKey", "api_key")})
                elif enabled:
                    raise ValidationError("enabled provider requires an explicit credential binding")
                for key in ("credentialRef", "credentialSecret", "credentialSecretKey"):
                    resolved.pop(key, None)
                providers.append(resolved)
            if "inference" in spec:
                inference = fields(spec["inference"], {"provider", "model"},
                                   {"provider", "model"}, "workspace inference")
                name(inference["provider"], "inference provider")
                string(inference["model"], "inference model")
                if inference["provider"] not in provider_names:
                    raise ValidationError("inference references a missing provider")
            sandboxes_doc = _document(files["sandbox.yaml"], "Sandboxes", {"sandboxes"})
            sandboxes = _list(sandboxes_doc.get("spec", {}).get("sandboxes", []), "sandboxes")
            sandbox_names = set()
            for item in sandboxes:
                fields(item, {"name", "type", "agent", "enabled", "image", "providers", "data", "model"},
                       {"name", "type"}, "sandbox")
                sandbox_name = name(item["name"], "sandbox name")
                if sandbox_name in sandbox_names:
                    raise ValidationError("duplicate sandbox name")
                sandbox_names.add(sandbox_name)
                enabled = _enabled(item)
                if item["type"] not in ("generic", "openclaw", "nemoclaw"):
                    raise ValidationError("unsupported sandbox type")
                if "data" in item:
                    data = fields(item["data"], {"name", "mountPath", "retainOnDelete"},
                                  {"name", "mountPath", "retainOnDelete"}, "sandbox data")
                    name(data["name"], "data name")
                    if data["mountPath"] != "/sandbox/persist" or data["retainOnDelete"] is not True:
                        raise ValidationError("sandbox data must use the retained /sandbox/persist contract")
                elif enabled:
                    raise ValidationError("enabled sandbox requires declared persistent data")
                attached = _list(item.get("providers", []), "sandbox providers")
                for provider in attached:
                    name(provider, "sandbox provider reference")
                    if provider not in provider_names:
                        raise ValidationError("sandbox references a missing provider")
                    if enabled and not next(_enabled(p) for p in providers if p["name"] == provider):
                        raise ValidationError("enabled sandbox references a disabled provider")
                if enabled and (not isinstance(item.get("image"), str) or not re.fullmatch(
                        r"[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}", item["image"])):
                    raise ValidationError("enabled sandbox image must be pinned by sha256 digest")
            result.append({"profile": profile, "name": ws_name, "workspace": deepcopy(workspace),
                           "providers": sorted(providers, key=lambda p: p["name"]),
                           "sandboxes": sorted(deepcopy(sandboxes), key=lambda s: s["name"])})
        if set(bindings) != used_bindings:
            raise ValidationError("unused credential binding in profile selection")
    return sorted(result, key=lambda ws: ws["name"])


def profile_fingerprint(resolved):
    """Non-secret profile identity only; NEVER hash Secret values here."""
    return hashlib.sha256(json.dumps(resolved, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()
