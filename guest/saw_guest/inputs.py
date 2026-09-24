"""Capture read-only projected files, then resolve SAW-BOM profiles locally."""

import base64
import json
from pathlib import Path

from openshell_saw.blueprints import API_VERSION, KEY, ValidationError, fields, load_document, name, string
from openshell_saw.profiles import resolve_profiles

LIMIT = 512 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class InputsChanged(ValidationError):
    pass


def validate_settings(settings):
    fields(settings, {"namespace", "instance", "ownerSubject", "enrollmentIdentity",
                      "profileConfigMaps", "providerSecrets", "oidcIssuer", "oidcAudience"},
           {"namespace", "instance", "ownerSubject", "enrollmentIdentity",
            "profileConfigMaps", "providerSecrets"}, "guest settings")
    name(settings["namespace"], "namespace")
    name(settings["instance"], "instance")
    string(settings["ownerSubject"], "owner subject", limit=512)
    string(settings["enrollmentIdentity"], "enrollment identity", r"[0-9a-f]{64}")
    for key in ("oidcIssuer", "oidcAudience"):
        if key in settings:
            string(settings[key], key, limit=2048)
    profiles = settings["profileConfigMaps"]
    if not isinstance(profiles, list) or len(profiles) > 64:
        raise ValidationError("invalid profile catalog")
    for profile in profiles:
        name(profile, "profile ConfigMap")
    if len(profiles) != len(set(profiles)):
        raise ValidationError("duplicate profile catalog")
    secrets = settings["providerSecrets"]
    if not isinstance(secrets, dict) or len(secrets) > 64:
        raise ValidationError("invalid provider catalog")
    for secret, keys in secrets.items():
        name(secret, "provider Secret")
        if not isinstance(keys, list) or not 1 <= len(keys) <= 32:
            raise ValidationError("invalid provider keys")
        for key in keys:
            string(key, "provider key", KEY)
    return settings


class MountedInputs:
    def __init__(self, root, settings):
        self.root = Path(root)
        self.settings = validate_settings(settings)

    def read(self, relative):
        # Projection symlinks such as ..data/key are valid, but must remain in
        # the specific approved mount, not escape into another mount or host path.
        path = self.root / relative
        mount = path.parent
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(mount.resolve()) or not mount.resolve().is_relative_to(self.root.resolve()):
            raise ValidationError("projected file escapes its mount")
        with resolved.open("rb") as source:
            value = source.read(LIMIT + 1)
        if len(value) > LIMIT:
            raise ValidationError("projected file exceeds limit")
        return value

    def _capture(self):
        raw = {"intent/instance.yaml": self.read("intent/instance.yaml"),
               "installer/installer-bom.yaml": self.read("installer/installer-bom.yaml")}
        cms = []
        total = sum(len(value) for value in raw.values())
        for cm in self.settings["profileConfigMaps"]:
            data = {}
            directory = self.root / "profiles" / cm
            entries = sorted(directory.iterdir())
            if len(entries) > 512:
                raise ValidationError("too many projected profile files")
            for entry in entries:
                if entry.name.startswith("."):
                    continue
                string(entry.name, "projected file key", KEY)
                relative = f"profiles/{cm}/{entry.name}"
                value = self.read(relative)
                total += len(value)
                if total > LIMIT:
                    raise ValidationError("profile inputs exceed limit")
                raw[relative] = value
                data[entry.name] = value.decode("utf-8")
            cms.append({"apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": {"name": cm, "namespace": self.settings["namespace"]}, "data": data})
        instance = load_document(raw["intent/instance.yaml"].decode("utf-8"))
        fields(instance, {"apiVersion", "kind", "metadata", "spec"},
               {"apiVersion", "kind", "metadata", "spec"}, "instance")
        fields(instance["metadata"], {"name"}, {"name"}, "instance metadata")
        spec = fields(instance["spec"], {"ownerSubject", "workspaces"},
                      {"ownerSubject", "workspaces"}, "instance spec")
        if (instance["apiVersion"] != API_VERSION or instance["kind"] != "SawInstance" or
                instance["metadata"]["name"] != self.settings["instance"] or
                spec["ownerSubject"] != self.settings["ownerSubject"]):
            raise ValidationError("instance does not match enrolled identity")
        if not isinstance(spec["workspaces"], list) or len(spec["workspaces"]) > 64:
            raise ValidationError("invalid workspace selections")
        graph = resolve_profiles(spec["workspaces"], cms, self.settings["namespace"])
        credentials = {}
        for workspace in graph:
            for member in workspace["workspace"].get("spec", {}).get("members", []):
                if member.pop("subjectRef", None) == "instanceOwner":
                    member["subject"] = self.settings["ownerSubject"]
            for provider in workspace["providers"]:
                if not provider.get("enabled", True) or not workspace["workspace"].get("spec", {}).get("enabled", True):
                    continue
                ref = provider["secretRef"]
                sn, key = ref["name"], ref["key"]
                if key not in self.settings["providerSecrets"].get(sn, []):
                    raise ValidationError("credential outside enrollment allowlist")
                relative = f"credentials/{sn}/{key}"
                if relative not in raw:
                    raw[relative] = self.read(relative)
                    total += len(raw[relative])
                if total > LIMIT or not 0 < len(raw[relative]) <= 65536:
                    raise ValidationError("empty or oversized credential inputs")
                credentials.setdefault(sn, {})[key] = base64.b64encode(raw[relative]).decode()
        snapshot = {"installerBOM": load_document(raw["installer/installer-bom.yaml"].decode("utf-8")),
                    "enrollmentIdentity": self.settings["enrollmentIdentity"],
                    "ownerSubject": self.settings["ownerSubject"],
                    "workspaces": graph, "credentials": credentials}
        if len(canonical(snapshot).encode()) > LIMIT:
            raise ValidationError("resolved snapshot exceeds limit")
        return raw, snapshot

    def capture(self):
        # Reopen files: held FDs and inotify alone miss kubelet projection swaps.
        # This detects changes during collection, not an atomic multi-object commit.
        first, snapshot = self._capture()
        second, _ = self._capture()
        if first != second:
            raise InputsChanged("mounted inputs changed during collection")
        return snapshot
