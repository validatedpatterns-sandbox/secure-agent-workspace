#!/usr/bin/env python3
"""Combine one user enrollment with the platform's approved SAW defaults."""
import argparse
from copy import deepcopy
from pathlib import Path

import yaml

from user_config import load_user


def load(path, parser):
    try:
        return yaml.safe_load(path.read_text()) or {}
    except OSError as exc:
        parser.error(f"cannot read {path}: {exc}")


def resolve_provider_bindings(instance, credentials):
    """Make profile bindings point at provider-named, user-local Secrets."""
    if not isinstance(instance, dict) or not isinstance(instance.get("workspaces", []), list):
        raise ValueError("sawUser.instance.workspaces must be an array")
    instance = deepcopy(instance)
    by_name = {item["name"]: item for item in credentials}
    by_remote = {item["remoteKey"]: item for item in credentials}
    selected = {}
    for workspace in instance.get("workspaces", []):
        if not isinstance(workspace, dict):
            raise ValueError("each workspace selection must be an object")
        bindings = workspace.get("credentialBindings", {}) or {}
        if not isinstance(bindings, dict):
            raise ValueError("credentialBindings must be a mapping")
        for binding_name, binding in bindings.items():
            if not isinstance(binding, dict):
                raise ValueError(f"credential binding {binding_name} must be an object")
            secret_ref = binding.get("secretRef")
            if (not isinstance(secret_ref, dict) or
                    not isinstance(secret_ref.get("name"), str) or
                    not isinstance(secret_ref.get("key"), str)):
                raise ValueError(f"credential binding {binding_name} must set secretRef.name and secretRef.key")
            slot_credential = by_name.get(binding_name)
            ref_credential = by_name.get(secret_ref["name"]) or by_remote.get(secret_ref["name"])
            if slot_credential and ref_credential and slot_credential != ref_credential:
                raise ValueError(f"credential binding {binding_name} references a different credential")
            credential = slot_credential or ref_credential
            if not credential:
                raise ValueError(f"credential binding {binding_name} has no matching sawUser.credentials entry")
            if secret_ref["key"] not in credential["keys"]:
                raise ValueError(f"credential binding {binding_name} uses a key outside its declared keys")
            secret_ref["name"] = credential["remoteKey"]
            selected[credential["remoteKey"]] = credential
    return instance, list(selected.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-values", required=True, type=Path,
                        help="admin-owned sawPlatform values")
    parser.add_argument("--user-values", required=True, type=Path,
                        help="one user-owned sawUser enrollment")
    parser.add_argument("--profiles-dir", type=Path, default=Path("charts/saw-bom/profiles"),
                        help="approved BOM profile directory")
    args = parser.parse_args()
    platform = load(args.platform_values, parser).get("sawPlatform", {})
    try:
        user = load_user(args.user_values)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    required_platform = (platform.get("platform"), platform.get("image"),
                         platform.get("installerRelease"))
    required_user = (user.get("name"), user.get("subject"))
    if not all(required_platform):
        parser.error(
            f"{args.platform_values} is an unconfigured sawPlatform template; "
            "set sawPlatform.platform (issuer and Vault connection), image "
            "(namespace, imported CDI DataSource, diskSizeGi), and installerRelease "
            "(the approved immutable InstallerBOM release) once before installing users"
        )
    if not all(required_user):
        parser.error("user values must define sawUser.name and immutable sawUser.subject")
    profiles = user.get("profiles", [])
    if not isinstance(profiles, list) or any(not isinstance(item, str) or not item for item in profiles):
        parser.error("sawUser.profiles must be an array of non-empty names")
    # A user enrollment may be rendered before profile selections are added.
    # Once it contains workspace intent, at least one approved BOM profile is
    # required to resolve that intent.
    instance = user.get("instance", {})
    if not profiles and isinstance(instance, dict) and instance.get("workspaces"):
        parser.error("user values with workspace intent must define one or more sawUser.profiles")

    image = platform["image"]
    if not all(image.get(key) for key in ("namespace", "dataSource", "diskSizeGi")):
        parser.error("sawPlatform.image must define namespace, dataSource, and diskSizeGi")

    tenant = dict(user)
    tenant.setdefault("username", tenant["name"])
    tenant.setdefault("credentials", [])
    vault_prefix = tenant.pop("vaultPrefix", None) or f"{platform['platform']['vault']['prefix'].rstrip('/')}/{tenant['username']}"
    instance = tenant.pop("instance", {"workspaces": []})
    profile_config_maps = tenant.pop("profileConfigMaps", [])
    if profiles and not profile_config_maps:
        profile_data = {}
        for profile in profiles:
            profile_root = args.profiles_dir / profile
            if not profile_root.is_dir():
                parser.error(f"selected profile does not exist: {profile_root}")
            for document in sorted(profile_root.glob("**/*.yaml")):
                relative = document.relative_to(profile_root)
                if len(relative.parts) != 2:
                    parser.error(f"invalid profile document path: {document}")
                workspace, filename = relative.parts
                profile_data[f"profiles__{profile}__{workspace}__{filename}"] = document.read_text()
        profile_config_maps = [{"name": f"{user['name']}-profiles", "data": profile_data}]
    if profiles and (not isinstance(instance, dict) or not instance.get("workspaces")):
        instance = {"workspaces": [
            {"profileRef": {"name": profile, "configMapRef": {"name": f"{user['name']}-profiles"}}}
            for profile in profiles
        ]}
    try:
        instance, provider_credentials = resolve_provider_bindings(instance, tenant["credentials"])
        from openshell_saw.profiles import resolve_profiles

        validation_configmaps = [{
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": item["name"], "namespace": "saw-validation"},
            "data": item["data"],
        } for item in profile_config_maps]
        resolve_profiles(instance.get("workspaces", []), validation_configmaps, "saw-validation")
    except (KeyError, TypeError, ValueError) as exc:
        parser.error(f"invalid profile selection or credential binding: {exc}")
    guest = tenant.pop("guest", {"enabled": True, "cores": 4, "memoryGi": 8, "runStrategy": "Halted"})
    tenant.pop("profiles", None)
    rendered = {"openshellSaw": {
        "platform": platform["platform"],
        "tenant": tenant,
        "vaultPrefix": vault_prefix,
        "providerCredentials": provider_credentials,
        "image": image,
        "instance": instance,
        "profileConfigMaps": profile_config_maps,
        "installerRelease": platform["installerRelease"],
        "guest": guest,
    }}
    print(yaml.safe_dump(rendered, sort_keys=False))


if __name__ == "__main__":
    main()
