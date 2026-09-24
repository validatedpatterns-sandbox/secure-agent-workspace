"""Shared validation and normalization for standalone SAW user files."""
from __future__ import annotations

import re
from pathlib import Path

import yaml


KEY_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$")
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
PREFIX_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(?:/[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


def load_user(path: Path) -> dict:
    """Load a user file and return the controller-facing normalized form."""
    document = yaml.safe_load(path.read_text()) or {}
    if not isinstance(document, dict):
        raise ValueError("user document must be an object")
    raw = document.get("sawUser", {})
    if not isinstance(raw, dict):
        raise ValueError("sawUser must be an object")

    identity = raw.get("user", {})
    if identity is None:
        identity = {}
    if not isinstance(identity, dict):
        raise ValueError("sawUser.user must be an object")

    user = dict(raw)
    user.pop("user", None)
    user["username"] = identity.get("username", user.get("username", user.get("name")))
    user["subject"] = identity.get("subject", user.get("subject"))
    user["vaultPrefix"] = identity.get("vaultPrefix", user.get("vaultPrefix"))
    if (not isinstance(user.get("name"), str) or len(user["name"]) > 63 or
            not NAME_RE.fullmatch(user["name"])):
        raise ValueError("sawUser.name must be a lowercase Kubernetes name")
    if (not isinstance(user.get("username"), str) or len(user["username"]) > 63 or
            not NAME_RE.fullmatch(user["username"])):
        raise ValueError("sawUser.username must be a lowercase Kubernetes name")
    if (not isinstance(user.get("subject"), str) or not user["subject"] or
            len(user["subject"]) > 512):
        raise ValueError("sawUser must define name, user.username, and user.subject")
    if user["vaultPrefix"] is not None and (
        not isinstance(user["vaultPrefix"], str) or not PREFIX_RE.fullmatch(user["vaultPrefix"])
    ):
        raise ValueError("sawUser.user.vaultPrefix must be a lowercase Vault path")

    profiles = user.get("profiles", [])
    if (not isinstance(profiles, list) or
            any(not isinstance(profile, str) or len(profile) > 63 or not NAME_RE.fullmatch(profile)
                for profile in profiles) or len(profiles) != len(set(profiles))):
        raise ValueError("sawUser.profiles must be a unique array of lowercase names")

    credentials = user.get("credentials", [])
    if not isinstance(credentials, list):
        raise ValueError("sawUser.credentials must be an array")
    normalized = []
    names, remote_keys = set(), set()
    for item in credentials:
        if not isinstance(item, dict):
            raise ValueError("each credential must be an object")
        name = item.get("name")
        remote_key = item.get("remoteKey", name)
        keys = item.get("keys")
        if "properties" in item:
            raise ValueError(f"credential {name}: replace properties with an explicit keys array")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or len(name) > 63:
            raise ValueError("credential.name must be a lowercase Kubernetes name")
        if not isinstance(remote_key, str) or not NAME_RE.fullmatch(remote_key) or len(remote_key) > 63:
            raise ValueError(f"credential {name}: remoteKey must be a lowercase name")
        if not isinstance(keys, list) or not keys or any(
            not isinstance(key, str) or not KEY_RE.fullmatch(key) for key in keys
        ):
            raise ValueError(f"credential {name}: keys must be a non-empty array of field names")
        if len(keys) != len(set(keys)):
            raise ValueError(f"credential {name}: keys must be unique")
        if name in names or remote_key in remote_keys:
            raise ValueError("credential names and remoteKeys must be unique")
        names.add(name)
        remote_keys.add(remote_key)
        normalized.append({"name": name, "remoteKey": remote_key, "keys": keys})
    user["credentials"] = normalized
    return user
