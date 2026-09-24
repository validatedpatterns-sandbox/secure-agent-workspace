#!/usr/bin/env python3
"""Validate and optionally publish complete provider records to Vault KV v2."""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import tempfile
from pathlib import Path

import yaml

from user_config import load_user


SAFE_PATH = re.compile(r"^[a-z0-9][a-z0-9-]*(?:/[a-z0-9][a-z0-9-]*)*$")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-values", type=Path, default=Path("config/saw-platform.yaml"))
    parser.add_argument("--users-dir", type=Path, default=Path("config/users"))
    parser.add_argument("--user", help="publish only this username")
    parser.add_argument("--apply", action="store_true", help="write records; default is validation/dry-run")
    args = parser.parse_args()

    platform = (yaml.safe_load(args.platform_values.read_text()) or {}).get("sawPlatform", {})
    vault = platform.get("platform", {}).get("vault", {})
    mount, prefix = vault.get("mount"), vault.get("prefix")
    issuer = platform.get("platform", {}).get("issuer")
    if not issuer or not mount or not prefix:
        parser.error("platform values must define platform.issuer and platform.vault mount/prefix")
    if not os.environ.get("VAULT_ADDR") and not args.apply:
        print("VAULT_ADDR is not required for dry-run")
    if args.apply and not os.environ.get("VAULT_TOKEN"):
        parser.error("VAULT_TOKEN must be supplied through the environment when using --apply")

    paths = [args.users_dir / args.user] if args.user else sorted(p for p in args.users_dir.iterdir() if p.is_dir())
    if not paths:
        parser.error(f"no user directories found under {args.users_dir}")
    count = 0
    for user_dir in paths:
        user_path = user_dir / "user.yaml"
        secret_path = user_dir / "secret.yaml"
        if not user_path.is_file() or not secret_path.is_file():
            parser.error(f"{user_dir} must contain user.yaml and secret.yaml")
        try:
            user = load_user(user_path)
            secret = yaml.safe_load(secret_path.read_text()) or {}
        except (OSError, ValueError, yaml.YAMLError) as exc:
            parser.error(f"{user_dir}: {exc}")
        providers = secret.get("providers")
        if not isinstance(providers, dict):
            parser.error(f"{secret_path}: providers must be an object")
        declared = {item["remoteKey"]: item for item in user["credentials"]}
        for remote_key, credential in declared.items():
            provider = providers.get(remote_key)
            if not isinstance(provider, dict):
                parser.error(f"{secret_path}: missing providers.{remote_key}")
            missing = [key for key in credential["keys"] if key not in provider]
            if missing:
                parser.error(f"{secret_path}: providers.{remote_key} is missing declared keys: {', '.join(missing)}")
            if not SAFE_PATH.fullmatch(remote_key):
                parser.error(f"credential remoteKey is not a safe Vault path: {remote_key}")
            vault_prefix = user.get("vaultPrefix") or f"{prefix.rstrip('/')}/{user['username']}"
            vault_path = f"{vault_prefix}/providers/{remote_key}"
            print(f"{ 'WRITE' if args.apply else 'CHECK'} {mount}/{vault_path}")
            if args.apply:
                with tempfile.NamedTemporaryFile(mode="w", prefix="saw-vault-", suffix=".yaml", delete=False) as tmp:
                    os.chmod(tmp.name, 0o600)
                    import json
                    json.dump(provider, tmp, separators=(",", ":"))
                    tmp.write("\n")
                    tmp_path = tmp.name
                try:
                    subprocess.run(["vault", "kv", "put", f"-mount={mount}", vault_path, f"@{tmp_path}"], check=True)
                finally:
                    Path(tmp_path).unlink(missing_ok=True)
            count += 1
    print(f"Validated {count} provider record(s).")
    if not args.apply:
        print("Dry-run only. Re-run with --apply to write records to Vault.")


if __name__ == "__main__":
    main()
