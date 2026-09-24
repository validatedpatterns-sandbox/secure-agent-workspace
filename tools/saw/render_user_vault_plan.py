#!/usr/bin/env python3
"""Render a least-privilege Vault policy/role plan for one standalone user."""
import argparse
import hashlib
import json
from pathlib import Path

import yaml

from user_config import load_user


def identity(issuer, subject, name):
    value = json.dumps([issuer, subject, name], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(value.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-values", required=True, type=Path)
    parser.add_argument("--user-values", required=True, type=Path)
    args = parser.parse_args()
    platform = (yaml.safe_load(args.platform_values.read_text()) or {}).get("sawPlatform", {})
    try:
        user = load_user(args.user_values)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    connection = platform.get("platform", {})
    vault = connection.get("vault", {})
    required = (connection.get("issuer"), vault.get("mount"), vault.get("prefix"),
                vault.get("authMount"), vault.get("audience"), user.get("name"),
                user.get("subject"))
    if not all(required):
        parser.error("platform issuer/vault and user name/subject are required")
    key = identity(connection["issuer"], user["subject"], user["name"])
    namespace = f"saw-{user['name'][:33]}-{key[:24]}"
    credentials = user.get("credentials", [])
    vault_prefix = user.get("vaultPrefix") or f"{vault['prefix'].rstrip('/')}/{user['username']}"
    paths = sorted({f"{vault['mount']}/data/{vault_prefix}/providers/{item['remoteKey']}"
                    for item in credentials})
    if not paths:
        parser.error("sawUser.credentials must contain at least one remoteKey")
    print(f"# User: {user['name']}\n# Namespace: {namespace}\n# Identity: {key}")
    print("# Review before applying with a Vault administrator identity.\n")
    print(f"# Save as {namespace}.hcl")
    for path in paths:
        print(f'path "{path}" {{\n  capabilities = ["read"]\n}}\n')
    print("# Then apply the reviewed policy and Kubernetes-auth role:")
    print(f"vault policy write {namespace} {namespace}.hcl")
    print(f"vault write auth/{vault['authMount']}/role/{namespace} \\")
    print("  bound_service_account_names=saw-vault-reader \\")
    print(f"  bound_service_account_namespaces={namespace} \\")
    print(f"  audience={vault['audience']} token_policies={namespace} token_ttl=5m token_max_ttl=15m")


if __name__ == "__main__":
    main()
