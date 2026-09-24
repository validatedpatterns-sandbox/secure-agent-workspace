#!/usr/bin/env python3
"""Render, but never apply, the least-privilege Vault policy and role for one tenant."""
import argparse
import hashlib
import json
from pathlib import Path

import yaml


def identity(issuer, subject, name):
    value = json.dumps([issuer, subject, name], separators=(",", ":"), ensure_ascii=False)
    value = value.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return hashlib.sha256(value.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--values", required=True, type=Path, help="Blueprint values YAML")
    parser.add_argument("--tenant", required=True, help="tenant.name to plan")
    args = parser.parse_args()
    values = yaml.safe_load(args.values.read_text()) or {}
    cfg = values.get("sawBlueprint", {})
    platform = cfg.get("platform", {})
    vault = platform.get("vault", {})
    tenant = next((item for item in cfg.get("tenants", []) if item.get("name") == args.tenant), None)
    required = (platform.get("issuer"), vault.get("mount"), vault.get("prefix"), vault.get("authMount"), vault.get("audience"), tenant)
    if not all(required):
        parser.error("values must define platform.issuer, platform.vault and the named tenant")
    key = identity(platform["issuer"], tenant["subject"], tenant["name"])
    namespace = f"saw-{tenant['name'][:33]}-{key[:24]}"
    vault_prefix = tenant.get("vaultPrefix") or f"{vault['prefix'].rstrip('/')}/{tenant['username']}"
    paths = sorted({f"{vault['mount']}/data/{vault_prefix}/providers/{item['remoteKey']}" for item in tenant.get("credentials", [])})
    if not paths:
        parser.error("tenant.credentials must not be empty")
    print(f"# Tenant: {tenant['name']}\n# Namespace: {namespace}\n# Identity: {key}\n# Review before applying with a Vault administrator identity.\n")
    print(f'# Save as {namespace}.hcl')
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
