#!/usr/bin/env python3
"""Fill empty SAW platform values from the active OpenShift cluster."""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path

import yaml


def oc_json(args):
    try:
        result = subprocess.run(["oc", *args, "-o", "json"], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def discover_issuer(cfg, warnings):
    platform = cfg["sawPlatform"]
    if platform.get("platform", {}).get("issuer"):
        return
    discovery = platform.get("discovery", {})
    namespace = discovery.get("keycloakNamespace", "openshell-agents")
    routes = oc_json(["get", "route", "-n", namespace]) or {}
    candidates = []
    for item in routes.get("items", []):
        name = item.get("metadata", {}).get("name", "").lower()
        host = item.get("spec", {}).get("host", "")
        if host and "keycloak" in name:
            candidates.append(host)
    if len(candidates) == 1:
        realm = discovery.get("keycloakRealm", "openshell")
        platform.setdefault("platform", {})["issuer"] = f"https://{candidates[0]}/realms/{realm}"
    else:
        warnings.append(f"could not uniquely discover a Keycloak route in {namespace}")


def discover_vault(cfg, warnings):
    platform = cfg["sawPlatform"]
    vault = platform.setdefault("platform", {}).setdefault("vault", {})
    discovery = platform.get("discovery", {})
    store = discovery.get("vaultStore", "vault-backend")
    namespace = discovery.get("vaultNamespace", "vault")
    store_obj = oc_json(["get", "clustersecretstore", store]) or {}
    provider = store_obj.get("spec", {}).get("provider", {}).get("vault", {})
    if not vault.get("server"):
        vault["server"] = provider.get("server", "")
    if not vault.get("caBundle"):
        ca = provider.get("caProvider", {})
        ca_namespace = ca.get("namespace", namespace)
        ca_name = ca.get("name")
        ca_key = ca.get("key", "ca.crt")
        if ca_name:
            kind = "configmap" if ca.get("type") == "ConfigMap" else "secret"
            obj = oc_json(["get", kind, ca_name, "-n", ca_namespace])
            if obj:
                if kind == "secret":
                    encoded = obj.get("data", {}).get(ca_key, "")
                    value = base64.b64decode(encoded).decode() if encoded else ""
                else:
                    value = obj.get("data", {}).get(ca_key, "")
                if value:
                    vault["caBundle"] = value
        if not vault.get("caBundle") and not str(vault.get("server", "")).startswith("http://"):
            warnings.append("could not discover the Vault CA bundle from ClusterSecretStore caProvider")
    if not vault.get("server"):
        warnings.append(f"could not discover Vault server from ClusterSecretStore {store}")


def discover_image(cfg, warnings):
    platform = cfg["sawPlatform"]
    image = platform.setdefault("image", {})
    namespace = image.get("namespace") or platform.get("discovery", {}).get("imageNamespace", "saw-images")
    image["namespace"] = namespace
    if image.get("dataSource"):
        return
    data_sources = oc_json(["get", "datasource", "-n", namespace]) or {}
    candidates = [item.get("metadata", {}).get("name", "") for item in data_sources.get("items", [])]
    candidates = [name for name in candidates if name]
    if len(candidates) == 1:
        image["dataSource"] = candidates[0]
        dv = oc_json(["get", "dv", candidates[0], "-n", namespace])
        quantity = (dv or {}).get("spec", {}).get("storage", {}).get("resources", {}).get("requests", {}).get("storage")
        if quantity and quantity.lower().endswith("gi"):
            image["diskSizeGi"] = int(quantity[:-2])
    elif len(candidates) == 0:
        warnings.append(f"no CDI DataSource found in {namespace}")
    else:
        warnings.append(f"multiple CDI DataSources found in {namespace}; set sawPlatform.image.dataSource explicitly")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    source = args.example if args.force or not args.output.exists() else args.output
    try:
        cfg = yaml.safe_load(source.read_text()) or {}
    except OSError as exc:
        parser.error(f"cannot read {source}: {exc}")
    if not isinstance(cfg.get("sawPlatform"), dict):
        parser.error("example must define sawPlatform")
    warnings = []
    discover_issuer(cfg, warnings)
    discover_vault(cfg, warnings)
    discover_image(cfg, warnings)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(yaml.safe_dump(cfg, sort_keys=False))
    args.output.chmod(0o600)
    print(f"wrote {args.output}")
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    print("installerRelease remains manual: fill the approved immutable release/BOM before publishing", file=sys.stderr)


if __name__ == "__main__":
    main()
