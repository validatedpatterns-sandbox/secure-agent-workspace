#!/usr/bin/env python3
"""Resolve one plain blueprint tenant into values for direct openshell-saw Helm use."""
import argparse
import hashlib
import json
from pathlib import Path

import yaml


def helm_hash(value):
    """Match Helm's deterministic JSON hash used for approved DataSource names."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    raw = raw.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return hashlib.sha256(raw.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--values", required=True, type=Path)
    parser.add_argument("--tenant", required=True, help="tenant.name")
    args = parser.parse_args()
    source = yaml.safe_load(args.values.read_text()) or {}
    cfg = source.get("sawBlueprint", {})
    platform = cfg.get("platform")
    tenant = next((item for item in cfg.get("tenants", []) if item.get("name") == args.tenant), None)
    if not platform or not tenant:
        parser.error("values must define sawBlueprint.platform and the named tenant")
    image = next((item for item in cfg.get("goldenImages", []) if item.get("name") == tenant.get("goldenImageRef")), None)
    if not image:
        parser.error("tenant.goldenImageRef must name one sawBlueprint.goldenImages entry")
    release_name = tenant.get("installerReleaseRef") or cfg.get("installer", {}).get("defaultRelease")
    release = next((item for item in cfg.get("installer", {}).get("releases", []) if item.get("name") == release_name), None)
    if not release:
        parser.error("tenant installerReleaseRef/defaultRelease must name one installer release")
    tenant_image = {"namespace": cfg.get("imageNamespace"),
                    "dataSource": f"{image['name'][:25]}-{helm_hash(image)[:24]}",
                    "diskSizeGi": image["diskSizeGi"]}
    if image.get("storageClass"):
        tenant_image["storageClassName"] = image["storageClass"]
    resolved = {
        "platform": platform,
        "tenant": tenant,
        "image": tenant_image,
        "instance": tenant["instance"],
        "profileConfigMaps": tenant.get("profileConfigMaps", []),
        "installerRelease": release,
        "guest": tenant.get("guest", {}),
    }
    print(yaml.safe_dump({"openshellSaw": resolved}, sort_keys=False))


if __name__ == "__main__":
    main()
