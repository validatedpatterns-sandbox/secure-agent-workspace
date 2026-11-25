#!/usr/bin/env python3
"""Extract the selected OpenAPI v3 schemas from pinned upstream CRDs."""

import json
import sys
from pathlib import Path

import yaml

TARGETS = {
    ("kataconfiguration.openshift.io", "KataConfig"): "v1",
    ("rhdh.redhat.com", "Backstage"): "v1alpha5",
    ("hco.kubevirt.io", "HyperConverged"): "v1beta1",
    ("tekton.dev", "Pipeline"): "v1",
    ("tekton.dev", "Task"): "v1",
}


def validation_only(value):
    """Keep schema rules, but remove upstream prose and sample values."""
    if isinstance(value, dict):
        return {key: validation_only(item) for key, item in value.items()
                if key not in {"description", "default", "example", "examples"}}
    if isinstance(value, list):
        return [validation_only(item) for item in value]
    return value


def main() -> int:
    destination = Path(__file__).resolve().parent / "schemas"
    for filename in sys.argv[1:]:
        document = yaml.safe_load(Path(filename).read_text(encoding="utf-8"))
        group = document["spec"]["group"]
        kind = document["spec"]["names"]["kind"]
        for version in document["spec"]["versions"]:
            if not version.get("served") or version["name"] != TARGETS[(group, kind)]:
                continue
            schema = validation_only(version["schema"]["openAPIV3Schema"])
            folder = destination / group
            folder.mkdir(parents=True, exist_ok=True)
            target = folder / f"{kind.lower()}_{version['name']}.json"
            target.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
            print(target.relative_to(destination.parent.parent.parent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
