#!/usr/bin/env python
"""List owner-restricted UI routes requested by SAW-BOM profiles."""

import json
import re
import sys
from pathlib import Path

import yaml


def ui_routes(catalog: Path, names: str) -> list[dict[str, object]]:
    routes: set[tuple[str, str]] = set()
    for name in names.split(","):
        name = name.strip()
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", name):
            raise ValueError(f"invalid SAW-BOM profile name: {name!r}")
        profile = catalog / name
        if not profile.is_dir():
            raise ValueError(f"SAW-BOM profile does not exist: {name}")
        for workspace_dir in profile.iterdir():
            if not workspace_dir.is_dir():
                continue
            workspace_file = workspace_dir / "workspace.yaml"
            sandbox_file = workspace_dir / "sandbox.yaml"
            if not workspace_file.exists() or not sandbox_file.exists():
                continue
            workspace = yaml.safe_load(workspace_file.read_text()) or {}
            if (workspace.get("spec") or {}).get("enabled", True) is False:
                continue
            workspace_name = (workspace.get("metadata") or {}).get("name") or workspace_dir.name
            sandboxes = yaml.safe_load(sandbox_file.read_text()) or {}
            for sandbox in (sandboxes.get("spec") or {}).get("sandboxes") or []:
                if sandbox.get("enabled", True) and (sandbox.get("ui") or {}).get("route"):
                    routes.add((workspace_name, sandbox["name"]))
    if len(routes) > 8:
        raise ValueError("at most 8 sandboxes can have UI routes")
    return [
        {"workspace": workspace, "sandbox": sandbox,
         "proxyPort": 4201 + index, "forwardPort": 14201 + index}
        for index, (workspace, sandbox) in enumerate(sorted(routes))
    ]


if __name__ == "__main__":
    catalog = Path(__file__).resolve().parents[1] / "charts/saw-bom/profiles"
    try:
        print(json.dumps(ui_routes(catalog, sys.argv[1])))
    except (IndexError, ValueError, KeyError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
