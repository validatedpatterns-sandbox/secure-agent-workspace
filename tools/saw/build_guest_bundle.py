#!/usr/bin/env python3
"""Build a reproducible guest-agent source bundle; never deploy or publish it.

This is an input to a sealed golden-image build, NOT a VM disk/container image.
No credentials, values files, executable BOM ConfigMaps or local caches are packed.
"""

import argparse
import gzip
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "installer"))
sys.path.insert(0, str(ROOT / "cli/src"))
from apply_bom import load_installer_bom  # noqa: E402

FILES = {
    **{f"guest/saw_guest/{file}": f"opt/saw/guest/saw_guest/{file}" for file in
       ("__init__.py", "__main__.py", "inputs.py", "reconcile.py", "installer.py", "mounts.py", "health.py", "errors.py", "release.py", "release_exec.py")},
    **{f"cli/src/openshell_saw/{file}": f"opt/saw/guest/openshell_saw/{file}" for file in
       ("__init__.py", "blueprints.py", "profiles.py")},
    **{f"guest/systemd/{file}": f"etc/systemd/system/{file}" for file in
       ("saw-guest.service", "saw-guest-mounts.service", "saw-openshell-gateway.service")},
    "guest/requirements.txt": "opt/saw/guest/requirements.txt",
}


def build(output, installer_bom):
    bom = load_installer_bom(installer_bom)
    contents = {destination: (ROOT / source).read_bytes() for source, destination in FILES.items()}
    # JSON is also YAML; canonical encoding makes equivalent input reproducible.
    manifest = {"installerBOM": bom,
                "gatewayUnitSha256": hashlib.sha256(contents["etc/systemd/system/saw-openshell-gateway.service"]).hexdigest()}
    contents["opt/saw/guest/build.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    with Path(output).open("xb") as target:
        with gzip.GzipFile(filename="", fileobj=target, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for destination, data in sorted(contents.items()):
                    info = tarfile.TarInfo(destination)
                    info.size, info.mode, info.uid, info.gid, info.mtime = len(data), 0o644, 0, 0, 0
                    archive.addfile(info, io.BytesIO(data))
    return hashlib.sha256(Path(output).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--installer-bom", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite an existing bundle")
    print(f"{build(args.output, args.installer_bom)}  {args.output.name}")


if __name__ == "__main__":
    main()
