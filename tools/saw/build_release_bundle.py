#!/usr/bin/env python3
"""Create an OCI build context for a signed, digest-pinned guest release."""

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
from build_guest_bundle import load_installer_bom  # noqa: E402


def build(output, name, bom, signing_key):
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    bundle = output / "bundle"
    bundle.mkdir(mode=0o700)
    apply = ROOT / "installer/apply_bom.py"
    bom_path = Path(bom)
    shutil.copyfile(apply, bundle / "apply_bom.py")
    shutil.copyfile(bom_path, bundle / "installer-bom.yaml")
    bom_doc = load_installer_bom(bom_path)
    if bom_doc["metadata"]["name"] != name:
        raise ValueError("release name must match InstallerBOM metadata.name")
    manifest = {
        "format": 1,
        "name": name,
        "bom": bom_doc,
        "files": {
            "apply_bom.py": hashlib.sha256((bundle / "apply_bom.py").read_bytes()).hexdigest(),
            "installer-bom.yaml": hashlib.sha256((bundle / "installer-bom.yaml").read_bytes()).hexdigest(),
        },
    }
    manifest_path = bundle / "release.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
    subprocess.run(["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(signing_key),
                    "-out", str(bundle / "release.json.sig"), str(manifest_path)], check=True)
    components = bom_doc["spec"]["openshell"]
    dockerfile = "\n".join([
        f"FROM {components['cli']['image']} AS cli",
        f"FROM {components['gateway']['image']} AS gateway",
        f"FROM {components['supervisor']['image']} AS supervisor",
        "FROM scratch",
        "COPY bundle /bundle",
        "COPY --from=cli /usr/local/bin/openshell /bundle/openshell",
        "COPY --from=gateway /usr/local/bin/openshell-gateway /bundle/openshell-gateway",
        "COPY --from=supervisor /openshell-sandbox /bundle/openshell-supervisor",
        "",
    ])
    (output / "Dockerfile").write_text(dockerfile)
    (output / "build-inputs.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--installer-bom", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite an existing output directory")
    try:
        bom = load_installer_bom(args.installer_bom)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        parser.error(f"invalid InstallerBOM: {exc}")
    if bom["metadata"]["name"] != args.name:
        parser.error("--name must match InstallerBOM metadata.name")
    print(json.dumps(build(args.output, args.name, args.installer_bom, args.signing_key), sort_keys=True))


if __name__ == "__main__":
    main()
