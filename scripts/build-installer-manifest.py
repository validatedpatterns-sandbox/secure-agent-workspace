#!/usr/bin/env python3
"""Build the deterministic manifest CI signs and verify-bundle checks.

Usage: build-installer-manifest.py <rendered-chart.yaml> <out-manifest.txt>

<rendered-chart.yaml> is the output of
`helm template <release> charts/openshell-saw --namespace <ns> --set sandboxName=<release>`.

Must match charts/openshell-saw/files/guest/verify-bundle's manifest_text()
exactly: the same file set (installer-bom.yaml, apply_bom.py,
setup-dashboard.sh, and every provider-profile-*.yaml, sorted), the same
"<sha256>  <path>\n" line format. Any drift between this script and
verify-bundle makes a genuine, unmodified installer fail signing.mode:
enforce for no reason (PR #54 review, 3). installer-tests.yml's drift-check
step catches that: it fails if the committed bundle.sigstore.json (when one
is committed) no longer verifies against a fresh render's manifest.
"""
import hashlib
import sys

import yaml

FIXED_FILES = ["installer-bom.yaml", "apply_bom.py", "setup-dashboard.sh"]
IDENTITY_FILES = ["identity.py", "saw_spire.pp.b64"]


def build_manifest(data):
    covered = sorted(
        FIXED_FILES
        + [name for name in IDENTITY_FILES if name in data]
        + [name for name in data if name.startswith("provider-profile-") and name.endswith(".yaml")]
    )
    lines = []
    for name in covered:
        if name not in data:
            raise SystemExit(f"installer ConfigMap is missing '{name}'; cannot build the manifest")
        digest = hashlib.sha256(data[name].encode("utf-8")).hexdigest()
        lines.append(f"{digest}  {name}\n")
    return "".join(lines)


def find_installer_configmap(rendered_path):
    with open(rendered_path, encoding="utf-8") as fh:
        docs = [d for d in yaml.safe_load_all(fh) if d]
    matches = [
        d for d in docs
        if d.get("kind") == "ConfigMap" and d["metadata"]["name"].endswith("-installer")
    ]
    if not matches:
        raise SystemExit(f"no *-installer ConfigMap found in {rendered_path}")
    if len(matches) > 1:
        raise SystemExit(f"more than one *-installer ConfigMap found in {rendered_path}")
    return matches[0]


def main(argv):
    if len(argv) != 3:
        raise SystemExit(f"usage: {argv[0]} <rendered-chart.yaml> <out-manifest.txt>")
    rendered_path, out_path = argv[1], argv[2]
    cm = find_installer_configmap(rendered_path)
    manifest = build_manifest(cm["data"])
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(manifest)
    print(f"wrote {out_path} ({len(manifest.splitlines())} file(s) covered)")


if __name__ == "__main__":
    main(sys.argv)
