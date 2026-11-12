#!/usr/bin/env python3
"""Build the deterministic manifest CI signs and verify-bundle checks.

Usage: build-installer-manifest.py <rendered-chart.yaml> <out-manifest.txt>

<rendered-chart.yaml> is the output of
`helm template <release> charts/openshell-saw --namespace <ns> \
  -f <target-cluster-topology.yaml> --set sandboxName=<release>`.

Must match charts/openshell-saw/files/guest/verify-bundle's manifest_text()
exactly: the same file set (installer-bom.yaml, apply_bom.py,
setup-dashboard.sh, every provider-profile-*.yaml, and all three tool-gate
files and both gateway PKI files, sorted), the same "<sha256>  <path>\n" line
format. Any drift between this script and verify-bundle makes a genuine,
unmodified installer fail signing.mode: enforce for no reason (PR #54 review,
3). installer-tests.yml's drift-check step catches that: it fails if the
committed bundle.sigstore.json (when one is committed) no longer verifies
against a fresh render's manifest.

The canonical saw_core.py, saw_admin.py and saw_ui_limit.py are embedded inside rendered
apply_bom.py, so their bytes are covered by that existing signed file. Keep this manifest set stable:
golden images with the original verifier can verify new bundles without an
unsigned adjacent module or a replacement verifier. Refuse raw source and
noncanonical embedded code before producing a signable payload.
"""
import ast
import base64
import binascii
import hashlib
from pathlib import Path
import sys

import yaml

FIXED_FILES = ["installer-bom.yaml", "apply_bom.py", "setup-dashboard.sh"]
TOOL_GATE_FILES = ["tool-actions.yaml", "tool-gate.mjs", "tool-gate-plugin.mjs"]
PKI_FILES = ["saw-gateway-pki", "openshell-gateway-pki.conf"]
CORE_SOURCE = Path(__file__).resolve().parents[1] / "charts/openshell-saw/files/installer/saw_core.py"
CORE_FIELD = "_SAW_CORE_EMBEDDED_B64"


def embedded_core(source, field=CORE_FIELD):
    """Inspect embedded source as data; never import or execute installer code."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError) as exc:
        raise SystemExit("rendered apply_bom.py is not valid Python") from exc
    values = [statement.value for statement in tree.body
              if isinstance(statement, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == field
                      for target in statement.targets)]
    if len(values) != 1 or not isinstance(values[0], ast.Constant) or not isinstance(values[0].value, str):
        raise SystemExit("rendered apply_bom.py must contain one literal shared-core embedding")
    encoded = values[0].value
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SystemExit("rendered apply_bom.py shared-core embedding is missing or malformed; render the chart first") from exc
    if not decoded or base64.b64encode(decoded).decode("ascii") != encoded:
        raise SystemExit("rendered apply_bom.py shared-core embedding is empty or noncanonical")
    return decoded


def validate_shared_core(data):
    if "apply_bom.py" not in data:
        raise SystemExit("installer ConfigMap is missing 'apply_bom.py'; cannot build the manifest")
    if "saw_core.py" in data:
        raise SystemExit("installer ConfigMap must embed saw_core.py, not ship an unsigned adjacent module")
    try:
        canonical = CORE_SOURCE.read_bytes()
    except OSError as exc:
        raise SystemExit("canonical saw_core.py is missing; cannot build the manifest") from exc
    if embedded_core(data["apply_bom.py"]) != canonical:
        raise SystemExit("rendered apply_bom.py does not embed the canonical saw_core.py; render the chart again")

    admin_source = CORE_SOURCE.with_name("saw_admin.py")
    if "saw_admin.py" in data:
        raise SystemExit("installer must embed saw_admin.py inside its signed artifact")
    if embedded_core(data["apply_bom.py"], "_SAW_ADMIN_EMBEDDED_B64") != admin_source.read_bytes():
        raise SystemExit("rendered apply_bom.py does not embed canonical saw_admin.py")
    if "saw_ui_limit.py" in data:
        raise SystemExit("installer must embed saw_ui_limit.py inside its signed artifact")
    if embedded_core(data["apply_bom.py"], "_SAW_UI_LIMIT_EMBEDDED_B64") != CORE_SOURCE.with_name("saw_ui_limit.py").read_bytes():
        raise SystemExit("rendered apply_bom.py does not embed canonical saw_ui_limit.py")


def build_manifest(data):
    validate_shared_core(data)
    covered = sorted(
        FIXED_FILES
        + [name for name in data if name.startswith("provider-profile-") and name.endswith(".yaml")]
        + TOOL_GATE_FILES
        + PKI_FILES
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
