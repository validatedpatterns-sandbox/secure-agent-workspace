"""Embedded core stays inside the existing signed/staged installer artifact.

No installer code is imported by the signing tool. The legacy manifest format
is deliberately independent here: old golden-image verifiers must cover exactly
the same bytes without acquiring a new module or a new verifier.
"""

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts/openshell-saw"
CORE = CHART / "files/installer/saw_core.py"
APPLY = CHART / "files/installer/apply_bom.py"
HELM = shutil.which("helm")
MARKER = '_SAW_CORE_EMBEDDED_B64 = "__SAW_CORE_SOURCE_BASE64__"'
LEGACY_FIXED = ("installer-bom.yaml", "apply_bom.py", "setup-dashboard.sh",
                "tool-actions.yaml", "tool-gate.mjs", "tool-gate-plugin.mjs",
                "saw-gateway-pki", "openshell-gateway-pki.conf")


@pytest.fixture(scope="module")
def signer():
    spec = importlib.util.spec_from_file_location("shared_core_manifest", ROOT / "scripts/build-installer-manifest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def helm_template(chart=CHART):
    return subprocess.run([
        HELM, "template", "saw-test", str(chart), "--namespace", "saw-test",
        "-f", str(ROOT / "tests/fixtures/saw-network-topology.yaml"),
        "-f", str(ROOT / "tests/fixtures/credential-proxy-values.yaml"),
        "--set", "sandboxName=saw-test",
    ], capture_output=True, text=True)


@pytest.fixture(scope="module")
def rendered_data():
    if not HELM:
        pytest.skip("helm is not installed")
    result = helm_template()
    assert result.returncode == 0, result.stderr
    return next(doc["data"] for doc in yaml.safe_load_all(result.stdout)
                if doc and doc["kind"] == "ConfigMap" and doc["metadata"]["name"] == "saw-test-installer")


def replace_core(source, data):
    encoded = base64.b64encode(data).decode("ascii")
    result, count = re.subn(r'^_SAW_CORE_EMBEDDED_B64 = .*$',
                           lambda _: f'_SAW_CORE_EMBEDDED_B64 = "{encoded}"', source, flags=re.MULTILINE)
    assert count == 1
    return result


def legacy_manifest(data):
    names = sorted((*LEGACY_FIXED, *(name for name in data
                   if name.startswith("provider-profile-") and name.endswith(".yaml"))))
    return "".join(f'{hashlib.sha256(data[name].encode("utf-8")).hexdigest()}  {name}\n'
                   for name in names)


def run_file(path, *, cwd=None, pythonpath=None):
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    if pythonpath is not None:
        env["PYTHONPATH"] = str(pythonpath)
    return subprocess.run([sys.executable, str(path), "--help"], cwd=cwd, env=env,
                          capture_output=True, text=True)


def test_render_embeds_exact_canonical_bytes_and_preserves_legacy_manifest(rendered_data, signer):
    assert "saw_ui_limit.py" not in rendered_data
    assert signer.embedded_core(rendered_data["apply_bom.py"], "_SAW_UI_LIMIT_EMBEDDED_B64") == CORE.with_name("saw_ui_limit.py").read_bytes()
    assert "saw_admin.py" not in rendered_data
    assert signer.embedded_core(rendered_data["apply_bom.py"], "_SAW_ADMIN_EMBEDDED_B64") == CORE.with_name("saw_admin.py").read_bytes()
    assert "saw_core.py" not in rendered_data
    assert MARKER not in rendered_data["apply_bom.py"]
    assert signer.embedded_core(rendered_data["apply_bom.py"]) == CORE.read_bytes()
    assert signer.build_manifest(rendered_data) == legacy_manifest(rendered_data)
    assert set(signer.FIXED_FILES + signer.TOOL_GATE_FILES + signer.PKI_FILES) == set(LEGACY_FIXED)


@pytest.mark.parametrize("change", ["missing", "duplicate"])
def test_chart_refuses_missing_or_duplicate_loader_marker(tmp_path, change):
    if not HELM:
        pytest.skip("helm is not installed")
    chart = tmp_path / "chart"
    shutil.copytree(CHART, chart)
    path = chart / "files/installer/apply_bom.py"
    source = path.read_text()
    path.write_text(source.replace(MARKER, "" if change == "missing" else MARKER + "\n" + MARKER))
    result = helm_template(chart)
    assert result.returncode != 0
    assert "exactly one shared-core embedding marker" in result.stderr


def test_chart_refuses_missing_canonical_core(tmp_path):
    if not HELM:
        pytest.skip("helm is not installed")
    chart = tmp_path / "chart"
    shutil.copytree(CHART, chart)
    (chart / "files/installer/saw_core.py").unlink()
    result = helm_template(chart)
    assert result.returncode != 0
    assert "canonical files/installer/saw_core.py is required" in result.stderr


@pytest.mark.parametrize("source", [
    "print('no embedded core')\n",
    MARKER + "\n",
    '_SAW_CORE_EMBEDDED_B64 = ""\n',
    '_SAW_CORE_EMBEDDED_B64 = "%%%"\n',
    '_SAW_CORE_EMBEDDED_B64 = "YWJj"\n_SAW_CORE_EMBEDDED_B64 = "YWJj"\n',
    '_SAW_CORE_EMBEDDED_B64 = __import__("saw_core").source\n',
])
def test_signer_refuses_unrendered_missing_or_malformed_core(rendered_data, signer, source):
    data = {**rendered_data, "apply_bom.py": source}
    with pytest.raises(SystemExit, match="shared-core|embedding"):
        signer.build_manifest(data)


def test_signer_refuses_noncanonical_core_and_unsigned_adjacent_module(rendered_data, signer):
    data = {**rendered_data, "apply_bom.py": replace_core(rendered_data["apply_bom.py"], CORE.read_bytes() + b"\n# drift\n")}
    with pytest.raises(SystemExit, match="canonical saw_core.py"):
        signer.build_manifest(data)
    with pytest.raises(SystemExit, match="unsigned adjacent module"):
        signer.build_manifest({**rendered_data, "saw_core.py": CORE.read_text()})


def test_signer_never_executes_installer_or_core_code(rendered_data, signer, tmp_path):
    witness = tmp_path / "must-not-exist"
    source = rendered_data["apply_bom.py"] + f'\nopen({str(witness)!r}, "w").write("executed")\n'
    signer.build_manifest({**rendered_data, "apply_bom.py": source})
    assert not witness.exists()


def test_embedded_installer_and_runtime_copy_ignore_adjacent_and_pythonpath_core(rendered_data, tmp_path):
    witness = tmp_path / "untrusted-import"
    hostile = f'open({str(witness)!r}, "w").write("imported")\nraise RuntimeError("untrusted core")\n'
    live, staged, user, cwd = (tmp_path / name for name in ("live", "verified", "runtime-user", "cwd"))
    for directory in (live, staged, user, cwd):
        directory.mkdir()
        (directory / "saw_core.py").write_text(hostile)
        (directory / "saw_admin.py").write_text(hostile)
        (directory / "saw_ui_limit.py").write_text(hostile)
    (live / "apply_bom.py").write_text(rendered_data["apply_bom.py"])
    # Golden-image staging and cmd_apply both copy the same complete artifact.
    shutil.copyfile(live / "apply_bom.py", staged / "apply_bom.py")
    shutil.copyfile(staged / "apply_bom.py", user / "apply_bom.py")
    for directory in (live, staged, user):
        result = run_file(directory / "apply_bom.py", cwd=cwd, pythonpath=cwd)
        assert result.returncode == 0, result.stderr
        assert "apply-profiles" in result.stdout
    assert not witness.exists()
    (user / "saw_core.py").unlink()
    assert run_file(user / "apply_bom.py", cwd=cwd, pythonpath=cwd).returncode == 0


@pytest.mark.parametrize("replacement", ["", '_SAW_CORE_EMBEDDED_B64 = "%%%"', '_SAW_CORE_EMBEDDED_B64 = ""'])
def test_missing_or_broken_embedded_payload_never_falls_back_to_adjacent_core(rendered_data, tmp_path, replacement):
    witness = tmp_path / "untrusted-import"
    (tmp_path / "saw_core.py").write_text(f'open({str(witness)!r}, "w").write("imported")\n')
    source = re.sub(r'^_SAW_CORE_EMBEDDED_B64 = .*$', lambda _: replacement,
                    rendered_data["apply_bom.py"], flags=re.MULTILINE)
    path = tmp_path / "apply_bom.py"
    path.write_text(source)
    assert run_file(path).returncode != 0
    assert not witness.exists()


def test_raw_source_with_missing_sibling_never_uses_cwd_or_pythonpath_core(tmp_path):
    source, cwd = tmp_path / "source", tmp_path / "cwd"
    source.mkdir()
    cwd.mkdir()
    shutil.copyfile(APPLY, source / "apply_bom.py")
    witness = tmp_path / "untrusted-import"
    (cwd / "saw_core.py").write_text(f'open({str(witness)!r}, "w").write("imported")\n')
    result = run_file(source / "apply_bom.py", cwd=cwd, pythonpath=cwd)
    assert result.returncode != 0
    assert not witness.exists()


@pytest.mark.skipif(not shutil.which("openssl"), reason="OpenSSL is required for signature test")
def test_legacy_signature_covers_embedded_core_bytes(rendered_data, tmp_path):
    key, pub, payload, signature = (tmp_path / name for name in ("key.pem", "pub.pem", "manifest", "signature"))
    subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-out", str(key)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], check=True, capture_output=True)
    payload.write_text(legacy_manifest(rendered_data))
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(signature), str(payload)],
                   check=True, capture_output=True)
    verify = ["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(signature), str(payload)]
    assert subprocess.run(verify, capture_output=True).returncode == 0
    changed = copy.deepcopy(rendered_data)
    changed["apply_bom.py"] = replace_core(changed["apply_bom.py"], CORE.read_bytes() + b"\n# modified core\n")
    payload.write_text(legacy_manifest(changed))
    assert subprocess.run(verify, capture_output=True).returncode != 0


@pytest.mark.skipif(sys.platform != "linux", reason="golden-image stager uses Linux tools")
def test_golden_verifier_stages_embedded_core_and_refuses_tampering(rendered_data, tmp_path):
    """Exercise the real shell verifier using the suite's OpenSSL cosign shim."""
    installer, trust, bindir = (tmp_path / name for name in ("installer", "trust", "bin"))
    for path in (installer, trust, bindir):
        path.mkdir()
    for name, content in rendered_data.items():
        (installer / name).write_text(content)
    (installer / "config.json").write_text(json.dumps({"signing": {"mode": "enforce"}}))
    witness = tmp_path / "untrusted-import"
    # An old verifier ignores this extra file. Signed embedded code must also
    # ignore it, including after staging and before apply-profiles handoff.
    (installer / "saw_core.py").write_text(f'open({str(witness)!r}, "w").write("imported")\n')
    key, pub = trust / "test.key", trust / "test.pub"
    subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-out", str(key)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], check=True, capture_output=True)
    payload = tmp_path / "manifest"
    payload.write_text(legacy_manifest(rendered_data))
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key), "-out",
                    str(installer / "bundle.sigstore.json"), str(payload)], check=True, capture_output=True)
    cosign = bindir / "cosign"
    cosign.write_text(
        '#!/bin/bash\nkey= bundle= previous=\n'
        'for arg in "$@"; do\n'
        '  [[ "$previous" == --key ]] && key=$arg\n'
        '  [[ "$previous" == --bundle ]] && bundle=$arg\n'
        '  previous=$arg\ndone\n'
        'payload=${@: -1}\n'
        'exec openssl dgst -sha256 -verify "$key" -signature "$bundle" "$payload"\n')
    cosign.chmod(0o755)
    status = tmp_path / "status.json"
    stage = tmp_path / "verified"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
           "SAW_INSTALLER_DIR": str(installer), "SAW_TRUST_DIR": str(trust),
           "SAW_STATUS_FILE": str(status), "SAW_STAGE_ROOT": str(stage),
           "SAW_SIGNING_FLOOR_FILE": str(tmp_path / "no-floor"), "SAW_TRUST_KEYS": "test"}
    command = ["bash", str(CHART / "files/guest/verify-bundle")]
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(status.read_text())["bundle"]["signature"] == "verified"
    staged_apply = stage / "installer/apply_bom.py"
    assert staged_apply.read_text() == rendered_data["apply_bom.py"]
    assert run_file(staged_apply).returncode == 0
    assert not witness.exists()
    (installer / "apply_bom.py").write_text(replace_core(
        rendered_data["apply_bom.py"], CORE.read_bytes() + f'\nopen({str(witness)!r}, "w").write("tampered")\n'.encode()))
    rejected = subprocess.run(command, env=env, capture_output=True, text=True)
    assert rejected.returncode == 1
    assert json.loads(status.read_text())["bundle"]["signature"] == "failed"
    assert staged_apply.read_text() == rendered_data["apply_bom.py"]
    assert run_file(staged_apply).returncode == 0
    assert not witness.exists()


@pytest.mark.parametrize("name", ["admin", "ui_limit"])
def test_shared_admin_tampering_and_unsigned_module_rejected(rendered_data, signer, name):
    filename = "saw_" + name + ".py"
    field = "_SAW_" + name.upper() + "_EMBEDDED_B64"
    changed = base64.b64encode(CORE.with_name(filename).read_bytes() + b"\n# drift\n").decode()
    source = re.sub(r'^' + field + r' = .*$',
                    lambda _: field + ' = "' + changed + '"',
                    rendered_data["apply_bom.py"], flags=re.MULTILINE)
    with pytest.raises(SystemExit, match="canonical " + filename):
        signer.build_manifest({**rendered_data, "apply_bom.py": source})
    with pytest.raises(SystemExit, match="signed artifact"):
        signer.build_manifest({**rendered_data, filename: "foreign"})
