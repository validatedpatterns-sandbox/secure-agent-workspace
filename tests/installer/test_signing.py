"""Signature checks: enforce stops before install, warn records unsigned."""

import json
import os
import re
import stat
import subprocess

import pytest


def _installer(ab, tmp_path, mode):
    shell = ab.Shell()
    return ab.ComponentInstaller(shell, tmp_path / "bin", tmp_path / "state" / "installed.json",
                                 signing_mode=mode)


def test_warn_unsigned_image_installs_and_records_unsigned(ab, bom, fake_env, tmp_path):
    fake_env.images_for_bom(bom)
    image = bom["spec"]["openshell"]["gateway"]["image"]
    (fake_env.state / "unsigned.json").write_text(json.dumps([image]))
    bom["spec"]["openshell"]["gateway"]["signature"] = {"keyRef": "openshell"}
    installer = _installer(ab, tmp_path, "warn")
    assert "gateway" in installer.install(bom)
    assert installer.signatures["gateway"] == "unsigned"
    assert (installer.bin_dir / "openshell-gateway").is_file()


def test_enforce_unsigned_image_installs_nothing(ab, bom, fake_env, tmp_path):
    fake_env.images_for_bom(bom)
    image = bom["spec"]["openshell"]["gateway"]["image"]
    (fake_env.state / "unsigned.json").write_text(json.dumps([image]))
    for entry in bom["spec"]["openshell"].values():
        entry["signature"] = {"keyRef": "openshell"}
    installer = _installer(ab, tmp_path, "enforce")
    with pytest.raises(ab.InstallerError, match=f"image {image} is not signed by openshell"):
        installer.install(bom)
    assert not installer.bin_dir.exists() or not any(installer.bin_dir.iterdir())
    assert [c for c in fake_env.podman_calls() if c[0] == "create"] == []


def test_enforce_without_a_signer_fails_before_pull(ab, bom, fake_env, tmp_path):
    fake_env.images_for_bom(bom)
    installer = _installer(ab, tmp_path, "enforce")
    with pytest.raises(ab.InstallerError, match="is not signed by a configured signer"):
        installer.install(bom)
    assert fake_env.podman_calls() == []


def test_verified_signature_is_recorded(ab, bom, fake_env, tmp_path):
    fake_env.images_for_bom(bom)
    bom["spec"]["openshell"]["cli"]["signature"] = {"keyRef": "openshell"}
    installer = _installer(ab, tmp_path, "warn")
    installer.install(bom)
    assert installer.signatures["cli"] == "verified"
    assert installer.signatures["gateway"] == "unsigned"


def test_off_does_not_record_signatures(ab, bom, fake_env, tmp_path):
    fake_env.images_for_bom(bom)
    installer = _installer(ab, tmp_path, "off")
    installer.install(bom)
    assert installer.signatures == {}
    assert all("--signature-policy" not in c for c in fake_env.podman_calls())


def test_enforce_checks_a_signer_regardless_of_registry(ab, bom, fake_env, tmp_path):
    """The per-pull policy is generated per image, not looked up from a
    static, registry-scoped rule: an image outside quay.io/opendatahub with
    a configured signer is checked exactly the same way (PR #54 review, 4).
    """
    image = "example.com/some-other-registry/gateway@sha256:" + "1" * 64
    bom["spec"]["openshell"]["gateway"]["image"] = image
    fake_env.images_for_bom(bom)
    (fake_env.state / "unsigned.json").write_text(json.dumps([image]))
    for entry in bom["spec"]["openshell"].values():
        entry["signature"] = {"keyRef": "openshell"}
    installer = _installer(ab, tmp_path, "enforce")
    with pytest.raises(ab.InstallerError, match=f"image {re.escape(image)} is not signed by openshell"):
        installer.install(bom)


def test_off_to_enforce_re_checks_an_already_installed_component(ab, bom, fake_env, tmp_path):
    """A component installed while signing.mode was off (never checked) must
    not report 'verified' just because its file and digest are unchanged
    once the mode is switched to enforce -- it was never actually checked
    (PR #54 review, 4)."""
    fake_env.images_for_bom(bom)
    for entry in bom["spec"]["openshell"].values():
        entry["signature"] = {"keyRef": "openshell"}
    off_installer = _installer(ab, tmp_path, "off")
    off_installer.install(bom)
    assert off_installer.signatures == {}
    image = bom["spec"]["openshell"]["gateway"]["image"]
    (fake_env.state / "unsigned.json").write_text(json.dumps([image]))
    enforce_installer = _installer(ab, tmp_path, "enforce")
    with pytest.raises(ab.InstallerError, match="image .* is not signed by openshell"):
        enforce_installer.install(bom)


def test_verified_signature_persists_across_reboots_without_re_pulling(ab, bom, fake_env, tmp_path):
    """A component already verified once should not be re-verified (and
    re-pulled) on every later boot just because it is signed."""
    fake_env.images_for_bom(bom)
    for entry in bom["spec"]["openshell"].values():
        entry["signature"] = {"keyRef": "openshell"}
    installer = _installer(ab, tmp_path, "enforce")
    installer.install(bom)
    assert set(installer.signatures.values()) == {"verified"}
    pulls_before = len(fake_env.podman_calls())
    installer2 = _installer(ab, tmp_path, "enforce")
    installer2.install(bom)
    assert set(installer2.signatures.values()) == {"verified"}
    assert len(fake_env.podman_calls()) == pulls_before


def test_golden_image_floor_overrides_an_unsigned_configmap(ab, tmp_path, monkeypatch):
    """config.json ships in the same, unsigned ConfigMap as apply_bom.py.
    A namespace editor setting signing.mode: off there must not be able to
    go below a floor the golden image pins (PR #54 review, 1)."""
    floor = tmp_path / "signing-mode"
    floor.write_text("enforce\n")
    monkeypatch.setattr(ab, "SIGNING_FLOOR_FILE", floor)
    assert ab.effective_signing_mode("off") == "enforce"
    assert ab.effective_signing_mode("warn") == "enforce"
    assert ab.effective_signing_mode("enforce") == "enforce"


def test_floor_can_only_tighten_never_loosen(ab, tmp_path, monkeypatch):
    floor = tmp_path / "signing-mode"
    floor.write_text("warn\n")
    monkeypatch.setattr(ab, "SIGNING_FLOOR_FILE", floor)
    assert ab.effective_signing_mode("off") == "warn"       # tightened
    assert ab.effective_signing_mode("enforce") == "enforce"  # unaffected, already stricter


def test_no_floor_file_means_no_floor(ab, tmp_path, monkeypatch):
    monkeypatch.setattr(ab, "SIGNING_FLOOR_FILE", tmp_path / "does-not-exist")
    assert ab.effective_signing_mode("off") == "off"


def test_load_config_applies_the_floor(ab, tmp_path, monkeypatch):
    floor = tmp_path / "signing-mode"
    floor.write_text("enforce")
    monkeypatch.setattr(ab, "SIGNING_FLOOR_FILE", floor)
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"vmName": "x", "signing": {"mode": "off"}}))
    cfg = ab.load_config(path)
    assert cfg["signing"]["mode"] == "enforce"


def test_verify_bundle_floor_overrides_config_json_off(tmp_path):
    """Same as the Python-side test above, but for the bash verifier: an
    unsigned bundle under a config.json mode: off still fails when the
    golden image pins a floor of enforce."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    script = root / "charts" / "openshell-saw" / "files" / "guest" / "verify-bundle"
    installer = tmp_path / "installer"
    installer.mkdir()
    for name in ("installer-bom.yaml", "apply_bom.py", "setup-dashboard.sh"):
        (installer / name).write_text(name + "\n")
    (installer / "config.json").write_text(json.dumps({"signing": {"mode": "off"}}))
    floor = tmp_path / "signing-mode"
    floor.write_text("enforce\n")
    status = tmp_path / "status.json"
    env = {**os.environ, "SAW_INSTALLER_DIR": str(installer), "SAW_TRUST_DIR": str(tmp_path / "trust"),
           "SAW_STATUS_FILE": str(status), "SAW_STAGE_ROOT": str(tmp_path / "verified"),
           "SAW_SIGNING_FLOOR_FILE": str(floor)}
    result = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
    # The floor makes this enforce, not off: an unsigned bundle fails.
    assert result.returncode == 1, result.stdout + result.stderr
    assert json.loads(status.read_text())["bundle"]["signature"] == "unsigned"


def test_verify_bundle_without_a_floor_file_respects_config_json(tmp_path):
    """No floor file (the common case today) changes nothing: config.json's
    own mode still applies."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    script = root / "charts" / "openshell-saw" / "files" / "guest" / "verify-bundle"
    installer = tmp_path / "installer"
    installer.mkdir()
    for name in ("installer-bom.yaml", "apply_bom.py", "setup-dashboard.sh"):
        (installer / name).write_text(name + "\n")
    (installer / "config.json").write_text(json.dumps({"signing": {"mode": "off"}}))
    status = tmp_path / "status.json"
    env = {**os.environ, "SAW_INSTALLER_DIR": str(installer), "SAW_TRUST_DIR": str(tmp_path / "trust"),
           "SAW_STATUS_FILE": str(status), "SAW_STAGE_ROOT": str(tmp_path / "verified"),
           "SAW_SIGNING_FLOOR_FILE": str(tmp_path / "no-such-file")}
    result = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(status.read_text())["bundle"]["signature"] == "off"


@pytest.mark.parametrize("signature, message", [
    ({"keyRef": "openshell", "identity": "https://example.com/id", "issuer": "https://example.com"},
     "not both"),
    ({}, "keyRef or both"),
    ({"keyRef": "../keys"}, "keyRef"),
    ({"identity": "https://example.com/id"}, "https URLs"),
    ({"issuer": "not-a-url", "identity": "also-not"}, "https URLs"),
])
def test_signature_shape_is_rejected(ab, bom, signature, message):
    bom["spec"]["openshell"]["cli"]["signature"] = signature
    with pytest.raises(ab.InstallerError, match=message):
        ab.validate_bom(bom)


def test_signature_policy_for_keyref(ab, tmp_path):
    installer = ab.ComponentInstaller(ab.Shell(), tmp_path / "bin", tmp_path / "state.json",
                                      trust_dir="/etc/saw/trust")
    policy = installer._signature_policy({"keyRef": "openshell"})
    assert policy == {"default": [{"type": "sigstoreSigned",
                                   "keyPath": "/etc/saw/trust/openshell.pub",
                                   "signedIdentity": {"type": "matchRepository"}}]}


def test_keyless_signature_policy_always_rejects(ab, tmp_path):
    """podman's policy.json can only match a Fulcio identity by an exact
    fulcio.subjectEmail. _validate_signature requires `identity` to be an
    https:// URI (the docs' own GitHub-Actions-workflow-ref example), so no
    identity that ever passes BOM validation can be email-shaped -- there
    is no field to check it against. Checking oidcIssuer alone would accept
    any signer from that issuer: with
    https://token.actions.githubusercontent.com, that is any GitHub Actions
    workflow anywhere. Reject rather than silently enforce less than the
    BOM asked for (PR #54 review round 2, 2)."""
    installer = ab.ComponentInstaller(ab.Shell(), tmp_path / "bin", tmp_path / "state.json")
    workflow_ref = installer._signature_policy({
        "identity": "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1",
        "issuer": "https://token.actions.githubusercontent.com"})
    assert workflow_ref == {"default": [{"type": "reject"}]}
    # Even an email-shaped identity is rejected: _validate_signature never
    # lets one reach here (identity must start with https://), and this
    # function does not special-case one either -- there is exactly one
    # policy for every keyless signature today.
    email_shaped = installer._signature_policy({
        "identity": "release@example.com",
        "issuer": "https://token.actions.githubusercontent.com"})
    assert email_shaped == {"default": [{"type": "reject"}]}


def test_signature_policy_rejects_by_default_with_no_signer(ab, tmp_path):
    installer = ab.ComponentInstaller(ab.Shell(), tmp_path / "bin", tmp_path / "state.json")
    assert installer._signature_policy(None) == {"default": [{"type": "reject"}]}


def test_keyless_signature_shape_is_accepted_but_never_verifies(ab, bom, fake_env, tmp_path):
    """The BOM schema still accepts identity/issuer as a valid shape (the
    docs document it), but a component configured this way can never pass
    verification today -- _signature_policy always returns reject for it.
    A real signer here would still (correctly) fail under enforce."""
    bom["spec"]["openshell"]["cli"]["signature"] = {
        "identity": "https://github.com/example/openshell/.github/workflows/release.yml@refs/tags/v1",
        "issuer": "https://token.actions.githubusercontent.com",
    }
    ab.validate_bom(bom)  # shape is valid
    fake_env.images_for_bom(bom)
    installer = ab.ComponentInstaller(ab.Shell(), tmp_path / "bin", tmp_path / "state" / "installed.json",
                                      signing_mode="enforce")
    with pytest.raises(ab.InstallerError, match="is not signed by"):
        installer.install(bom)


def test_verify_bundle_warn_allows_unsigned_and_enforce_stops(tmp_path):
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    script = root / "charts" / "openshell-saw" / "files" / "guest" / "verify-bundle"
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    installer = tmp_path / "installer"
    installer.mkdir()
    for name in ("installer-bom.yaml", "apply_bom.py", "setup-dashboard.sh"):
        (installer / name).write_text(name + "\n")
    status = tmp_path / "status.json"
    staged = tmp_path / "verified" / "installer"
    env = {**os.environ, "SAW_INSTALLER_DIR": str(installer), "SAW_TRUST_DIR": str(tmp_path / "trust"),
           "SAW_STATUS_FILE": str(status), "SAW_STAGE_ROOT": str(tmp_path / "verified")}

    def run(mode):
        (installer / "config.json").write_text(json.dumps({"signing": {"mode": mode}}))
        return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)

    warned = run("warn")
    assert warned.returncode == 0, warned.stdout + warned.stderr
    assert "unsigned" in warned.stderr
    assert json.loads(status.read_text())["bundle"]["signature"] == "unsigned"
    # warn still publishes the staged, executable copy apply_bom.py runs from.
    assert (staged / "apply_bom.py").read_text() == "apply_bom.py\n"
    enforced = run("enforce")
    assert enforced.returncode == 1
    assert json.loads(status.read_text())["bundle"]["signature"] == "unsigned"
    # enforce refused to publish; the prior (warn-published) revision is
    # untouched, so apply_bom.py would still run from that known copy.
    assert (staged / "apply_bom.py").read_text() == "apply_bom.py\n"


def _manifest_text(directory, names):
    """Same format as verify-bundle's manifest_text(): sorted '<sha256>  <name>' lines."""
    import hashlib
    from pathlib import Path
    lines = []
    for name in sorted(names):
        digest = hashlib.sha256((Path(directory) / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}\n")
    return "".join(lines)


def test_identity_inputs_are_covered_by_signed_manifest():
    """A signed installer must cover the identity script and SELinux module."""
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        "build_installer_manifest", root / "scripts" / "build-installer-manifest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    data = {
        "installer-bom.yaml": "bom", "apply_bom.py": "installer",
        "setup-dashboard.sh": "dashboard", "identity.py": "identity",
        "saw_spire.pp.b64": "policy",
    }
    manifest = module.build_manifest(data)
    assert "  identity.py\n" in manifest
    assert "  saw_spire.pp.b64\n" in manifest
    data["identity.py"] = "tampered"
    assert module.build_manifest(data) != manifest


@pytest.mark.parametrize("edited", ("apply_bom.py", "identity.py", "saw_spire.pp.b64"))
def test_edited_bundle_fails_enforce_and_warns(tmp_path, edited):
    """Tampering with installer or identity inputs invalidates the signed bundle."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    script = root / "charts" / "openshell-saw" / "files" / "guest" / "verify-bundle"
    installer = tmp_path / "installer"
    installer.mkdir()
    covered = ("installer-bom.yaml", "apply_bom.py", "setup-dashboard.sh",
               "identity.py", "saw_spire.pp.b64")
    for name in covered:
        (installer / name).write_text(name + "\n")
    trust = tmp_path / "trust"
    trust.mkdir()
    key = trust / "test.key"
    pub = trust / "test.pub"
    subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-out", str(key)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], check=True, capture_output=True)
    payload = tmp_path / "payload"
    payload.write_text(_manifest_text(installer, covered))
    bundle = installer / "bundle.sigstore.json"
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(bundle), str(payload)],
                   check=True, capture_output=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "cosign").write_text(
        "#!/bin/bash\n"
        "key= bundle= prev=\n"
        "for a in \"$@\"; do\n"
        "  [[ \"$prev\" == --key ]] && key=$a\n"
        "  [[ \"$prev\" == --bundle ]] && bundle=$a\n"
        "  prev=$a\n"
        "done\n"
        "payload=${@: -1}\n"
        "exec openssl dgst -sha256 -verify \"$key\" -signature \"$bundle\" \"$payload\"\n")
    (bindir / "cosign").chmod(0o755)
    installed = tmp_path / "openshell"
    installed.write_text("old-binary\n")
    status = tmp_path / "status.json"
    staged_apply_bom = tmp_path / "verified" / "installer" / "apply_bom.py"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
           "SAW_INSTALLER_DIR": str(installer), "SAW_TRUST_DIR": str(trust),
           "SAW_STATUS_FILE": str(status), "SAW_STAGE_ROOT": str(tmp_path / "verified")}

    def run(mode):
        (installer / "config.json").write_text(json.dumps({"signing": {"mode": mode}}))
        return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)

    assert run("enforce").returncode == 0
    assert json.loads(status.read_text())["bundle"]["signature"] == "verified"
    assert staged_apply_bom.read_text() == "apply_bom.py\n"
    (installer / edited).write_text("tampered\n")
    enforced = run("enforce")
    assert enforced.returncode == 1
    assert json.loads(status.read_text())["bundle"]["signature"] == "failed"
    # The core point of the fix: apply_bom.py is executed from the staged
    # copy, never the live ConfigMap. A tampered edit that fails enforce
    # must never reach that staged copy, or the "old binaries keep running"
    # guarantee would be worthless (PR #54 review, 2).
    assert staged_apply_bom.read_text() == "apply_bom.py\n"
    warned = run("warn")
    assert warned.returncode == 0
    assert json.loads(status.read_text())["bundle"]["signature"] == "failed"
    assert installed.read_text() == "old-binary\n"
    # warn does publish a failed bundle, so the edited file takes effect
    # (matches the documented "warn logs ... and continues"). Other covered
    # files stay as they were.
    assert (tmp_path / "verified" / "installer" / edited).read_text() == "tampered\n"
    if edited != "apply_bom.py":
        assert staged_apply_bom.read_text() == "apply_bom.py\n"


def test_a_byte_shifted_between_files_is_rejected(tmp_path):
    """A raw concatenation of the three files left their boundary ambiguous:
    moving bytes from the end of one file to the start of the next kept the
    concatenated payload, and so the signature, unchanged. The manifest
    signs each file's hash independently, so the same boundary shift now
    changes two lines and is caught (PR #54 review, 3)."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    script = root / "charts" / "openshell-saw" / "files" / "guest" / "verify-bundle"
    installer = tmp_path / "installer"
    installer.mkdir()
    (installer / "installer-bom.yaml").write_text("AAAA")
    (installer / "apply_bom.py").write_text("BBBB")
    (installer / "setup-dashboard.sh").write_text("CCCC")
    trust = tmp_path / "trust"
    trust.mkdir()
    key, pub = trust / "test.key", trust / "test.pub"
    subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-out", str(key)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)],
                   check=True, capture_output=True)
    payload = tmp_path / "payload"
    payload.write_text(_manifest_text(installer, ("installer-bom.yaml", "apply_bom.py", "setup-dashboard.sh")))
    bundle = installer / "bundle.sigstore.json"
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(bundle), str(payload)],
                   check=True, capture_output=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "cosign").write_text(
        "#!/bin/bash\n"
        "key= bundle= prev=\n"
        "for a in \"$@\"; do\n"
        "  [[ \"$prev\" == --key ]] && key=$a\n"
        "  [[ \"$prev\" == --bundle ]] && bundle=$a\n"
        "  prev=$a\n"
        "done\n"
        "payload=${@: -1}\n"
        "exec openssl dgst -sha256 -verify \"$key\" -signature \"$bundle\" \"$payload\"\n")
    (bindir / "cosign").chmod(0o755)
    status = tmp_path / "status.json"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
           "SAW_INSTALLER_DIR": str(installer), "SAW_TRUST_DIR": str(trust),
           "SAW_STATUS_FILE": str(status), "SAW_STAGE_ROOT": str(tmp_path / "verified")}

    def run():
        (installer / "config.json").write_text(json.dumps({"signing": {"mode": "enforce"}}))
        return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)

    assert run().returncode == 0
    assert json.loads(status.read_text())["bundle"]["signature"] == "verified"
    # Move one byte from the end of apply_bom.py's old content to the end of
    # installer-bom.yaml's: the three-file concatenation is byte-for-byte
    # the same as before ("AAAA"+"BBBB"+"CCCC" == "AAAAB"+"BBB"+"CCCC");
    # each file's own content, and so the manifest, is not.
    before = "".join((installer / n).read_text() for n in
                     ("installer-bom.yaml", "apply_bom.py", "setup-dashboard.sh"))
    (installer / "installer-bom.yaml").write_text("AAAAB")
    (installer / "apply_bom.py").write_text("BBB")
    after = "".join((installer / n).read_text() for n in
                    ("installer-bom.yaml", "apply_bom.py", "setup-dashboard.sh"))
    assert before == after, "the concatenation must be unchanged for this to test anything"
    tampered = run()
    assert tampered.returncode == 1
    assert json.loads(status.read_text())["bundle"]["signature"] == "failed"


def test_unit_runs_verifier_before_apply_bom():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    unit = (root / "charts" / "openshell-saw" / "files" / "guest" / "saw-install.service").read_text()
    pre = [line for line in unit.splitlines() if line.startswith("ExecStartPre=")]
    start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
    # saw-stage-installer runs verify-bundle when the golden image has it,
    # and always publishes the staged copy apply_bom.py runs from -- both
    # install and apply used to trust the live mount directly (PR #54
    # review, 2).
    assert any("saw-stage-installer" in line for line in pre)
    assert pre.index(next(line for line in pre if "saw-stage-installer" in line)) < len(pre)
    assert unit.index("saw-stage-installer") < unit.index(start)
    assert "/var/lib/saw/verified/installer/apply_bom.py" in start
    stager = (root / "charts" / "openshell-saw" / "files" / "guest" / "saw-stage-installer").read_text()
    assert "verify-bundle" in stager
    assert "apply_bom.py install" in start
