import importlib.util
import json
import stat
import subprocess
import tarfile
from pathlib import Path

from saw_guest import release as guest_release

ROOT = Path(__file__).resolve().parents[2]


def test_release_bundle_context_is_signed_and_digest_pinned(tmp_path):
    private = tmp_path / "signing.key"
    public = tmp_path / "signing.pub"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out = tmp_path / "release"
    result = subprocess.run([
        str(ROOT / ".venv-saw/bin/python"), str(ROOT / "tools/saw/build_release_bundle.py"),
        "--output", str(out), "--name", "test-release", "--installer-bom",
        str(ROOT / "examples/saw/installer-bom.yaml"), "--signing-key", str(private)],
        check=True, capture_output=True, text=True)
    manifest = json.loads((out / "bundle/release.json").read_text())
    assert manifest["name"] == "test-release"
    assert "apply_bom.py" in manifest["files"]
    subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public), "-signature",
                    str(out / "bundle/release.json.sig"), str(out / "bundle/release.json")], check=True,
                   stdout=subprocess.DEVNULL)
    assert "FROM quay.io/opendatahub/odh-openshell-cli@sha256:" in (out / "Dockerfile").read_text()


def test_image_context_does_not_embed_release_installer(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "image_context", ROOT / "tools/saw/build_image_context.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "context"
    module.create_context(output, ROOT / "examples/saw/installer-bom.yaml")
    with tarfile.open(output / "guest.tar.gz") as archive:
        names = set(archive.getnames())
    assert "opt/saw/installer/apply_bom.py" not in names
    assert "opt/saw/guest/saw_guest/release.py" in names
    assert "payload" not in (output / "Dockerfile").read_text()


def test_rootless_bundle_copy_can_write_into_existing_release_stage(tmp_path, monkeypatch):
    destination = tmp_path / "staging"
    destination.mkdir(mode=0o700)
    ownership = []
    original_path = Path

    def mapped_path(value):
        if value == "/var/lib/saw/release-podman":
            return tmp_path / "podman-home"
        if value == "/var/lib/saw/release-podman/runtime":
            return tmp_path / "podman-home" / "runtime"
        return original_path(value)

    def chown(path, uid, gid):
        ownership.append((Path(path), uid, gid))

    def run(args, **kwargs):
        podman_args = args[4:]
        if podman_args[:2] == ["/usr/bin/podman", "cp"]:
            assert stat.S_IMODE(destination.stat().st_mode) == 0o700
            assert ownership[-1] == (destination, 1000, 1000)
            (destination / "release.json").write_text("verified later")
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(guest_release.os, "chown", chown)
    monkeypatch.setattr(guest_release, "Path", mapped_path)
    monkeypatch.setattr(guest_release.subprocess, "run", run)

    guest_release._pull_bundle(
        "ghcr.io/example/saw-installer@sha256:" + "a" * 64,
        destination,
    )

    assert (destination / "release.json").is_file()
    assert ownership[-2:] == [
        (destination / "release.json", 0, 0),
        (destination, 0, 0),
    ]
    assert stat.S_IMODE(destination.stat().st_mode) == 0o755
