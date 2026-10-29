"""The live root scan must find credentials without reading special files."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "scripts/scan-guest-credentials.py"
spec = importlib.util.spec_from_file_location("guest_scan", SOURCE)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


def test_finds_credentials_across_read_boundaries_and_ca_keys(tmp_path):
    (tmp_path / "ordinary").write_bytes(b"safe")
    target = tmp_path / "credential"
    target.write_bytes(b"x" * (1024 * 1024 - 3) + b"test-key-123" + b"tail")
    ca_key = tmp_path / "ca.key"
    ca_key.write_bytes(b"private signing material")
    assert scan.credential_hits(b"test-key-123", str(tmp_path)) == sorted([str(target), str(ca_key)])


def test_skips_live_control_fifos_and_symlinks(tmp_path):
    os.mkfifo(tmp_path / "podman-ctl")
    (tmp_path / "fifo-link").symlink_to(tmp_path / "podman-ctl")
    result = subprocess.run(
        [sys.executable, "-c", SOURCE.read_text() +
         "\nimport sys; assert credential_hits(b'absent-key', sys.argv[1]) == []", str(tmp_path)],
        capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr


def test_key_blind_digests_find_a_token_across_the_chunk_boundary(tmp_path):
    import hashlib
    key = b"nvapi-" + b"credential1234567890" * 3
    (tmp_path / "boundary").write_bytes(b" " * (1024 * 1024 - 12) + key + b"\n")
    os.mkfifo(tmp_path / "fifo")
    (tmp_path / "link").symlink_to(tmp_path / "fifo")
    digests = scan.token_digests(str(tmp_path))
    assert hashlib.sha256(key).digest()[:8] in digests
    assert all(len(digest) == 8 for digest in digests)


def test_key_blind_ca_filename_check(tmp_path):
    (tmp_path / "ca.key").touch()
    assert scan.ca_key_files(str(tmp_path)) == [str(tmp_path / "ca.key")]


def test_live_scan_never_transmits_a_provider_needle_to_the_vm():
    script = (SOURCE.parents[1] / "tests/test-credential-isolation.sh").read_text()
    assert 'base64 -d | vm_exec' not in script
    assert 'needle = sys.stdin' not in script
    assert 'vm_exec "$remote" </dev/null' in script
    assert 'hashlib.sha256(part).digest()[:8]' in script
    assert 'key = key.strip()' in script


def test_google_material_components_are_in_the_key_blind_scan(tmp_path):
    import hashlib
    import re
    material = [b"123456789012-private-client-identifier.apps.googleusercontent.com",
                b"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7890", b"1//private-refresh-token-12345678901234567890"]
    (tmp_path / "leaked-material").write_bytes(b"\n".join(material))
    digests = scan.token_digests(str(tmp_path))
    for value in material:
        parts = re.findall(rb"[A-Za-z0-9_-]{20,512}", value)
        assert parts and all(hashlib.sha256(part).digest()[:8] in digests for part in parts)
