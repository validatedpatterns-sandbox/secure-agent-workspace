"""Gateway CA and admin authority do not persist on the VM disk."""

import os
import subprocess
from pathlib import Path

import pytest

from conftest import CHART


def test_guest_generator_keeps_ca_key_in_runtime_tmpfs(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    config = tmp_path / "etc"
    config.mkdir()
    (config / "server-sans").write_text("gateway.example.test\n")
    (config / "pki-generation").write_text("1\n")
    fake_gateway = tmp_path / "openshell-gateway"
    fake_gateway.write_text('''#!/usr/bin/env python3
import subprocess, sys
from pathlib import Path
args = sys.argv[1:]
assert args[0] == "generate-certs"
out = Path(args[args.index("--output-dir") + 1])
sans = [args[i + 1] for i, arg in enumerate(args) if arg == "--server-san"]
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(out / "ca.key"),
                "-out", str(out / "ca.crt"), "-subj", "/CN=test-ca", "-days", "30"],
               check=True, capture_output=True)
for part in ("server", "client"):
    dest = out / part
    dest.mkdir()
    csr = out / (part + ".csr")
    ext = out / (part + ".ext")
    ext.write_text("subjectAltName=" + ",".join("DNS:" + s for s in sans) + "\\n" if part == "server" else "extendedKeyUsage=clientAuth\\n")
    subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(dest / "tls.key"),
                    "-out", str(csr), "-subj", "/CN=test-" + part], check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(out / "ca.crt"),
                    "-CAkey", str(out / "ca.key"), "-set_serial", "0x123456", "-days", "30",
                    "-extfile", str(ext), "-out", str(dest / "tls.crt")], check=True, capture_output=True)
''')
    fake_gateway.chmod(0o755)
    script = CHART / "files/guest/saw-gateway-pki"
    env = dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR=str(runtime),
               SAW_PKI_TEST_MODE="1", SAW_PKI_CONFIG_DIR=str(config),
               SAW_GATEWAY_BIN=str(fake_gateway))
    subprocess.run(["bash", str(script)], env=env, check=True, capture_output=True)
    tls = home / ".local/state/openshell/tls"
    assert not list(home.rglob("ca.key"))
    assert (tls / "client-ca.pem").read_bytes() == (tls / "ca.crt").read_bytes()
    assert (tls / "relay/tls.key").is_file()
    subject = subprocess.run(["openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253",
                              "-in", str(tls / "relay/tls.crt")], capture_output=True, text=True,
                             check=True).stdout
    assert "OU=openshell-user" in subject and "CN=saw-relay" in subject
    before = (tls / "ca.crt").read_bytes()
    (tls / "client-ca.pem").write_bytes(before + b"stale admin CA\n")
    subprocess.run(["bash", str(script)], env=env, check=True, capture_output=True)
    assert (tls / "ca.crt").read_bytes() == before
    assert (tls / "client-ca.pem").read_bytes() == before
    (config / "pki-generation").write_text("2\n")
    subprocess.run(["bash", str(script)], env=env, check=True, capture_output=True)
    assert (tls / "pki-generation").read_text() == "2\n"
    assert not list(home.rglob("ca.key"))


@pytest.mark.parametrize("raise_inside", [False, True])
def test_admin_session_removes_ca_and_key_even_on_failure(ab, fake_env, raise_inside):
    tls = fake_env.home / ".local/state/openshell/tls"
    ca = (tls / "ca.crt").read_text()
    try:
        with ab.admin_session({}, fake_env.home, None, as_current_user=True) as (admin_tls, config_home):
            assert (tls / "client-ca.pem").read_text().count("BEGIN CERTIFICATE") == 2
            assert (admin_tls / "client/tls.key").is_file()
            assert config_home.is_dir()
            assert "OU=openshell-admin" in subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-nameopt", "sep_multiline",
                 "-in", str(admin_tls / "client/tls.crt")], capture_output=True, text=True,
                check=True).stdout
            if raise_inside:
                raise ValueError("child failed")
    except ValueError:
        assert raise_inside
    assert (tls / "client-ca.pem").read_text() == ca
    assert not admin_tls.parent.exists() and not config_home.exists()
    assert not list(fake_env.home.rglob("ca.key"))


def test_admin_session_cleans_first_directory_if_setup_fails(ab, fake_env, monkeypatch):
    runtime = Path(os.environ["SAW_RUNTIME_DIR"])
    original = ab.tempfile.mkdtemp
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated setup failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(ab.tempfile, "mkdtemp", fail_second)
    with pytest.raises(OSError, match="simulated setup failure"):
        with ab.admin_session({}, fake_env.home, None, as_current_user=True):
            pass
    assert not list(runtime.glob("saw-admin.*"))
    assert not list(fake_env.home.rglob("ca.key"))
