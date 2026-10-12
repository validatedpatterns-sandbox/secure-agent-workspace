"""scripts/check-oidc-ca.sh: does this cluster need oidc.caBundle, before install."""
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-oidc-ca.sh"
PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def run(tmp_path, custom_cert="", curl_rc=0, curl_err=""):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "oc").write_text(f"""#!/bin/sh
case "$*" in
  whoami*) echo admin ;;
  *ingresses.config*) printf apps.example.com ;;
  *ingresscontroller*) printf '{custom_cert}' ;;
  *default-ingress-cert*) printf '%s' '{PEM}' ;;
esac
""")
    (bin_dir / "curl").write_text(f"#!/bin/sh\necho '{curl_err}' >&2\nexit {curl_rc}\n")
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "CA_OUT": str(tmp_path / "ca.pem")}
    return subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, env=env, cwd=tmp_path)


def test_the_self_signed_default_is_handled_by_the_pattern_not_the_quickstart(tmp_path):
    r = run(tmp_path)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "self-signed default" in r.stdout
    assert "Validated pattern (./pattern.sh make install): nothing to do" in r.stdout
    assert (tmp_path / "ca.pem").read_text().startswith("-----BEGIN CERTIFICATE-----")
    assert "caBundle: |" in r.stdout and "            -----BEGIN CERTIFICATE-----" in r.stdout
    assert "overrides/saw-users.yaml" in r.stdout


def test_a_publicly_trusted_custom_certificate_needs_nothing(tmp_path):
    r = run(tmp_path, custom_cert="letsencrypt-apps")
    assert r.returncode == 0 and "Nothing to do" in r.stdout
    assert not (tmp_path / "ca.pem").exists()


def test_a_private_custom_certificate_needs_the_ca(tmp_path):
    r = run(tmp_path, custom_cert="corp-apps", curl_rc=60,
            curl_err="curl: (60) SSL certificate problem: unable to get local issuer certificate")
    assert r.returncode == 3 and "does not verify against public CAs" in r.stdout


def test_unreachable_routes_are_not_a_verdict(tmp_path):
    r = run(tmp_path, custom_cert="corp-apps", curl_rc=6, curl_err="curl: (6) Could not resolve host")
    assert r.returncode == 1 and "Could not reach" in r.stdout


def test_an_external_issuer_with_a_private_ca_needs_the_bundle(tmp_path):
    bin_dir = tmp_path / "bin"
    r = run(tmp_path, curl_rc=60, curl_err="curl: (60) SSL certificate problem: self-signed certificate")
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "ISSUER": "https://sso.corp/realms/x"}
    r = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, env=env, cwd=tmp_path)
    assert r.returncode == 2 and "Set oidc.caBundle" in r.stdout
