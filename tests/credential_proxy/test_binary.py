"""Smoke-test the built serve command; Go tests cover fake upstream rewriting."""

import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError
from urllib.request import urlopen

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


REPO = Path(__file__).resolve().parents[2]


def _port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _ca(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "proxy-test-ca")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                       critical=False)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "ca.crt", tmp_path / "ca.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()))
    return cert_path, key_path


def _health(port):
    try:
        with urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
            return response.status
    except HTTPError as exc:
        return exc.code


def test_built_proxy_refuses_unknown_marker_and_unready_secret(tmp_path):
    binary = tmp_path / "saw-credential-proxy"
    subprocess.run([os.environ.get("GO", "go"), "build", "-o", str(binary),
                    "./cmd/saw-credential-proxy"], cwd=REPO / "credential-proxy", check=True)
    cert, key = _ca(tmp_path)
    secrets = tmp_path / "secrets" / "inference"
    secrets.mkdir(parents=True)
    credential = secrets / "api_key"
    credential.write_text("real-test-key", encoding="utf-8")
    (secrets / "provider").write_text("nvidia", encoding="utf-8")
    policy = tmp_path / "config.json"
    policy.write_text(json.dumps({
        "markerPrefix": "saw-cred", "allowHosts": ["api.example.test"],
        "profiles": {"nvidia": ["api.example.test"]},
        "bindings": [{"secret": "inference", "key": "api_key", "providers": ["nvidia"]}],
    }), encoding="utf-8")
    proxy_port, health_port = _port(), _port()
    while health_port == proxy_port:
        health_port = _port()
    env = {**os.environ, "SAW_CONFIG": str(policy),
           "SAW_SECRETS": str(tmp_path / "secrets"),
           "SAW_CA_CERT": str(cert), "SAW_CA_KEY": str(key),
           "SAW_PROXY_ADDR": f"127.0.0.1:{proxy_port}",
           "SAW_HEALTH_ADDR": f"127.0.0.1:{health_port}"}
    process = subprocess.Popen([str(binary), "serve"], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while True:
            if process.poll() is not None:
                raise AssertionError(f"proxy exited: {process.stderr.read().decode()}")
            try:
                if _health(health_port) == 200:
                    break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise AssertionError("proxy health did not become ready")
            time.sleep(0.05)

        with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as raw:
            raw.sendall(b"CONNECT api.example.test:443 HTTP/1.1\r\n"
                        b"Host: api.example.test:443\r\n\r\n")
            response = b""
            while b"\r\n\r\n" not in response:
                response += raw.recv(4096)
            assert response.startswith(b"HTTP/1.1 200")
            context = ssl.create_default_context(cafile=str(cert))
            with context.wrap_socket(raw, server_hostname="api.example.test") as tunnel:
                tunnel.sendall(b"GET /v1 HTTP/1.1\r\nHost: api.example.test\r\n"
                               b"Authorization: Bearer saw-cred.unknown.api_key\r\n"
                               b"Connection: close\r\n\r\n")
                assert tunnel.recv(4096).startswith(b"HTTP/1.1 502")

        credential.unlink()
        assert _health(health_port) == 503
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
