"""Private-CA HTTPS fixture shared by the Keycloak integration tests."""
import ssl
import subprocess

import pytest


@pytest.fixture(scope="session")
def keycloak_tls(tmp_path_factory):
    directory = tmp_path_factory.mktemp("keycloak-tls")
    ca, key = directory / "ca.pem", directory / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=Keycloak test CA", "-keyout", str(key), "-out", str(ca),
        "-addext", "subjectAltName=IP:127.0.0.1",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
        "-addext", "extendedKeyUsage=serverAuth",
    ], check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca, key)
    return context, ca
