"""scripts/oidc-login.sh browser flow against a fake curl and a fake `open`
that plays the browser: it calls the local callback like Keycloak's redirect."""
import base64
import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "oidc-login.sh"

FAKE_CURL = r'''#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
assert "--insecure" not in args
expected_ca = __import__("os").environ.get("OIDC_CA_BUNDLE")
if expected_ca:
    assert args[args.index("--cacert") + 1] == expected_ca
if __import__("os").environ.get("AUTO_CA_PATH"):
    from pathlib import Path
    ca = Path(args[args.index("--cacert") + 1])
    assert "BEGIN CERTIFICATE" in ca.read_text()
    Path(__import__("os").environ["AUTO_CA_PATH"]).write_text(str(ca))
url = next(a for a in args if a.startswith("http"))
if url.endswith("/.well-known/openid-configuration"):
    print(json.dumps({"authorization_endpoint": __import__("os").environ.get("AUTH_URL", "https://kc.example/auth"),
                      "token_endpoint": "https://kc.example/token",
                      "device_authorization_endpoint": "https://kc.example/device"}))
elif url == "https://kc.example/device":
    import os
    if os.environ.get("DEVICE_PKCE"):
        form = dict(args[i + 1].split("=", 1) for i, arg in enumerate(args) if arg == "-d")
        assert form.get("code_challenge_method") == "S256", "Missing PKCE S256"
        open(os.environ["DEVICE_PKCE"], "w").write(form["code_challenge"])
    print(json.dumps({"device_code": "code", "interval": 0,
                      "verification_uri": os.environ.get("DEVICE_URI", "http://kc.example/verify")}))
elif url == "https://kc.example/token":
    import os, base64, hashlib
    if os.environ.get("DEVICE_PKCE"):
        from pathlib import Path
        form = dict(args[i + 1].split("=", 1) for i, arg in enumerate(args) if arg == "-d")
        verifier = form.get("code_verifier", "")
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        assert Path(os.environ["DEVICE_PKCE"]).read_text() == expected
    if os.environ.get("DEVICE_PENDING"):
        from pathlib import Path
        pending = Path(os.environ["TOKEN_REQ"])
        if not pending.exists():
            pending.write_text("pending")
            if "-fsSL" in args:
                sys.exit(22)  # curl --fail discards the OAuth HTTP 400 body
            print(json.dumps({"error": "authorization_pending"}))
            sys.exit(0)
    open(__import__("os").environ["TOKEN_REQ"], "w").write(" ".join(args))
    print(__import__("os").environ["TOKEN_RESPONSE"])
else:
    sys.exit(22)
'''

# Plays the browser: after the listener is up, call the redirect URI with the
# state from the auth URL (or BROWSER_STATE) and a code.
FAKE_OPEN = r'''#!/usr/bin/env python3
import os, sys, time, urllib.parse, urllib.request, urllib.error
q = urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query)
state = os.environ.get("BROWSER_STATE") or q["state"][0]
redirect = q["redirect_uri"][0]
if os.fork():
    sys.exit(0)
devnull = os.open(os.devnull, os.O_RDWR)   # don't hold the test's pipes open
for fd in (0, 1, 2):
    os.dup2(devnull, fd)
for _ in range(50):
    time.sleep(0.1)
    try:
        urllib.request.urlopen(f"{redirect}?code=the-code&state={state}", timeout=2)
        break
    except urllib.error.HTTPError:
        break
    except OSError:
        continue
'''


def jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def env(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("curl", FAKE_CURL), ("open", FAKE_OPEN)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    (bin_dir / "oc").write_text("#!/bin/sh\nexit 1\n")
    (bin_dir / "oc").chmod(0o755)
    port = free_port()
    return {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmp_path),
            "OIDC_ISSUER": "https://kc.example/realms/openshell", "OIDC_CALLBACK_PORT": str(port),
            "OIDC_TOKEN_DIR": str(tmp_path / "oidc"), "TOKEN_REQ": str(tmp_path / "token-req"),
            "TOKEN_RESPONSE": json.dumps({"access_token": jwt({"preferred_username": "alice"}),
                                          "expires_in": 600})}


def login(env, **extra):
    return subprocess.run(["bash", str(SCRIPT), "login"], env={**env, **extra},
                          capture_output=True, text=True, timeout=30)


def test_browser_login_saves_the_token(env, tmp_path):
    r = login(env)
    assert r.returncode == 0, r.stderr
    assert "Logged in as: alice" in r.stdout
    assert json.loads((tmp_path / "oidc" / "token.json").read_text())["issuer_url"] == env["OIDC_ISSUER"]
    req = (tmp_path / "token-req").read_text()
    assert "code=the-code" in req and "code_verifier=" in req


def test_a_callback_from_another_login_is_refused(env, tmp_path):
    """Found live: two `make login` runs; the browser answered the older one,
    whose token exchange then failed with no explanation."""
    r = login(env, BROWSER_STATE="state-of-another-run")
    assert r.returncode == 1
    assert "state mismatch" in r.stderr
    assert not (tmp_path / "token-req").exists()      # no token request with a foreign code
    assert not (tmp_path / "oidc" / "token.json").exists()


def test_a_busy_callback_port_is_reported(env):
    with socket.socket() as s:
        s.bind(("127.0.0.1", int(env["OIDC_CALLBACK_PORT"])))
        s.listen()
        r = login(env, BROWSER_STATE="x")
    assert r.returncode == 1
    assert "cannot listen on localhost" in r.stderr and "another `make login`" in r.stderr


def test_explicit_ca_bundle_with_spaces(env, tmp_path):
    import ssl
    ca = tmp_path / "private CA.pem"
    cert = ssl.create_default_context().get_ca_certs(binary_form=True)[0]
    ca.write_text(ssl.DER_cert_to_PEM_cert(cert))
    r = login(env, OIDC_CA_BUNDLE=str(ca))
    assert r.returncode == 0, r.stdout + r.stderr


def test_missing_ca_bundle_stops_before_sending_a_token(env, tmp_path):
    r = login(env, OIDC_CA_BUNDLE=str(tmp_path / "missing"))
    assert r.returncode != 0
    assert not (tmp_path / "token-req").exists()


def test_login_discovers_ingress_ca_and_removes_temporary_bundle(env, tmp_path):
    import ssl
    cert = ssl.create_default_context().get_ca_certs(binary_form=True)[0]
    ca = ssl.DER_cert_to_PEM_cert(cert)
    oc = tmp_path / "bin" / "oc"
    oc.write_text("#!/usr/bin/env python3\nimport json, sys\n"
                  "if sys.argv[2] == 'ingresses.config.openshift.io':\n"
                  "    print(json.dumps({'spec': {'domain': 'apps.cluster.test'}}))\n"
                  "else:\n"
                  f"    print(json.dumps({{'data': {{'ca-bundle.crt': {ca!r}}}}}))\n")
    selected = tmp_path / "selected-ca"
    r = login(env, OIDC_ISSUER="https://kc.apps.cluster.test/realms/openshell",
              AUTO_CA_PATH=str(selected))
    assert r.returncode == 0, r.stdout + r.stderr
    assert selected.exists()
    assert not Path(selected.read_text()).exists()


@pytest.mark.parametrize("url", ["http://kc.example/auth", "https://user:pass@kc.example/auth"])
def test_browser_refuses_unsafe_authorization_url(env, tmp_path, url):
    result = login(env, AUTH_URL=url)
    assert result.returncode != 0
    assert "HTTPS" in result.stderr
    assert "Opening browser" not in result.stdout
    assert not (tmp_path / "token-req").exists()


def test_device_refuses_http_verification_url(env, tmp_path):
    result = login(env, OIDC_FLOW="device-code")
    assert result.returncode != 0
    assert "HTTPS" in result.stderr
    assert "http://kc.example/verify" not in result.stdout
    assert not (tmp_path / "token-req").exists()


def test_device_poll_waits_for_authorization(env, tmp_path):
    """authorization_pending comes back as HTTP 400; curl --fail would drop it."""
    result = login(env, OIDC_FLOW="device-code", DEVICE_URI="https://kc.example/verify",
                   DEVICE_PENDING="1")
    assert result.returncode == 0, result.stdout + result.stderr


def test_device_pkce_waits_for_authorization(env, tmp_path):
    result = login(env, OIDC_FLOW="device-code", DEVICE_URI="https://kc.example/verify",
                   DEVICE_PKCE=str(tmp_path / "device-challenge"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Logged in as: alice" in result.stdout
    assert (tmp_path / "oidc" / "token.json").exists()
