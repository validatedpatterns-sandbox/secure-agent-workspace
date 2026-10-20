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
url = next(a for a in args if a.startswith("http"))
if url.endswith("/.well-known/openid-configuration"):
    print(json.dumps({"authorization_endpoint": "https://kc.example/auth",
                      "token_endpoint": "https://kc.example/token"}))
elif url == "https://kc.example/token":
    open(__import__("os").environ["TOKEN_REQ"], "w").write(" ".join(args))
    if "--data-binary" in args:
        open(__import__("os").environ["TOKEN_REQ"] + ".body", "w").write(sys.stdin.read())
    if __import__("os").environ.get("TOKEN_HTTP_ERROR"):
        sys.exit(22)
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
    return {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmp_path),
            "OIDC_ISSUER": "https://kc.example/realms/openshell",
            "OIDC_TOKEN_DIR": str(tmp_path / "oidc"), "TOKEN_REQ": str(tmp_path / "token-req"),
            "TOKEN_RESPONSE": json.dumps({"access_token": jwt({"preferred_username": "alice"}),
                                          "expires_in": 600})}


def login(env, **extra):
    login_env = {**env, **extra}
    if login_env.get("OIDC_FLOW", "browser") == "browser" and "OIDC_CALLBACK_PORT" not in login_env:
        login_env["OIDC_CALLBACK_PORT"] = str(free_port())
    return subprocess.run(["bash", str(SCRIPT), "login"], env=login_env,
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
    env["OIDC_CALLBACK_PORT"] = str(free_port())
    with socket.socket() as s:
        s.bind(("127.0.0.1", int(env["OIDC_CALLBACK_PORT"])))
        s.listen()
        r = login(env, BROWSER_STATE="x")
    assert r.returncode == 1
    assert "cannot listen on localhost" in r.stderr and "another `make login`" in r.stderr


def test_password_login_encodes_credentials_without_exposing_them(env, tmp_path):
    from urllib.parse import parse_qs

    password = "Generated&+%= secret!?"
    username = "alice+ci@example.com"
    r = login(env, OIDC_FLOW="password", OIDC_USERNAME=username, OIDC_PASSWORD=password)
    assert r.returncode == 0, r.stderr
    form = parse_qs((tmp_path / "token-req.body").read_text())
    assert form == {"grant_type": ["password"], "username": [username],
                    "password": [password], "client_id": ["openshell-cli"],
                    "scope": ["openid email profile"]}
    assert password not in (tmp_path / "token-req").read_text()
    assert password not in r.stdout + r.stderr
    assert "Opening browser" not in r.stdout
    token_file = tmp_path / "oidc/token.json"
    assert token_file.stat().st_mode & 0o777 == 0o600
    assert token_file.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("response", ['{}', '{"access_token":null}',
                                       '{"access_token":{}}', 'not-json',
                                       '{"access_token":"token","expires_in":0}',
                                       '{"access_token":"token","expires_in":"600"}'])
def test_password_login_rejects_malformed_tokens(env, tmp_path, response):
    r = login(env, OIDC_FLOW="password", OIDC_USERNAME="alice", OIDC_PASSWORD="secret",
              TOKEN_RESPONSE=response)
    assert r.returncode != 0
    assert "invalid token response" in r.stderr
    assert not (tmp_path / "oidc/token.json").exists()


def test_password_login_rejects_http_error_without_saving_token(env, tmp_path):
    r = login(env, OIDC_FLOW="password", OIDC_USERNAME="alice", OIDC_PASSWORD="secret",
              TOKEN_HTTP_ERROR="1")
    assert r.returncode != 0
    assert "Password login failed" in r.stderr
    assert "secret" not in r.stdout + r.stderr
    assert not (tmp_path / "oidc/token.json").exists()


@pytest.mark.parametrize("missing", ["OIDC_USERNAME", "OIDC_PASSWORD"])
def test_password_login_requires_credentials(env, missing):
    extra = {"OIDC_FLOW": "password", "OIDC_USERNAME": "alice", "OIDC_PASSWORD": "secret"}
    extra[missing] = ""
    r = login(env, **extra)
    assert r.returncode != 0
    assert f"{missing} is required" in r.stderr
