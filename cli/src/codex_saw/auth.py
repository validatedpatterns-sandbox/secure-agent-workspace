"""OIDC authentication for codex-saw TUI."""

import base64
import json
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx


def _token_file(token_dir):
    return Path(token_dir) / "token.json"


def _discover(issuer):
    url = f"{issuer}/.well-known/openid-configuration"
    r = httpx.get(url, timeout=10, verify=False)
    r.raise_for_status()
    return r.json()


def _decode_jwt_payload(token):
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    padding = 4 - len(payload) % 4
    if padding < 4:
        payload += "=" * padding
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _save_token(response, issuer, token_dir):
    access_token = response.get("access_token")
    if not access_token:
        raise RuntimeError("No access_token in response.")

    tf = _token_file(token_dir)
    tf.parent.mkdir(parents=True, exist_ok=True)
    tf.parent.chmod(0o700)

    response["issuer_url"] = issuer
    response["saved_at"] = int(time.time())
    tf.write_text(json.dumps(response, indent=2))
    tf.chmod(0o600)


def get_username(token_dir):
    tf = _token_file(token_dir)
    if not tf.exists():
        return None
    with open(tf) as f:
        data = json.load(f)
    payload = _decode_jwt_payload(data.get("access_token", ""))
    return payload.get("preferred_username") or payload.get("sub")


def get_token(token_dir, client_id="openshell-cli", issuer=None):
    tf = _token_file(token_dir)
    if not tf.exists():
        return None

    with open(tf) as f:
        data = json.load(f)

    saved_at = data.get("saved_at", 0)
    expires_in = data.get("expires_in", 0)
    if saved_at + expires_in > time.time() + 30:
        return data.get("access_token")

    refresh_token = data.get("refresh_token")
    if not refresh_token:
        return None

    stored_issuer = data.get("issuer_url") or issuer
    if not stored_issuer:
        return None

    try:
        discovery = _discover(stored_issuer)
        token_endpoint = discovery.get("token_endpoint")
        resp = httpx.post(
            token_endpoint,
            data={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
            },
            timeout=10,
            verify=False,
        )
        if resp.status_code == 200 and "access_token" in resp.json():
            _save_token(resp.json(), stored_issuer, token_dir)
            return resp.json()["access_token"]
    except Exception:
        pass

    return None


def browser_login(issuer, client_id, token_dir, callback_port=8400):
    """Browser-based OIDC login with PKCE."""
    import hashlib
    import secrets as secrets_mod

    discovery = _discover(issuer)
    auth_endpoint = discovery.get("authorization_endpoint")
    token_endpoint = discovery.get("token_endpoint")
    if not auth_endpoint or not token_endpoint:
        raise RuntimeError("Authorization or token endpoint not found.")

    verifier = secrets_mod.token_urlsafe(96)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    state = secrets_mod.token_hex(16)
    redirect_uri = f"http://localhost:{callback_port}/callback"

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
    webbrowser.open(auth_url)

    code_holder = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if "code" in qs:
                code_holder["code"] = qs["code"][0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h2>Login successful!</h2>"
                    b"<p>You can close this tab.</p></body></html>"
                )
            else:
                self.send_response(400)
                self.end_headers()

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", callback_port), Handler)
    server.handle_request()
    server.server_close()

    auth_code = code_holder.get("code")
    if not auth_code:
        raise RuntimeError("No authorization code received.")

    resp = httpx.post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": auth_code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
        timeout=10,
        verify=False,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Token exchange failed: {resp.text}")

    _save_token(resp.json(), issuer, token_dir)
    return resp.json().get("access_token")


def device_code_login(issuer, client_id, token_dir):
    """Device-code OIDC login (TUI-friendly). Returns (verification_uri, user_code, poll_fn).

    poll_fn() should be called repeatedly; returns access_token on success, None if pending,
    raises on error.
    """
    discovery = _discover(issuer)
    device_endpoint = discovery.get("device_authorization_endpoint")
    token_endpoint = discovery.get("token_endpoint")
    if not device_endpoint:
        raise RuntimeError("Device authorization endpoint not found. Configure browser flow.")

    resp = httpx.post(
        device_endpoint,
        data={"client_id": client_id, "scope": "openid email profile"},
        timeout=10,
        verify=False,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Device authorization failed: {resp.text}")

    data = resp.json()
    device_code = data.get("device_code")
    user_code = data.get("user_code", "")
    verification_uri = data.get("verification_uri_complete") or data.get("verification_uri", "")
    interval = int(data.get("interval", 5))

    def poll():
        nonlocal interval
        time.sleep(interval)
        r = httpx.post(
            token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": device_code,
            },
            timeout=10,
            verify=False,
        )
        body = r.json()
        error = body.get("error", "")
        if error == "authorization_pending":
            return None
        if error == "slow_down":
            interval += 5
            return None
        if not error:
            _save_token(body, issuer, token_dir)
            return body.get("access_token")
        raise RuntimeError(f"Authentication failed: {error}")

    return verification_uri, user_code, poll


def ensure_authenticated(config):
    """Return a valid access token, or raise if login is needed."""
    oidc = config["oidc"]
    token = get_token(oidc["token_dir"], oidc["client_id"])
    return token
