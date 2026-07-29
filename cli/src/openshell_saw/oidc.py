"""OIDC authentication — native Python implementation."""

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import click
import requests

from . import helm, kube


def _token_file(token_dir):
    return Path(token_dir) / "token.json"


def _discover(issuer):
    """Fetch OIDC discovery document."""
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        r = requests.get(url, timeout=10, verify=False)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise click.ClickException(f"Failed to fetch OIDC discovery from {url}: {e}") from e


def _generate_pkce():
    verifier = secrets.token_urlsafe(96)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _decode_jwt_payload(token):
    """Decode the payload of a JWT without verification."""
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


def auto_detect_issuer(issuer, namespace, token_dir, client_id, shared_namespace=None):
    """4-step OIDC issuer auto-detection chain.

    Steps 2 and 4 look in the shared namespace (where Keycloak and gateway live),
    not the per-user namespace.
    """
    if issuer:
        return issuer

    lookup_ns = shared_namespace or namespace

    # Step 2: from Keycloak CR status (RHBK operator)
    r = kube.run(
        ["oc", "get", "keycloak", "openshell-keycloak", "-n", lookup_ns,
         "-o", "jsonpath={.status.externalURL}"],
        capture=True, check=False,
    )
    if r.returncode == 0 and r.stdout.strip():
        return f"{r.stdout.strip()}/realms/openshell"

    # Step 3: from saved token file
    tf = _token_file(token_dir)
    if tf.exists():
        try:
            with open(tf) as f:
                data = json.load(f)
            detected = data.get("issuer_url")
            if detected:
                return detected
        except Exception:
            pass

    # Step 4: from Keycloak route by label (always in shared namespace)
    r = kube.run(
        ["oc", "get", "route", "-n", lookup_ns, "-l", "app=keycloak",
         "-o", "jsonpath={.items[0].spec.host}"],
        capture=True, check=False,
    )
    if r.returncode == 0 and r.stdout.strip():
        return f"https://{r.stdout.strip()}/realms/openshell"

    return None


def login(issuer, namespace, client_id, flow, token_dir, callback_port=8400):
    """Perform OIDC login."""
    issuer = auto_detect_issuer(issuer, namespace, token_dir, client_id)
    if not issuer:
        raise click.ClickException(
            "OIDC issuer not found. Set --issuer, deploy Keycloak, or deploy the gateway with OIDC."
        )

    discovery = _discover(issuer)
    if flow == "browser":
        _browser_login(issuer, discovery, client_id, token_dir, callback_port)
    elif flow in ("device-code", "device"):
        _device_login(issuer, discovery, client_id, token_dir)
    else:
        raise click.ClickException(f"Unknown OIDC flow: {flow}. Use 'browser' or 'device-code'.")


def _browser_login(issuer, discovery, client_id, token_dir, callback_port):
    auth_endpoint = discovery.get("authorization_endpoint")
    token_endpoint = discovery.get("token_endpoint")
    if not auth_endpoint or not token_endpoint:
        raise click.ClickException("Authorization or token endpoint not found in discovery.")

    verifier, challenge = _generate_pkce()
    state = secrets.token_hex(16)
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

    click.echo("Opening browser for authentication...")
    click.echo(f"If the browser does not open, visit:\n  {auth_url}\n")
    webbrowser.open(auth_url)

    auth_code = _wait_for_callback(callback_port)
    if not auth_code:
        raise click.ClickException("No authorization code received.")

    resp = requests.post(
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
        raise click.ClickException(f"Token exchange failed: {resp.text}")

    _save_token(resp.json(), issuer, token_dir)


def _wait_for_callback(port):
    """Start a local HTTP server and wait for the OIDC callback."""
    code_holder = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if "code" in params:
                code_holder["code"] = params["code"][0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h2>Login successful!</h2>"
                    b"<p>You can close this tab and return to the terminal.</p></body></html>"
                )
            else:
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                error = params.get("error", ["unknown"])[0]
                self.wfile.write(f"<html><body><h2>Login failed: {error}</h2></body></html>".encode())

        def log_message(self, format, *args):
            pass

    click.echo(f"Waiting for callback on localhost:{port}...")
    server = HTTPServer(("127.0.0.1", port), Handler)
    server.handle_request()
    server.server_close()
    return code_holder.get("code")


def _device_login(issuer, discovery, client_id, token_dir):
    device_endpoint = discovery.get("device_authorization_endpoint")
    token_endpoint = discovery.get("token_endpoint")
    if not device_endpoint:
        raise click.ClickException(
            "Device authorization endpoint not found. Try --flow browser."
        )

    resp = requests.post(
        device_endpoint,
        data={"client_id": client_id, "scope": "openid email profile"},
        timeout=10,
        verify=False,
    )
    if resp.status_code != 200:
        raise click.ClickException(f"Device authorization failed: {resp.text}")

    data = resp.json()
    device_code = data.get("device_code")
    user_code = data.get("user_code")
    verification_uri = data.get("verification_uri_complete") or data.get("verification_uri")
    interval = int(data.get("interval", 5))

    click.echo(f"\nTo sign in, open this URL:\n  {verification_uri}")
    if user_code:
        click.echo(f"\nEnter the code: {user_code}")
    click.echo("\nWaiting for authentication...")

    deadline = time.time() + 600
    while time.time() < deadline:
        time.sleep(interval)
        resp = requests.post(
            token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": device_code,
            },
            timeout=10,
            verify=False,
        )
        body = resp.json()
        error = body.get("error", "")
        if error == "authorization_pending":
            continue
        elif error == "slow_down":
            interval += 5
            continue
        elif not error:
            _save_token(body, issuer, token_dir)
            return
        else:
            raise click.ClickException(f"Authentication failed: {error}")

    raise click.ClickException("Authentication timed out after 10 minutes.")


def _save_token(response, issuer, token_dir):
    access_token = response.get("access_token")
    if not access_token:
        raise click.ClickException("No access_token in response.")

    tf = _token_file(token_dir)
    tf.parent.mkdir(parents=True, exist_ok=True)
    tf.parent.chmod(0o700)

    response["issuer_url"] = issuer
    response["saved_at"] = int(time.time())
    tf.write_text(json.dumps(response, indent=2))
    tf.chmod(0o600)

    payload = _decode_jwt_payload(access_token)
    username = payload.get("preferred_username") or payload.get("sub", "unknown")
    expires_in = response.get("expires_in", 0)

    click.echo(f"\nLogged in as: {username}")
    click.echo(f"Token expires in: {expires_in // 60} minutes")
    click.echo(f"Token saved to: {tf}")


def get_token(token_dir, client_id=None, issuer=None):
    """Get a valid access token, refreshing if needed. Returns the token string or None."""
    tf = _token_file(token_dir)
    if not tf.exists():
        return None

    with open(tf) as f:
        data = json.load(f)

    saved_at = data.get("saved_at", 0)
    expires_in = data.get("expires_in", 0)
    if saved_at + expires_in > time.time() + 30:
        return data.get("access_token")

    # Try refresh
    refresh_token = data.get("refresh_token")
    if not refresh_token:
        return None

    stored_issuer = data.get("issuer_url") or issuer
    if not stored_issuer:
        return None

    try:
        discovery = _discover(stored_issuer)
        token_endpoint = discovery.get("token_endpoint")
        resp = requests.post(
            token_endpoint,
            data={
                "grant_type": "refresh_token",
                "client_id": client_id or "openshell-cli",
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


def whoami(token_dir):
    """Show current OIDC identity."""
    tf = _token_file(token_dir)
    if not tf.exists():
        raise click.ClickException("Not authenticated. Run 'openshell-saw login' first.")

    with open(tf) as f:
        data = json.load(f)

    access_token = data.get("access_token", "")
    payload = _decode_jwt_payload(access_token)

    saved_at = data.get("saved_at", 0)
    expires_in = data.get("expires_in", 0)
    is_valid = saved_at + expires_in > time.time() + 30

    if not is_valid:
        click.echo("(token expired -- showing last known identity)")

    click.echo("Identity:")
    click.echo(f"  Subject:    {payload.get('sub', 'n/a')}")
    click.echo(f"  Username:   {payload.get('preferred_username', 'n/a')}")
    click.echo(f"  Email:      {payload.get('email', 'n/a')}")
    click.echo(f"  Issuer:     {payload.get('iss', 'n/a')}")

    roles = payload.get("realm_access", {}).get("roles", [])
    click.echo(f"  Roles:      {', '.join(roles) if roles else 'n/a'}")

    exp = payload.get("exp", 0)
    if exp:
        import datetime
        click.echo(f"  Expires:    {datetime.datetime.fromtimestamp(exp)}")

    click.echo(f"  Status:     {'valid' if is_valid else 'EXPIRED'}")


def logout(token_dir, client_id, namespace):
    """Revoke OIDC token, clear local file, clear tokens from running VMs."""
    tf = _token_file(token_dir)
    if tf.exists():
        with open(tf) as f:
            data = json.load(f)

        stored_issuer = data.get("issuer_url")
        refresh_token = data.get("refresh_token")

        # Revoke at IdP
        if stored_issuer and refresh_token:
            try:
                discovery = _discover(stored_issuer)
                end_session = discovery.get("end_session_endpoint")
                if end_session:
                    requests.post(
                        end_session,
                        data={
                            "client_id": client_id,
                            "refresh_token": refresh_token,
                        },
                        timeout=3,
                        verify=False,
                    )
            except Exception:
                pass

        tf.unlink()
        click.echo("Logged out. Token revoked and cleared.")
    else:
        click.echo("Not logged in.")

    # Clear tokens from running VMs
    click.echo("Clearing OIDC tokens from running sandboxes...")
    sandboxes = helm.list_sandboxes(namespace)
    for sb in sandboxes:
        name = sb["name"]
        click.echo(f"  {name}: clearing token...")
        ok, _ = kube.run_in_vm(
            name, namespace,
            "sudo rm -f /etc/openshell/gateway.toml ~/.config/openshell/gateway.toml "
            "&& sudo systemctl restart openshell-gateway-setup.service",
        )
        click.echo(f"  {name}: {'done' if ok else 'skipped (VM unreachable)'}")

    click.echo("Logout complete.")
