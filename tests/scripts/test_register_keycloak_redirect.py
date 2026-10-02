"""charts/openshell-saw/files/register-keycloak-redirect.sh: the prepare Job
adds this VM's callbacks (the dashboard's and each sandbox UI route's) to the
shared Keycloak client openshell-dashboard. Runs against a fake kubectl and a
small fake Keycloak."""
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "charts" / "openshell-saw" / "files" / "register-keycloak-redirect.sh"

FAKE_KUBECTL = """#!/bin/sh
# get route <vm>-webui ... -> its host; get secret <kc>-initial-admin -> base64 field
case "$*" in
  *"get route alice-webui"*) [ -n "$FAKE_WEBUI_HOST" ] && printf %s "$FAKE_WEBUI_HOST"; exit 0;;
  *"get secret openshell-keycloak-initial-admin"*"{.data.username}"*) printf %s a2MtYWRtaW4=; exit 0;;
  *"get secret openshell-keycloak-initial-admin"*"{.data.password}"*) printf %s cGFzcw==; exit 0;;
esac
exit 1
"""


class FakeKeycloak:
    def __init__(self, client):
        self.client = client
        self.puts = 0

    def serve(self):
        kc = self

        class H(BaseHTTPRequestHandler):
            def _reply(self, code, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _authed(self):
                return self.headers.get("Authorization") == "Bearer admin-token"

            def do_POST(self):
                form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
                ok = form.get("username") == ["kc-admin"] and form.get("password") == ["pass"]
                self._reply(200, {"access_token": "admin-token"} if ok else {"error": "invalid_grant"})

            def do_GET(self):
                url = urlsplit(self.path)
                if not self._authed():
                    return self._reply(401)
                if url.path == "/admin/realms/openshell/clients":
                    want = parse_qs(url.query).get("clientId", [""])[0]
                    return self._reply(200, [kc.client] if kc.client and kc.client["clientId"] == want else [])
                if kc.client and url.path == f"/admin/realms/openshell/clients/{kc.client['id']}":
                    return self._reply(200, kc.client)
                self._reply(404)

            def do_PUT(self):
                if not self._authed():
                    return self._reply(401)
                kc.client = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                kc.puts += 1
                self._reply(204)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def run(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    kubectl = bin_dir / "kubectl"
    kubectl.write_text(FAKE_KUBECTL)
    kubectl.chmod(0o755)
    servers = []

    def go(kc, webui_host="alice-webui-saw-alice.apps.example.com", ui_hosts="", dashboard="true"):
        server, url = kc.serve()
        servers.append(server)
        env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", VM_NAME="alice", NS="saw-alice",
                   OIDC_KEYCLOAK_NAME="openshell-keycloak", OIDC_REALM="openshell", KEYCLOAK_NS="saw-keycloak",
                   DASHBOARD_CLIENT_ID="openshell-dashboard", OIDC_ISSUER_URL=f"{url}/realms/openshell",
                   DASHBOARD_ENABLED=dashboard, UI_ROUTE_HOSTS=ui_hosts, FAKE_WEBUI_HOST=webui_host)
        return subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60)
    yield go
    for s in servers:
        s.shutdown()


def dashboard_client(**extra):
    return {"id": "c1", "clientId": "openshell-dashboard", "redirectUris": ["https://bob-webui/oauth2/callback"],
            "webOrigins": ["https://bob-webui"], "publicClient": True, **extra}


def test_adds_the_dashboard_and_ui_callbacks_and_keeps_other_vms(run):
    kc = FakeKeycloak(dashboard_client())
    result = run(kc, ui_hosts="alice-default-notebook-ui.apps.example.com ")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Redirect URIs registered" in result.stdout
    assert kc.client["redirectUris"] == sorted([
        "https://bob-webui/oauth2/callback",
        "https://alice-webui-saw-alice.apps.example.com/oauth2/callback",
        "https://alice-default-notebook-ui.apps.example.com/oauth2/callback"])
    assert set(kc.client["webOrigins"]) == {"https://bob-webui", "https://alice-webui-saw-alice.apps.example.com",
                                            "https://alice-default-notebook-ui.apps.example.com"}
    assert kc.client["publicClient"] is True                 # the rest of the client is kept


def test_running_again_adds_nothing_twice(run):
    kc = FakeKeycloak(dashboard_client())
    run(kc, ui_hosts="alice-default-notebook-ui.apps.example.com")
    first = dict(kc.client)
    run(kc, ui_hosts="alice-default-notebook-ui.apps.example.com")
    assert kc.client["redirectUris"] == first["redirectUris"]
    assert len(kc.client["webOrigins"]) == len(set(kc.client["webOrigins"]))


def test_only_ui_routes_when_the_dashboard_is_off(run):
    kc = FakeKeycloak(dashboard_client(redirectUris=[], webOrigins=[]))
    result = run(kc, ui_hosts="alice-default-notebook-ui.apps.example.com", dashboard="false")
    assert result.returncode == 0
    assert kc.client["redirectUris"] == ["https://alice-default-notebook-ui.apps.example.com/oauth2/callback"]


def test_nothing_to_register_makes_no_keycloak_call(run):
    kc = FakeKeycloak(dashboard_client())
    result = run(kc, dashboard="false")
    assert result.returncode == 0 and "No redirect URIs to register" in result.stdout
    assert kc.puts == 0


def test_a_missing_client_is_reported_not_created(run):
    kc = FakeKeycloak(None)
    result = run(kc)
    assert result.returncode == 0                             # best effort: the prepare Job goes on
    assert "openshell-dashboard' not found" in result.stdout
    assert kc.puts == 0
