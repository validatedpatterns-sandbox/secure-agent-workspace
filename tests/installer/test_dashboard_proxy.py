"""Check the dashboard proxy setup used by the guest installer."""
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "charts/openshell-saw/files/installer/setup-dashboard.sh"


def test_proxy_can_read_only_the_explicit_user_allowlist(tmp_path):
    home = tmp_path / "home"
    ca = home / ".local/state/openshell/tls/ca.crt"
    ca.parent.mkdir(parents=True)
    ca.write_text("public test certificate\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("systemctl", "curl", "sleep"):
        command = bin_dir / name
        command.write_text("#!/bin/sh\nexit 0\n")
        command.chmod(0o755)
    env = {
        **os.environ,
        "HOME": str(home),
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "RUNTIME": "podman",
        "DASHBOARD_ENABLED": "true",
        "DASHBOARD_IMAGE": "test-dashboard",
        "DASHBOARD_PROXY_IMAGE": "test-proxy",
        "DASHBOARD_COOKIE_SECRET": "test-cookie-value",
        "DASHBOARD_REDIRECT_URL": "https://example.com/oauth2/callback",
        "DASHBOARD_ALLOWED_USERS": "developer,admin",
        "OIDC_ISSUER": "https://example.com/realms/test",
    }
    subprocess.run(["bash", str(SCRIPT)], env=env, check=True, capture_output=True, text=True)

    config = home / ".config/openshell"
    users = config / "dashboard-users"
    assert users.read_text().splitlines() == ["developer", "admin"]
    assert users.stat().st_mode & 0o444 == 0o444
    proxy_env = (config / "dashboard-proxy.env").read_text()
    assert "OAUTH2_PROXY_AUTHENTICATED_EMAILS_FILE=/etc/saw/dashboard-users" in proxy_env
    assert "OAUTH2_PROXY_EMAIL_DOMAINS=" not in proxy_env
    dashboard_env = (config / "dashboard.env").read_text().splitlines()
    assert "ADMIN_ROLE=openshell-admin" in dashboard_env
    assert "USER_ROLE=openshell-user" in dashboard_env
