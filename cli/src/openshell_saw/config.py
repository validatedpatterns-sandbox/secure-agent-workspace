"""Configuration and path resolution."""

import base64
import json
import os
import re
import subprocess
from functools import lru_cache
from pathlib import Path

import yaml

SHARED_NAMESPACE = "openshell-agents"
USER_NS_PREFIX = "saw-"

DEFAULTS = {
    "namespace": SHARED_NAMESPACE,
    "shared_namespace": SHARED_NAMESPACE,
    "ssh_key": os.path.expanduser("~/.ssh/id_ed25519"),
    "source_mode": "containerDisk",
    "agent": "openclaw",
    "oidc": {
        "client_id": "openshell-cli",
        "flow": "browser",
        "token_dir": os.path.expanduser("~/.config/openshell/oidc"),
        "callback_port": 8400,
    },
}

CONFIG_DIR = Path(os.path.expanduser("~/.config/openshell-saw"))
CONFIG_FILE = CONFIG_DIR / "config.yaml"


def load_config():
    cfg = dict(DEFAULTS)
    cfg["oidc"] = dict(DEFAULTS["oidc"])
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            user_cfg = yaml.safe_load(f) or {}
        for k, v in user_cfg.items():
            if k == "oidc" and isinstance(v, dict):
                cfg["oidc"].update(v)
            else:
                cfg[k] = v
    return cfg


@lru_cache(maxsize=1)
def repo_root():
    """Find the git repo root, or None if not in a repo."""
    env_root = os.environ.get("OPENSHELL_REPO_ROOT")
    if env_root:
        p = Path(env_root)
        if (p / "helm").is_dir():
            return p
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            p = Path(result.stdout.strip())
            if (p / "helm").is_dir():
                return p
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def chart_path(chart_name):
    """Resolve a Helm chart path. Prefers repo charts over bundled ones."""
    root = repo_root()
    if root:
        repo_chart = root / "helm" / chart_name
        if repo_chart.is_dir():
            return str(repo_chart)
    bundled = Path(__file__).parent / "charts" / chart_name
    if bundled.is_dir():
        return str(bundled)
    raise FileNotFoundError(
        f"Chart '{chart_name}' not found. "
        f"Run from the openshell-nvidia repo, or set OPENSHELL_REPO_ROOT."
    )


def oidc_script_path():
    """Resolve the oidc-login.sh script path, or None if not available."""
    root = repo_root()
    if root:
        script = root / "scripts" / "oidc-login.sh"
        if script.is_file():
            return str(script)
    return None


def ssh_pubkey(key_path):
    """Read the SSH public key from key_path.pub."""
    pub = Path(key_path).expanduser().with_suffix(
        Path(key_path).suffix + ".pub" if Path(key_path).suffix else ".pub"
    )
    # Handle keys like id_ed25519 -> id_ed25519.pub
    if not key_path.endswith(".pub"):
        pub = Path(key_path + ".pub").expanduser()
    else:
        pub = Path(key_path).expanduser()
    if not pub.exists():
        raise FileNotFoundError(
            f"SSH public key not found at {pub}. "
            f"Set --ssh-key or configure ssh_key in {CONFIG_FILE}"
        )
    return pub.read_text().strip()


def user_namespace(username):
    """Derive a per-user namespace from a username."""
    sanitized = re.sub(r"[^a-z0-9-]", "-", username.lower()).strip("-")[:58]
    return f"{USER_NS_PREFIX}{sanitized}"


def get_username_from_token(token_dir):
    """Extract preferred_username from the saved OIDC token, or None."""
    tf = Path(token_dir) / "token.json"
    if not tf.exists():
        return None
    try:
        with open(tf) as f:
            data = json.load(f)
        access_token = data.get("access_token", "")
        parts = access_token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding < 4:
            payload += "=" * padding
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return claims.get("preferred_username")
    except Exception:
        return None
