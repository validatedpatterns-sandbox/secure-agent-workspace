"""Configuration for codex-saw TUI."""

import os
from pathlib import Path

import yaml

DEFAULTS = {
    "api_url": "",
    "oidc": {
        "issuer_url": "",
        "client_id": "openshell-cli",
        "token_dir": "~/.config/codex-saw/oidc",
    },
}

CONFIG_FILE = "~/.config/codex-saw/config.yaml"


def load_config():
    cfg = dict(DEFAULTS)
    cfg["oidc"] = dict(DEFAULTS["oidc"])

    config_path = Path(CONFIG_FILE).expanduser()
    if config_path.exists():
        with open(config_path) as f:
            user_cfg = yaml.safe_load(f) or {}
        for key in ("api_url",):
            if key in user_cfg:
                cfg[key] = user_cfg[key]
        if "oidc" in user_cfg and isinstance(user_cfg["oidc"], dict):
            cfg["oidc"].update(user_cfg["oidc"])

    env_url = os.environ.get("SAW_CODEX_API_URL")
    if env_url:
        cfg["api_url"] = env_url

    env_issuer = os.environ.get("SAW_CODEX_OIDC_ISSUER")
    if env_issuer:
        cfg["oidc"]["issuer_url"] = env_issuer

    cfg["oidc"]["token_dir"] = os.path.expanduser(cfg["oidc"]["token_dir"])

    return cfg
