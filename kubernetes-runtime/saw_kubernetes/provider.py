"""Verify Kubernetes proxy bindings against the same shipped governance profiles as the VM."""
import re
import ipaddress
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from .core import shared

PROFILES = Path(shared.__file__).resolve().parents[1] / "provider-profiles"
SUPPORTED = {"openai", "anthropic", "nvidia", "slack", "gmail"}


@lru_cache(maxsize=5)
def document(kind):
    if kind not in SUPPORTED:
        raise ValueError("unsupported governed provider")
    return yaml.safe_load((PROFILES / (kind + ".yaml")).read_text())


def custom_host(url):
    """The namespace credential broker intercepts only HTTPS on port 443."""
    if not isinstance(url, str) or shared.check_base_url(url) != url:
        raise ValueError("invalid custom inference base URL")
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("credential broker requires a DNS hostname")
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if (parsed.scheme != "https" or parsed.port not in (None, 443)
            or len(hostname) > 253 or not re.fullmatch(rf"{label}(?:\.{label})+", hostname)
            or not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)*/v1", parsed.path)):
        raise ValueError("custom inference requires an approved HTTPS v1 endpoint on port 443")
    return parsed.hostname


def requirements(kind, custom_url=None):
    if kind == "custom-inference" and custom_url:
        return {"name":"api_key", "env_vars":["CUSTOM_INFERENCE_API_KEY"]}, [custom_host(custom_url)]
    doc = document(kind)
    slot, = doc["credentials"]
    hosts = sorted({e["host"] for e in doc["endpoints"]})
    return slot, hosts


def checked_marker(provider, bindings, custom_url=None):
    """The plan carries only the public routing marker; keys remain in the proxy."""
    slot, _ = requirements(provider.type, custom_url)
    expected = {"secret": provider.credential_secret, "key": provider.credential_secret_key,
                "type": provider.type, "refresh": bool(provider.refresh_strategy)}
    if (expected not in bindings or provider.credentials_spec or provider.base_url or provider.base_url_secret_key
            or provider.refresh_strategy not in ("", "oauth2_refresh_token") or provider.inference_timeout
            or (provider.type != "nvidia" and (provider.model or provider.nemoclaw_provider))
            or provider.model_secret_key):
        raise ValueError("provider configuration differs from enrolled proxy binding")
    if expected["refresh"] and (slot.get("refresh") or {}).get("strategy") != provider.refresh_strategy:
        raise ValueError("provider refresh is not supported by its governance profile")
    if not re.fullmatch(r"[a-z0-9-]+", expected["secret"]) or not re.fullmatch(r"[a-zA-Z0-9_-]+", expected["key"]):
        raise ValueError("invalid proxy marker reference")
    return {slot["env_vars"][0]: shared.credential_marker("saw-cred", expected["secret"], expected["key"])}


def check_policy(kind, credentials, policy, custom_url=None):
    slot, hosts = requirements(kind, custom_url)
    if kind == "custom-inference":
        # Same contract as the VM: the trusted Secret's url supplies the marker
        # host. No static profile may add hosts, even under another binding.
        return (policy.get("markerPrefix") == "saw-cred"
                and not policy["profiles"].get(kind)
                and policy["allowHosts"] == hosts
                and len(policy["bindings"]) == 1
                and any(b.get("providers") == [kind] and b.get("key") == "api_key"
                        and not b.get("refresh") and credentials == {slot["env_vars"][0]:
                        shared.credential_marker("saw-cred", b["secret"], b["key"])} for b in policy["bindings"]))

    if (policy.get("markerPrefix") != "saw-cred" or sorted(policy["profiles"].get(kind, [])) != hosts or
            not set(hosts) <= set(policy["allowHosts"])):
        return False
    for binding in policy["bindings"]:
        if kind not in binding["providers"]:
            continue
        if set(binding["providers"]) - ({kind, "build"} if kind=="nvidia" else {kind}):
            continue
        marker = shared.credential_marker("saw-cred", binding["secret"], binding["key"])
        if credentials != {slot["env_vars"][0]: marker}:
            continue
        refresh = binding.get("refresh")
        if refresh:
            contract = slot.get("refresh", {})
            if (refresh.get("strategy") != contract.get("strategy") or
                    refresh.get("tokenURL") != contract.get("token_url") or
                    refresh.get("material") != {"clientID":"client_id", "clientSecret":"client_secret", "refreshToken":"refresh_token"}):
                return False
        return True
    return False
