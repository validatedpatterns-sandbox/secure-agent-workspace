"""Verified issuer trust shared by the CLI and repository shell tools.

Can run directly with only the Python standard library installed.
"""
import functools
import json
import os
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit


# Cached: prepare_ca_bundle runs per request, and the device-code flow polls
# the token endpoint every few seconds. Cluster metadata does not change
# within one command.
@functools.lru_cache(maxsize=None)
def _oc_json(*args):
    try:
        result = subprocess.run(
            ["oc", "get", *args, "-o", "json", "--request-timeout=5s"],
            capture_output=True, text=True, timeout=10,
        )
        data = json.loads(result.stdout) if result.returncode == 0 else {}
        return data if isinstance(data, dict) else {}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {}


def require_https(url):
    """Validate remote authentication URLs; the local callback is separate."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("OIDC and Keycloak endpoints must use HTTPS without URL credentials")
    return parsed


def _write_with_public_cas(destination, pem):
    """Tools that take a CA file replace their roots with it, so keep the
    public and locally installed corporate CAs alongside the extra one."""
    context = ssl.create_default_context()
    public = "".join(ssl.DER_cert_to_PEM_cert(cert) for cert in context.get_ca_certs(binary_form=True))
    context.load_verify_locations(cadata=pem)
    Path(destination).write_text(public + pem, encoding="utf-8")
    return str(destination)


def prepare_ca_bundle(url, destination, ca_bundle=None, combine=False):
    """Return a CA file, or None for system trust. Never disable verification.

    Only cluster ingress hosts inherit the CA read through the user's oc
    session. External issuers need an explicit bundle or system trust. An
    explicit bundle is used on its own unless `combine` asks for system trust
    as well, so that pinning a private CA stays possible.
    """
    parsed = require_https(url)
    explicit = ca_bundle or os.environ.get("OIDC_CA_BUNDLE")
    if explicit:
        ssl.create_default_context(cafile=explicit)
        if not combine:
            return str(explicit)
        return _write_with_public_cas(destination, Path(explicit).read_text(encoding="utf-8"))
    domain = (_oc_json("ingresses.config.openshift.io", "cluster").get("spec") or {}).get("domain")
    if not domain or not parsed.hostname.endswith("." + domain.lower().rstrip(".")):
        return None
    ingress = _oc_json("cm", "default-ingress-cert", "-n", "openshift-config-managed")
    pem = (ingress.get("data") or {}).get("ca-bundle.crt")
    if not pem:
        return None
    return _write_with_public_cas(destination, pem)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 2:
            require_https(sys.argv[1])
        else:
            print(prepare_ca_bundle(sys.argv[1], sys.argv[2],
                                    combine=os.environ.get("SAW_CA_COMBINE") == "1") or "")
    except (OSError, ValueError) as exc:
        sys.exit(f"Cannot configure TLS trust: {exc}. Set OIDC_CA_BUNDLE to a readable PEM CA bundle.")
