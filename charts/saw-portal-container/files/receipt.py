"""Fetch only the writer's Ed25519 public receipt key using its service identity."""
import base64
import re
import ssl
import urllib.request


def receipt_key(service, namespace, ca_file, *, opener=None):
    label = r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"
    if not all(re.fullmatch(label, s) for s in (service, namespace)):
        raise ValueError("invalid writer service")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            raise ValueError("writer redirect refused")
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
    with opener.open(f"https://{service}.{namespace}.svc:8443/v1/receipt-key", timeout=8) as response:
        raw = response.read(65)
    der = base64.b64decode(raw, validate=True)
    if len(der) != 44 or der[:12] != bytes.fromhex("302a300506032b6570032100"):
        raise ValueError("expected Ed25519 SubjectPublicKeyInfo")
    return raw.decode("ascii")
