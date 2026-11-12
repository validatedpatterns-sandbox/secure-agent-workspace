#!/usr/bin/env python3
"""Gate RHDH startup on verified public OIDC discovery; never handles secrets."""
import json
import ssl
import sys
import time
import urllib.parse
import urllib.request


def discover(issuer, context):
    if urllib.parse.urlsplit(issuer).scheme != "https":
        raise ValueError("OIDC issuer must use HTTPS")
    request = urllib.request.Request(
        issuer + "/.well-known/openid-configuration",
        headers={"Accept": "application/json"},
    )
    with urllib.request.urlopen(request, context=context, timeout=10) as response:
        if response.status != 200:
            raise ValueError("OIDC discovery did not return HTTP 200")
        if urllib.parse.urlsplit(response.geturl()).scheme != "https":
            raise ValueError("OIDC discovery redirected away from HTTPS")
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("OIDC discovery exceeds size limit")
    metadata = json.loads(data)
    if not isinstance(metadata, dict) or metadata.get("issuer") != issuer:
        raise ValueError("OIDC discovery issuer mismatch")
    for name in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"):
        if urllib.parse.urlsplit(metadata.get(name, "")).scheme != "https":
            raise ValueError("OIDC discovery lacks a secure endpoint")


def wait(issuer, cafile, timeout=600):
    context = ssl.create_default_context(cafile=cafile)
    deadline = time.monotonic() + timeout
    while True:
        try:
            discover(issuer, context)
            print("OIDC discovery ready; issuer and TLS verified", flush=True)
            return 0
        except (OSError, ValueError, TypeError) as error:
            # Never log response bodies, redirect URLs or credential material.
            print("Waiting for OIDC discovery: " + type(error).__name__, flush=True)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print("OIDC discovery deadline exceeded; RHDH startup blocked", flush=True)
            return 1
        time.sleep(min(5, remaining))


if __name__ == "__main__":
    sys.exit(wait(sys.argv[1], sys.argv[2]))
