#!/usr/bin/env python3
"""Guest-side negative probes: emit statuses and token digests, never responses."""
import argparse
import base64
import gzip
import hashlib
import http.client
import json
import re
import ssl
from urllib.parse import urlsplit


def probes(proxy, ca, host, marker):
    endpoint = urlsplit(proxy)
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=ca)
    results, digests = [], set()

    def record(test_id, connection, method, path, headers, allowed):
        try:
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            # A bound protects the probe from an infinite upstream response;
            # reaching it is INCONCLUSIVE, never a passing leak test.
            body = response.read(2 * 1024 * 1024 + 1)
            captured = (str(response.status) + "\n" + "\n".join(
                name + ": " + value for name, value in response.getheaders())).encode() + b"\n" + body
            digests.update(hashlib.sha256(m.group()).digest()[:8]
                           for m in re.finditer(rb"[A-Za-z0-9_-]{20,512}", captured))
            verdict = "PASS" if response.status in allowed and len(body) <= 2*1024*1024 else "FAIL"
            results.append({"id": test_id, "status": response.status, "result": verdict})
        except (OSError, http.client.HTTPException):
            results.append({"id": test_id, "result": "INCONCLUSIVE", "error": "connection-failed"})
        finally:
            connection.close()

    for target in ("not-allowlisted.saw.invalid:443", "169.254.169.254:443"):
        connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=10)
        record("deny-target-" + target, connection, "CONNECT", target, {"Host": target}, {403})
    for path in ("/debug/pprof", "/metrics", "/healthz", "/debug/vars"):
        connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=10)
        record("deny-debug-" + path, connection, "GET", path, {}, {405})
    for test_id, headers in (
        ("deny-host-spoof", {"Host": "attacker.saw.invalid", "Authorization": "Bearer " + marker}),
        ("deny-unbound-marker", {"Authorization": "Bearer saw-cred.unknown.api_key"}),
        ("forwarded-headers", {"Authorization": "Bearer " + marker, "X-Forwarded-Host": "attacker.saw.invalid",
                               "X-Forwarded-For": "169.254.169.254", "Forwarded": "host=attacker.saw.invalid"}),
    ):
        connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port, context=context, timeout=20)
        connection.set_tunnel(host, 443)
        record(test_id, connection, "GET", "/v1/models", headers, {502} if test_id.startswith("deny-") else {200})
    return {"tests": results, "digests": base64.b64encode(gzip.compress(b"".join(sorted(digests)))).decode()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--host", default="integrate.api.nvidia.com")
    parser.add_argument("--marker", default="saw-cred.inference.api_key")
    args = parser.parse_args()
    print(json.dumps(probes(args.proxy, args.ca, args.host, args.marker), sort_keys=True))
