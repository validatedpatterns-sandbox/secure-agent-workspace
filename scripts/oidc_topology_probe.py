"""Verify OIDC discovery from the trusted Pod's DNS and TLS trust context."""
import http.client
import ipaddress
import json
import socket
import ssl
import sys
from urllib.parse import urlsplit


def probe(issuer):
    url = urlsplit(issuer)
    port = url.port or 443
    answers = {row[4][0] for row in socket.getaddrinfo(url.hostname, port, type=socket.SOCK_STREAM)}
    context = ssl.create_default_context()
    for address in sorted(answers):
        ip = ipaddress.ip_address(address)
        if ip.version != 4 or ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_reserved:
            raise ValueError("unsupported or unsafe issuer address")
        # Connect directly to each DNS answer. SNI, hostname verification and
        # the HTTP Host header still use the configured issuer's hostname.
        conn = http.client.HTTPSConnection(url.hostname, port, timeout=5, context=context)
        try:
            with socket.create_connection((address, port), timeout=5) as sock:
                conn.sock = context.wrap_socket(sock, server_hostname=url.hostname)
                conn.request("GET", url.path.rstrip("/") + "/.well-known/openid-configuration")
                response = conn.getresponse()
                data = response.read(1024 * 1024 + 1)
                if response.status != 200 or len(data) > 1024 * 1024 or json.loads(data).get("issuer") != issuer:
                    raise ValueError("issuer discovery mismatch")
        finally:
            conn.close()
    return sorted(answers)


if __name__ == "__main__":
    try:
        result = probe(sys.argv[1])
    except socket.gaierror:
        result = {"error": "dns"}
    except ssl.SSLError:
        result = {"error": "tls"}
    except (OSError, http.client.HTTPException):
        result = {"error": "connection"}
    except (ValueError, AttributeError):
        result = {"error": "discovery"}
    print(json.dumps(result))
