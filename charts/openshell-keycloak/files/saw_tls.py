#!/usr/bin/env python3
"""Verified HTTPS to Keycloak for the in-cluster helpers.

Mounted at /scripts beside redirect-registrar.py and owner-resolver.py, which
both send Keycloak credentials and so must not fall back to plaintext or to an
unverified certificate. Each caller passes its own authenticated Kubernetes GET
so this module stays free of an API client of its own. Standard library only.
"""
import ssl
import urllib.parse
import urllib.request

INGRESS_CA = ("/api/v1/namespaces/openshift-config-managed/"
              "configmaps/default-ingress-cert")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def require_https(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Keycloak endpoints must use HTTPS without URL credentials")
    return parsed


def keycloak_url(name, namespace, kube_get):
    """Find the operator's HTTPS Route without guessing its ingress host."""
    routes = kube_get(f"/apis/route.openshift.io/v1/namespaces/{namespace}/routes").get("items", [])
    hosts = set()
    for route in routes:
        meta, spec = route.get("metadata") or {}, route.get("spec") or {}
        owned = any(owner.get("kind") == "Ingress" and owner.get("name") == f"{name}-ingress"
                    and owner.get("controller") for owner in meta.get("ownerReferences", []))
        if ((owned or meta.get("name") == f"{name}-ingress")
                and (spec.get("to") or {}).get("name") == f"{name}-service"
                and spec.get("tls") and spec.get("host")):
            hosts.add(spec["host"])
    if len(hosts) == 1:
        return f"https://{hosts.pop()}"
    raise ValueError(f"Keycloak HTTPS Route for {namespace}/{name} is missing or ambiguous; "
                     "set keycloakUrl for a custom Route")


def ingress_domain(kube_get):
    return kube_get("/apis/config.openshift.io/v1/ingresses/cluster")["spec"]["domain"]


def tls_context(url, kube_get, log, ca_file=None):
    """System trust, plus the cluster ingress CA for hosts under its domain."""
    parsed = require_https(url)
    ctx = ssl.create_default_context()
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
        return ctx
    try:
        domain = ingress_domain(kube_get)
        if not parsed.hostname.endswith("." + domain.lower().rstrip(".")):
            return ctx
        pem = (kube_get(INGRESS_CA).get("data") or {}).get("ca-bundle.crt")
    except (OSError, KeyError, ValueError) as exc:
        log(f"ingress CA unavailable; using system certificate verification: {exc}")
        return ctx
    if pem:
        ctx.load_verify_locations(cadata=pem)
    return ctx
