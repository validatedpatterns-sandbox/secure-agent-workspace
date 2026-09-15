"""Configuration from environment variables."""

import os


OIDC_ISSUER_URL = os.environ.get(
    "OIDC_ISSUER_URL",
    "https://keycloak.openshell-agents.svc/realms/openshell",
)
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "openshell-cli")
MANAGED_NAMESPACE = os.environ.get("MANAGED_NAMESPACE", "openshell-agents")
SAW_CHART_PATH = os.environ.get("SAW_CHART_PATH", "/app/charts/openshell-saw/")
K8S_CHART_PATH = os.environ.get("K8S_CHART_PATH", "/app/charts/openshell-saw-kubernetes/")
DEFAULT_BACKEND = os.environ.get("DEFAULT_BACKEND", "kubernetes")
OIDC_JWKS_CACHE_TTL = int(os.environ.get("OIDC_JWKS_CACHE_TTL", "3600"))
SESSION_TOKEN_TTL = int(os.environ.get("SESSION_TOKEN_TTL", "300"))
MAX_SESSIONS_PER_USER = int(os.environ.get("MAX_SESSIONS_PER_USER", "3"))
