"""Format Kubernetes API errors without exposing response data."""
from urllib.parse import urlsplit


def format_http_error(error):
    """Return only the status and Kubernetes API path for an HTTP error."""
    status = getattr(error, "code", None)
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        return "HTTPError"

    detail = f"HTTP {status}"
    url = getattr(error, "url", None)
    if not isinstance(url, str):
        return detail

    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname != "kubernetes.default.svc":
            return detail
    except ValueError:
        return detail

    path = parsed.path
    if not path.startswith(("/api/", "/apis/")):
        return detail
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        return detail
    return f"{detail} {path}"
