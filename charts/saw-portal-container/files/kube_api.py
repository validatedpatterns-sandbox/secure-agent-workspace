"""Build safe JSON headers for Kubernetes API requests."""


def request_headers(token, patch=False):
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
    }
    if patch:
        headers["Content-Type"] = "application/merge-patch+json"
    return headers
