"""Enrollment diagnostics expose API status and path only."""
import importlib.util
import io
from pathlib import Path
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "enrollment_http_errors", ROOT / "charts/saw-portal-container/files/http_errors.py")
HTTP_ERRORS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HTTP_ERRORS)


def test_http_error_shows_status_and_kubernetes_api_path_only():
    error = HTTPError(
        "https://kubernetes.default.svc/api/v1/namespaces/saw-ctl-fixture/configmaps/gateway-ca?token=query-secret",
        403,
        "private response body",
        {"Authorization": "header-secret"},
        io.BytesIO(b"body-secret"),
    )

    result = HTTP_ERRORS.format_http_error(error)

    assert result == "HTTP 403 /api/v1/namespaces/saw-ctl-fixture/configmaps/gateway-ca"
    assert all(secret not in result for secret in (
        "kubernetes.default.svc", "query-secret", "private response body",
        "header-secret", "body-secret"))


def test_http_error_hides_non_kubernetes_urls():
    error = HTTPError("https://user:password@external.example.test/private?token=secret",
                      401, "private", {}, io.BytesIO(b"secret"))

    assert HTTP_ERRORS.format_http_error(error) == "HTTP 401"


def test_http_error_without_a_valid_status_is_type_only():
    class InvalidError:
        code = 700
        url = "https://kubernetes.default.svc/api/v1/secrets/private"

    assert HTTP_ERRORS.format_http_error(InvalidError()) == "HTTPError"
