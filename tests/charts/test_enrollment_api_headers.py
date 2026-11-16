"""Enrollment uses JSON headers that match each Kubernetes API method."""
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "enrollment_kube_api", ROOT / "charts/saw-portal-container/files/kube_api.py")
KUBE_API = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KUBE_API)


def test_get_uses_accept_without_a_request_content_type():
    headers = KUBE_API.request_headers("test-token")

    assert headers == {
        "Authorization": "Bearer test-token",
        "Accept": "application/json",
    }


def test_patch_uses_merge_patch_content_type():
    headers = KUBE_API.request_headers("test-token", patch=True)

    assert headers == {
        "Authorization": "Bearer test-token",
        "Accept": "application/json",
        "Content-Type": "application/merge-patch+json",
    }
