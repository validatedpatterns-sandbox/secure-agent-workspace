"""Dependency failures must delay stock RHDH, not poison its OIDC provider."""
import importlib.util
import io
import json
from pathlib import Path
import ssl
import urllib.error

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "charts/openshell-rhdh/files/wait-oidc.py"
spec = importlib.util.spec_from_file_location("wait_oidc", SOURCE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
ISSUER = "https://identity.example/realms/saw"


def metadata():
    return {"issuer": ISSUER, **{k: ISSUER + "/" + k for k in (
        "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri")}}


class Response(io.BytesIO):
    status = 200

    def geturl(self):
        return ISSUER + "/.well-known/openid-configuration"


def test_verified_discovery_without_credentials(monkeypatch):
    context = ssl.create_default_context()

    def request(req, **kwargs):
        assert req.full_url == ISSUER + "/.well-known/openid-configuration"
        assert req.get_header("Authorization") is None
        assert kwargs == {"context": context, "timeout": 10}
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        return Response(json.dumps(metadata()).encode())

    monkeypatch.setattr(gate.urllib.request, "urlopen", request)
    gate.discover(ISSUER, context)


@pytest.mark.parametrize("fault", ["issuer", "endpoint", "non-object", "oversize"])
def test_bad_metadata_never_unblocks_backend(monkeypatch, fault):
    value = metadata()
    if fault == "issuer":
        value["issuer"] = "https://other.example"
    if fault == "endpoint":
        value["token_endpoint"] = "http://identity.example/token"
    if fault == "non-object":
        value = []
    body = b"x" * (1024 * 1024 + 1) if fault == "oversize" else json.dumps(value).encode()
    monkeypatch.setattr(gate.urllib.request, "urlopen", lambda *a, **k: Response(body))
    with pytest.raises(ValueError):
        gate.discover(ISSUER, ssl.create_default_context())


@pytest.mark.parametrize("recover", [False, True])
def test_discovery_retries_and_deadline_fail_closed(monkeypatch, recover, capsys):
    clock = [0]
    attempts = []
    monkeypatch.setattr(gate.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(gate.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    context = ssl.create_default_context()
    monkeypatch.setattr(gate.ssl, "create_default_context", lambda **kw: context)

    def discover(issuer, ctx):
        assert issuer == ISSUER and ctx is context
        attempts.append(clock[0])
        if len(attempts) == 1 or not recover:
            raise urllib.error.HTTPError(ISSUER, 503, "private-response", {}, None)

    monkeypatch.setattr(gate, "discover", discover)
    assert gate.wait(ISSUER, "/public-ca.crt", timeout=10) == (0 if recover else 1)
    assert len(attempts) == (2 if recover else 3)
    assert "private-response" not in capsys.readouterr().out
