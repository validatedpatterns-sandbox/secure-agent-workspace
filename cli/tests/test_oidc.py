"""Tests for oidc module."""

import json
import time
from unittest.mock import MagicMock, patch

from openshell_saw import oidc


class TestDecodeJwtPayload:
    def test_decodes_valid_jwt(self):
        import base64
        payload = {"sub": "user1", "preferred_username": "alice"}
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        token = f"header.{encoded}.signature"
        result = oidc._decode_jwt_payload(token)
        assert result["sub"] == "user1"
        assert result["preferred_username"] == "alice"

    def test_handles_invalid_jwt(self):
        assert oidc._decode_jwt_payload("not-a-jwt") == {}
        assert oidc._decode_jwt_payload("") == {}


class TestGeneratePkce:
    def test_generates_verifier_and_challenge(self):
        v, c = oidc._generate_pkce()
        assert len(v) <= 128
        assert len(c) > 0
        assert v != c


class TestAutoDetectIssuer:
    def test_returns_explicit_issuer(self):
        result = oidc.auto_detect_issuer("https://my-issuer", "ns", "/tmp", "client")
        assert result == "https://my-issuer"

    def test_from_gateway_values(self):
        values = {"oidc": {"enabled": True, "issuerUrl": "https://gw-issuer"}}
        with patch("openshell_saw.helm.get_values", return_value=values):
            result = oidc.auto_detect_issuer(None, "ns", "/nonexistent", "client")
        assert result == "https://gw-issuer"

    def test_from_token_file(self, tmp_path):
        token_file = tmp_path / "token.json"
        token_file.write_text(json.dumps({"issuer_url": "https://saved-issuer"}))
        with patch("openshell_saw.helm.get_values", return_value=None):
            result = oidc.auto_detect_issuer(None, "ns", str(tmp_path), "client")
        assert result == "https://saved-issuer"

    def test_from_keycloak_route(self):
        with (
            patch("openshell_saw.helm.get_values", return_value=None),
            patch("openshell_saw.kube.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(
                returncode=0, stdout="keycloak.apps.cluster.example.com"
            )
            result = oidc.auto_detect_issuer(None, "ns", "/nonexistent", "client")
        assert result == "https://keycloak.apps.cluster.example.com/realms/openshell"

    def test_none_when_nothing_found(self):
        with (
            patch("openshell_saw.helm.get_values", return_value=None),
            patch("openshell_saw.kube.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            result = oidc.auto_detect_issuer(None, "ns", "/nonexistent", "client")
        assert result is None


class TestGetToken:
    def test_returns_valid_token(self, tmp_path):
        token_file = tmp_path / "token.json"
        token_file.write_text(json.dumps({
            "access_token": "my-token",
            "saved_at": int(time.time()),
            "expires_in": 3600,
        }))
        result = oidc.get_token(str(tmp_path))
        assert result == "my-token"

    def test_returns_none_when_no_file(self, tmp_path):
        assert oidc.get_token(str(tmp_path)) is None

    def test_returns_none_when_expired_no_refresh(self, tmp_path):
        token_file = tmp_path / "token.json"
        token_file.write_text(json.dumps({
            "access_token": "expired-token",
            "saved_at": int(time.time()) - 7200,
            "expires_in": 3600,
        }))
        result = oidc.get_token(str(tmp_path))
        assert result is None


class TestSaveToken:
    def test_saves_token_file(self, tmp_path):
        response = {
            "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlIiwiZXhwIjoxOTk5OTk5OTk5fQ.sig",
            "expires_in": 300,
            "refresh_token": "refresh-abc",
        }
        oidc._save_token(response, "https://issuer", str(tmp_path))
        tf = tmp_path / "token.json"
        assert tf.exists()
        data = json.loads(tf.read_text())
        assert data["issuer_url"] == "https://issuer"
        assert "saved_at" in data


class TestLogout:
    def test_clears_token_file(self, tmp_path):
        token_file = tmp_path / "token.json"
        token_file.write_text(json.dumps({
            "access_token": "tok",
            "refresh_token": "ref",
            "issuer_url": "https://issuer",
        }))
        with (
            patch("openshell_saw.oidc._discover", return_value={"end_session_endpoint": "https://issuer/logout"}),
            patch("requests.post"),
            patch("openshell_saw.helm.list_sandboxes", return_value=[]),
        ):
            oidc.logout(str(tmp_path), "client", "ns")
        assert not token_file.exists()
