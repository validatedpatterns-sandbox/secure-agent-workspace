"""Tests for oidc module."""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from openshell_saw import oidc


@pytest.fixture(autouse=True)
def no_live_cluster(monkeypatch):
    monkeypatch.setattr(oidc.tls, "_oc_json", lambda *args: {})


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

    def test_from_keycloak_status(self):
        with patch("openshell_saw.kube.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="https://keycloak.example.com")
            result = oidc.auto_detect_issuer(None, "ns", "/nonexistent", "client")
        assert result == "https://keycloak.example.com/realms/openshell"

    def test_from_token_file(self, tmp_path):
        token_file = tmp_path / "token.json"
        token_file.write_text(json.dumps({"issuer_url": "https://saved-issuer"}))
        with patch("openshell_saw.kube.run", return_value=MagicMock(returncode=1, stdout="")):
            result = oidc.auto_detect_issuer(None, "ns", str(tmp_path), "client")
        assert result == "https://saved-issuer"

    def test_from_keycloak_route(self):
        with (
            patch("openshell_saw.kube.run") as mock_run,
        ):
            mock_run.side_effect = [
                MagicMock(returncode=1, stdout=""),
                MagicMock(returncode=0, stdout="keycloak.apps.cluster.example.com"),
            ]
            result = oidc.auto_detect_issuer(None, "ns", "/nonexistent", "client")
        assert result == "https://keycloak.apps.cluster.example.com/realms/openshell"

    def test_none_when_nothing_found(self):
        with (
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
            "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlIiwiZXhwIjoxOTk5OTk5OTk5fQ.sig",  # notsecret
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
            patch("requests.post") as post,
            patch("openshell_saw.helm.list_sandboxes", return_value=[]),
        ):
            oidc.logout(str(tmp_path), "client", "ns")
        assert not token_file.exists()
        assert post.call_args.kwargs["verify"] is not False


def test_discovery_verifies_tls():
    with patch("requests.get") as get:
        oidc._discover("https://external.test")
    assert get.call_args.kwargs["verify"] is not False


def test_device_authorization_and_poll_verify_tls(tmp_path):
    import base64
    import hashlib

    with patch("requests.post") as post, patch.object(oidc.time, "sleep"):
        post.side_effect = [
            MagicMock(status_code=200, json=lambda: {"device_code": "code", "interval": 0,
                                                    "verification_uri": "https://external.test/verify"}),
            MagicMock(json=lambda: {"access_token": "tok", "expires_in": 300}),
        ]
        oidc._device_login("https://external.test", {
            "device_authorization_endpoint": "https://external.test/device",
            "token_endpoint": "https://external.test/token",
        }, "client", str(tmp_path))
    assert all(call.kwargs["verify"] is not False for call in post.call_args_list)
    authorization, poll = [call.kwargs["data"] for call in post.call_args_list]
    assert authorization["code_challenge_method"] == "S256"
    verifier = poll["code_verifier"]
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert authorization["code_challenge"] == expected


def test_browser_token_exchange_verifies_tls(tmp_path):
    with patch("requests.post") as post, patch.object(oidc, "_wait_for_callback", return_value="code"), \
            patch.object(oidc.webbrowser, "open"):
        post.return_value = MagicMock(status_code=200, json=lambda: {"access_token": "tok"})
        oidc._browser_login("https://external.test", {
            "authorization_endpoint": "https://external.test/auth",
            "token_endpoint": "https://external.test/token",
        }, "client", str(tmp_path), 8400)
    assert post.call_args.kwargs["verify"] is not False


def test_refresh_verifies_tls(tmp_path):
    (tmp_path / "token.json").write_text(json.dumps({
        "refresh_token": "ref", "issuer_url": "https://external.test", "saved_at": 0,
    }))
    with patch("requests.get") as get, patch("requests.post") as post:
        get.return_value.json.return_value = {"token_endpoint": "https://external.test/token"}
        post.return_value = MagicMock(status_code=200, json=lambda: {"access_token": "new"})
        assert oidc.get_token(str(tmp_path)) == "new"
    assert get.call_args.kwargs["verify"] is not False
    assert post.call_args.kwargs["verify"] is not False


def test_login_ca_option_reaches_oidc(tmp_path):
    from click.testing import CliRunner
    from openshell_saw.cli import main

    ca = tmp_path / "custom CA.pem"
    ca.write_text("configured by the caller")
    with patch.object(oidc, "login") as login:
        result = CliRunner().invoke(main, ["login", "--ca-bundle", str(ca)])
    assert result.exit_code == 0, result.output
    assert login.call_args.kwargs["ca_bundle"] == str(ca)


@pytest.mark.parametrize("url", ["http://issuer.test/auth", "https://user:pass@issuer.test/auth"])
def test_browser_rejects_unsafe_authorization_url(tmp_path, url):
    with patch.object(oidc.webbrowser, "open") as browser, \
            patch.object(oidc, "_wait_for_callback", return_value=None):
        with pytest.raises(ValueError, match="HTTPS"):
            oidc._browser_login("https://issuer.test", {
                "authorization_endpoint": url, "token_endpoint": "https://issuer.test/token",
            }, "client", str(tmp_path), 8400)
        browser.assert_not_called()


def test_device_rejects_http_verification_url(tmp_path, capsys):
    response = MagicMock(status_code=200, json=lambda: {
        "device_code": "code", "verification_uri": "http://issuer.test/verify",
    })
    with patch("requests.post", return_value=response) as post:
        with pytest.raises(ValueError, match="HTTPS"):
            oidc._device_login("https://issuer.test", {
                "device_authorization_endpoint": "https://issuer.test/device",
                "token_endpoint": "https://issuer.test/token",
            }, "client", str(tmp_path))
        assert post.call_count == 1
    assert "http://issuer.test/verify" not in capsys.readouterr().out
