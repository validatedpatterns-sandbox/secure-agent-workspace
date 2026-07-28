"""Tests for config module."""

from unittest.mock import MagicMock, patch

import pytest

from openshell_saw import config


@pytest.fixture(autouse=True)
def clear_caches():
    config.repo_root.cache_clear()
    yield
    config.repo_root.cache_clear()


class TestLoadConfig:
    def test_defaults(self, tmp_path):
        with patch.object(config, "CONFIG_FILE", tmp_path / "nonexistent.yaml"):
            cfg = config.load_config()
        assert cfg["namespace"] == "openshell-agents"
        assert cfg["source_mode"] == "containerDisk"
        assert cfg["agent"] == "openclaw"
        assert cfg["oidc"]["client_id"] == "openshell-cli"
        assert cfg["oidc"]["flow"] == "browser"

    def test_user_override(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("namespace: my-ns\noidc:\n  flow: device-code\n")
        with patch.object(config, "CONFIG_FILE", cfg_file):
            cfg = config.load_config()
        assert cfg["namespace"] == "my-ns"
        assert cfg["oidc"]["flow"] == "device-code"
        assert cfg["oidc"]["client_id"] == "openshell-cli"


class TestRepoRoot:
    def test_env_var(self, tmp_path):
        (tmp_path / "helm").mkdir()
        with patch.dict("os.environ", {"OPENSHELL_REPO_ROOT": str(tmp_path)}):
            assert config.repo_root() == tmp_path

    def test_env_var_no_helm_dir(self, tmp_path):
        with patch.dict("os.environ", {"OPENSHELL_REPO_ROOT": str(tmp_path)}), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert config.repo_root() is None

    def test_git_fallback(self, tmp_path):
        (tmp_path / "helm").mkdir()
        with patch.dict("os.environ", {}, clear=True), patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=str(tmp_path)
            )
            assert config.repo_root() == tmp_path

    def test_no_repo(self):
        with patch.dict("os.environ", {}, clear=True), patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=128)
            assert config.repo_root() is None


class TestChartPath:
    def test_repo_chart(self, tmp_path):
        (tmp_path / "helm" / "openshell-sandbox").mkdir(parents=True)
        with patch.object(config, "repo_root", return_value=tmp_path):
            result = config.chart_path("openshell-sandbox")
        assert result == str(tmp_path / "helm" / "openshell-sandbox")

    def test_not_found(self):
        with patch.object(config, "repo_root", return_value=None), \
             pytest.raises(FileNotFoundError, match="Chart 'nonexistent' not found"):
            config.chart_path("nonexistent")


class TestSshPubkey:
    def test_reads_pubkey(self, tmp_path):
        key = tmp_path / "id_ed25519"
        pub = tmp_path / "id_ed25519.pub"
        pub.write_text("ssh-ed25519 AAAA... user@host")
        result = config.ssh_pubkey(str(key))
        assert result == "ssh-ed25519 AAAA... user@host"

    def test_missing_pubkey(self, tmp_path):
        key = tmp_path / "id_ed25519"
        with pytest.raises(FileNotFoundError, match="SSH public key not found"):
            config.ssh_pubkey(str(key))


class TestUserNamespace:
    def test_basic(self):
        assert config.user_namespace("alice") == "saw-alice"

    def test_uppercase(self):
        assert config.user_namespace("Alice") == "saw-alice"

    def test_special_chars(self):
        assert config.user_namespace("alice@example.com") == "saw-alice-example-com"

    def test_long_username(self):
        result = config.user_namespace("a" * 100)
        assert result.startswith("saw-")
        assert len(result) <= 62


class TestGetUsernameFromToken:
    def test_extracts_username(self, tmp_path):
        import base64
        import json
        payload = {"preferred_username": "alice", "sub": "user-id"}
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        token_data = {"access_token": f"header.{encoded}.sig"}
        (tmp_path / "token.json").write_text(json.dumps(token_data))
        assert config.get_username_from_token(str(tmp_path)) == "alice"

    def test_no_token_file(self, tmp_path):
        assert config.get_username_from_token(str(tmp_path)) is None

    def test_invalid_token(self, tmp_path):
        (tmp_path / "token.json").write_text('{"access_token": "bad"}')
        assert config.get_username_from_token(str(tmp_path)) is None
