"""Tests for CLI commands (click integration tests)."""

from unittest.mock import patch

from click.testing import CliRunner

from openshell_saw.cli import main


@patch("openshell_saw.config.repo_root", return_value=None)
class TestHelp:
    def test_main_help(self, _):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Secure Agent Workspace" in result.output
        assert "sandbox" in result.output
        assert "login" in result.output

    def test_sandbox_help(self, _):
        runner = CliRunner()
        result = runner.invoke(main, ["sandbox", "--help"])
        assert result.exit_code == 0
        assert "create" in result.output
        assert "list" in result.output
        assert "delete" in result.output

    def test_build_help(self, _):
        runner = CliRunner()
        result = runner.invoke(main, ["build", "--help"])
        assert result.exit_code == 0
        assert "gateway-image" in result.output


@patch("openshell_saw.config.repo_root", return_value=None)
class TestSandboxList:
    def test_empty_list(self, _):
        with patch("openshell_saw.helm.list_sandboxes", return_value=[]):
            runner = CliRunner()
            result = runner.invoke(main, ["sandbox", "list"])
            assert result.exit_code == 0
            assert "No sandboxes found" in result.output

    def test_with_sandboxes(self, _):
        sandboxes = [
            {
                "name": "test-sb",
                "status": "deployed",
                "vm_status": "Running",
                "updated": "2026-07-27 10:00:00",
            }
        ]
        with patch("openshell_saw.helm.list_sandboxes", return_value=sandboxes):
            runner = CliRunner()
            result = runner.invoke(main, ["sandbox", "list"])
            assert result.exit_code == 0
            assert "test-sb" in result.output
            assert "Running" in result.output


@patch("openshell_saw.config.repo_root", return_value=None)
class TestSandboxUrl:
    def test_shows_urls(self, _):
        with patch("openshell_saw.kube.get_route_url") as mock_route:
            mock_route.side_effect = lambda name, ns: (
                "https://gw.example.com" if "gateway" in name
                else "https://dash.example.com"
            )
            runner = CliRunner()
            result = runner.invoke(main, ["sandbox", "url", "my-sb"])
            assert result.exit_code == 0
            assert "https://gw.example.com" in result.output
            assert "https://dash.example.com" in result.output

    def test_not_found(self, _):
        with patch("openshell_saw.kube.get_route_url", return_value=None):
            runner = CliRunner()
            result = runner.invoke(main, ["sandbox", "url", "my-sb"])
            assert result.exit_code == 0
            assert "route not found" in result.output


@patch("openshell_saw.config.repo_root", return_value=None)
class TestSandboxCreate:
    def test_missing_provider(self, _):
        runner = CliRunner()
        result = runner.invoke(main, ["sandbox", "create", "test"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_create_no_oidc(self, _, tmp_path):
        with (
            patch("openshell_saw.oidc.auto_detect_issuer", return_value=None),
            patch("openshell_saw.config.ssh_pubkey", return_value="ssh-ed25519 AAAA"),
            patch("openshell_saw.kube.ensure_ssh_secret"),
            patch("openshell_saw.config.chart_path", return_value="/charts/sandbox"),
            patch("openshell_saw.helm.install_chart"),
            patch("openshell_saw.kube.get_route_url", return_value=None),
        ):
            runner = CliRunner()
            result = runner.invoke(main, [
                "sandbox", "create", "test",
                "--provider", "gemini",
                "--model", "gemini-2.5-flash",
                "--api-key", "key123",
            ])
            assert result.exit_code == 0
            assert "deployed" in result.output.lower()


@patch("openshell_saw.config.repo_root", return_value=None)
class TestNamespaceOverride:
    def test_namespace_flag(self, _):
        with patch("openshell_saw.helm.list_sandboxes", return_value=[]) as mock_list:
            runner = CliRunner()
            result = runner.invoke(main, ["-n", "custom-ns", "sandbox", "list"])
            assert result.exit_code == 0
            mock_list.assert_called_once_with("custom-ns")

    def test_auto_namespace_from_token(self, _):
        with (
            patch("openshell_saw.config.get_username_from_token", return_value="alice"),
            patch("openshell_saw.helm.list_sandboxes", return_value=[]) as mock_list,
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["sandbox", "list"])
            assert result.exit_code == 0
            mock_list.assert_called_once_with("saw-alice")

    def test_namespace_flag_overrides_token(self, _):
        with (
            patch("openshell_saw.config.get_username_from_token", return_value="alice"),
            patch("openshell_saw.helm.list_sandboxes", return_value=[]) as mock_list,
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["-n", "my-ns", "sandbox", "list"])
            assert result.exit_code == 0
            mock_list.assert_called_once_with("my-ns")

    def test_no_token_uses_default(self, _):
        with (
            patch("openshell_saw.config.get_username_from_token", return_value=None),
            patch("openshell_saw.helm.list_sandboxes", return_value=[]) as mock_list,
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["sandbox", "list"])
            assert result.exit_code == 0
            mock_list.assert_called_once_with("openshell-agents")
