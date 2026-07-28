"""Tests for helm module."""

import json
from unittest.mock import MagicMock, patch

import pytest

from openshell_saw import helm


class TestInstallChart:
    def test_basic_install(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            helm.install_chart("my-release", "/charts/my-chart", "my-ns")
            args = mock_run.call_args[0][0]
            assert args[:6] == [
                "helm", "upgrade", "--install", "my-release", "/charts/my-chart",
                "--namespace",
            ]
            assert "my-ns" in args
            assert "--create-namespace" in args

    def test_with_sets(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            helm.install_chart(
                "rel", "/chart", "ns",
                sets={"key1": "val1", "key2": "val2"},
            )
            args = mock_run.call_args[0][0]
            assert "--set" in args
            idx = args.index("--set")
            assert args[idx + 1] == "key1=val1"

    def test_with_set_strings(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            helm.install_chart(
                "rel", "/chart", "ns",
                set_strings={"token": "abc123"},
            )
            args = mock_run.call_args[0][0]
            assert "--set-string" in args

    def test_failure_raises(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            with pytest.raises(RuntimeError, match="Helm install failed"):
                helm.install_chart("rel", "/chart", "ns")


class TestUninstall:
    def test_uninstall(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            helm.uninstall("my-release", "my-ns")
            args = mock_run.call_args[0][0]
            assert args == ["helm", "uninstall", "my-release", "--namespace", "my-ns"]


class TestListReleases:
    def test_returns_releases(self):
        releases = [{"name": "test", "chart": "openshell-sandbox-0.1.0"}]
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=json.dumps(releases)
            )
            result = helm.list_releases("ns")
        assert len(result) == 1
        assert result[0]["name"] == "test"

    def test_empty_on_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            result = helm.list_releases("ns")
        assert result == []


class TestListSandboxes:
    def test_filters_sandbox_charts(self):
        releases = [
            {"name": "sb1", "chart": "openshell-sandbox-0.1.0", "status": "deployed", "updated": "2026-07-27 10:00:00.123"},
            {"name": "gw", "chart": "openshell-gateway-0.1.0", "status": "deployed", "updated": "2026-07-27 09:00:00.456"},
        ]
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=json.dumps(releases)
            )
            with patch("openshell_saw.kube.list_vms", return_value={"sb1": "Running"}):
                result = helm.list_sandboxes("ns")
        assert len(result) == 1
        assert result[0]["name"] == "sb1"
        assert result[0]["vm_status"] == "Running"


class TestGetValues:
    def test_returns_values(self):
        values = {"oidc": {"enabled": True, "issuerUrl": "https://keycloak/realms/openshell"}}
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=json.dumps(values)
            )
            result = helm.get_values("release", "ns")
        assert result == values

    def test_none_on_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            result = helm.get_values("release", "ns")
        assert result is None
