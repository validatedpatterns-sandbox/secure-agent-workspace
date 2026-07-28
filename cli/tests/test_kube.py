"""Tests for kube module."""

import json
from unittest.mock import MagicMock, patch

from openshell_saw import kube


class TestGetRouteUrl:
    def test_returns_url(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="https://my-route.apps.cluster.example.com"
            )
            result = kube.get_route_url("my-route", "ns")
        assert result == "https://my-route.apps.cluster.example.com"

    def test_none_on_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            result = kube.get_route_url("my-route", "ns")
        assert result is None


class TestGetVmStatus:
    def test_returns_status(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="Running"
            )
            assert kube.get_vm_status("vm1", "ns") == "Running"

    def test_na_on_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert kube.get_vm_status("vm1", "ns") == "n/a"


class TestEnsureSshSecret:
    def test_creates_secret(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="apiVersion: v1\nkind: Secret\n"),
                MagicMock(returncode=0, stdout="secret/openshell-aap-ssh configured"),
            ]
            kube.ensure_ssh_secret("/path/to/key", "ns")
            assert mock_run.call_count == 2

    def test_raises_on_dry_run_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="error")
            import pytest
            with pytest.raises(RuntimeError, match="Failed to create SSH secret"):
                kube.ensure_ssh_secret("/path/to/key", "ns")


class TestRunInVm:
    def test_success(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ok")
            ok, out = kube.run_in_vm("vm1", "ns", "echo hello")
        assert ok is True
        assert out == "ok"

    def test_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            ok, out = kube.run_in_vm("vm1", "ns", "echo hello")
        assert ok is False


class TestListVms:
    def test_returns_vm_statuses(self):
        vms = {
            "items": [
                {"metadata": {"name": "vm1"}, "status": {"printableStatus": "Running"}},
                {"metadata": {"name": "vm2"}, "status": {"printableStatus": "Stopped"}},
            ]
        }
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=json.dumps(vms)
            )
            result = kube.list_vms("ns")
        assert result == {"vm1": "Running", "vm2": "Stopped"}

    def test_empty_on_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            assert kube.list_vms("ns") == {}
