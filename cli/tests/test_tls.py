"""Issuer trust uses verified cluster metadata, never the peer certificate."""
from unittest.mock import MagicMock, patch

import pytest

from openshell_saw import tls


def test_public_issuer_uses_default_trust(tmp_path):
    with patch.object(tls, "_oc_json", return_value={"spec": {"domain": "apps.cluster.test"}}):
        assert tls.prepare_ca_bundle("https://external.test/realm", tmp_path / "ca.pem") is None


def test_cluster_ca_is_scoped_to_ingress_domain(tmp_path):
    with patch.object(tls, "_oc_json", side_effect=[
        {"spec": {"domain": "apps.cluster.test"}},
        {"data": {"ca-bundle.crt": "cluster-ca"}},
    ]), patch.object(tls.ssl, "create_default_context") as context:
        context.return_value.get_ca_certs.return_value = []
        out = tmp_path / "ca.pem"
        assert tls.prepare_ca_bundle("https://kc.apps.cluster.test/realm", out) == str(out)
        assert out.read_text() == "cluster-ca"
        context.return_value.load_verify_locations.assert_called_once_with(cadata="cluster-ca")


@pytest.mark.parametrize("url", ["https://evilapps.cluster.test", "https://apps.cluster.test.evil"])
def test_domain_suffix_cannot_match_another_domain(tmp_path, url):
    with patch.object(tls, "_oc_json", return_value={"spec": {"domain": "apps.cluster.test"}}) as oc:
        assert tls.prepare_ca_bundle(url, tmp_path / "ca.pem") is None
        assert oc.call_count == 1


def test_explicit_bundle_wins_without_cluster_access(tmp_path, monkeypatch):
    ca = tmp_path / "private CA.pem"
    ca.write_text("configured-ca")
    monkeypatch.setenv("OIDC_CA_BUNDLE", str(ca))
    with patch.object(tls, "_oc_json") as oc, patch.object(tls.ssl, "create_default_context"):
        assert tls.prepare_ca_bundle("https://external.test", tmp_path / "out") == str(ca)
        oc.assert_not_called()


def test_missing_explicit_bundle_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("OIDC_CA_BUNDLE", str(tmp_path / "missing"))
    with pytest.raises((OSError, ValueError)):
        tls.prepare_ca_bundle("https://external.test", tmp_path / "out")


def test_cluster_access_failure_preserves_system_verification(tmp_path):
    with patch.object(tls.subprocess, "run", return_value=MagicMock(returncode=1)):
        assert tls.prepare_ca_bundle("https://external.test", tmp_path / "out") is None


def test_http_issuer_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="HTTPS"):
        tls.prepare_ca_bundle("http://issuer.test", tmp_path / "out")


def test_unreadable_cluster_ca_keeps_verification_enabled(tmp_path):
    with patch.object(tls, "_oc_json", side_effect=[
        {"spec": {"domain": "apps.cluster.test"}}, {},
    ]):
        assert tls.prepare_ca_bundle("https://kc.apps.cluster.test", tmp_path / "out") is None


def test_invalid_cluster_ca_is_refused(tmp_path):
    with patch.object(tls, "_oc_json", side_effect=[
        {"spec": {"domain": "apps.cluster.test"}}, {"data": {"ca-bundle.crt": "not a certificate"}},
    ]), pytest.raises((OSError, ValueError)):
        tls.prepare_ca_bundle("https://kc.apps.cluster.test", tmp_path / "out")
    assert not (tmp_path / "out").exists()
