"""Topology discovery and per-user preflight without a live cluster."""

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("network_topology", ROOT / "scripts/network-topology.py")
TOPOLOGY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOPOLOGY)


@pytest.fixture
def cluster(monkeypatch):
    objects = {
        ("get", "network.config", "cluster"): {"status": {
            "clusterNetwork": [{"cidr": "10.232.0.0/14"}],
            "serviceNetwork": ["172.231.0.0/16"]}},
        ("get", "service", "kubernetes", "-n", "default"): {"spec": {
            "clusterIP": "172.231.0.1", "ports": [{"protocol": "TCP", "port": 443}]}},
        ("get", "endpointslice", "-n", "default", "-l",
         "kubernetes.io/service-name=kubernetes"): {"items": [{
             "addressType": "IPv4", "ports": [{"protocol": "TCP", "port": 443}],
             "endpoints": [{"addresses": ["198.51.100.20"], "conditions": None}]}]},
        ("get", "nodes", "-l", "node-role.kubernetes.io/control-plane"): {"items": []},
    }
    monkeypatch.setattr(TOPOLOGY, "oc_json", lambda *args: objects[args])
    return objects


def test_discover_exact_hosted_api_and_reject_conflicting_overlay(tmp_path, cluster):
    output = tmp_path / "discovered.json"
    TOPOLOGY.discover(output, None)
    assert json.loads(output.read_text()) == {
        "networkPolicy": {"clusterNetworkCIDRs": ["10.232.0.0/14"],
                          "serviceNetworkCIDRs": ["172.231.0.0/16"]},
        "cleanupApi": {"serviceIP": "172.231.0.1",
                       "endpoints": [{"ip": "198.51.100.20", "port": 443}]}}
    values = tmp_path / "site.yaml"
    values.write_text(yaml.safe_dump({"cleanupApi": {
        "endpoints": [{"ip": "198.51.100.20", "port": 6443}]}}))
    output.unlink()
    with pytest.raises(TOPOLOGY.TopologyError, match="remove or correct that override"):
        TOPOLOGY.discover(output, values)
    assert not output.exists()


def test_enabled_pattern_user_requires_exact_topology(tmp_path, cluster, capsys):
    values = tmp_path / "users.yaml"
    live = TOPOLOGY.live_topology()
    values.write_text(yaml.safe_dump({"users": [
        {"name": "alice", "values": {"networkPolicy": {"enabled": False}}},
        {"name": "bob", "values": {"networkPolicy": {"enabled": True}}}],
        "defaults": {"openshellSaw": live}}))
    TOPOLOGY.check_pattern(values)
    assert "saw-bob" in capsys.readouterr().out
    site = yaml.safe_load(values.read_text())
    site["users"][1]["values"]["cleanupApi"] = {
        "endpoints": [{"ip": "198.51.100.21", "port": 443}]}
    values.write_text(yaml.safe_dump(site))
    with pytest.raises(TOPOLOGY.TopologyError, match="saw-bob.*endpoints differ") as exc:
        TOPOLOGY.check_pattern(values)
    assert "defaults:" in str(exc.value) and "198.51.100.20" in str(exc.value)
    site["users"][1]["values"].pop("cleanupApi")
    site["users"][1]["values"]["networkPolicy"]["clusterNetworkCIDRs"] = ["10.0.0.0/8"]
    values.write_text(yaml.safe_dump(site))
    with pytest.raises(TOPOLOGY.TopologyError, match="pod CIDRs differ"):
        TOPOLOGY.check_pattern(values)


def test_staged_user_is_off_and_hosted_cleanup_needs_endpoints(tmp_path, cluster, capsys):
    values = tmp_path / "users.yaml"
    values.write_text(yaml.safe_dump({"users": [{"name": "alice"}]}))
    TOPOLOGY.check_pattern(values)
    assert "staged off" in capsys.readouterr().out
    values.write_text(yaml.safe_dump({"users": [{"name": "alice", "pruneOnRemove": True}]}))
    with pytest.raises(TOPOLOGY.TopologyError, match="hosted control plane cleanup needs"):
        TOPOLOGY.check_pattern(values)
    site = yaml.safe_load(values.read_text())
    site["defaults"] = {"openshellSaw": TOPOLOGY.live_topology()}
    values.write_text(yaml.safe_dump(site))
    TOPOLOGY.check_pattern(values)
