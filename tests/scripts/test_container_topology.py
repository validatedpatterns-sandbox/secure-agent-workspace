"""Role-scoped topology, review protection, and the in-Pod HTTPS check."""
import copy
import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


topo = module("container_topology")
probe = module("oidc_topology_probe")


@pytest.fixture
def cluster(monkeypatch):
    calls = []
    addresses = ["10.10.10.101", "10.10.10.102"]
    def command(*args):
        calls.append(args)
        if "print-json" in args:
            return json.dumps({"cleanupApi": {"serviceIP": "172.30.0.1", "endpoints": [
                {"ip": "10.10.1.2", "port": 6443}]}})
        if "dns-default" in args:
            return json.dumps({"spec": {"clusterIP": "172.30.0.10",
                "selector": {"dns.operator.openshift.io/daemonset-dns": "default"},
                "ports": [{"name": p.lower(), "port": 53, "protocol": p} for p in ["TCP", "UDP"]]}})
        if "endpointslice" in args:
            return json.dumps({"items": [{"addressType": "IPv4", "ports": [
                {"name": p.lower(), "port": 5353, "protocol": p} for p in ["UDP", "TCP"]]}]})
        if "ingress.config.openshift.io" in args:
            return '{"spec":{"domain":"apps.cluster.example.test"}}'
        if args[0].endswith("keycloak-host.sh"):
            return "keycloak.apps.cluster.example.test"
        if "exec" in args:
            assert args[1:5] == ("-n", "trusted-tools", "exec", "pod/network-probe")
            return json.dumps(addresses)
        pytest.fail(f"unexpected command: {args[:3]}")
    monkeypatch.setattr(topo, "command", command)
    return addresses, calls


@pytest.fixture
def base():
    site = yaml.safe_load((ROOT / "tests/fixtures/container-site.yaml").read_text())["portal"]["containerSites"]["alice"]
    site["automaticEnrollment"]["enabled"] = False
    for prefix, field in [(topo.GATEWAY + ("kubernetes", "network"), "gatewayEgress"),
                          (topo.BOOTSTRAP[:-1], "bootstrapEgress"), (topo.RELAY, "egress")]:
        topo.path_value(site, prefix)[field] = []
    return {"containerSites": {"alice": site}, "global": {"clusterDomain": "cluster.example.test"}}


def test_overlay_uses_one_probe_and_preserves_separation(base, cluster):
    addresses, calls = cluster
    site = base["containerSites"]["alice"]
    operator_rule = {"to": [{"podSelector": {"matchLabels": {"role": "proxy"}}}],
                     "ports": [{"port": 3128, "protocol": "TCP"}]}
    topo.path_value(site, topo.GATEWAY + ("kubernetes", "network", "gatewayEgress")).append(operator_rule)
    base["portal"] = {"containerSites": {"alice": copy.deepcopy(site)}}
    before = copy.deepcopy(base)
    overlay = topo.container_overlay(base, "trusted-tools/network-probe", "tools")
    assert base == before
    assert len([c for c in calls if "exec" in c]) == 1
    assert overlay["portal"]["containerSites"] == overlay["containerSites"]
    result = overlay["containerSites"]["alice"]
    gateway = topo.path_value(result, topo.GATEWAY + ("kubernetes", "network", "gatewayEgress"))
    relay = topo.path_value(result, topo.RELAY + ("egress",))
    bootstrap = topo.path_value(result, topo.BOOTSTRAP)
    assert gateway == [operator_rule, *relay]
    assert relay == bootstrap + [topo.host_rule(ip, 443) for ip in addresses]
    assert bootstrap == overlay["projection"]["egress"]
    assert topo.host_rule("172.30.0.1", 443) in bootstrap
    assert topo.host_rule("10.10.1.2", 6443) in bootstrap
    assert topo.host_rule("10.10.1.2", 443) not in bootstrap
    assert {"to": [{"ipBlock": {"cidr": "172.30.0.10/32"}}],
            "ports": [{"protocol": "TCP", "port": 53}, {"protocol": "UDP", "port": 53}]} in bootstrap
    assert set(result["stack"]) == {"gateway", "proxy"}
    assert set(result["stack"]["proxy"]["values"]["network"]) == {"bootstrapEgress"}


def test_make_bootstrap_saves_once_enrolled_apply_rechecks_and_delete_works_offline(base, cluster, tmp_path):
    values = copy.deepcopy(base)
    file = tmp_path / "net.yaml"
    topo.install_values(values, "alice", file, "trusted-tools/network-probe", None, verify=True)
    approved = file.read_bytes()
    cluster[0].append("10.10.10.103")
    with pytest.raises(ValueError, match="stale"):
        topo.install_values(copy.deepcopy(base), "alice", file, "trusted-tools/network-probe", None, verify=True)
    assert file.read_bytes() == approved
    calls = len(cluster[1])
    topo.install_values(copy.deepcopy(base), "alice", file, None, None, verify=False)
    assert len(cluster[1]) == calls
    base["containerSites"]["alice"]["automaticEnrollment"]["enabled"] = True
    with pytest.raises(ValueError, match="review"):
        topo.install_values(base, "alice", tmp_path/"missing", "trusted-tools/network-probe", None, verify=True)
    assert not (tmp_path/"missing").exists()


def test_default_and_conflicting_issuer(base, cluster):
    site = base["containerSites"]["alice"]
    del topo.path_value(site, topo.GATEWAY + ("oidc",))["issuerUrl"]
    del topo.path_value(site, topo.RELAY)["issuer"]
    result = topo.container_overlay(base, "trusted-tools/network-probe")
    assert topo.path_value(result["containerSites"]["alice"], topo.RELAY + ("issuer",)) == (
        "https://keycloak.apps.cluster.example.test/realms/openshell")
    topo.put(site, topo.RELAY + ("issuer",), "https://a.example/realm")
    topo.put(site, topo.GATEWAY + ("oidc", "issuerUrl"), "https://b.example/realm")
    with pytest.raises(ValueError, match="same issuer"):
        topo.container_overlay(base, "trusted-tools/network-probe")


@pytest.mark.parametrize("url", ["http://issuer.example", "https://me@issuer.example", "https://issuer.example?q=1",
                                 "https://issuer.example/#here", "https://issuer.example:0",
                                 "https://issuer.example?", "https://issuer.example/#", "https://issuer.example\\path"])
def test_unsafe_issuer_rejected_before_exec(url, cluster):
    with pytest.raises(ValueError):
        topo.discover_issuer(url, "trusted-tools/network-probe", None)
    assert not cluster[1]


@pytest.mark.parametrize(("status", "claimed", "passes"), [(200, "https://k.test:8443/realm", True),
    (302, "https://k.test:8443/realm", False), (200, "https://different.test/realm", False)])
def test_each_address_uses_original_tls_name_and_checks_document(monkeypatch, status, claimed, passes):
    hosts = ["10.0.0.50", "10.0.0.51"]
    tls = MagicMock()
    monkeypatch.setattr(probe.ssl, "create_default_context", lambda: tls)
    monkeypatch.setattr(probe.socket, "getaddrinfo", lambda *a, **kw: [(None, None, None, None, (ip, 8443)) for ip in hosts])
    connect = MagicMock()
    monkeypatch.setattr(probe.socket, "create_connection", connect)
    https = MagicMock()
    monkeypatch.setattr(probe.http.client, "HTTPSConnection", https)
    response = https.return_value.getresponse.return_value
    response.status = status
    response.read.return_value = json.dumps({"issuer": claimed}).encode()
    issuer = "https://k.test:8443/realm"
    if not passes:
        with pytest.raises(ValueError, match="mismatch"):
            probe.probe(issuer)
        return
    assert probe.probe(issuer) == hosts
    assert [c.args[0] for c in connect.call_args_list] == [(ip, 8443) for ip in hosts]
    assert all(c.kwargs["server_hostname"] == "k.test" for c in tls.wrap_socket.call_args_list)
    assert all(c.args == ("GET", "/realm/.well-known/openid-configuration") for c in https.return_value.request.call_args_list)


@pytest.mark.parametrize("bad", ["127.0.0.1", "169.254.169.254", "224.0.0.1", "::1"])
def test_probe_refuses_unsafe_or_unhandled_answers(monkeypatch, bad):
    monkeypatch.setattr(probe.socket, "getaddrinfo", lambda *a, **kw: [(None, None, None, None, (bad, 443))])
    connect = MagicMock()
    monkeypatch.setattr(probe.socket, "create_connection", connect)
    with pytest.raises(ValueError, match="unsafe"):
        probe.probe("https://keycloak.example/realms/openshell")
    connect.assert_not_called()


@pytest.mark.parametrize("hostname", ["issuer.example", "wrong.example"])
def test_probe_verifies_certificate_over_real_tls(tmp_path, monkeypatch, hostname):
    import socket
    import ssl
    import subprocess
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=issuer.example", "-addext", "subjectAltName=DNS:issuer.example",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    issuer = f"https://{hostname}/realms/test"
    response_read = Event()
    client_sock, server_sock = socket.socketpair()
    for sock in (client_sock, server_sock):
        sock.settimeout(5)
    monkeypatch.setattr(probe.socket, "getaddrinfo",
                        lambda *args, **kwargs: [(None, None, None, None, ("10.0.1.2", 443))])
    monkeypatch.setattr(probe.socket, "create_connection", lambda *args, **kwargs: client_sock)

    def serve():
        with server.wrap_socket(server_sock, server_side=True) as stream:
            with stream.makefile("rb") as request:
                assert request.readline() == b"GET /realms/test/.well-known/openid-configuration HTTP/1.1\r\n"
                headers = []
                while (line := request.readline()) not in (b"\r\n", b""):
                    headers.append(line)
                assert b"Host: issuer.example\r\n" in headers
            payload = json.dumps({"issuer": issuer}).encode()
            stream.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\n\r\n".encode() + payload)
            assert response_read.wait(timeout=5)

    with client_sock, server_sock, ThreadPoolExecutor(max_workers=1) as pool:
        served = pool.submit(serve)
        if hostname == "issuer.example":
            try:
                assert probe.probe(issuer) == ["10.0.1.2"]
            finally:
                response_read.set()
            served.result(timeout=5)
        else:
            with pytest.raises(ssl.SSLCertVerificationError):
                probe.probe(issuer)
            with pytest.raises(ssl.SSLError):
                served.result(timeout=5)


@pytest.mark.ci_external
def test_make_commands_and_helm_gateway_policy(tmp_path, monkeypatch, base):
    import subprocess
    import os
    import sys

    # The synthetic oc is only a cluster fixture. Exercise the real VM discovery
    # script, Make entry points, YAML review comparison and stock Helm template.
    oc = tmp_path / "oc"
    oc.write_text("""#!/usr/bin/env python3
import sys, json, os
args = sys.argv[1:]
if "exec" in args:
    data = [os.environ["MOCK_ISSUER_IP"]]
elif "network.config" in args:
    data = {"status":{"clusterNetwork":[{"cidr":"10.128.0.0/14"}],"serviceNetwork":["172.30.0.0/16"]}}
elif "ingress.config.openshift.io" in args:
    data = {"spec":{"domain":"apps.cluster.example.test"}}
elif "service" in args and "kubernetes" in args:
    data = {"spec":{"clusterIP":"172.30.0.1","ports":[{"port":443}]}}
elif "endpointslice" in args and "default" in args:
    data = {"items":[{"addressType":"IPv4","ports":[{"port":6443}],"endpoints":[{"addresses":["10.0.0.3"]}]}]}
elif "service" in args and "dns-default" in args:
    data = {"spec":{"clusterIP":"172.30.0.10","selector":{"dns.operator.openshift.io/daemonset-dns":"default"},
        "ports":[{"name":p.lower(),"port":53,"protocol":p} for p in ["UDP","TCP"]]}}
elif "endpointslice" in args and "openshift-dns" in args:
    data = {"items":[{"addressType":"IPv4","ports":[{"name":p.lower(),"port":5353,"protocol":p} for p in ["UDP","TCP"]]}]}
else:
    sys.exit(3)
print(json.dumps(data))
""")
    oc.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("MOCK_ISSUER_IP", "10.10.10.101")
    base_file = tmp_path / "site.yaml"
    out = tmp_path / "overlay.yaml"
    base_file.write_text(yaml.safe_dump(base))
    monkeypatch.setenv("SAW_USERS_VALUES_FILE", str(base_file))
    monkeypatch.setenv("SAW_TOPOLOGY_OVERLAY", str(out))
    monkeypatch.setenv("SAW_TOPOLOGY_PROBE", "trusted-tools/network-probe")
    make = ["make", "--no-print-directory", "PYTHON=" + sys.executable]
    out.write_text(subprocess.check_output([*make, "container-topology"], text=True, cwd=ROOT))
    subprocess.run([*make, "check-container-topology"], check=True, cwd=ROOT)
    gateway = yaml.safe_load(out.read_text())["containerSites"]["alice"]["stack"]["gateway"]["values"]
    rendered = subprocess.check_output(["helm", "template", "saw-test", "charts/openshell-saw-kubernetes",
        "-n", "saw-test", "--api-versions", "agents.x-k8s.io/v1beta1/Sandbox",
        "--api-versions", "policy.networking.k8s.io/v1alpha1/AdminNetworkPolicy", "-f", "tests/fixtures/saw-kubernetes-values.yaml",
        "-f", "-"], input=yaml.safe_dump(gateway), text=True, cwd=ROOT)
    policies = [r for r in yaml.safe_load_all(rendered) if r and r["kind"] == "NetworkPolicy"]
    matching = [r for r in policies if topo.host_rule("10.10.10.101", 443) in r["spec"].get("egress", [])]
    assert len(matching) == 1 and matching[0]["spec"]["podSelector"]["matchLabels"]["openshell.pattern/role"] == "gateway"
    monkeypatch.setenv("MOCK_ISSUER_IP", "10.10.10.111")
    drift = subprocess.run([*make, "check-container-topology"], text=True, cwd=ROOT, capture_output=True)
    assert drift.returncode and "topology drift" in drift.stderr
