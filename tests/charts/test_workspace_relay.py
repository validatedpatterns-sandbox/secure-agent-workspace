import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml
from helm_cache import run_helm

CHART = Path(__file__).resolve().parents[2] / "charts/saw-workspace-relay"
pytestmark = [pytest.mark.ci_external, pytest.mark.skipif(not shutil.which("helm"), reason="Helm required")]


def test_secret_and_membership_boundaries(tmp_path):
    values = dict(enabled=True, clientID="site-agent", keycloakNamespace="kc", keycloakAdminSecret="kc-admin",
                  issuer="https://kc.example/realms/openshell", trustedNamespace="trusted", gatewayNamespace="runtime",
                  installationID="installation", gateway="gateway", workspace="agent", workspaceID="old-id",
                  sandbox="assistant", ownerLogin="alice", ownerSubject="owner", subject="relay",
                  imageBuildNamespace="build", sdkImage="example/sdk@sha256:"+"f"*64,
                  host="alice.apps.example", egress=[{"ports":[{"port":443}]}])
    path = tmp_path / "values.yaml"
    path.write_text(yaml.safe_dump(values))
    output = run_helm(["helm","template","relay",str(CHART),"-n","ui","-f",str(path)],
                      capture_output=True,text=True)
    assert output.returncode == 0, output.stderr
    resources = list(yaml.safe_load_all(output.stdout))
    deployment = next(d for d in resources if d["kind"] == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert [v["secret"]["secretName"] for v in pod["volumes"] if "secret" in v] == ["relay-credentials"]
    containers = {c["name"]:c for c in pod["containers"]}
    assert "credential" not in {v["name"] for v in containers["forward"]["volumeMounts"]}
    assert "--local 127.0.0.1:28789" in containers["forward"]["args"][0]
    assert containers["transport"]["command"] == ["python3", "-I", "/config/saw_ui_limit.py", "18789", "28789", "16", "--connect-only"]
    assert containers["transport"]["volumeMounts"] == [{"name": "config", "mountPath": "/config", "readOnly": True}]
    assert containers["transport"]["securityContext"] == containers["forward"]["securityContext"]
    canonical = CHART.parent / "openshell-saw/files/installer/saw_ui_limit.py"
    assert (CHART / "files/saw_ui_limit.py").read_bytes() == canonical.read_bytes()
    config = next(d for d in resources if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "relay")
    assert config["data"]["saw_ui_limit.py"] == canonical.read_text()
    assert "--authenticated-emails-file=/config/users" in containers["browser-login"]["args"]
    jobs = {d["metadata"]["namespace"]:d["spec"]["template"]["spec"] for d in resources if d["kind"]=="Job"}
    assert jobs["trusted"]["automountServiceAccountToken"] is False
    assert not any("secret" in v for v in jobs["trusted"]["volumes"])
    volumes = {v["name"]: v for v in jobs["trusted"]["volumes"]}
    assert volumes["identity"]["configMap"]["name"] == "gateway-gateway-ca"
    assert volumes["admin-session"]["emptyDir"] == {"medium": "Memory", "sizeLimit": "4Mi"}
    runtime_role = next(d for d in resources if d["kind"] == "Role" and d["metadata"]["namespace"] == "runtime")
    assert runtime_role["rules"] == [{"apiGroups": [""], "resources": ["secrets"],
                                     "resourceNames": ["gateway-client-ca"], "verbs": ["get", "update"]}]
    binding = next(d for d in resources if d["kind"] == "RoleBinding" and d["metadata"].get("namespace") == "runtime")
    assert binding["subjects"] == [{"kind": "ServiceAccount", "name": "relay", "namespace": "trusted"}]
    assert [v["secret"]["secretName"] for v in jobs["kc"]["volumes"] if "secret" in v] == ["kc-admin"]
    role = next(d for d in resources if d["kind"]=="Role" and d["metadata"].get("namespace", "ui") == "ui")
    assert role["rules"] == [{"apiGroups":[""],"resources":["secrets"],"resourceNames":["relay-credentials"],"verbs":["get","patch"]}]


def test_rendered_transport_starts_beside_projected_token_module(tmp_path):
    values = dict(enabled=True, clientID="site-agent", keycloakNamespace="kc", keycloakAdminSecret="kc-admin",
                  issuer="https://kc.example/realms/openshell", trustedNamespace="trusted", gatewayNamespace="runtime",
                  installationID="installation", gateway="gateway", workspace="agent", workspaceID="workspace-id",
                  sandbox="assistant", ownerLogin="alice", ownerSubject="owner", subject="relay",
                  imageBuildNamespace="build", sdkImage="example/sdk@sha256:"+"f"*64,
                  host="alice.apps.example", egress=[{"ports":[{"port":443}]}])
    rendered = subprocess.run(["helm", "template", "relay", str(CHART), "-n", "ui", "-f", "-"],
                              input=yaml.safe_dump(values), capture_output=True, text=True, check=True)
    docs = list(yaml.safe_load_all(rendered.stdout))
    config = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "relay")
    pod = next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]
    command = list(next(c for c in pod["containers"] if c["name"] == "transport")["command"])
    script = tmp_path / "saw_ui_limit.py"
    script.write_text(config["data"]["saw_ui_limit.py"])
    # Projected token.py is an OIDC helper, not Python's stdlib token module.
    # asyncio -> logging -> tokenize must not import it from the script directory.
    (tmp_path / "token.py").write_text("raise RuntimeError('projected-token-shadow')\n")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    command[0] = sys.executable
    command[command.index("/config/saw_ui_limit.py")] = str(script)
    command[command.index("18789")] = str(port)
    with subprocess.Popen(command, cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    _, error = process.communicate()
                    pytest.fail("rendered transport exited before listening: " + error)
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "transport did not start listening"
                    time.sleep(0.02)
        finally:
            process.terminate()
            process.communicate(timeout=3)
    # The regression fixture must reproduce the original failure without -I.
    unsafe = subprocess.run([arg for arg in command if arg != "-I"], cwd=tmp_path,
                            capture_output=True, text=True, timeout=5)
    assert unsafe.returncode != 0 and "projected-token-shadow" in unsafe.stderr


def test_relay_jobs_change_with_images_and_mount_their_exact_scripts():
    values = dict(enabled=True, clientID="site-agent", keycloakNamespace="kc", keycloakAdminSecret="kc-admin",
                  issuer="https://kc.example/realms/openshell", trustedNamespace="trusted", gatewayNamespace="runtime",
                  installationID="installation", gateway="gateway", workspace="agent", workspaceID="workspace-id",
                  sandbox="assistant", ownerLogin="alice", ownerSubject="owner", subject="relay",
                  imageBuildNamespace="build", sdkImage="example/sdk@sha256:"+"f"*64,
                  host="alice.apps.example", egress=[{"ports":[{"port":443}]}])
    def jobs(v):
        result = subprocess.run(["helm", "template", "relay", str(CHART), "-n", "ui", "-f", "-"],
                          input=yaml.safe_dump(v), capture_output=True, text=True, check=True)
        docs = list(yaml.safe_load_all(result.stdout))
        configs = {(o["metadata"].get("namespace", "ui"), o["metadata"]["name"]): o
                   for o in docs if o["kind"] == "ConfigMap"}
        names = set()
        for job in [o for o in docs if o["kind"] == "Job"]:
            script, = [v for v in job["spec"]["template"]["spec"]["volumes"] if v["name"] == "script"]
            assert configs[(job["metadata"]["namespace"], script["configMap"]["name"])]["immutable"] is True
            names.add(job["metadata"]["name"])
        return names
    initial = jobs(values)
    assert jobs(values) == initial
    changed = jobs({**values, "sdkImage": "example/sdk@sha256:"+"a"*64,
                    "pythonImage": "example/python@sha256:"+"a"*64})
    assert initial.isdisjoint(changed)
