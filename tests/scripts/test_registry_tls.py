"""Registry credentials must only reach certificate-verified HTTPS peers."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from keycloak_tls import keycloak_tls  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]


def test_shipped_paths_have_no_tls_verification_bypasses():
    bypass = re.compile(r"\bverify\s*=\s*False|--insecure(?:=true)?(?:\s|$)|"
                        r"--(?:src|dest)-tls-verify=false|\bcurl\s+-[a-zA-Z]*k[a-zA-Z]*\b")
    offenders = []
    for directory in ("scripts", "charts", "image-builder-charts", "cli/src"):
        for path in (ROOT / directory).rglob("*"):
            if path.suffix in (".sh", ".py", ".yaml") and bypass.search(path.read_text()):
                offenders.append(str(path.relative_to(ROOT)))
    assert not offenders


def executable(path, body):
    path.write_text("#!/bin/bash\nset -euo pipefail\n" + body)
    path.chmod(0o755)


@pytest.mark.parametrize("script,args", [
    ("images-mirror.sh", []),
    ("push-image.sh", ["test-build", "gateway", "ghcr.io/example", "v1"]),
    ("import-golden-image.sh", []),
])
def test_registry_scripts_use_cluster_ca_without_insecure_retry(tmp_path, keycloak_tls, script, args):
    _, ca = keycloak_tls
    bindir = tmp_path / "bin"
    bindir.mkdir()
    calls = tmp_path / "calls"
    executable(bindir / "uname", 'echo Linux\n')
    executable(bindir / "oc", r'''
case "$*" in
  "get ingresses.config.openshift.io cluster "*) echo '{"spec":{"domain":"apps.example"}}' ;;
  "get cm default-ingress-cert "*) printf '{"data":{"ca-bundle.crt":%s}}' "$(python3 -c 'import json,os; print(json.dumps(open(os.environ["TEST_CA"]).read()))')" ;;
  "get cm openshift-service-ca.crt "*) cat "$TEST_CA" ;;
  "get routes "*) echo '{"items":[{"metadata":{"name":"default-route"},"spec":{"host":"registry.apps.example"}}]}' ;;
  "get dv "*) [[ -f "$APPLIED" ]] && echo Succeeded || true ;;
  "apply "*) cat >/dev/null; touch "$APPLIED" ;;
  "registry login "*|"image mirror "*)
    python3 -c 'import json,os,sys; from pathlib import Path; print(json.dumps({"args":sys.argv[1:], "ca":Path(os.environ["SSL_CERT_FILE"]).read_text(), "path":os.environ["SSL_CERT_FILE"]}))' "$@" >> "$CALLS"
    [[ "${FAIL_MIRROR:-0}" != 1 ]] ;;
esac
''')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", TEST_CA=str(ca),
               CALLS=str(calls), APPLIED=str(tmp_path / "applied"), OIDC_CA_BUNDLE="",
               REGISTRY_CA_BUNDLE="", IMAGE_TAG="latest", IMAGE_REPO="ghcr.io/example")
    result = subprocess.run(["bash", str(ROOT / "scripts" / script), *args],
                            env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    recorded = [json.loads(line) for line in calls.read_text().splitlines()]
    for call in recorded:
        assert not any(arg.startswith("--insecure") for arg in call["args"])
        assert ca.read_text() in call["ca"]
        if call["args"][:2] == ["image", "mirror"]:
            assert call["args"][call["args"].index("--certificate-authority") + 1] == call["path"]
        assert not Path(call["path"]).exists(), "temporary trust must be cleaned up"
    assert any(call["args"][:2] == ["image", "mirror"] for call in recorded)


def test_mirror_job_mounts_service_ca_and_verifies_both_registries():
    job = yaml.safe_load((ROOT / "scripts/mirror-images-job.yaml").read_text())
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    command = container["command"][2]
    assert "--src-tls-verify=true --dest-tls-verify=true" in command
    volume = next(v for v in pod["volumes"] if v["name"] == "service-ca")
    assert volume["configMap"] == {
        "name": "openshift-service-ca.crt",
        "items": [{"key": "service-ca.crt", "path": "ca.crt"}],
    }
    mount = next(v for v in container["volumeMounts"] if v["name"] == "service-ca")
    assert mount["readOnly"] is True
    assert "--dest-cert-dir=" + mount["mountPath"] in command


@pytest.mark.skipif(not shutil.which("oc"), reason="real oc client is required")
@pytest.mark.parametrize("trust,host,success", [
    ("explicit", "127.0.0.1", True),
    ("missing", "127.0.0.1", False),
    ("explicit", "localhost", False),
    ("invalid", "127.0.0.1", False),
])
def test_real_registry_request_checks_certificate_and_hostname(tmp_path, keycloak_tls, trust, host, success):
    context, ca = keycloak_tls
    requests = []
    config_data = json.dumps({"architecture": "amd64", "os": "linux", "config": {},
                              "rootfs": {"type": "layers", "diff_ids": []}}).encode()
    digest = "sha256:" + hashlib.sha256(config_data).hexdigest()
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                           "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
                                      "size": len(config_data), "digest": digest}, "layers": []}).encode()

    class Registry(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.headers.get("Authorization"))
            if not requests[-1]:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="registry"')
            else:
                self.send_response(200)
            body = config_data if "/blobs/" in self.path else manifest
            self.send_header("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
            self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Registry)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        registry = f"{host}:{server.server_port}"
        config = tmp_path / "kubeconfig"
        config.write_text(yaml.safe_dump({
            "apiVersion": "v1", "kind": "Config", "current-context": "test",
            "clusters": [{"name": "test", "cluster": {"server": "https://api.example"}}],
            "contexts": [{"name": "test", "context": {"cluster": "test", "user": "test"}}],
            "users": [{"name": "test", "user": {"token": "test-registry-token"}}],
        }))
        bindir = tmp_path / "bin"
        bindir.mkdir()
        executable(bindir / "oc", r'''
if [[ "$1" == get ]]; then
  case "$*" in
    "get ingresses.config.openshift.io "*) echo '{"spec":{"domain":"example"}}' ;;
    "get cm default-ingress-cert "*) printf '{"data":{"ca-bundle.crt":%s}}' "$(python3 -c 'import json,os; print(json.dumps(open(os.environ["TEST_CA"]).read()))')" ;;
  esac
else
  exec "$REAL_OC" "$@"
fi
''')
        invalid = tmp_path / "invalid.pem"
        invalid.write_text("invalid CA")
        env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", REAL_OC=shutil.which("oc"),
                   KUBECONFIG=str(config), REGISTRY=registry, AUTH_FILE=str(tmp_path / "auth.json"),
                   TEST_CA=str(ca), OIDC_CA_BUNDLE="", REGISTRY_CA_BUNDLE="")
        if trust == "explicit":
            env["REGISTRY_CA_BUNDLE"] = str(ca)
        elif trust == "invalid":
            env["REGISTRY_CA_BUNDLE"] = str(invalid)
        result = subprocess.run([
            "bash", "-ec", 'source "$1/scripts/registry-tls.sh"; '
            'saw_registry_tls_init "$REGISTRY"; '
            'oc registry login --registry="$REGISTRY" --to="$AUTH_FILE"; '
            'oc image info "$REGISTRY/gateway:latest" --registry-config="$AUTH_FILE" '
            '"${REGISTRY_TLS_OPTS[@]}"', "bash", str(ROOT),
        ], env=env, capture_output=True, text=True, timeout=20)
        assert (result.returncode == 0) is success, result.stderr
        if success:
            assert any(request and request.startswith("Basic ") for request in requests)
        else:
            assert not requests, "an untrusted peer must receive no HTTP request or credentials"
    finally:
        server.shutdown()
        worker.join()
        server.server_close()
