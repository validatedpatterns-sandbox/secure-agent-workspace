"""Registry input boundaries and mirror shell injection regressions."""
import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def executable(path, body):
    path.write_text("#!/bin/bash\nset -euo pipefail\n" + body)
    path.chmod(0o755)


@pytest.mark.parametrize("repo", ["ghcr.io:443/validatedpatterns-sandbox", "ghcr.io:0443/validatedpatterns-sandbox/sub", "https://ghcr.io/validatedpatterns-sandbox", "ghcr.io/example;true", "ghcr.io/example ", "ghcr.io/example/../validatedpatterns-sandbox"])
def test_publish_guard_rejects_aliases_and_malformed_repositories(repo):
    result = subprocess.run(["bash", str(ROOT / "scripts/check-build-repo.sh"), repo], capture_output=True, text=True)
    assert result.returncode != 0


@pytest.mark.parametrize("repo", ["", "ghcr.io/example", "localhost:5000/team", "registry.example:443/team/project"])
def test_publish_guard_accepts_internal_or_other_namespaces(repo):
    result = subprocess.run(["bash", str(ROOT / "scripts/check-build-repo.sh"), repo], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("variable,value", [("IMAGE_REPO", 'ghcr.io/$(touch "$INJECTION_MARKER")'), ("IMAGE_TAG", 'latest";true;#'), ("BUILD_NS", "bad.namespace"), ("IMAGES", "gateway;true"), ("IMAGES", "a" * 57), ("IMAGES", "openshell-gateway\nbad;true")])
def test_invalid_mirror_inputs_stop_before_cluster_work(tmp_path, variable, value):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    calls = tmp_path / "calls"
    executable(bindir / "oc", 'echo called >> "$CALLS"\nexit 93\n')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", CALLS=str(calls),
               BUILD_NS="test-build", IMAGE_REPO="ghcr.io/example", IMAGE_TAG="latest", IMAGES="openshell-gateway")
    env[variable] = value
    result = subprocess.run(["bash", str(ROOT / "scripts/mirror-images-incluster.sh")], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert not calls.exists(), "invalid inputs must fail before any cluster mutation"


def test_mirror_values_are_data_not_shell_source(tmp_path):
    template = (ROOT / "scripts/mirror-images-job.yaml").read_text()
    marker = tmp_path / "injected"
    malicious = f'ghcr.io/$(touch {marker})/example'
    env = dict(os.environ, IMAGE="openshell-gateway", IMAGE_REPO=malicious, VERSION="latest", BUILD_NS="test-build")
    rendered = subprocess.check_output(["envsubst", "${IMAGE} ${BUILD_NS} ${IMAGE_REPO} ${VERSION}"], input=template, env=env, text=True)
    job = yaml.safe_load(rendered)
    container = job["spec"]["template"]["spec"]["containers"][0]
    command = container["command"][2]
    assert malicious not in command
    bindir = tmp_path / "bin"
    bindir.mkdir()
    captured = tmp_path / "args"
    executable(bindir / "cat", 'printf fake-token\n')
    executable(bindir / "skopeo", 'printf "%s\n" "$@" > "$CAPTURED"\n')
    env.update({item["name"]: item["value"] for item in container["env"]})
    env.update(PATH=f"{bindir}:{os.environ['PATH']}", CAPTURED=str(captured))
    result = subprocess.run(["bash", "-c", command], env=env, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert "docker://" + malicious + "/openshell-gateway:latest" in captured.read_text().splitlines()
