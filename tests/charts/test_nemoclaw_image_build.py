"""GitHub and OpenShift must build the same reviewed MCPorter dependency graph."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "image-builder-charts/helm/nemoclaw-imagestream"
RUNTIME = CHART / "files/mcporter-runtime"
CLI_CHART = ROOT / "image-builder-charts/helm/nemoclaw-cli-imagestream"
HELM = shutil.which("helm")


def test_github_supplies_the_same_reviewed_runtime(tmp_path):
    workflow = yaml.safe_load((ROOT / ".github/workflows/build-nemoclaw-sandbox.yml").read_text())
    injection = next(s["run"] for s in workflow["jobs"]["build"]["steps"]
                     if "install-reviewed-runtime.sh" in s.get("run", ""))
    target = tmp_path / "agents/openclaw/mcporter-runtime"
    target.mkdir(parents=True)
    for name in ("package.json", "package-lock.json"):
        (target / name).write_text("old upstream graph")
    subprocess.run(["bash", "-eu", "-c", injection], cwd=ROOT,
                   env=dict(os.environ, UPSTREAM_DIR=str(tmp_path), BASH_ENV="/dev/null"), check=True)
    for name in ("package.json", "package-lock.json"):
        assert (target / name).read_bytes() == (RUNTIME / name).read_bytes()


def test_reviewed_lock_contains_fixed_dependencies():
    manifest = json.loads((RUNTIME / "package.json").read_text())
    lock = json.loads((RUNTIME / "package-lock.json").read_text())
    for package, minimum in (("@modelcontextprotocol/sdk", (1, 31, 0)),
                             ("fast-uri", (3, 1, 7)), ("proxy-addr", (2, 0, 8))):
        version = lock["packages"][f"node_modules/{package}"]["version"]
        assert manifest["overrides"][package] == version
        assert tuple(map(int, version.split("."))) >= minimum


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_openshift_supplies_the_reviewed_runtime_to_the_upstream_dockerfile():
    rendered = subprocess.check_output([HELM, "template", "image", str(CHART),
        "--set-string", "source.discoveryImage=image-registry.example/build/nemoclaw-discovery-runtime@sha256:" + "a" * 64], text=True)
    resources = [d for d in yaml.safe_load_all(rendered) if d]
    build = next(d for d in resources if d["kind"] == "BuildConfig" and d["metadata"]["name"] == "nemoclaw-sandbox")
    source = next(s for s in build["spec"]["source"]["configMaps"]
                  if s["destinationDir"] == "agents/openclaw/mcporter-runtime")
    config = next(d for d in resources if d["kind"] == "ConfigMap"
                  and d["metadata"]["name"] == source["configMap"]["name"])
    for name in ("package.json", "package-lock.json"):
        assert config["data"][name] == (RUNTIME / name).read_text()
    assert build["spec"]["strategy"]["dockerStrategy"]["dockerfilePath"] == "Dockerfile"


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_cli_builds_share_one_dockerfile_and_values():
    workflow = yaml.safe_load((ROOT / ".github/workflows/build-nemoclaw-cli.yml").read_text())
    action = next(s for s in workflow["jobs"]["build"]["steps"] if "with" in s)
    shared = ROOT / action["with"]["dockerfile"]
    assert shared == CLI_CHART / "files/Dockerfile"
    rendered = subprocess.check_output([HELM, "template", "image", str(CLI_CHART),
        "--set", "build.nodeImage=node:test", "--set", "build.maxOpenshellVersion=0.0.123"], text=True)
    build = next(d for d in yaml.safe_load_all(rendered) if d and d["kind"] == "BuildConfig")
    assert build["spec"]["source"]["dockerfile"].rstrip() == shared.read_text().rstrip()
    args = {a["name"]: a["value"] for a in build["spec"]["strategy"]["dockerStrategy"]["buildArgs"]}
    assert args == {"NODE_IMAGE": "node:test", "MAX_OPENSHELL_VERSION": "0.0.123"}


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_discovery_build_generates_artifacts_and_sandbox_consumes_digest():
    image = "image-registry.example/build/nemoclaw-discovery-runtime@sha256:" + "a" * 64
    rendered = subprocess.check_output([HELM, "template", "image", str(CHART),
        "--set-string", f"source.discoveryImage={image}"], text=True)
    docs = [d for d in yaml.safe_load_all(rendered) if d]
    build = next(d for d in docs if d["kind"] == "BuildConfig" and d["metadata"]["name"] == "nemoclaw-sandbox")
    assert build["spec"]["source"]["images"] == [{
        "from": {"kind": "DockerImage", "name": image},
        "paths": [{"sourcePath": "/reviewed-runtime-bundle/mcp-tool-discovery/.",
                   "destinationDir": "tools/mcp-tool-discovery-runtime/reviewed-runtime-bundle/mcp-tool-discovery"}],
    }]
    discovery = next(d for d in docs if d["kind"] == "BuildConfig" and d["metadata"]["name"] == "nemoclaw-discovery-runtime")
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert discovery["spec"]["strategy"]["dockerStrategy"]["buildArgs"] == [
        {"name": "NODE_VERSION", "value": values["build"]["discoveryNodeVersion"]},
        {"name": "NODE_DIGEST", "value": values["build"]["discoveryNodeDigest"]}]
    dockerfile = discovery["spec"]["source"]["dockerfile"]
    assert values["build"]["discoveryNodeDigest"] == "sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df"
    node_digest = values["build"]["discoveryNodeDigest"]
    assert f"ARG NODE_DIGEST={node_digest}" in dockerfile
    assert "FROM docker.io/library/node:${NODE_VERSION}-bookworm-slim@${NODE_DIGEST} AS builder" in dockerfile
    assert discovery["spec"]["triggers"] == []
    assert discovery["spec"]["output"]["to"] == {"kind": "ImageStreamTag", "name": "nemoclaw-discovery-runtime:latest"}
    assert not any(d.get("metadata", {}).get("name") == "nemoclaw-discovery-runtime" and d["kind"] == "ConfigMap" for d in docs)
    inputs = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "nemoclaw-discovery-build-inputs")
    for name in ("package.json", "package-lock.json"):
        assert inputs["data"][name] == (CHART / "files/discovery-runtime" / name).read_text()
    assert inputs["data"]["install-reviewed-runtime.sh"] == (CHART / "files/install-reviewed-runtime.sh").read_text()
    assert discovery["spec"]["source"]["dockerfile"].rstrip() == (CHART / "files/discovery-runtime/Dockerfile").read_text().rstrip()
    assert discovery["spec"]["strategy"]["dockerStrategy"]["dockerfilePath"] == "Dockerfile"
    assert "sh install-reviewed-runtime.sh" in discovery["spec"]["source"]["dockerfile"]
    assert "COPY --from=builder /reviewed-runtime-bundle/ /reviewed-runtime-bundle/" in discovery["spec"]["source"]["dockerfile"]
    assert not (CHART / "files/discovery-runtime/bundle").exists()


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_sandbox_build_is_not_created_without_a_discovery_digest():
    rendered = subprocess.check_output([HELM, "template", "image", str(CHART)], text=True)
    docs = [d for d in yaml.safe_load_all(rendered) if d]
    assert not any(d["kind"] == "BuildConfig" and d["metadata"]["name"] == "nemoclaw-sandbox" for d in docs)
    for image in ("image-registry.example/build/discovery:latest", "image-registry.example/build/discovery@sha256:"):
        result = subprocess.run([HELM, "template", "image", str(CHART), "--set-string", f"source.discoveryImage={image}"], capture_output=True, text=True)
        assert result.returncode != 0
        assert "digest" in result.stderr


def test_ci_generates_discovery_before_building_from_the_same_recipe():
    workflow = yaml.safe_load((ROOT / ".github/workflows/build-nemoclaw-sandbox.yml").read_text())
    steps = workflow["jobs"]["build"]["steps"]
    generation = next(i for i, s in enumerate(steps) if "sh install-reviewed-runtime.sh" in s.get("run", ""))
    image_build = next(i for i, s in enumerate(steps) if s.get("uses") == "./.github/actions/build-push-image")
    assert generation < image_build
    assert "cmp" not in steps[generation]["run"]
    assert "reviewed-runtime-bundle/mcp-tool-discovery" in steps[generation]["run"]
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    params = next(s["run"] for s in steps if s.get("id") == "params")
    assert ".build.discoveryNodeVersion" in params
    node = next(s for s in steps if s.get("uses", "").startswith("actions/setup-node"))
    assert node["with"]["node-version"] == "${{ steps.params.outputs.discovery_node_version }}"
    assert values["build"]["discoveryNodeVersion"] == "24.19.0"


def test_discovery_runtime_keeps_vulnerability_and_integrity_checks():
    script = (CHART / "files/install-reviewed-runtime.sh").read_text()
    assert "npm audit --audit-level=high" in script
    assert "npm audit signatures" in script
    assert "skipping npm audit" not in script
