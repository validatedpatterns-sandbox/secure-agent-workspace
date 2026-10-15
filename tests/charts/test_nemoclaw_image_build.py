"""GitHub and OpenShift must build the same reviewed MCPorter dependency graph."""

import json
import os
import shlex
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
NODE = shutil.which("node")


def sandbox_label_patch_command():
    recipe = (CLI_CHART / "files/Dockerfile").read_text().replace("\\\n", "")
    commands = [shlex.split(line[4:]) for line in recipe.splitlines()
                if line.startswith("RUN node -e ") and "sandbox.type" in line]
    assert len(commands) == 1, "shared CLI Dockerfile must label native NemoClaw sandboxes"
    return commands[0]


@pytest.mark.skipif(not NODE, reason="node is not installed")
@pytest.mark.parametrize("agent", [None, "openclaw", "hermes", "langchain-deepagents-code"])
def test_cli_build_labels_both_native_create_plans(tmp_path, agent):
    path = tmp_path / "src/lib/onboard/sandbox-create-plan-materialization.ts"
    path.parent.mkdir(parents=True)
    # Both upstream constructors must be patched; retain neighboring request fields.
    constructor = '''({
      sandboxName: intent.sandboxName,
      source: Object.freeze({ reference: fromRef }),
      providers: ["nvidia"],
    })'''
    path.write_text("const plans = [" + constructor + "," + constructor + "];\n")
    subprocess.run(sandbox_label_patch_command(), cwd=tmp_path, check=True)
    result = subprocess.check_output([NODE, "-e",
        "const intent = {sandboxName: 'assistant', policy: {options: "
        + json.dumps({"agentName": agent} if agent else {})
        + "}}; const fromRef = 'image@sha256:abc';\n"
        + path.read_text() + "\nconsole.log(JSON.stringify(plans));"], text=True)
    plans = json.loads(result)
    assert len(plans) == 2
    for plan in plans:
        assert plan == {"sandboxName": "assistant", "source": {"reference": "image@sha256:abc"},
                        "providers": ["nvidia"],
                        "labels": {"sandbox.type": "agent", "sandbox.agent": agent or "openclaw"}}


@pytest.mark.skipif(not NODE, reason="node is not installed")
@pytest.mark.parametrize("original", [
    "changed upstream create-plan format\n",
    '''({
      sandboxName: intent.sandboxName,
      source: Object.freeze({ reference: fromRef }),
      labels: {existing: "preserve-me"},
    })''' * 2,
], ids=["changed-shape", "upstream-labels"])
def test_cli_label_patch_rejects_changed_upstream_source(tmp_path, original):
    path = tmp_path / "src/lib/onboard/sandbox-create-plan-materialization.ts"
    path.parent.mkdir(parents=True)
    path.write_text(original)
    result = subprocess.run(sandbox_label_patch_command(), cwd=tmp_path,
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "review sandbox labels patch" in result.stderr
    assert path.read_text() == original


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
    values = yaml.safe_load((CLI_CHART / "values.yaml").read_text())
    workflow = yaml.safe_load((ROOT / ".github/workflows/build-nemoclaw-cli.yml").read_text())
    action = next(s for s in workflow["jobs"]["build"]["steps"] if "with" in s)
    shared = ROOT / action["with"]["dockerfile"]
    assert shared == CLI_CHART / "files/Dockerfile"
    rendered = subprocess.check_output([HELM, "template", "image", str(CLI_CHART),
        "--set", "build.nodeImage=node:test", "--set", "build.maxOpenshellVersion=0.0.123"], text=True)
    build = next(d for d in yaml.safe_load_all(rendered) if d and d["kind"] == "BuildConfig")
    assert build["spec"]["source"]["dockerfile"].rstrip() == shared.read_text().rstrip()
    args = {a["name"]: a["value"] for a in build["spec"]["strategy"]["dockerStrategy"]["buildArgs"]}
    assert args == {"NODE_IMAGE": "node:test", "MAX_OPENSHELL_VERSION": "0.0.123",
                    "NEMOCLAW_VERSION": values["build"]["nemoclawVersion"],
                    "SOURCE_REVISION": values["source"]["git"]["ref"]}


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


def test_nemoclaw_pins_match_across_builds():
    sandbox = yaml.safe_load((CHART / "values.yaml").read_text())
    cli = yaml.safe_load((CLI_CHART / "values.yaml").read_text())
    assert sandbox["source"]["git"]["ref"]
    assert sandbox["source"]["git"] == cli["source"]["git"]
    version = cli["build"]["nemoclawVersion"]
    assert version
    assert sandbox["build"]["baseImage"] == f"ghcr.io/nvidia/nemoclaw/sandbox-base:v{version}"


@pytest.mark.skipif(not HELM, reason="helm is not installed")
def test_discovery_typecheck_scope_is_shared_by_ci_and_openshift():
    runtime = CHART / "files/discovery-runtime"
    config = json.loads((runtime / "tsconfig.json").read_text())
    assert "managed-startup-direct-entry.ts" not in config["include"]
    assert "mcp-tool-discovery.ts" in config["include"]
    assert "streamable-http-client.test.ts" in config["include"]
    rendered = subprocess.check_output([HELM, "template", "image", str(CHART)], text=True)
    inputs = next(d for d in yaml.safe_load_all(rendered)
                  if d and d["metadata"]["name"] == "nemoclaw-discovery-build-inputs")
    assert json.loads(inputs["data"]["tsconfig.json"]) == config
    workflow = (ROOT / ".github/workflows/build-nemoclaw-sandbox.yml").read_text()
    assert "files/discovery-runtime/tsconfig.json" in workflow


def test_cli_build_identity_uses_the_pinned_release_and_commit():
    recipe = (CLI_CHART / "files/Dockerfile").read_text()
    assert "printf '%s\\n' \"$NEMOCLAW_VERSION\" > .version" in recipe
    assert "printf '%s\\n' \"$SOURCE_REVISION\" > .source-revision" in recipe
    assert "0000000000000000000000000000000000000000" not in recipe
    workflow = (ROOT / ".github/workflows/build-nemoclaw-cli.yml").read_text()
    assert "SOURCE_REVISION=${{ steps.params.outputs.git_ref }}" in workflow
    assert "NEMOCLAW_VERSION=${{ steps.params.outputs.nemoclaw_version }}" in workflow
