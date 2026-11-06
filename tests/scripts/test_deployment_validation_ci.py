"""Checks for the offline parts of deployment validation."""

import json
import io
import sys
import shutil
from pathlib import Path
from types import SimpleNamespace
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.ci import deployment_validation as dv
from scripts.ci.vendor_crd_schemas import validation_only


@pytest.mark.skipif(not shutil.which("helm"), reason="Helm is required")
def test_enabled_chart_graph_renders_every_component(tmp_path):
    result = dv.Validation()
    dv.render_charts(result, tmp_path)
    assert result.errors == []
    for chart in dv.charts():
        name = chart.parent.relative_to(dv.ROOT).as_posix().replace("/", "_")
        documents = list(dv.yaml.safe_load_all((tmp_path / (name + ".yaml")).read_text()))
        assert any(isinstance(item, dict) and item.get("kind") for item in documents)
    controller = dv.yaml.safe_load((tmp_path / "saw-c-a8cb6cbd0eb62f31-gateway-inputs.json").read_text())
    assert controller["kubernetes"]["experimental"] is True
    assert controller["kubernetes"]["identity"]["clientCaSecret"] == "alice-client-ca"


def test_vendored_schemas_have_no_upstream_sample_data():
    source = {"properties": {"password": {"type": "string", "example": "sample"}},
              "description": "sample", "default": "sample"}
    assert validation_only(source) == {"properties": {"password": {"type": "string"}}}
    for path in (dv.ROOT / "scripts/ci/schemas").glob("*/*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        assert document == validation_only(document), path


def test_vendored_crd_schema_names_match_kubeconform_lookup():
    expected = (
        ("rhdh.redhat.com", "backstage_v1alpha5.json"),
        ("hco.kubevirt.io", "hyperconverged_v1beta1.json"),
        ("tekton.dev", "pipeline_v1.json"),
        ("tekton.dev", "task_v1.json"),
        ("apiextensions.k8s.io", "customresourcedefinition_v1.json"),
    )
    for group, filename in expected:
        assert (dv.ROOT / "scripts/ci/schemas" / group / filename).is_file()


def test_dependency_discovery_reports_source_and_value_path():
    refs = dv.collect_references()
    assert any(
        item.source == "charts/openshell-saw/values.yaml"
        and item.path == "bom.spec.openshell.gateway.image"
        and item.kind == "image"
        for item in refs
    )
    assert any(
        item.source == "image-builder-charts/helm/nemoclaw-imagestream/values.yaml"
        and item.path == "source.git.ref"
        and item.kind == "git"
        for item in refs
    )
    assert dv.is_own_image("ghcr.io/validatedpatterns-sandbox/nemoclaw-sandbox:latest")
    assert dv.is_own_image("ghcr.io/validatedpatterns-sandbox/saw-credential-proxy:latest")
    assert str(dv.ROOT / "tests/fixtures/credential-proxy-values.yaml") not in dv.chart_args(
        dv.ROOT / "charts/openshell-saw")
    assert not dv.is_own_image("quay.io/opendatahub/odh-openshell-gateway:v0.1.2")
    assert not any("ghcr.io/mkhaas/apf/" in item.value for item in refs)


def test_bom_mismatch_fails_with_value_path(monkeypatch):
    original = dv.read_yaml

    def changed(path):
        data = original(path)
        if path.name == "values.yaml" and path.parent.name == "openshell-gateway-image":
            data["openshell"]["gatewayImage"] = "quay.io/example/gateway:v9"
        return data

    monkeypatch.setattr(dv, "read_yaml", changed)
    result = dv.Validation()
    dv.check_bom(result)
    assert any("openshell.gatewayImage" in item for item in result.errors)


def test_missing_schema_and_skipped_resource_fail(monkeypatch, tmp_path):
    (tmp_path / "sample.yaml").write_text("apiVersion: example/v1\nkind: Example\n")
    report = {
        "resources": [
            {"filename": "sample.yaml", "kind": "Example", "status": "ERROR",
             "msg": "could not find schema for Example"}
        ],
        "summary": {"valid": 0, "invalid": 0, "errors": 1, "skipped": 1},
    }
    monkeypatch.setattr(
        dv.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=json.dumps(report), stderr=""),
    )
    result = dv.Validation()
    dv.validate_schemas(result, tmp_path)
    assert any("could not find schema" in item for item in result.errors)
    assert any("skipped" in item for item in result.errors)


def test_failed_external_dependency_never_passes(monkeypatch):
    refs = [
        dv.Reference("image", "quay.io/example/missing:1", "one.yaml", "image"),
        dv.Reference("git", "https://github.com/example/missing.git#v1", "two.yaml", "source.git.ref"),
        dv.Reference("package", "https://registry.npmjs.org/missing/-/missing-1.tgz",
                     "package-lock.json", "packages.node_modules/missing.resolved"),
    ]
    monkeypatch.setattr(dv, "collect_references", lambda _output_dir=None: refs)
    monkeypatch.setattr(dv, "package_references", lambda: [])

    def fail(_):
        raise RuntimeError("not found")

    monkeypatch.setattr(dv, "check_reference", fail)
    result = dv.Validation()
    dv.check_dependencies(result)
    assert len(result.errors) == 3
    assert all("not found" in item for item in result.errors)


def test_rendered_build_args_resolve_dockerfile_image(tmp_path):
    path = tmp_path / "image-builder-charts_helm_example.yaml"
    path.write_text("""apiVersion: build.openshift.io/v1
kind: BuildConfig
metadata:
  name: example
spec:
  source:
    dockerfile: 'FROM ${NODE_IMAGE} AS build'
  strategy:
    dockerStrategy:
      buildArgs:
        - name: NODE_IMAGE
          value: docker.io/library/node:22-slim
""")
    refs = dv.collect_references(tmp_path)
    assert any(ref.kind == "image" and ref.value == "docker.io/library/node:22-slim"
               and ref.path == "BuildConfig.example.dockerfile.line 1" for ref in refs)


def test_redhat_catalog_verifies_login_only_tag(monkeypatch):
    urls = []

    def fake_open(request, **_kwargs):
        urls.append(request.full_url)
        return io.BytesIO(b'{"data":[{"_id":"test"}]}')

    monkeypatch.setattr(dv.urllib.request, "urlopen", fake_open)
    dv.check_reference(dv.Reference("image", "registry.redhat.io/rhel9/postgresql-16:latest",
                                    "values.yaml", "postgres.image"))
    assert urls == ["https://catalog.redhat.com/api/containers/v1/repositories/"
                    "registry/registry.access.redhat.com/repository/"
                    "rhel9/postgresql-16/tag/latest"]


def test_skopeo_uses_digest_without_tag(monkeypatch):
    commands = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(dv.subprocess, "run", fake_run)
    digest = "sha256:" + "a" * 64
    dv.check_reference(dv.Reference("image", f"docker.io/library/node:24@{digest}",
                                    "values.yaml", "image"))
    assert commands == [["skopeo", "inspect", "--raw",
                         f"docker://docker.io/library/node@{digest}"]]
