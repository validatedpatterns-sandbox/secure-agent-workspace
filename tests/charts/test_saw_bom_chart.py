"""Render the saw-bom chart and check the harness packaging guards.

Needs `helm` on PATH (CI installs it).
"""

import base64
import hashlib
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts" / "saw-bom"
HARNESS = CHART / "harness"
GOVERNANCE_PROFILES = ROOT / "charts" / "governance-policy" / "profiles"
SCRIPT = ROOT / "charts" / "openshell-saw" / "files" / "installer" / "apply_bom.py"
HELM = shutil.which("helm")

pytestmark = pytest.mark.skipif(not HELM, reason="helm is not installed")


@pytest.fixture(scope="module")
def ab():
    spec = importlib.util.spec_from_file_location("apply_bom", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["apply_bom"] = module
    spec.loader.exec_module(module)
    return module


def helm_template(chart=CHART, *args, release="saw-bom-test", namespace="saw-alice"):
    return subprocess.run([HELM, "template", release, str(chart), "--namespace", namespace, *args],
                          capture_output=True, text=True)


# This suite exercises harness packaging, so render with the demo bundle on
# unless a test is specifically about the harnessEnabled=false default.
def render(chart=CHART, *args, demo_harness=True):
    args = (("--set=harnessEnabled=true",) if demo_harness else ()) + args
    result = helm_template(chart, *args)
    assert result.returncode == 0, result.stderr
    docs = [d for d in yaml.safe_load_all(result.stdout) if d]
    return {(d["kind"], d["metadata"]["name"]): d for d in docs}


def render_error(chart=CHART, *args, demo_harness=True):
    args = (("--set=harnessEnabled=true",) if demo_harness else ()) + args
    result = helm_template(chart, *args)
    assert result.returncode != 0, "render was expected to fail"
    return result.stderr


def bom_data(**kwargs):
    docs = render(**kwargs)
    return docs[("ConfigMap", "saw-bom-profiles")]["data"]


def harness_key(bundle, rel):
    """The content-addressed ConfigMap key configmap-bom.yaml derives for
    `rel` inside `bundle`: harness__<bundle>__<sha256(rel)[:16]>."""
    return f"harness__{bundle}__{hashlib.sha256(rel.encode()).hexdigest()[:16]}"


def ds_default_digest(ab):
    files = {str(p.relative_to(HARNESS / "ds-default")): p.read_bytes()
             for p in sorted((HARNESS / "ds-default").rglob("*")) if p.is_file()}
    return ab.tree_digest(files)


def test_demo_harness_is_off_by_default():
    """With harnessEnabled off, no sandbox gets a harnessRef and nothing harness-
    shaped is shipped, so an upgrade with defaults never recreates a sandbox."""
    data = bom_data(demo_harness=False)
    assert "harnessRef" not in data["profiles__data-science__default__sandbox.yaml"]
    assert not [k for k in data if k.startswith("harness__")]
    assert "harness-index.yaml" not in data


def test_demo_harness_true_ships_the_bundle_and_ref():
    data = bom_data(demo_harness=True)
    assert "harnessRef" in data["profiles__data-science__default__sandbox.yaml"]
    assert harness_key("ds-default", "harness.yaml") in data
    assert "harness__ds-default__map" in data
    assert "harness-index.yaml" in data


def test_inline_profile_obeys_harness_gate_and_ships_its_bundle(tmp_path):
    """Operator-supplied profiles get the same harness handling as chart profiles."""
    path = "profiles/identity/default/sandbox.yaml"
    profile = {"apiVersion": "saw.redhat.com/v1alpha1", "kind": "Sandboxes",
               "spec": {"sandboxes": [{"name": "agent", "type": "generic",
                                      "harnessRef": {"name": "ds-default"}}]}}
    values = tmp_path / "inline-values.yaml"
    values.write_text(yaml.safe_dump({"profiles": [], "profileFiles": {
        path: yaml.safe_dump(profile)}}))

    off = render(CHART, "-f", str(values), demo_harness=False)
    off_data = off[("ConfigMap", "saw-bom-profiles")]["data"]
    assert "harnessRef" not in off_data[path.replace("/", "__")]
    assert "harness-index.yaml" not in off_data

    on = render(CHART, "-f", str(values), demo_harness=True)
    on_data = on[("ConfigMap", "saw-bom-profiles")]["data"]
    assert "harnessRef" in on_data[path.replace("/", "__")]
    assert harness_key("ds-default", "harness.yaml") in on_data
    assert "harness-index.yaml" in on_data


def test_no_governance_list_is_kept_in_the_chart():
    """Governance is checked in the guest against the gateway's live catalog;
    a copy of the profile names here would only drift."""
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert "governanceProfiles" not in values
    index = yaml.safe_load(bom_data()["harness-index.yaml"])
    assert "enrolledGovernanceProfiles" not in index


def test_configmap_ships_the_harness_manifest_byte_for_byte():
    data = bom_data()
    key = harness_key("ds-default", "harness.yaml")
    assert key in data
    on_disk = (HARNESS / "ds-default" / "harness.yaml").read_bytes()
    assert base64.b64decode(data[key]) == on_disk


def test_harness_index_digest_matches_tree_digest(ab):
    data = bom_data()
    index = yaml.safe_load(data["harness-index.yaml"])
    assert index["bundles"]["ds-default"] == ds_default_digest(ab)


def test_harness_ref_digest_mismatch_fails_the_render(tmp_path):
    copy = tmp_path / "saw-bom"
    shutil.copytree(CHART, copy)
    sandbox_path = copy / "profiles" / "data-science" / "default" / "sandbox.yaml"
    doc = yaml.safe_load(sandbox_path.read_text())
    doc["spec"]["sandboxes"][0]["harnessRef"] = {"name": "ds-default", "digest": "sha256:deadbeef"}
    sandbox_path.write_text(yaml.safe_dump(doc))
    err = render_error(copy)
    assert "harnessRef digest mismatch" in err


def test_harness_ref_without_a_digest_renders(tmp_path):
    """The digest pin is optional: bundle and pin ship in the same chart."""
    docs = render()
    assert harness_key("ds-default", "harness.yaml") in docs[("ConfigMap", "saw-bom-profiles")]["data"]


def _with_ref(tmp_path, ref):
    copy = tmp_path / "saw-bom"
    shutil.copytree(CHART, copy)
    sandbox_path = copy / "profiles" / "data-science" / "default" / "sandbox.yaml"
    doc = yaml.safe_load(sandbox_path.read_text())
    doc["spec"]["sandboxes"][0]["harnessRef"] = ref
    sandbox_path.write_text(yaml.safe_dump(doc))
    return copy


def test_an_oci_harness_ref_renders_without_shipping_the_bundle(tmp_path):
    image = "ghcr.io/example/saw-harness-ds-default@sha256:" + "a" * 64
    docs = render(_with_ref(tmp_path, {"image": image}))
    data = docs[("ConfigMap", "saw-bom-profiles")]["data"]
    assert not [k for k in data if k.startswith("harness__")]
    assert "harness-index.yaml" in data


def test_an_unpinned_oci_harness_ref_fails_the_render(tmp_path):
    err = render_error(_with_ref(tmp_path, {"image": "ghcr.io/example/saw-harness-ds-default:latest"}))
    assert "pinned by digest" in err


def test_a_long_bundle_name_over_the_joliet_limit_fails_the_render(tmp_path):
    """Keys are content-addressed (harness__<bundle>__<hash>), so a deep or
    long path no longer matters; only a long bundle *name* can still overflow
    the fixed-width key."""
    copy = tmp_path / "saw-bom"
    shutil.copytree(CHART, copy)
    long_bundle = "x" * 40
    bundle_dir = copy / "harness" / long_bundle
    bundle_dir.mkdir(parents=True)
    (bundle_dir / "harness.yaml").write_text("metadata:\n  name: x\n")
    sandbox_path = copy / "profiles" / "data-science" / "default" / "sandbox.yaml"
    doc = yaml.safe_load(sandbox_path.read_text())
    doc["spec"]["sandboxes"][0]["harnessRef"] = {"name": long_bundle}
    sandbox_path.write_text(yaml.safe_dump(doc))
    err = render_error(copy)
    assert "Joliet" in err


def test_a_deep_bundle_path_under_the_joliet_limit_renders(tmp_path):
    """A path that would have overflowed the old path-derived key now fits,
    since the ConfigMap key is a hash of the relpath, not the relpath."""
    copy = tmp_path / "saw-bom"
    shutil.copytree(CHART, copy)
    long_dir = copy / "harness" / "ds-default" / "skills" / ("x" * 40)
    long_dir.mkdir(parents=True)
    (long_dir / "SKILL.md").write_text("x\n")
    data = bom_data(chart=copy)
    assert harness_key("ds-default", f"skills/{'x' * 40}/SKILL.md") in data


def test_a_bundle_name_with_a_double_underscore_fails_the_render(tmp_path):
    """The bundle name is still a flat-key segment (harness__<bundle>__<hash>);
    parse_harness_files requires exactly 3 "__"-separated parts, so a bundle
    named e.g. "my__bundle" would render but break the installer."""
    copy = tmp_path / "saw-bom"
    shutil.copytree(CHART, copy)
    bundle_dir = copy / "harness" / "my__bundle"
    bundle_dir.mkdir(parents=True)
    (bundle_dir / "harness.yaml").write_text("metadata:\n  name: x\n")
    err = render_error(copy)
    assert "contains \"__\"" in err
