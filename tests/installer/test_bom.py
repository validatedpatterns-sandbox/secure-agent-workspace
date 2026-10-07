"""InstallerBOM validation and version handling."""

import copy

import pytest
import yaml


def test_chart_default_bom_is_valid(ab, bom):
    assert ab.validate_bom(bom) is bom


def test_example_bom_file_matches_chart_default(ab, chart_bom):
    from conftest import ROOT
    example = yaml.safe_load((ROOT / "examples" / "saw" / "installer-bom.yaml").read_text())
    assert ab.validate_bom(example)["spec"]["openshell"] == chart_bom["spec"]["openshell"]


def test_load_bom_reads_yaml_file(ab, bom, tmp_path):
    path = tmp_path / "bom.yaml"
    path.write_text(yaml.safe_dump(bom))
    assert ab.load_bom(path)["metadata"]["name"] == bom["metadata"]["name"]


def test_load_bom_reports_unreadable_file(ab, tmp_path):
    with pytest.raises(ab.InstallerError, match="cannot read InstallerBOM"):
        ab.load_bom(tmp_path / "missing.yaml")


@pytest.mark.parametrize("mutate, message", [
    (lambda b: b["spec"]["openshell"]["gateway"].update(image="quay.io/x/gateway:v0.0.116"),
     "pinned by digest"),
    (lambda b: b["spec"]["openshell"]["cli"].update(image="quay.io/x/cli@sha256:abc"),
     "pinned by digest"),
    (lambda b: b["spec"]["openshell"].pop("supervisor"), "missing supervisor"),
    (lambda b: b["spec"]["openshell"].update(dashboard={"version": "1.0.0", "image": "x"}),
     "unknown field"),
    (lambda b: b.update(kind="Something"), "kind InstallerBOM"),
    (lambda b: b.update(apiVersion="v1"), "kind InstallerBOM"),
    (lambda b: b["metadata"].update(name="Not_A_Label"), "DNS label"),
    (lambda b: b["spec"].update(installerVersion="9.9.9"), "this installer is"),
    (lambda b: b["spec"]["openshell"]["gateway"].update(version="latest"), "version string"),
    (lambda b: b["spec"]["openshell"]["gateway"].update(path="relative/bin"), "absolute path"),
    (lambda b: b["spec"]["openshell"]["gateway"].update(extra=1), "unknown field"),
    (lambda b: b["spec"].update(nemoclaw={}), "missing cliImage"),
    (lambda b: b["spec"].update(nemoclaw={"cliImage": "Bad Image"}), "not a valid image"),
    (lambda b: b.pop("spec"), "missing spec"),
])
def test_invalid_boms_are_rejected(ab, bom, mutate, message):
    broken = copy.deepcopy(bom)
    mutate(broken)
    with pytest.raises(ab.InstallerError, match=message):
        ab.validate_bom(broken)


def test_non_mapping_bom_is_rejected(ab):
    with pytest.raises(ab.InstallerError, match="expected a mapping"):
        ab.validate_bom(["not", "a", "mapping"])


def test_nemoclaw_tag_is_accepted_with_a_warning(ab, bom, capsys):
    bom["spec"]["nemoclaw"] = {"cliImage": "quay.io/rh-ai-quickstart/nemoclaw-cli:latest"}
    ab.validate_bom(bom)
    assert "not pinned by digest" in capsys.readouterr().out


def test_nemoclaw_digest_has_no_warning(ab, bom, capsys):
    bom["spec"]["nemoclaw"] = {"cliImage": "quay.io/x/nemoclaw-cli@sha256:" + "a" * 64}
    ab.validate_bom(bom)
    assert "not pinned" not in capsys.readouterr().out


def test_component_path_override_is_allowed(ab, bom):
    bom["spec"]["openshell"]["supervisor"]["path"] = "/usr/bin/openshell-sandbox"
    ab.validate_bom(bom)


@pytest.mark.parametrize("a, b", [
    ("0.1.2+rhaiv.0", "0.1.2-rhaiv.0"),
    ("v0.1.2-rhaiv.0", "0.1.2-rhaiv.0"),
    ("0.1.2", "v0.1.2"),
])
def test_version_normalisation_equal(ab, a, b):
    assert ab.normalize_version(a) == ab.normalize_version(b)


def test_version_normalisation_distinguishes_releases(ab):
    assert ab.normalize_version("0.1.2-rhaiv.0") != ab.normalize_version("0.1.3-rhaiv.0")


@pytest.mark.parametrize("output, expected", [
    ("openshell-gateway 0.1.2-rhaiv.0", "0.1.2-rhaiv.0"),
    ("openshell v0.1.2\n", "v0.1.2"),
    ("version: 1.2.3+build.4 (commit abc)", "1.2.3+build.4"),
    ("no version here", None),
    ("", None),
])
def test_reported_version(ab, output, expected):
    assert ab.reported_version(output) == expected
