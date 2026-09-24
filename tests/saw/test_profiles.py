"""A/B preflight profile contracts: no VM/runtime claims."""

import json
from copy import deepcopy

import pytest
import yaml
from click.testing import CliRunner

from openshell_saw import config
from openshell_saw.blueprints import ValidationError
from openshell_saw.cli import main
from openshell_saw.profiles import profile_fingerprint, resolve_profiles


def edit_doc(cms, filename, change):
    key = f"profiles__data-science__default__{filename}"
    doc = yaml.safe_load(cms[0]["data"][key])
    change(doc)
    cms[0]["data"][key] = yaml.safe_dump(doc)


def test_resolve_profile_binding_without_secret_values(profile_inputs):
    selections, cms = profile_inputs
    before = deepcopy(profile_inputs)
    out = resolve_profiles(selections, cms, "saw-test")
    assert profile_inputs == before
    assert out[0]["providers"][0]["secretRef"] == {"name": "saw-provider-nvidia", "key": "api_key"}
    assert "credentialRef" not in out[0]["providers"][0]
    assert out[0]["sandboxes"][0]["data"]["retainOnDelete"] is True


@pytest.mark.parametrize("mutation", ["missing-cm", "missing-profile", "cross-namespace", "duplicate",
                                     "inline", "missing-file", "traversal", "missing-slot", "unused-slot"])
def test_invalid_selection_fails(profile_inputs, mutation):
    selections, cms = profile_inputs
    if mutation == "missing-cm":
        cms.clear()
    elif mutation == "missing-profile":
        selections[0]["profileRef"]["name"] = "missing"
    elif mutation == "cross-namespace":
        cms[0]["metadata"]["namespace"] = "other-user"
    elif mutation == "duplicate":
        selections.append(deepcopy(selections[0]))
    elif mutation == "inline":
        selections[0]["providers"] = []
    elif mutation == "missing-file":
        del cms[0]["data"]["profiles__data-science__default__workspace.yaml"]
    elif mutation == "traversal":
        cms[0]["data"]["profiles__data-science__..__workspace.yaml"] = "{}"
    elif mutation == "missing-slot":
        selections[0]["credentialBindings"].clear()
    else:
        selections[0]["credentialBindings"]["extra"] = {"secretRef": {"name": "unused", "key": "key"}}
    with pytest.raises(ValidationError):
        resolve_profiles(selections, cms, "saw-test")


@pytest.mark.parametrize("key,value", [
    ("credentialSecret", "legacy"), ("credentialRef", "unknown"), ("enabled", "false"),
    ("apiKey", "CANARY"), ("name", "../provider"),
])
def test_invalid_provider(profile_inputs, key, value):
    selections, cms = profile_inputs
    edit_doc(cms, "providers.yaml", lambda d: d["spec"]["providers"][0].update({key: value}))
    with pytest.raises(ValidationError) as exc:
        resolve_profiles(selections, cms, "saw-test")
    assert "CANARY" not in str(exc.value)


@pytest.mark.parametrize("key,value", [
    ("image", "registry.test/image:latest"), ("providers", ["missing"]),
    ("data", {"name": "data", "mountPath": "/etc", "retainOnDelete": True}),
    ("data", {"name": "data", "mountPath": "/sandbox/persist", "retainOnDelete": False}),
    ("enabled", "true"), ("type", "unqualified"),
])
def test_invalid_sandbox(profile_inputs, key, value):
    selections, cms = profile_inputs
    edit_doc(cms, "sandbox.yaml", lambda d: d["spec"]["sandboxes"][0].update({key: value}))
    with pytest.raises(ValidationError):
        resolve_profiles(selections, cms, "saw-test")


def test_profile_aggregate_uses_explicit_key(profile_inputs):
    selections, cms = profile_inputs
    selections[0]["credentialBindings"]["inference-main"]["secretRef"] = {
        "name": "saw-profile-science", "key": "nvidia_api_key"}
    result = resolve_profiles(selections, cms, "saw-test")
    assert result[0]["providers"][0]["secretRef"]["key"] == "nvidia_api_key"


def test_legacy_reference_is_explicit_not_implicit_fallback(profile_inputs):
    selections, cms = profile_inputs
    selections[0]["credentialBindings"].clear()
    def legacy(doc):
        provider = doc["spec"]["providers"][0]
        del provider["credentialRef"]
        provider.update(credentialSecret="inference", credentialSecretKey="api_key")
    edit_doc(cms, "providers.yaml", legacy)
    assert resolve_profiles(selections, cms, "saw-test")[0]["providers"][0]["secretRef"]["name"] == "inference"


def test_metadata_and_unselected_profile_edits_do_not_change_plan(profile_inputs):
    selections, cms = profile_inputs
    before = profile_fingerprint(resolve_profiles(selections, cms, "saw-test"))
    cms[0]["metadata"]["resourceVersion"] = "opaque-token"
    cms[0]["data"]["profiles__unselected__other__workspace.yaml"] = "invalid: ["
    after = profile_fingerprint(resolve_profiles(selections, cms, "saw-test"))
    assert before == after
    edit_doc(cms, "sandbox.yaml", lambda d: d["spec"]["sandboxes"][0].update(
        image="registry.example.test/test@sha256:" + "c" * 64))
    assert profile_fingerprint(resolve_profiles(selections, cms, "saw-test")) != before


def test_same_provider_name_in_two_workspaces_remains_scoped(profile_inputs):
    selections, cms = profile_inputs
    for key, raw in list(cms[0]["data"].items()):
        doc = yaml.safe_load(raw)
        if key.endswith("workspace.yaml"):
            doc["metadata"]["name"] = "second"
        if key.endswith("providers.yaml"):
            doc["spec"]["providers"][0]["credentialRef"] = "other-account"
        cms[0]["data"][key.replace("__default__", "__second__")] = yaml.safe_dump(doc)
    selections[0]["credentialBindings"]["other-account"] = {
        "secretRef": {"name": "saw-provider-personal", "key": "api_key"}}
    out = resolve_profiles(selections, cms, "saw-test")
    assert [ws["providers"][0]["secretRef"]["name"] for ws in out] == [
        "saw-provider-nvidia", "saw-provider-personal"]


def test_overlapping_profiles_rejected(profile_inputs):
    selections, cms = profile_inputs
    extra = deepcopy(selections[0])
    extra["profileRef"]["name"] = "another"
    selections.append(extra)
    for key, raw in list(cms[0]["data"].items()):
        cms[0]["data"][key.replace("__data-science__", "__another__")] = raw
    with pytest.raises(ValidationError, match="overlapping"):
        resolve_profiles(selections, cms, "saw-test")


def test_profile_cli_offline(profile_inputs, tmp_path, monkeypatch):
    selections, cms = profile_inputs
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "absent")
    instance, snapshots = tmp_path / "instance.yaml", tmp_path / "profiles.yaml"
    instance.write_text(yaml.safe_dump({"apiVersion": "saw.redhat.com/v1alpha1", "kind": "SawInstance",
                                        "spec": {"workspaces": selections}}))
    snapshots.write_text(yaml.safe_dump({"apiVersion": "v1", "kind": "List", "items": cms}))
    def forbidden(*args, **kwargs):
        raise AssertionError("offline plan attempted subprocess execution")
    monkeypatch.setattr("subprocess.run", forbidden)
    result = CliRunner().invoke(main, ["blueprint", "profile-plan", "--namespace", "saw-test",
                                      "--instance", str(instance), "--profile-configmaps", str(snapshots)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["workspaces"][0]["name"] == "default"
