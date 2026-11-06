"""Pure local intent generation; no network, Kubernetes API or credential access."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from saw_kubernetes.compiler import OWNER, canonical, digest
from saw_kubernetes.intent import IntentError, build_intent
from .test_runtime import flat_profile, source


@pytest.fixture
def inputs(source):
    profile = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        "name": "saw-alice-bom", "namespace": "saw-alice",
        "uid": "c8c8a0c0-063b-4412-b196-2788bf732cac", "resourceVersion": "opaque-rv"},
        "data": flat_profile(source)}
    return profile, source[1]


def build(inputs, **kwargs):
    return build_intent(*inputs, name="saw-runtime-intent", generation=kwargs.pop("generation", 1), **kwargs)


def test_builder_outputs_exact_controller_envelope_without_mutating_inputs(inputs):
    original = copy.deepcopy(inputs)
    result = build(inputs)
    assert result["metadata"] == {"name": "saw-runtime-intent", "namespace": "saw-alice",
                                   "labels": {OWNER: inputs[1]["ownerID"]}}
    assert set(result["data"]) == {"intent.json"}
    intent = json.loads(result["data"]["intent.json"])
    assert intent == {"schemaVersion": 1, "generation": 1, "desiredState": "Running",
                      "profileRef": {"name": "saw-alice-bom", "uid": inputs[0]["metadata"]["uid"],
                                     "sha256": digest(inputs[0]["data"])}, "bindings": inputs[1]}
    assert result["data"]["intent.json"] == canonical(intent)
    assert inputs == original


def test_hash_covers_exact_data_strings_not_metadata_or_yaml_reserialization(inputs):
    first = json.loads(build(inputs)["data"]["intent.json"])["profileRef"]["sha256"]
    inputs[0]["metadata"].update(resourceVersion="new", annotations={"arbitrary": "not included"})
    assert json.loads(build(inputs)["data"]["intent.json"])["profileRef"]["sha256"] == first
    key = next(iter(inputs[0]["data"]))
    inputs[0]["data"][key] += "\n"
    assert json.loads(build(inputs)["data"]["intent.json"])["profileRef"]["sha256"] != first


@pytest.mark.parametrize("change", [
    lambda p, b: p["metadata"].pop("uid"),
    lambda p, b: p["metadata"].update(uid="<observed-uid>"),
    lambda p, b: p["metadata"].pop("resourceVersion"),
    lambda p, b: p["metadata"].update(deletionTimestamp="now"),
    lambda p, b: p["metadata"].update(namespace="other"),
    lambda p, b: p.update(kind="Secret"),
    lambda p, b: p.update(binaryData={"payload": "encoded"}),
    lambda p, b: p["data"].update({"../file": "content"}),
    lambda p, b: b.update(ownerID="<installation-id>"),
])
def test_missing_observation_or_invalid_scope_rejected(inputs, change):
    change(*inputs)
    with pytest.raises(IntentError):
        build(inputs)


@pytest.mark.parametrize("generation", [0, -1, True, "1"])
def test_generation_must_be_a_positive_integer(inputs, generation):
    with pytest.raises(IntentError):
        build(inputs, generation=generation)


@pytest.mark.parametrize("bad_name", ["a.-b", "a-.b", "a..b", "a.-.b"])
def test_builder_never_emits_an_invalid_dns_subdomain_name(inputs, bad_name):
    with pytest.raises(IntentError, match="name must be valid"):
        build_intent(*inputs, name=bad_name, generation=1)


def test_builder_accepts_valid_dotted_intent_name(inputs):
    result = build_intent(*inputs, name="runtime-intent.prod-1", generation=1)
    assert result["metadata"]["name"] == "runtime-intent.prod-1"


def test_complete_profile_is_compiled_before_output(inputs):
    key = next(k for k in inputs[0]["data"] if k.endswith("sandbox.yaml"))
    doc = yaml.safe_load(inputs[0]["data"][key])
    doc["spec"]["sandboxes"][0]["type"] = "openclaw"
    inputs[0]["data"][key] = yaml.safe_dump(doc)
    with pytest.raises(IntentError, match="unsupported or invalid"):
        build(inputs)


def test_previous_intent_allows_exact_retry_but_requires_new_generation_for_change(inputs):
    previous = build(inputs)
    assert build(inputs, previous=previous) == previous
    with pytest.raises(IntentError, match="reused"):
        build(inputs, desired_state="Stopped", previous=previous)
    stopped = build(inputs, generation=2, desired_state="Stopped", previous=previous)
    assert json.loads(stopped["data"]["intent.json"])["desiredState"] == "Stopped"
    with pytest.raises(IntentError, match="rolled back"):
        build(inputs, previous=stopped)


def test_previous_intent_cannot_hide_same_name_profile_uid_replacement(inputs):
    previous = build(inputs)
    inputs[0]["metadata"]["uid"] = "8ef68f29-ac12-4836-a8d7-e0d969672c53"
    with pytest.raises(IntentError, match="explicit controller recovery"):
        build(inputs, generation=2, previous=previous)


def test_previous_intent_from_another_owner_is_not_accepted(inputs):
    previous = build(inputs)
    previous["metadata"]["labels"][OWNER] = "someone-else"
    with pytest.raises(IntentError, match="another controller scope"):
        build(inputs, previous=previous)


@pytest.fixture
def cli(inputs, tmp_path):
    profile, bindings = tmp_path / "observed-profile.json", tmp_path / "admin-bindings.yaml"
    profile.write_text(json.dumps(inputs[0]))
    bindings.write_text(yaml.safe_dump(inputs[1]))
    root = Path(__file__).resolve().parents[2]
    env = dict(os.environ, PYTHONPATH=str(root / "kubernetes-runtime"), PYTHONDONTWRITEBYTECODE="1")
    command = [sys.executable, "-m", "saw_kubernetes.intent", "--profile-configmap", str(profile),
               "--bindings", str(bindings), "--name", "saw-runtime-intent", "--generation", "1",
               "--desired-state", "Running"]
    return command, env, profile, bindings


def test_cli_writes_only_validated_json_to_stdout(inputs, cli):
    command, env, profile, bindings = cli
    before = {p: p.read_bytes() for p in [profile, bindings]}
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    assert result.returncode == 0 and result.stderr == ""
    assert json.loads(result.stdout) == build(inputs)
    assert all(path.read_bytes() == raw for path, raw in before.items())


def test_cli_errors_are_sanitized_with_empty_stdout(cli):
    command, env, profile, _ = cli
    profile.write_text('{"private-secret-token": invalid-json}')
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    assert result.returncode == 1 and result.stdout == ""
    assert "private-secret-token" not in result.stderr and "Traceback" not in result.stderr


def test_cli_rejects_duplicate_json_keys(cli):
    command, env, profile, _ = cli
    raw = profile.read_text()
    profile.write_text('{"kind":"ConfigMap",' + raw[1:])
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    assert result.returncode == 1 and result.stdout == ""


def test_cli_rejects_duplicate_yaml_binding_keys(cli):
    command, env, _, bindings = cli
    bindings.write_text(bindings.read_text() + "\nnamespace: saw-alice\n")
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    assert result.returncode == 1 and result.stdout == ""


def test_cli_argument_errors_do_not_echo_supplied_values(cli):
    command, env, _, _ = cli
    command[command.index("--generation") + 1] = "private-misplaced-value"
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    assert result.returncode == 1 and result.stdout == ""
    assert result.stderr == "invalid command-line arguments\n"


def test_cli_previous_intent_update_validation(inputs, cli, tmp_path):
    command, env, _, _ = cli
    previous = tmp_path / "previous-intent.json"
    previous.write_text(json.dumps(build(inputs, generation=2)))
    result = subprocess.run(command + ["--previous-intent", str(previous)], env=env, capture_output=True, text=True)
    assert result.returncode == 1 and result.stdout == ""
    assert "generation" in result.stderr
