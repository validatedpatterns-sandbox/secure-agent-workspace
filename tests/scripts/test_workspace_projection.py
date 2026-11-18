"""The portal adapter and other installation entry points share one projection."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("shared_workspace", ROOT / "charts/saw-users/files/workspace.py")
workspace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(workspace)
CATALOG = json.loads((ROOT / "charts/saw-users/files/profile-catalog.json").read_text())["profiles"]


def inputs():
    owner = dict(name="alice", ownerSubject="11111111-1111-4111-8111-111111111111",
                 installationID="22222222-2222-4222-8222-222222222222", registration="a"*16,
                 profiles=["data-science"], values={"deployment": {"mode": "container"}},
                 lifecycleVersion=1, initialModelInputs={"inference.model": "first"},
                 modelInputs={"inference.model": "second"}, desiredState="Running", restartGeneration=2)
    site = dict(subject=owner["ownerSubject"], automaticEnrollment={"approvedProfiles": {"data-science": "b"*64}},
                profileImageOverrides={"data-science": {"default": {"notebook": "example/agent@sha256:"+"c"*64}}})
    return owner, site


def test_projection_uses_catalog_targets_and_preserves_callers_inputs():
    owner, site = inputs()
    before = copy.deepcopy((owner, site))
    result = workspace.project_workspace(owner, {"defaults": {}}, site, CATALOG)
    projected = result["containerSites"]["alice"]
    assert set(projected["targets"]) == {"default/notebook", "cuda-dev/cuda-sandbox"}
    assert projected["modelInputs"] == {"inference.model": "first"}
    assert projected["requestedModels"] == {"inference.model": "second"}
    assert projected["restartGeneration"] == 2
    assert projected["selectedDigest"] == "b"*64
    assert result["users"][0]["imageOverrides"] == site["profileImageOverrides"]["data-science"]
    assert (owner, site) == before
    assert "enrollment" not in projected


@pytest.mark.parametrize("fault", ["subject", "profile", "identity", "endpoint"])
def test_projection_rejects_unbound_input(fault):
    owner, site = inputs()
    if fault == "subject": site["subject"] = "replacement-owner"
    if fault == "profile": owner["profiles"] = ["personal-assistant"]
    if fault == "identity": del owner["installationID"]
    if fault == "endpoint": owner["customInferenceURL"] = "https://unexpected.example/v1"
    with pytest.raises(workspace.WorkspaceError):
        workspace.project_workspace(owner, {}, site, CATALOG)


def test_legacy_vm_remains_vm_and_reserved_modes_never_fall_back():
    result = workspace.project_workspace({"name": "alice"}, {}, {}, CATALOG)
    assert result["users"][0]["values"]["deployment"]["mode"] == "vm"
    for mode in ("unknown", "confidential"):
        with pytest.raises(workspace.WorkspaceError, match="unsupported"):
            workspace.project_workspace({"name": "alice", "values": {"deployment": {"mode": mode}}}, {}, {}, CATALOG)


def test_packaged_projector_is_exactly_the_canonical_source():
    assert (ROOT / "charts/openshell-rhdh/files/workspace.py").read_bytes() == Path(SPEC.origin).read_bytes()


def test_disabling_enrollment_cannot_silently_prune_an_existing_runtime():
    owner, site = inputs()
    site["automaticEnrollment"]["enabled"] = False
    observed = {"immutable": True, "metadata": {"labels": {"saw.redhat.com/runtime-owner": owner["installationID"]}},
                "data": {"binding.json": "{}"}}
    with pytest.raises(workspace.WorkspaceError, match="cannot disable"):
        workspace.project_workspace(owner, {}, site, CATALOG, lambda _: observed)
    projected = workspace.project_workspace(owner, {}, site, CATALOG, lambda _: {})
    assert "enrollment" not in projected["containerSites"]["alice"]


def test_foundation_requires_no_synthetic_approval_hash():
    owner, site = inputs()
    site["automaticEnrollment"] = {"enabled": False}
    result = workspace.project_workspace(owner, {}, site, CATALOG, lambda _: {})
    assert not result["containerSites"]["alice"]["selectedDigest"]
    site["automaticEnrollment"]["enabled"] = True
    with pytest.raises(workspace.WorkspaceError):
        workspace.project_workspace(owner, {}, site, CATALOG, lambda _: {})


@pytest.mark.parametrize("mode", ["vm", "container"])
def test_operator_revision_pin_is_shared_and_does_not_change_repository(mode):
    owner, site = inputs()
    owner["values"]["deployment"]["mode"] = mode
    # Registration fields are not an authority to select source code.
    owner["workspaceRevisions"] = {"alice": "c"*40}
    owner["values"]["global"] = {"targetRevision": "tenant-branch", "repoURL": "https://foreign.example/repo"}
    defaults = {"global": {"repoURL": "https://approved.example/repo", "targetRevision": "site-main"},
                "workspaceRevisions": {"alice": "a"*40, "bob": "b"*40}}
    before = copy.deepcopy((owner, defaults, site))
    result = workspace.project_workspace(owner, defaults, site, CATALOG)
    assert result["global"] == {"repoURL": defaults["global"]["repoURL"], "targetRevision": "a"*40}
    assert "workspaceRevisions" not in result
    assert (owner, defaults, site) == before
    del defaults["workspaceRevisions"]["alice"]
    assert workspace.project_workspace(owner, defaults, site, CATALOG)["global"] == defaults["global"]


@pytest.mark.parametrize("pins", [None, [], {"alice": "main"}, {"alice": "a"*39},
    {"alice": "A"*40}, {"alice": {"repoURL": "https://foreign.example/repo", "revision": "a"*40}},
    {"../alice": "a"*40}, {"alice": 123}])
def test_revision_pin_requires_operator_mapping_of_owner_to_full_commit(pins):
    with pytest.raises(workspace.WorkspaceError, match="workspaceRevisions"):
        workspace.project_workspace({"name": "alice"}, {"workspaceRevisions": pins}, {}, CATALOG)


def test_kata_requires_reviewed_placement_and_reuses_the_same_targets():
    owner, site = inputs()
    targets = workspace.project_workspace(owner, {}, site, CATALOG)["containerSites"]["alice"]["targets"]
    owner["values"]["deployment"]["mode"] = "kata"
    with pytest.raises(workspace.WorkspaceError, match="RuntimeClass"):
        workspace.project_workspace(owner, {}, site, CATALOG)
    site["kataRuntimeClass"] = {"name": "saw-kata", "uid": owner["installationID"], "sha256": "f"*64}
    actual = workspace.project_workspace(owner, {}, site, CATALOG)["containerSites"]["alice"]
    assert actual["targets"] == targets
    assert actual["kataRuntimeClass"] == site["kataRuntimeClass"]
    owner["values"]["deployment"]["mode"] = "container"
    with pytest.raises(workspace.WorkspaceError, match="Kata approval"):
        workspace.project_workspace(owner, {}, site, CATALOG)
