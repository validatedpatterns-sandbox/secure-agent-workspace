"""Profile pruning removes only objects the installer recorded."""

import json
from pathlib import Path

import pytest

from conftest import harness_files, profile_files
from test_custom_endpoint import custom_secrets  # noqa: F401  (reused fixture)

def _harness(ab):
    return {"bundles": ab.parse_harness_files(harness_files())}


SHIPPED_OPENAI_PROFILE = (
    Path(__file__).resolve().parents[2]
    / "charts" / "openshell-saw" / "files" / "provider-profiles" / "openai.yaml"
)


@pytest.fixture
def profiles(ab, shipped_profile_files):
    return ab.parse_profiles(shipped_profile_files)


@pytest.fixture
def creds(ab, profiles, secrets_dir):
    return ab.resolve_credentials(profiles, secrets_dir)


def test_first_apply_adopts_and_deletes_nothing(ab, fake_env, config, profiles, creds, tmp_path, capsys):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    saved = json.loads(ledger.read_text())
    assert saved["adopted"] is True
    assert saved["lastPrune"] == {"pruned": [], "wouldPrune": []}
    assert "cuda-dev/cuda-sandbox" in fake_env.openshell_state()["sandboxes"]
    assert "pruning nothing" in capsys.readouterr().out


def test_report_mode_keeps_a_removed_sandbox(ab, fake_env, config, profiles, creds, tmp_path, capsys):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "report", "sandboxes": True, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    for profile in profiles:
        for ws in profile.workspaces:
            ws.sandboxes = [sb for sb in ws.sandboxes if sb.name != "cuda-sandbox"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    assert "cuda-dev/cuda-sandbox" in fake_env.openshell_state()["sandboxes"]
    assert "would delete sandbox cuda-dev/cuda-sandbox" in capsys.readouterr().out


def test_on_mode_deletes_a_removed_sandbox_and_empty_workspace(ab, fake_env, config, profiles, creds, tmp_path):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    for profile in profiles:
        profile.workspaces = [ws for ws in profile.workspaces if ws.name != "cuda-dev"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    state = fake_env.openshell_state()
    assert "cuda-dev/cuda-sandbox" not in state["sandboxes"]
    assert "cuda-dev" not in state["workspaces"]
    assert "default" in state["workspaces"]


def test_sandboxes_stay_when_prune_sandboxes_is_false(ab, fake_env, config, profiles, creds, tmp_path):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": False, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    for profile in profiles:
        profile.workspaces = [ws for ws in profile.workspaces if ws.name != "cuda-dev"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    state = fake_env.openshell_state()
    assert "cuda-dev/cuda-sandbox" in state["sandboxes"]
    assert "cuda-dev" in state["workspaces"]


def test_a_hand_created_sandbox_is_never_deleted(ab, fake_env, config, profiles, creds, tmp_path):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/mine"] = {"image": "base", "providers": [], "phase": "Ready"}
    fake_env.set_openshell_state(state)
    for profile in profiles:
        for ws in profile.workspaces:
            ws.sandboxes = [sb for sb in ws.sandboxes if sb.name != "notebook"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    assert "default/mine" in fake_env.openshell_state()["sandboxes"]


def test_empty_profiles_delete_nothing(ab, fake_env, config, profiles, creds, tmp_path):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    before = fake_env.openshell_state()["sandboxes"].keys()
    with pytest.raises(ab.InstallerError, match="missing or empty"):
        ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply([])
    assert set(fake_env.openshell_state()["sandboxes"]) == set(before)


def test_default_workspace_is_never_deleted(ab, fake_env, config, creds, tmp_path):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}
    # Seed an adopted ledger entry and prune directly. apply refuses an empty
    # profile list, so this does not go through apply.
    applier = ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab))
    applier.ledger.data = {
        "version": 1, "adopted": True,
        "objects": [{"kind": "workspace", "workspace": "", "name": "default",
                     "profile": "data-science", "adopted": True, "createdAt": "t"}],
    }
    applier.desired = set()
    applier.prune()
    assert any(obj["name"] == "default" for obj in applier.ledger.data["objects"])


def _drop_provider(profiles, workspace, name):
    for profile in profiles:
        for ws in profile.workspaces:
            if ws.name == workspace:
                ws.providers = [p for p in ws.providers if p.name != name]


def test_removing_a_provider_deletes_it_only_when_on(ab, fake_env, config, profiles, creds, tmp_path, capsys):
    ledger = tmp_path / "managed.json"
    report = {**config, "prune": {"mode": "report", "sandboxes": False, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), report, creds, harness=_harness(ab)).apply(profiles)
    _drop_provider(profiles, "default", "brave")
    before = [c for c in fake_env.openshell_calls() if "delete" in c]
    ab.ProfileApplier(ab.Shell(), report, creds, harness=_harness(ab)).apply(profiles)
    assert "default/brave" in fake_env.openshell_state()["providers"]
    assert [c for c in fake_env.openshell_calls() if "delete" in c] == before
    assert "would delete provider default/brave" in capsys.readouterr().out
    on = {**config, "prune": {"mode": "on", "sandboxes": False, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), on, creds, harness=_harness(ab)).apply(profiles)
    assert "default/brave" not in fake_env.openshell_state()["providers"]


def test_hand_made_workspace_and_provider_are_never_deleted(ab, fake_env, config, profiles, creds, tmp_path):
    ledger = tmp_path / "managed.json"
    cfg = {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    state = fake_env.openshell_state()
    state["workspaces"].append("notes")
    state["providers"]["default/mine"] = {"type": "openai", "credential": "local"}
    fake_env.set_openshell_state(state)
    for profile in profiles:
        profile.workspaces = [ws for ws in profile.workspaces if ws.name != "cuda-dev"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    state = fake_env.openshell_state()
    assert "notes" in state["workspaces"]
    assert "default/mine" in state["providers"]


# --- Repros from the PR #54 review: 6a, 6b, 6c (fixed in this change) -----

@pytest.fixture
def custom_inference_profiles(ab):
    """Separate from the module's `profiles` fixture (data-science) to avoid
    a name collision: this is the custom-inference profile."""
    return ab.parse_profiles(profile_files("custom-inference"))


def _apply_on(ab, config, creds, profiles, ledger, docs=None):
    cfg = {**config, "prune": {"mode": "on", "sandboxes": False, "ledgerPath": str(ledger)}}
    ab.ProfileApplier(ab.Shell(), cfg, creds, docs, harness=_harness(ab)).apply(profiles)


def test_imported_profile_is_not_pruned_while_its_provider_still_uses_it(
        ab, fake_env, config, custom_inference_profiles, custom_secrets, tmp_path):
    """6a: import_provider_profile only remembered the profile on the run
    that imported it. The next apply (provider already exists, so no
    re-import) pruned the profile out from under the provider still using
    it, and the run after that re-imported it."""
    fake_env.without_profiles("openai")
    creds = ab.resolve_credentials(custom_inference_profiles, custom_secrets)
    ledger = tmp_path / "managed.json"
    docs = {"openai": SHIPPED_OPENAI_PROFILE.read_text()}
    _apply_on(ab, config, creds, custom_inference_profiles, ledger, docs)  # imports, adopts
    _apply_on(ab, config, creds, custom_inference_profiles, ledger, docs)  # provider exists: bug pruned it here
    state = fake_env.openshell_state()
    assert "openai" in state.get("imported_profiles", {}).get("default", []), state.get("imported_profiles")
    pruned = json.loads(ledger.read_text())["lastPrune"]["pruned"]
    assert not any("profile" in p for p in pruned), pruned


def test_skipped_provider_is_not_pruned_on_a_transient_catalog_gap(
        ab, fake_env, config, custom_inference_profiles, custom_secrets, tmp_path):
    """6b: a provider skipped because the gateway briefly had no profile for
    its type (governance restarting, a catalog gap, ...) was never
    remembered, so prune deleted it (and its inference route) even though
    nothing about the desired profile changed."""
    creds = ab.resolve_credentials(custom_inference_profiles, custom_secrets)
    ledger = tmp_path / "managed.json"
    _apply_on(ab, config, creds, custom_inference_profiles, ledger)   # adopt, provider created
    _apply_on(ab, config, creds, custom_inference_profiles, ledger)
    assert "default/custom" in fake_env.openshell_state()["providers"]
    fake_env.without_profiles("openai")        # governance briefly not serving the profile
    _apply_on(ab, config, creds, custom_inference_profiles, ledger)
    state = fake_env.openshell_state()
    assert "default/custom" in state["providers"]


def test_kept_sandbox_does_not_lose_its_providers(ab, fake_env, config, shipped_profile_files,
                                                  secrets_dir, tmp_path):
    """6c: removing a workspace from the profile deleted the providers (and
    inference route) of a sandbox that prune.sandboxes: false is keeping,
    even though the sandbox object itself was correctly left alone."""
    profiles = ab.parse_profiles(shipped_profile_files)
    creds = ab.resolve_credentials(profiles, secrets_dir)
    ledger = tmp_path / "managed.json"
    _apply_on(ab, config, creds, profiles, ledger)
    for profile in profiles:
        profile.workspaces = [ws for ws in profile.workspaces if ws.name != "cuda-dev"]
    _apply_on(ab, config, creds, profiles, ledger)
    state = fake_env.openshell_state()
    assert "cuda-dev/cuda-sandbox" in state["sandboxes"]
    kept = state["sandboxes"]["cuda-dev/cuda-sandbox"]["providers"]
    missing = [p for p in kept if f"cuda-dev/{p}" not in state["providers"]]
    assert not missing, f"sandbox lost providers: {missing}"


def test_kept_sandbox_providers_are_protected_when_listing_fails(
        ab, fake_env, config, shipped_profile_files, secrets_dir, tmp_path):
    """A failed `sandbox provider list` must not make kept_sandbox_providers
    think a kept sandbox uses nothing, or every provider in its workspace
    becomes prunable -- fail safe the same direction workspace_contents
    already does for a failed listing (PR #54 review round 2, 3)."""
    profiles = ab.parse_profiles(shipped_profile_files)
    creds = ab.resolve_credentials(profiles, secrets_dir)
    ledger = tmp_path / "managed.json"
    _apply_on(ab, config, creds, profiles, ledger)
    for profile in profiles:
        profile.workspaces = [ws for ws in profile.workspaces if ws.name != "cuda-dev"]
    fake_env.deny("sandbox provider")
    _apply_on(ab, config, creds, profiles, ledger)
    state = fake_env.openshell_state()
    assert "cuda-dev/cuda-sandbox" in state["sandboxes"]
    assert "cuda-dev/nvidia" in state["providers"], "provider pruned despite a kept sandbox using it"
