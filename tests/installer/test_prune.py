"""Profile pruning removes only objects the installer recorded."""

import json
from pathlib import Path

import pytest

from conftest import harness_files, profile_files
from test_custom_endpoint import custom_secrets as _custom_secrets  # noqa: F401  (reused fixture)

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
def custom_secrets(_custom_secrets):
    """The reused Secret, labelled for the `openai` type these repros use."""
    (_custom_secrets / "inference" / "provider").write_text("openai\n")
    return _custom_secrets


@pytest.fixture
def custom_inference_profiles(ab):
    """Separate from the module's `profiles` fixture (data-science) to avoid
    a name collision: the custom-inference profile with its provider on the
    shipped `openai` type, as it was when these repros were found (what is
    under test is a shipped profile being imported, skipped and pruned; the
    deployment-profile type the shipped BOM uses now is covered in
    test_custom_endpoint.py)."""
    files = profile_files("custom-inference")
    key = next(k for k in files if k.endswith("providers.yaml"))
    files[key] = files[key].replace("type: custom-inference", "type: openai")
    return ab.parse_profiles(files)


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


def _on(config, ledger):
    return {**config, "prune": {"mode": "on", "sandboxes": True, "ledgerPath": str(ledger)}}


def _ledger_names(ledger, kind):
    saved = json.loads(ledger.read_text())
    return [obj["name"] for obj in saved["objects"] if obj["kind"] == kind]


def test_managed_label_text_accepts_both_cli_formats(ab):
    """Workspace get is `key=value`; sandbox human text is `key: value`."""
    assert ab._managed_label_in_text("  Labels: saw.redhat.com/managed=true")
    assert ab._managed_label_in_text("Labels:\n    saw.redhat.com/managed: true")
    assert ab._managed_label_from_json('{"labels": {"saw.redhat.com/managed": "true"}}') is True
    assert not ab._managed_label_in_text("Labels: saw.redhat.com/managed=false")
    assert not ab._managed_label_in_text("Labels:\n    saw.redhat.com/managed: false")
    assert ab._managed_label_from_json('{"labels": {}}') is False


def test_output_flag_rejection_is_claps_exact_phrase(ab):
    """Only Clap's `unexpected argument '--output'` retries as human text."""
    assert ab._cli_rejected_output_flag("error: unexpected argument '--output' found\n")
    assert not ab._cli_rejected_output_flag(
        "error: unexpected argument '--workspace' found\n"
        "Usage: openshell sandbox get <NAME> --output")
    assert not ab._cli_rejected_output_flag("unrecognized option '--output'")


def test_not_found_is_distinct_from_other_cli_failures(ab):
    assert ab._resource_not_found("Error: sandbox 'extra' not found")
    assert ab._resource_not_found("Error: workspace not found")
    assert ab._resource_not_found("Error: workspace 'notes' not found")
    assert ab._resource_not_found(
        'status: NotFound, message: "sandbox \'extra\' not found", details: []')
    assert not ab._resource_not_found("Error: provider 'brave' is attached to a sandbox")
    assert not ab._resource_not_found(
        "Error: provider profile 'brave' was not found in the requested scope")
    assert not ab._resource_not_found("error: unexpected argument '--output' found")


def test_post_adoption_sandbox_is_pruned_from_json_labels(
        ab, fake_env, config, profiles, creds, tmp_path, capsys):
    """Objects created after the first apply are adopted=false, so prune
    reads the label. The fake prints the OpenShell 0.0.116 and 0.1.2 JSON
    shape for sandbox get."""
    ledger = tmp_path / "managed.json"
    cfg = _on(config, ledger)
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    for profile in profiles:
        for ws in profile.workspaces:
            if ws.name == "default":
                ws.sandboxes.append(ab.Sandbox(name="extra", image="base", providers=["nvidia"]))
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    saved = json.loads(ledger.read_text())
    extra = next(obj for obj in saved["objects"] if obj["kind"] == "sandbox" and obj["name"] == "extra")
    assert extra["adopted"] is False
    for profile in profiles:
        for ws in profile.workspaces:
            ws.sandboxes = [sb for sb in ws.sandboxes if sb.name != "extra"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    assert "default/extra" not in fake_env.openshell_state()["sandboxes"]
    assert "extra" not in _ledger_names(ledger, "sandbox")
    assert "sandbox default/extra" in json.loads(ledger.read_text())["lastPrune"]["pruned"]
    assert "deleted sandbox default/extra" in capsys.readouterr().out


def test_post_adoption_sandbox_without_label_is_kept(
        ab, fake_env, config, profiles, creds, tmp_path, capsys):
    ledger = tmp_path / "managed.json"
    cfg = _on(config, ledger)
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    for profile in profiles:
        for ws in profile.workspaces:
            if ws.name == "default":
                ws.sandboxes.append(ab.Sandbox(name="extra", image="base", providers=["nvidia"]))
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    state = fake_env.openshell_state()
    state.get("labels", {}).pop("sandbox/default/extra", None)
    fake_env.set_openshell_state(state)
    for profile in profiles:
        for ws in profile.workspaces:
            ws.sandboxes = [sb for sb in ws.sandboxes if sb.name != "extra"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    out = capsys.readouterr().out
    assert "default/extra" in fake_env.openshell_state()["sandboxes"]
    assert "extra" in _ledger_names(ledger, "sandbox")
    assert "sandbox default/extra" not in json.loads(ledger.read_text())["lastPrune"]["pruned"]
    assert "not labeled" in out
    assert "deleted sandbox default/extra" not in out


def test_post_adoption_sandbox_prunes_when_json_output_is_unsupported(
        ab, fake_env, config, profiles, creds, tmp_path):
    """A CLI that rejects `--output json` is retried as human `key: value` text."""
    ledger = tmp_path / "managed.json"
    cfg = _on(config, ledger)
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    for profile in profiles:
        for ws in profile.workspaces:
            if ws.name == "default":
                ws.sandboxes.append(ab.Sandbox(name="extra", image="base", providers=["nvidia"]))
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    fake_env.reject_json_output()
    for profile in profiles:
        for ws in profile.workspaces:
            ws.sandboxes = [sb for sb in ws.sandboxes if sb.name != "extra"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    assert "default/extra" not in fake_env.openshell_state()["sandboxes"]
    assert "extra" not in _ledger_names(ledger, "sandbox")


def test_post_adoption_workspace_is_pruned_from_equals_labels(
        ab, fake_env, config, profiles, creds, tmp_path):
    """workspace get stays `Labels: key=value`. A workspace added after
    adoption must still match that form and be deleted once it is empty."""
    ledger = tmp_path / "managed.json"
    cfg = _on(config, ledger)
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    profiles[0].workspaces.append(ab.Workspace(name="notes"))
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    saved = json.loads(ledger.read_text())
    notes = next(obj for obj in saved["objects"] if obj["kind"] == "workspace" and obj["name"] == "notes")
    assert notes["adopted"] is False
    assert "notes" in fake_env.openshell_state()["workspaces"]
    for profile in profiles:
        profile.workspaces = [ws for ws in profile.workspaces if ws.name != "notes"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    assert "notes" not in fake_env.openshell_state()["workspaces"]
    assert "notes" not in _ledger_names(ledger, "workspace")
    assert "workspace -/notes" in json.loads(ledger.read_text())["lastPrune"]["pruned"]


def test_manually_deleted_sandbox_leaves_the_ledger(
        ab, fake_env, config, profiles, creds, tmp_path, capsys):
    """A sandbox removed by hand makes `sandbox get` fail during the label
    check. That is gone, so the ledger drops it instead of logging
    "not labeled" on every reconcile."""
    ledger = tmp_path / "managed.json"
    cfg = _on(config, ledger)
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    for profile in profiles:
        for ws in profile.workspaces:
            if ws.name == "default":
                ws.sandboxes.append(ab.Sandbox(name="extra", image="base", providers=["nvidia"]))
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"].pop("default/extra")
    fake_env.set_openshell_state(state)
    for profile in profiles:
        for ws in profile.workspaces:
            ws.sandboxes = [sb for sb in ws.sandboxes if sb.name != "extra"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    out = capsys.readouterr().out
    assert "extra" not in _ledger_names(ledger, "sandbox")
    assert "sandbox default/extra" in json.loads(ledger.read_text())["lastPrune"]["pruned"]
    assert "not found" in out
    assert "not labeled" not in out
    assert "delete failed" not in out


def test_manually_deleted_workspace_leaves_the_ledger(
        ab, fake_env, config, profiles, creds, tmp_path, capsys):
    """OpenShell 0.1.2 `workspace delete` does not pass allow_missing. A
    workspace the user already removed must leave the ledger instead of
    logging "delete failed" on every reconcile."""
    ledger = tmp_path / "managed.json"
    cfg = _on(config, ledger)
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    state = fake_env.openshell_state()
    state["workspaces"] = [name for name in state["workspaces"] if name != "cuda-dev"]
    fake_env.set_openshell_state(state)
    for profile in profiles:
        profile.workspaces = [ws for ws in profile.workspaces if ws.name != "cuda-dev"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    out = capsys.readouterr().out
    saved = json.loads(ledger.read_text())
    assert "cuda-dev" not in _ledger_names(ledger, "workspace")
    assert "workspace -/cuda-dev" in saved["lastPrune"]["pruned"]
    assert "not found" in out
    assert "delete failed" not in out


def test_manually_deleted_post_adoption_workspace_is_not_unlabeled(
        ab, fake_env, config, profiles, creds, tmp_path, capsys):
    """A workspace created after adoption is label-checked via `workspace get`.
    Not found there drops the ledger entry instead of "not labeled"."""
    ledger = tmp_path / "managed.json"
    cfg = _on(config, ledger)
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    profiles[0].workspaces.append(ab.Workspace(name="notes"))
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    state = fake_env.openshell_state()
    state["workspaces"] = [name for name in state["workspaces"] if name != "notes"]
    fake_env.set_openshell_state(state)
    for profile in profiles:
        profile.workspaces = [ws for ws in profile.workspaces if ws.name != "notes"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    out = capsys.readouterr().out
    assert "notes" not in _ledger_names(ledger, "workspace")
    assert "not found" in out
    assert "not labeled" not in out
    assert "delete failed" not in out


def _delete_call(calls, kind, name, workspace):
    for index, call in enumerate(calls):
        if call[:2] != [kind, "delete"] or name not in call:
            continue
        if workspace == "default":
            if "--workspace" not in call:
                return index
        elif "--workspace" in call and call[call.index("--workspace") + 1] == workspace:
            return index
    return None


def test_sandbox_is_deleted_before_its_provider(
        ab, fake_env, config, profiles, creds, tmp_path, capsys):
    """PRUNE_ORDER is sandbox then provider. Deleting both in one apply must
    remove the sandbox first, or the fake refuses the provider delete while
    the sandbox still lists it."""
    ledger = tmp_path / "managed.json"
    cfg = _on(config, ledger)
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    for profile in profiles:
        for ws in profile.workspaces:
            if ws.name != "cuda-dev":
                continue
            ws.sandboxes = [sb for sb in ws.sandboxes if sb.name != "cuda-sandbox"]
            ws.providers = [p for p in ws.providers if p.name != "nvidia"]
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    state = fake_env.openshell_state()
    assert "cuda-dev/cuda-sandbox" not in state["sandboxes"]
    assert "cuda-dev/nvidia" not in state["providers"]
    calls = fake_env.openshell_calls()
    sandbox_at = _delete_call(calls, "sandbox", "cuda-sandbox", "cuda-dev")
    provider_at = _delete_call(calls, "provider", "nvidia", "cuda-dev")
    assert sandbox_at is not None and provider_at is not None
    assert sandbox_at < provider_at
    saved = json.loads(ledger.read_text())
    assert "sandbox cuda-dev/cuda-sandbox" in saved["lastPrune"]["pruned"]
    assert "provider cuda-dev/nvidia" in saved["lastPrune"]["pruned"]
    assert not any(
        obj["kind"] == "provider" and obj["name"] == "nvidia" and obj.get("workspace") == "cuda-dev"
        for obj in saved["objects"])
    assert any(
        obj["kind"] == "provider" and obj["name"] == "nvidia" and obj.get("workspace") == "default"
        for obj in saved["objects"])
    out = capsys.readouterr().out
    assert "attached to a sandbox" not in out
    assert "delete failed" not in out


def test_failed_provider_delete_stays_in_the_ledger(
        ab, fake_env, config, profiles, creds, tmp_path, capsys):
    """A provider still attached to a sandbox (here, one the ledger does not
    track) makes the CLI fail. The installer must not log success or drop
    the ledger entry; status.json copies lastPrune, so the provider is not
    recorded as pruned either."""
    ledger = tmp_path / "managed.json"
    cfg = _on(config, ledger)
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    state = fake_env.openshell_state()
    state["sandboxes"]["default/hand"] = {"image": "base", "providers": ["brave"], "phase": "Ready"}
    fake_env.set_openshell_state(state)
    _drop_provider(profiles, "default", "brave")
    ab.ProfileApplier(ab.Shell(), cfg, creds, harness=_harness(ab)).apply(profiles)
    out = capsys.readouterr().out
    assert "default/brave" in fake_env.openshell_state()["providers"]
    assert "default/hand" in fake_env.openshell_state()["sandboxes"]
    assert "brave" in _ledger_names(ledger, "provider")
    pruned = json.loads(ledger.read_text())["lastPrune"]["pruned"]
    assert "provider default/brave" not in pruned
    assert "deleted provider default/brave" not in out
    assert "delete failed" in out


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
