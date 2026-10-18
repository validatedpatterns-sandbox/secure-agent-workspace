"""Reconcile decides install vs apply from input hashes."""

import json
import os
import shutil
import sys

import yaml


def test_reconcile_actions(ab):
    current = {"installer": "a", "profiles": "b", "secrets": "c"}
    assert ab.reconcile_actions(current, {}, True, True) == []
    assert ab.reconcile_actions(current, {}, False, False) == ["install", "apply"]
    assert ab.reconcile_actions(current, current, True, True) == []
    changed_bom = {**current, "installer": "a2"}
    assert ab.reconcile_actions(changed_bom, current, True, True) == ["install", "apply"]
    changed_secret = {**current, "secrets": "c2"}
    assert ab.reconcile_actions(changed_secret, current, True, True) == ["apply"]
    changed_both = {**current, "installer": "a2", "profiles": "b2"}
    assert ab.reconcile_actions(changed_both, current, True, True) == ["install", "apply"]


def test_saw_reconcile_runs_the_staged_verified_copy(ab):
    """saw-reconcile.service verifies and stages the installer tree first
    (ExecStartPre=saw-stage-installer); the saw-reconcile script itself must
    then exec apply_bom.py from that staged copy, not the live virtiofs
    mount it was staged from. Before this, an edited apply_bom.py on a
    ConfigMap/Secret a namespace editor could reach took effect on the next
    reconcile with no verification at all (PR #54 review, 2)."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    script = (root / "charts" / "openshell-saw" / "files" / "guest" / "saw-reconcile").read_text()
    unit = (root / "charts" / "openshell-saw" / "files" / "guest" / "saw-reconcile.service").read_text()
    assert "ExecStartPre=/usr/local/sbin/saw-stage-installer" in unit
    assert "/var/lib/saw/verified/installer/apply_bom.py" in script
    assert "/run/saw/installer/apply_bom.py" not in script
    assert "--installer-dir /var/lib/saw/verified/installer" in script


def test_reconcile_backoff_only_applies_to_the_same_failed_hash(ab):
    current = {"installer": "a", "profiles": "b", "secrets": "c"}
    data = {}
    assert ab.reconcile_backoff_remaining(data, current) == 0
    import datetime as dt
    data["inputs"] = {"lastFailedHash": current,
                      "lastFailedAt": dt.datetime.now(dt.timezone.utc).isoformat()}
    assert ab.reconcile_backoff_remaining(data, current) > 0
    changed = {**current, "secrets": "c2"}
    assert ab.reconcile_backoff_remaining(data, changed) == 0


def test_reconcile_does_not_retry_a_freshly_failed_input(ab, tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    ab.write_inputs_failure(state, {"installer": "a"}, "install failed")
    calls = []
    monkeypatch.setattr(ab, "cmd_install", lambda args: calls.append("install") or 1)
    monkeypatch.setattr(ab, "reconcile_actions", lambda *a: ["install", "apply"])
    monkeypatch.setattr(ab, "input_hashes", lambda inputs: {"installer": "a"})

    class Args:
        inputs = str(tmp_path / "run-saw")
        state_dir = str(state)
        dry_run = False
        as_current_user = True
        installer_dir = None

    assert ab.cmd_reconcile(Args()) == 0
    assert calls == []          # backed off: install was never even attempted


def test_reconcile_retries_immediately_once_the_input_changes_again(ab, tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    ab.write_inputs_failure(state, {"installer": "a"}, "install failed")
    calls = []
    monkeypatch.setattr(ab, "cmd_install", lambda args: calls.append("install") or 1)
    monkeypatch.setattr(ab, "reconcile_actions", lambda *a: ["install", "apply"])
    monkeypatch.setattr(ab, "input_hashes", lambda inputs: {"installer": "a2"})   # changed since the failure

    class Args:
        inputs = str(tmp_path / "run-saw")
        state_dir = str(state)
        dry_run = False
        as_current_user = True
        installer_dir = None

    assert ab.cmd_reconcile(Args()) == 1
    assert calls == ["install"]   # a new change always gets a fresh attempt


def test_tree_hash_ignores_configmap_dot_dirs(ab, tmp_path):
    root = tmp_path / "secrets" / "inference"
    data = root / "..2026"
    data.mkdir(parents=True)
    (data / "model").write_text("new\n")
    link_data = root / "..data"
    link_data.symlink_to("..2026")
    (root / "model").symlink_to("..data/model")
    first = ab.tree_hash(root)
    (data / "model").write_text("rotated\n")
    assert ab.tree_hash(root) != first


def test_reconcile_after_boot_is_a_noop_until_metadata_changes(tmp_path, inputs_dir, fake_env):
    bom = yaml.safe_load((inputs_dir / "installer" / "installer-bom.yaml").read_text())
    fake_env.images_for_bom(bom)
    state = tmp_path / "var-lib-saw"
    home = tmp_path / "home-cloud-user"
    (home / ".local" / "state").mkdir(parents=True)
    shutil.copytree(fake_env.home / ".local" / "state" / "openshell",
                    home / ".local" / "state" / "openshell")
    script = inputs_dir / "installer" / "apply_bom.py"
    base = ["--inputs", str(inputs_dir), "--state-dir", str(state), "--as-current-user"]
    install_flags = ["--bin-dir", str(tmp_path / "bin"), "--opt-dir", str(tmp_path / "opt"),
                     "--skip-gateway", "--etc-dir", str(tmp_path / "etc")]
    env = {**os.environ, "HOME": str(home)}

    def run(cmd):
        extra = install_flags if cmd in ("install", "reconcile") else []
        return __import__("subprocess").run(
            [sys.executable, str(script), cmd, *base, *extra],
            capture_output=True, text=True, env=env)

    assert run("install").returncode == 0
    assert run("apply").returncode == 0
    pulls = len(fake_env.podman_calls())
    assert run("reconcile").returncode == 0
    status = json.loads((state / "status.json").read_text())
    assert status["inputs"]["upToDate"] is True
    assert len(fake_env.podman_calls()) == pulls
    metadata = inputs_dir / "secrets" / "inference" / "model"
    metadata.write_text("rotated-model\n")
    changed = run("reconcile")
    assert changed.returncode == 0, changed.stdout + changed.stderr
    assert "running apply" in changed.stdout
    assert "running install" not in changed.stdout
    status = json.loads((state / "status.json").read_text())
    assert status["inputs"]["upToDate"] is True
    assert status["inputs"]["message"] == "applied changed inputs"
    updates = [c for c in fake_env.openshell_calls() if "update" in c and "provider" in c]
    assert updates
