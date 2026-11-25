"""A tool-gate policy update reaches an existing container workspace."""
import json

import pytest

from saw_kubernetes.prepare_gate import publish_model, publish_tree, verify


def tree(policy, owner="alice"):
    identity = {"username": owner, "subject": "s-" + owner, "sandbox": "notebook", "workspace": "default"}
    return {"tool-actions.yaml": (policy, False),
            "identity.json": ((json.dumps(identity, sort_keys=True) + "\n").encode(), False),
            "plugin/index.js": (b"plugin", False)}


def test_a_policy_update_replaces_the_gate_and_keeps_the_running_tree(tmp_path):
    target = tmp_path / "bundle"
    old, new = tree(b"rules: [old]\n"), tree(b"rules: [new]\n")
    publish_tree(tmp_path, target, old, replace=True)
    running = target.stat().st_ino  # a sandbox's subPath mount follows this inode
    publish_tree(tmp_path, target, new, replace=True)
    verify(target, new)
    (kept,) = [p / "bundle" for p in tmp_path.glob("superseded-*")]
    assert kept.stat().st_ino == running
    verify(kept, old)


def test_republishing_the_same_policy_changes_nothing(tmp_path):
    target = tmp_path / "bundle"
    files = tree(b"rules: []\n")
    publish_tree(tmp_path, target, files, replace=True)
    inode = target.stat().st_ino
    publish_tree(tmp_path, target, files, replace=True)
    assert target.stat().st_ino == inode and not list(tmp_path.glob("superseded-*"))


def test_the_model_and_proof_follow_the_new_tree(tmp_path):
    target = tmp_path / "bundle"
    publish_tree(tmp_path, target, tree(b"a\n"), model_selector=True, browser=True, replace=True)
    publish_model(tmp_path, target, "first", 3)
    (target / "relay-proof").write_bytes(b"0" * 64)
    publish_tree(tmp_path, target, tree(b"b\n"), model_selector=True, browser=True, replace=True)
    assert not (target / "model.json").exists()
    publish_model(tmp_path, target, "first", 3)  # the Job republishes its selection
    verify(target, tree(b"b\n"), model_selector=True, browser=True)


def test_another_owner_never_takes_over_a_gate_volume(tmp_path):
    target = tmp_path / "bundle"
    publish_tree(tmp_path, target, tree(b"a\n", "alice"), replace=True)
    with pytest.raises(ValueError, match="another owner"):
        publish_tree(tmp_path, target, tree(b"a\n", "bob"), replace=True)
    verify(target, tree(b"a\n", "alice"))


def test_content_addressed_trees_stay_write_once(tmp_path):
    target = tmp_path / "harness-x"
    publish_tree(tmp_path, target, tree(b"a\n"))
    with pytest.raises(ValueError, match="differs"):
        publish_tree(tmp_path, target, tree(b"b\n"))


def test_a_symlinked_gate_is_refused(tmp_path):
    real = tmp_path / "elsewhere"
    publish_tree(tmp_path, real, tree(b"a\n"))
    (tmp_path / "bundle").symlink_to(real)
    with pytest.raises(ValueError, match="invalid gate directory"):
        publish_tree(tmp_path, tmp_path / "bundle", tree(b"b\n"), replace=True)


def test_a_long_running_sandbox_keeps_its_tree_through_later_updates(tmp_path):
    """A sandbox mounts its tree by inode and is not restarted by a policy
    update, so no number of later updates may remove the tree it started on."""
    target = tmp_path / "bundle"
    publish_tree(tmp_path, target, tree(b"v0\n"), replace=True)
    first = target.stat().st_ino
    for n in range(1, 5):
        publish_tree(tmp_path, target, tree(f"v{n}\n".encode()), replace=True)
    (running,) = [p / "bundle" for p in tmp_path.glob("superseded-*") if (p / "bundle").stat().st_ino == first]
    assert (running / "tool-actions.yaml").read_bytes() == b"v0\n"
    assert len(list(tmp_path.glob("superseded-*"))) == 4
    verify(target, tree(b"v4\n"))
