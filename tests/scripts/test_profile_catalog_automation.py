"""Adding a profile is only adding its directory: the pre-commit hook and the
Profile catalog workflow regenerate the RHDH form and the profile catalogs.

Both are exercised for real in a scratch git repository holding the
generator, the profiles and the generated files.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts" / "saw-profile-catalog.py"
WORKFLOW = ROOT / ".github" / "workflows" / "profile-catalog.yml"
HOOK = ROOT / ".githooks" / "pre-commit"


def outputs():
    listed = subprocess.run([sys.executable, str(GENERATOR), "--list"],
                            capture_output=True, text=True, check=True).stdout.split()
    return listed


def test_list_names_every_generated_file():
    listed = outputs()
    assert len(listed) == 6
    assert "charts/openshell-rhdh/files/create-workspace.yaml" in listed
    assert "charts/saw-users/files/profile-catalog.json" in listed
    assert all((ROOT / p).is_file() for p in listed)


@pytest.fixture
def scratch(tmp_path):
    """A git repo with the generator, the profiles and their outputs, and a
    PATH whose python/python3 are this interpreter (it has PyYAML)."""
    repo = tmp_path / "repo"
    for rel in ["scripts/saw-profile-catalog.py", ".githooks/pre-commit", *outputs()]:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, repo / rel)
    shutil.copytree(ROOT / "charts" / "saw-bom" / "profiles", repo / "charts" / "saw-bom" / "profiles")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("python", "python3"):
        (bin_dir / name).symlink_to(sys.executable)
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
               GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")
    env.pop("CI", None)

    def git(*args, check=True):
        return subprocess.run(["git", *args], cwd=repo, env=env, capture_output=True,
                              text=True, check=check)

    git("init", "-q", "-b", "main")
    git("add", "-A")
    git("commit", "-q", "-m", "base", "--no-verify")
    return repo, env, git


def add_profile(repo, name="demo-new"):
    src = repo / "charts" / "saw-bom" / "profiles" / "custom-inference"
    dst = repo / "charts" / "saw-bom" / "profiles" / name
    shutil.copytree(src, dst)
    for f in dst.rglob("*.yaml"):
        f.write_text(f.read_text().replace("profile: custom-inference", f"profile: {name}"))


def test_the_hook_regenerates_and_commits_the_form_for_a_new_profile(scratch):
    repo, env, git = scratch
    add_profile(repo)
    git("add", "charts/saw-bom/profiles/demo-new")
    result = git("-c", "core.hooksPath=.githooks", "commit", "-q", "-m", "add demo-new",
                 check=False)
    assert result.returncode == 0, result.stderr
    committed = git("show", "--name-only", "--format=", "HEAD").stdout.split()
    assert "charts/openshell-rhdh/files/create-workspace.yaml" in committed
    assert "demo-new" in (repo / "charts/openshell-rhdh/files/create-workspace.yaml").read_text()
    assert git("status", "--porcelain").stdout == ""         # nothing left behind


def test_the_hook_leaves_unrelated_commits_alone(scratch):
    repo, env, git = scratch
    (repo / "README.md").write_text("hello\n")
    git("add", "README.md")
    git("-c", "core.hooksPath=.githooks", "commit", "-q", "-m", "readme")
    assert git("show", "--name-only", "--format=", "HEAD").stdout.split() == ["README.md"]


def commit_step():
    doc = yaml.safe_load(WORKFLOW.read_text())
    steps = doc["jobs"]["regenerate"]["steps"]
    return next(s for s in steps if s.get("name") == "Commit it, or say how to")["run"]


def run_step(repo, env, same_repo):
    step_env = dict(env, SAME_REPO="true" if same_repo else "false", BRANCH="feat")
    return subprocess.run(["bash", "-c", commit_step()], cwd=repo, env=step_env,
                          capture_output=True, text=True)


def test_the_workflow_pushes_the_regenerated_files_to_a_same_repo_branch(scratch, tmp_path):
    repo, env, git = scratch
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    git("remote", "add", "origin", str(origin))
    git("checkout", "-q", "-b", "feat")
    add_profile(repo)
    git("add", "-A")
    git("commit", "-q", "-m", "add demo-new", "--no-verify")      # catalog not regenerated
    subprocess.run([sys.executable, "scripts/saw-profile-catalog.py"], cwd=repo, env=env, check=True)

    result = run_step(repo, env, same_repo=True)
    assert result.returncode == 0, result.stdout + result.stderr
    log = subprocess.run(["git", "--git-dir", str(origin), "log", "--format=%s", "feat"],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    assert log[0] == "chore(catalog): regenerate the profile catalog"
    pushed = subprocess.run(["git", "--git-dir", str(origin), "show",
                             "feat:charts/openshell-rhdh/files/create-workspace.yaml"],
                            capture_output=True, text=True, check=True).stdout
    assert "demo-new" in pushed


def test_the_workflow_hands_a_fork_a_patch_instead(scratch):
    repo, env, git = scratch
    add_profile(repo)
    subprocess.run([sys.executable, "scripts/saw-profile-catalog.py"], cwd=repo, env=env, check=True)
    result = run_step(repo, env, same_repo=False)
    assert result.returncode == 1
    assert "::error::The profile catalog is stale" in result.stdout
    patch = (repo / "profile-catalog.patch").read_text()
    assert "demo-new" in patch
    # The patch applies on a clean tree.
    git("checkout", "-q", "--", ".")
    assert git("apply", "--check", "profile-catalog.patch", check=False).returncode == 0


def test_the_workflow_is_quiet_when_nothing_changed(scratch):
    repo, env, git = scratch
    result = run_step(repo, env, same_repo=True)
    assert result.returncode == 0 and "up to date" in result.stdout


def test_the_workflow_runs_on_profile_changes_without_pull_request_target():
    doc = yaml.safe_load(WORKFLOW.read_text())
    on = doc.get("on", doc.get(True))                 # YAML 1.1 reads `on:` as True
    assert "pull_request_target" not in on
    assert "charts/saw-bom/profiles/**" in on["pull_request"]["paths"]
    assert doc["permissions"] == {"contents": "write"}


def test_the_hook_is_executable():
    assert os.access(HOOK, os.X_OK)
