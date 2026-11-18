"""Adding a profile is only adding its directory: the pre-commit hook and the
Profile catalog workflow regenerate the RHDH form and the profile catalogs.

Both are exercised for real in a scratch git repository holding the
generator, the profiles and the generated files.
"""
import os
import shlex
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
UI_SOURCE = "charts/openshell-saw/files/installer/saw_ui_limit.py"
UI_MIRROR = "charts/saw-workspace-relay/files/saw_ui_limit.py"


def outputs():
    listed = subprocess.run([sys.executable, str(GENERATOR), "--list"],
                            capture_output=True, text=True, check=True).stdout.split()
    return listed


@pytest.mark.parametrize("enabled", [False, True])
def test_attached_model_fields_follow_enabled_sandbox_providers(scratch, enabled):
    repo, env, _ = scratch
    folder = repo / "charts/saw-bom/profiles/data-science/default"
    source = folder / "providers.yaml"
    providers = yaml.safe_load(source.read_text())
    for p in providers["spec"]["providers"]:
        if p["name"] in ("openai", "anthropic"):
            p["enabled"] = enabled
    source.write_text(yaml.safe_dump(providers))
    source = folder / "sandbox.yaml"
    doc = yaml.safe_load(source.read_text())
    sb = doc["spec"]["sandboxes"][0]
    sb["providers"] += ["openai", "anthropic"] if enabled else []
    sb["inference"]["models"] = {
        name: {"secretKeyRef": {"name": f"inference-{name}", "key": "model"},
               "default": model, "title": f"Model ({name})"}
        for name, model in [("openai", "gpt-6-luna"), ("anthropic", "claude-sonnet-4-6")]}
    source.write_text(yaml.safe_dump(doc))
    subprocess.run([sys.executable, str(repo / "scripts/saw-profile-catalog.py")],
                   env=env, capture_output=True, text=True, check=True)
    import json
    catalog = json.loads((repo / "charts/saw-users/files/profile-catalog.json").read_text())
    secrets = catalog["profiles"]["data-science"]["secrets"]
    for name, model in [("openai", "gpt-6-luna"), ("anthropic", "claude-sonnet-4-6")]:
        if enabled:
            fields = {f["key"]: f for f in secrets[f"inference-{name}"]["fields"]}
            assert fields["model"]["kind"] == "text"
            assert fields["api_key"]["kind"] == "secret"
            assert fields["model"]["default"] == model
            assert fields["model"]["required"] is False
        else:
            assert f"inference-{name}" not in secrets


def test_list_names_every_generated_file():
    listed = outputs()
    # Catalogs, owner/admin forms, shared broker inputs and the governance mirrors.
    mirrored = [p for p in listed if p.startswith("charts/openshell-saw/files/provider-profiles/")]
    shipped = sorted(p.name for p in (ROOT / "charts/governance-policy/profiles").glob("*.yaml"))
    # ... plus the mirror directory itself (so a removed mirror is staged too).
    assert "charts/saw-users/templates/_governed-proxy-policy.tpl" in listed
    assert "charts/saw-users/files/governed-profiles.json" in listed
    assert "charts/openshell-rhdh/files/set-workspace-state.yaml" in listed
    assert "charts/openshell-rhdh/files/workspace.py" in listed
    assert "charts/openshell-rhdh/files/saw_keycloak_admin.py" in listed
    assert UI_MIRROR in listed
    assert len(listed) == 12 + len(shipped) + 1
    assert sorted(p.rsplit("/", 1)[1] for p in mirrored) == shipped
    assert "charts/openshell-saw/files/provider-profiles" in listed
    assert "charts/openshell-rhdh/files/create-workspace.yaml" in listed
    assert "charts/saw-users/files/profile-catalog.json" in listed
    assert all((ROOT / p).is_file() or (ROOT / p).is_dir() for p in listed)


@pytest.fixture
def scratch(tmp_path):
    """A git repo with the generator, the profiles and their outputs, and a
    PATH whose python/python3 are this interpreter (it has PyYAML)."""
    repo = tmp_path / "repo"
    for rel in ["scripts/saw-profile-catalog.py", ".githooks/pre-commit", "charts/openshell-saw/templates/_governed-proxy-policy.tpl", "charts/saw-users/files/workspace.py", "charts/openshell-keycloak/files/saw_keycloak_admin.py", UI_SOURCE, *outputs()]:
        if (ROOT / rel).is_dir():          # the mirror directory is listed as an owned path
            continue
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, repo / rel)
    shutil.copytree(ROOT / "charts" / "saw-bom" / "profiles", repo / "charts" / "saw-bom" / "profiles")
    shutil.copytree(ROOT / "charts" / "governance-policy" / "profiles",
                    repo / "charts" / "governance-policy" / "profiles")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("python", "python3"):
        # Relocating a venv executable via a symlink loses pyvenv.cfg and
        # its site-packages. Execute its original path instead.
        interpreter = bin_dir / name
        interpreter.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} "$@"\n')
        interpreter.chmod(0o755)
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


@pytest.mark.parametrize("file,key", [("providers.yaml", "secretKey"), ("sandbox.yaml", "name")])
def test_invalid_profile_reports_its_source_without_a_traceback(scratch, file, key):
    repo, env, _ = scratch
    source = repo / "charts/saw-bom/profiles/custom-inference/default" / file
    doc = yaml.safe_load(source.read_text())
    if key == "secretKey":
        doc["spec"]["providers"][0]["credentials"] = {"api_key": {}}
    else:
        doc["spec"]["sandboxes"][0].pop("name")
    source.write_text(yaml.safe_dump(doc))
    before = {p: (repo / p).read_bytes() for p in outputs() if (repo / p).is_file()}
    result = subprocess.run([sys.executable, "scripts/saw-profile-catalog.py"], cwd=repo,
                            env=env, capture_output=True, text=True)
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert str(source.relative_to(repo)) in result.stderr and key in result.stderr
    assert all((repo / p).read_bytes() == content for p, content in before.items())


def test_the_catalog_rejects_an_optional_model_with_an_empty_default(scratch):
    repo, env, _ = scratch
    source = repo / "charts/saw-bom/profiles/custom-inference/default/sandbox.yaml"
    doc = yaml.safe_load(source.read_text())
    doc["spec"]["sandboxes"][0]["inference"]["model"]["default"] = ""
    source.write_text(yaml.safe_dump(doc))
    result = subprocess.run([sys.executable, "scripts/saw-profile-catalog.py", "--check"],
                            cwd=repo, env=env, capture_output=True, text=True)
    assert result.returncode == 1 and "Traceback" not in result.stderr
    assert "inference model must be non-empty" in result.stderr


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
    # The patch applies on a clean tree (the step staged the files to diff
    # them; put the tree back as it was before the generator ran).
    git("reset", "-q", "--hard")
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
    for event in ("pull_request", "push"):
        assert UI_SOURCE in on[event]["paths"]
        assert UI_MIRROR in on[event]["paths"]


@pytest.mark.parametrize("changed", [UI_SOURCE, UI_MIRROR])
def test_transport_source_or_mirror_only_change_runs_generation(scratch, changed):
    repo, env, git = scratch
    target = repo / changed
    target.write_text(target.read_text() + "\n# transport fixture change\n")
    git("add", changed)
    result = subprocess.run(["bash", ".githooks/pre-commit"], cwd=repo, env=env,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (repo / UI_MIRROR).read_bytes() == (repo / UI_SOURCE).read_bytes()
    assert git("show", ":" + UI_MIRROR).stdout == (repo / UI_SOURCE).read_text()
    if changed == UI_SOURCE:
        assert UI_MIRROR in git("diff", "--cached", "--name-only").stdout
    else:
        assert git("diff", "--cached", "--name-only").stdout == ""


def test_the_hook_is_executable():
    assert os.access(HOOK, os.X_OK)


def test_the_workflow_and_hook_see_an_added_and_a_removed_governance_profile(scratch, tmp_path):
    """Review: `git diff` misses an untracked (new) mirror file, and --list
    left out mirrors the generator removes, so adding or dropping a
    governance profile could report "up to date" with the installer mirror
    out of step. Both stage the generator's owned paths with `git add -A`."""
    repo, env, git = scratch
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    git("remote", "add", "origin", str(origin))
    git("checkout", "-q", "-b", "feat")
    gov = repo / "charts" / "governance-policy" / "profiles"
    (gov / "acme-llm.yaml").write_text("id: acme-llm\ncategory: inference\nendpoints: []\n")
    (gov / "gemini.yaml").unlink()
    git("add", "-A")
    git("commit", "-q", "-m", "swap a governance profile", "--no-verify")   # mirror not regenerated
    subprocess.run([sys.executable, "scripts/saw-profile-catalog.py"], cwd=repo, env=env, check=True)
    listed = subprocess.run([sys.executable, "scripts/saw-profile-catalog.py", "--list"],
                            cwd=repo, env=env, capture_output=True, text=True, check=True).stdout.split()
    assert "charts/openshell-saw/files/provider-profiles/acme-llm.yaml" in listed
    assert "charts/openshell-saw/files/provider-profiles" in listed   # the directory: removals too

    result = run_step(repo, env, same_repo=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "up to date" not in result.stdout
    tree = subprocess.run(["git", "--git-dir", str(origin), "ls-tree", "--name-only", "feat",
                           "charts/openshell-saw/files/provider-profiles/"],
                          capture_output=True, text=True, check=True).stdout.split()
    assert "charts/openshell-saw/files/provider-profiles/acme-llm.yaml" in tree
    assert "charts/openshell-saw/files/provider-profiles/gemini.yaml" not in tree

    # The hook does the same on a commit that touches a governance profile.
    git("config", "core.hooksPath", ".githooks")
    (gov / "acme-llm.yaml").write_text("id: acme-llm\ncategory: inference\nendpoints: [{host: llm.acme, port: 443}]\n")
    git("add", "charts/governance-policy/profiles/acme-llm.yaml")
    git("commit", "-q", "-m", "edit acme-llm")
    shown = git("show", "--stat", "--format=", "HEAD").stdout
    assert "provider-profiles/acme-llm.yaml" in shown
