"""Check gateway selection before governance profile commands run."""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/governance-profile.sh"


@pytest.fixture
def profile_env(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    calls = tmp_path / "openshell-calls"
    openshell = bindir / "openshell"
    openshell.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "$CALLS"\nprintf "github\\n"\n')
    openshell.chmod(0o755)
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", CALLS=str(calls))
    env.pop("OPENSHELL_SAW_NAME", None)
    env.pop("SAW_NAME", None)
    return env, calls


@pytest.mark.parametrize("names", [
    {"OPENSHELL_SAW_NAME": "alice"},
    {"SAW_NAME": "alice"},
    {"OPENSHELL_SAW_NAME": "alice", "SAW_NAME": "alice"},
])
def test_direct_list_uses_selected_gateway(profile_env, names):
    env, calls = profile_env
    result = subprocess.run(["bash", str(SCRIPT), "list"], env={**env, **names},
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "Profiles enforced on alice:" in result.stdout
    assert calls.read_text().splitlines() == ["--gateway", "alice", "provider", "list-profiles"]


def test_direct_list_without_gateway_shows_local_profiles(profile_env):
    env, calls = profile_env
    result = subprocess.run(["bash", str(SCRIPT), "list"], env=env,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "Profiles in this repository:" in result.stdout
    assert not calls.exists()


@pytest.mark.parametrize("args", [
    ("add", "github"),
    ("remove", "github"),
    ("create", "github", "/no-such-profile.yaml"),
])
def test_changes_require_gateway_before_side_effects(profile_env, args):
    env, calls = profile_env
    result = subprocess.run(["bash", str(SCRIPT), *args], env=env,
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "OPENSHELL_SAW_NAME is required" in result.stderr
    assert not calls.exists()


@pytest.mark.parametrize("args", [("list",), ("remove", "github")])
def test_conflicting_gateway_names_fail_before_work(profile_env, args):
    env, calls = profile_env
    env.update(OPENSHELL_SAW_NAME="alice", SAW_NAME="bob")
    result = subprocess.run(["bash", str(SCRIPT), *args], env=env,
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "name different gateways" in result.stderr
    assert not calls.exists()
