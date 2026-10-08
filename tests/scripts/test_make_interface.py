"""Local contract tests for the public Make targets."""

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run_make(*args, env=None):
    return subprocess.run(
        ["make", "-s", *args], cwd=ROOT, env=env, capture_output=True, text=True
    )


def executable(path, body):
    path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body)
    path.chmod(0o755)


def test_help_lists_public_targets_once_without_make_warnings():
    result = run_make("help")
    assert result.returncode == 0, result.stderr
    assert not result.stderr
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    targets = (
        "pattern-install pattern-uninstall uninstall pre-uninstall lint test test-deployment "
        "prereqs-check quickstart-prereqs-check ssh-key-generate sandbox-build cli-build gateway-build "
        "gateway-build-podman gateway-build-docker images-mirror keycloak-deploy "
        "keycloak-delete keycloak-check keycloak-password login logout whoami "
        "saw-create saw-configure saw-list saw-logs saw-status saw-restart "
        "saw-vm-ssh saw-ssh saw-tui saw-gui saw-delete quickstart-delete "
        "governance-deploy governance-delete governance-profile-list "
        "governance-profile-add governance-profile-remove governance-profile-create "
        "status .check-saw-name .check-ssh-key .check-gateway-ca .check-prereqs"
    ).split()
    for target in targets:
        assert len(re.findall(rf"^  {target}\s", plain, re.MULTILINE)) == 1
    for old, new in (
        ("openshell-saw-create", "saw-create"),
        ("generate-keys", "ssh-key-generate"),
        ("copy-images", "images-mirror"),
        ("keycloak", "keycloak-deploy"),
        ("governance-create-profile", "governance-profile-create"),
    ):
        assert re.search(rf"^  {old}\s+use {new}$", plain, re.MULTILINE)


def test_name_validation_stops_before_cluster_work():
    for name in ("", "UPPER", "a" * 20, "bad.name", "-bad"):
        result = run_make("saw-delete", f"OPENSHELL_SAW_NAME={name}")
        assert result.returncode != 0
        assert "OPENSHELL_SAW_NAME" in result.stderr


def test_invalid_runtime_stops_before_build():
    result = run_make("gateway-build", "CONTAINER_RUNTIME=invalid")
    assert result.returncode != 0
    assert "podman or docker" in result.stderr


def test_alias_warns_and_forwards_to_canonical_target(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    marker = tmp_path / "called"
    executable(scripts / "generate-keys.sh", 'printf called > "$MARKER"\n')
    env = dict(os.environ, MARKER=str(marker))
    result = run_make("generate-keys", f"SCRIPTS_DIR={scripts}", env=env)
    assert result.returncode == 0, result.stderr
    assert "deprecated. Use ssh-key-generate" in result.stderr
    assert marker.read_text() == "called"


def test_saw_list_alias_warns_and_forwards(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    marker = tmp_path / "called"
    executable(scripts / "saw-list.sh", 'printf listed > "$MARKER"\n')
    result = run_make("openshell-saw-list", f"SCRIPTS_DIR={scripts}",
                      env=dict(os.environ, MARKER=str(marker)))
    assert result.returncode == 0, result.stderr
    assert "deprecated. Use saw-list" in result.stderr
    assert marker.read_text() == "listed"


def test_profile_path_with_spaces_is_one_argument(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "check-saw-name.sh").symlink_to(ROOT / "scripts" / "check-saw-name.sh")
    marker = tmp_path / "arguments"
    profile = tmp_path / "profile file.yaml"
    profile.write_text("name: example\n")
    executable(scripts / "governance-profile.sh", 'printf "%s\\n" "$@" > "$MARKER"\n')
    result = run_make("governance-profile-create", "OPENSHELL_SAW_NAME=review-01",
                      "PROFILE_NAME=example", f"PROFILE_FILE={profile}",
                      f"SCRIPTS_DIR={scripts}", env=dict(os.environ, MARKER=str(marker)))
    assert result.returncode == 0, result.stderr
    assert marker.read_text().splitlines() == ["create", "example", str(profile)]


def test_saw_ssh_uses_sandbox_and_workspace(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    marker = tmp_path / "ssh-args"
    executable(bindir / "ssh", 'printf "%s\\n" "$@" > "$MARKER"\n')
    home = tmp_path / "home"
    ca = home / ".config" / "openshell" / "gateways" / "review-01" / "mtls" / "ca.crt"
    ca.parent.mkdir(parents=True)
    ca.write_text("test CA")
    env = dict(os.environ, HOME=str(home), MARKER=str(marker),
               PATH=f"{bindir}:{os.environ['PATH']}")
    result = run_make("saw-ssh", "OPENSHELL_SAW_NAME=review-01",
                      "SANDBOX_NAME=cuda-sandbox", "WORKSPACE=cuda-dev", env=env)
    assert result.returncode == 0, result.stderr
    args = marker.read_text().splitlines()
    assert "ProxyCommand=openshell ssh-proxy --gateway-name review-01 --name cuda-sandbox --workspace cuda-dev" in args
    assert args[-1] == "sandbox@openshell-cuda-sandbox.cuda-dev"


def test_lint_checks_each_shell_file_and_uses_ci_python(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    marker = tmp_path / "lint-calls"
    executable(bindir / "helm", 'exit 0\n')
    executable(bindir / "python", 'printf "python %s\\n" "$*" >> "$MARKER"\n')
    executable(bindir / "uv", 'printf "unexpected uv\\n" >&2\nexit 19\n')
    bash_stub = bindir / "bash"
    bash_stub.write_text('''#!/bin/bash
set -euo pipefail
if [[ "$1" == -n ]]; then printf 'bash %s\\n' "$2" >> "$MARKER"; fi
exec /bin/bash "$@"
''')
    bash_stub.chmod(0o755)
    env = dict(os.environ, CI="true", MARKER=str(marker),
               PATH=f"{bindir}:{os.environ['PATH']}")
    result = run_make("lint", env=env)
    assert result.returncode == 0, result.stderr
    calls = marker.read_text().splitlines()
    shell_files = [call.removeprefix("bash ") for call in calls if call.startswith("bash ")]
    assert len(shell_files) >= 42 and len(shell_files) == len(set(shell_files))
    assert "charts/openshell-saw/files/prepare.sh" not in shell_files
    assert "scripts/test-deployment.sh" in shell_files
    assert "python scripts/lint-rendered-shell.py" in calls
    assert any(call.startswith("python -m pytest") for call in calls)


def test_saw_create_preserves_special_characters_in_environment(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "check-saw-name.sh").symlink_to(ROOT / "scripts" / "check-saw-name.sh")
    executable(scripts / "openshell-saw-create.sh", 'printf "%s" "$API_KEY" > "$MARKER"\n')
    marker = tmp_path / "captured"
    key = 'space $HOME $(false) "quote" * apostrophe\'s'
    env = dict(os.environ, API_KEY=key, MARKER=str(marker))
    result = run_make("saw-create", "OPENSHELL_SAW_NAME=test-saw",
                      f"SCRIPTS_DIR={scripts}", env=env)
    assert result.returncode == 0, result.stderr
    assert marker.read_text() == key
    assert key not in result.stdout + result.stderr


def test_canonical_script_failure_is_visible(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    executable(scripts / "saw-list.sh", 'echo "registry access denied" >&2\nexit 17\n')
    result = run_make("saw-list", f"SCRIPTS_DIR={scripts}")
    assert result.returncode != 0
    assert "registry access denied" in result.stderr


def test_key_generation_preserves_private_key_and_recovers_public_key(tmp_path):
    key = tmp_path / "keys" / "saw key"
    secret_file = tmp_path / "values-secret.yaml"
    env = dict(os.environ, SSH_KEY_PATH=str(key), VALUES_SECRET=str(secret_file))
    first = run_make("ssh-key-generate", env=env)
    assert first.returncode == 0, first.stderr
    private = key.read_bytes()
    public = key.with_name(key.name + ".pub")
    public.unlink()
    second = run_make("ssh-key-generate", env=env)
    assert second.returncode == 0, second.stderr
    assert key.read_bytes() == private
    assert public.read_text().startswith("ssh-ed25519 ")
    assert secret_file.exists()


def test_prereqs_distinguish_missing_operator_from_access_failure(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    executable(bindir / "openshell", 'printf "openshell 0.1.2\\n"\n')
    executable(bindir / "oc", '''
case "$*" in
  whoami) exit 0 ;;
  "get storageclass -o json")
    echo '{"items":[{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}]}' ;;
  "get nodes -o json")
    echo '{"items":[{"spec":{},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' ;;
  "get csv -n openshift-cnv -o json")
    if [[ "${OC_MODE}" == denied ]]; then
      echo "Forbidden" >&2
      exit 3
    fi
    echo '{"items":[]}' ;;
  *) echo "unexpected oc call" >&2; exit 4 ;;
esac
''')
    base = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    missing = run_make("quickstart-prereqs-check", env=dict(base, OC_MODE="missing"))
    assert missing.returncode != 0
    assert "not installed" in missing.stderr
    denied = run_make("quickstart-prereqs-check", env=dict(base, OC_MODE="denied"))
    assert denied.returncode != 0
    assert "Forbidden" in denied.stderr
    assert "not installed" not in denied.stderr


def test_pattern_prereqs_do_not_require_operators(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    executable(bindir / "openshell", 'printf "openshell 0.1.2\\n"\n')
    executable(bindir / "oc", '''
case "$*" in
  whoami) exit 0 ;;
  "get storageclass -o json")
    echo '{"items":[{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}]}' ;;
  "get nodes -o json")
    echo '{"items":[{"spec":{},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' ;;
  "get routes -n openshift-image-registry -o json") echo '{"items":[]}' ;;
  *) echo "unexpected oc call: $*" >&2; exit 4 ;;
esac
''')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    result = run_make("prereqs-check", env=env)
    assert result.returncode == 0, result.stderr
    assert "Default StorageClass: available" in result.stdout


def test_prereqs_reject_incompatible_openshell_cli(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    executable(bindir / "openshell", 'printf "openshell 0.0.116\\n"\n')
    executable(bindir / "oc", 'echo "oc must not run" >&2\nexit 9\n')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    result = run_make("prereqs-check", env=env)
    assert result.returncode != 0
    assert "does not match gateway BOM 0.1.2-rhaiv.0" in result.stderr
    assert "oc must not run" not in result.stderr
