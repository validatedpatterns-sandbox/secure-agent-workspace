"""Local contract tests for the public Make targets."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

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
        "saw-create saw-configure saw-list saw-logs saw-status saw-restart saw-restart-pending "
        "saw-vm-ssh saw-ssh saw-tui saw-gui saw-delete quickstart-delete "
        "governance-deploy governance-delete governance-profile-list "
        "governance-profile-add governance-profile-remove governance-profile-create "
        "status check-oidc-ca test-credential-proxy credential-proxy-image test-credential-isolation"
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


def test_credential_isolation_offline_render():
    result = subprocess.run(["bash", "tests/test-credential-isolation.sh"], cwd=ROOT,
                            env=dict(os.environ, SKIP_LIVE="1"), capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "VM mounts metadata only" in result.stdout


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
    executable(bindir / "uv", 'exit 0\n')
    executable(bindir / "openshell", 'printf "openshell 0.1.2\\n"\n')
    executable(bindir / "oc", '''
case "$*" in
  whoami) exit 0 ;;
  "get network.config cluster -o json")
    echo '{"status":{"clusterNetwork":[{"cidr":"10.232.0.0/14"}],"serviceNetwork":["172.231.0.0/16"]}}' ;;
  "get service kubernetes -n default -o json")
    echo '{"spec":{"clusterIP":"172.231.0.1","ports":[{"port":443,"protocol":"TCP"}]}}' ;;
  "get endpointslice -n default -l kubernetes.io/service-name=kubernetes -o json")
    echo '{"items":[{"addressType":"IPv4","ports":[{"port":6443,"protocol":"TCP"}],"endpoints":[{"addresses":["10.10.10.10"]}]}]}' ;;
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
    executable(bindir / "uv", 'exit 0\n')
    executable(bindir / "openshell", 'printf "openshell 0.1.2\\n"\n')
    executable(bindir / "oc", '''
case "$*" in
  whoami) exit 0 ;;
  "get network.config cluster -o json")
    echo '{"status":{"clusterNetwork":[{"cidr":"10.232.0.0/14"}],"serviceNetwork":["172.231.0.0/16"]}}' ;;
  "get service kubernetes -n default -o json")
    echo '{"spec":{"clusterIP":"172.231.0.1","ports":[{"port":443,"protocol":"TCP"}]}}' ;;
  "get endpointslice -n default -l kubernetes.io/service-name=kubernetes -o json")
    echo '{"items":[{"addressType":"IPv4","ports":[{"port":6443,"protocol":"TCP"}],"endpoints":[{"addresses":["10.10.10.10"]}]}]}' ;;
  "get storageclass -o json")
    echo '{"items":[{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}]}' ;;
  "get nodes -o json")
    echo '{"items":[{"spec":{},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}' ;;
  "get routes -n openshift-image-registry -o json") echo '{"items":[]}' ;;
  *) echo "unexpected oc call: $*" >&2; exit 4 ;;
esac
''')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}",
               CA_OUT=str(tmp_path / "ingress-ca.pem"))
    result = run_make("prereqs-check", env=env)
    assert result.returncode == 0, result.stderr
    assert "Default StorageClass: available" in result.stdout


def test_prereqs_reject_incompatible_openshell_cli(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    executable(bindir / "uv", 'exit 0\n')
    executable(bindir / "openshell", 'printf "openshell 0.0.116\\n"\n')
    executable(bindir / "oc", 'echo "oc must not run" >&2\nexit 9\n')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    result = run_make("prereqs-check", env=env)
    assert result.returncode != 0
    assert "does not match gateway BOM 0.1.2-rhaiv.0" in result.stderr
    assert "oc must not run" not in result.stderr


def test_both_prereq_modes_require_uv_before_cluster_calls(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("oc", "helm", "jq", "openssl", "openshell"):
        executable(bindir / tool, 'echo "cluster tool must not run" >&2\nexit 9\n')
    # Isolate PATH: uv can be installed in /usr/bin on the developer's host.
    for tool in ("make", "bash"):
        (bindir / tool).symlink_to(shutil.which(tool))
    env = dict(os.environ, PATH=str(bindir))
    for target in ("prereqs-check", "quickstart-prereqs-check"):
        result = run_make(target, env=env)
        assert result.returncode != 0
        assert "uv is required" in result.stderr
        assert "cluster tool must not run" not in result.stderr


def test_logout_clears_gateway_when_oidc_revocation_fails(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    creds = tmp_path / "credentials"
    creds.mkdir()
    for name in ("alice", "bob"):
        (creds / name).write_text("stored credential")
    log = tmp_path / "logout.log"
    executable(scripts / "oidc-login.sh", 'echo oidc >> "$LOGOUT_LOG"\nexit 7\n')
    (scripts / "openshell-saw-logout.sh").symlink_to(
        ROOT / "scripts/openshell-saw-logout.sh")
    executable(bindir / "openshell", '''
if [[ "$*" == 'gateway list -o json' ]]; then
  printf '%s\\n' '[{"name":"alice"},{"name":"bob"}]'
elif [[ "$1 $2" == 'gateway logout' ]]; then
  echo "gateway:$3" >> "$LOGOUT_LOG"
  rm "$CREDENTIALS_DIR/$3"
else
  echo "unexpected openshell command" >&2
  exit 2
fi
''')
    env = dict(os.environ, LOGOUT_LOG=str(log), CREDENTIALS_DIR=str(creds),
               OPENSHELL_SAW_NAME="", PATH=f"{bindir}:{os.environ['PATH']}")
    result = run_make("logout", f"SCRIPTS_DIR={scripts}", env=env)
    assert result.returncode != 0
    assert log.read_text().splitlines() == ["oidc", "gateway:alice", "gateway:bob"]
    assert list(creds.iterdir()) == []
    assert "revocations or local cleanup" in result.stderr


def test_local_logout_can_select_one_gateway(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    creds = tmp_path / "credentials"
    creds.mkdir()
    for name in ("alice", "bob"):
        (creds / name).write_text("stored credential")
    executable(bindir / "openshell", '''
if [[ "$*" == 'gateway list -o json' ]]; then
  printf '%s\\n' '[{"name":"alice"},{"name":"bob"}]'
elif [[ "$1 $2" == 'gateway logout' ]]; then
  rm "$CREDENTIALS_DIR/$3"
else
  exit 2
fi
''')
    env = dict(os.environ, CREDENTIALS_DIR=str(creds), OPENSHELL_SAW_NAME="alice",
               PATH=f"{bindir}:{os.environ['PATH']}")
    result = subprocess.run(["bash", str(ROOT / "scripts/openshell-saw-logout.sh")],
                            cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in creds.iterdir()) == ["bob"]


@pytest.mark.parametrize("tag", ["latest", "sha-review"])
def test_image_mirror_uses_selected_ghcr_tag_without_fallback(tmp_path, tag):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "mirror.log"
    executable(bindir / "uname", 'printf "Linux\\n"\n')
    executable(bindir / "oc", r'''case "$*" in
  "get routes -n openshift-image-registry -o json")
    echo '{"items":[{"metadata":{"name":"default-route"},"spec":{"host":"registry.example"}}]}' ;;
  "image mirror "*)
    echo "$*" >> "$MIRROR_LOG"
    if [[ "${FAIL_MIRROR:-0}" == 1 ]]; then echo "manifest unknown" >&2; exit 2; fi ;;
  "tag "*) echo "$*" >> "$MIRROR_LOG" ;;
  *) : ;;
esac
''')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", MIRROR_LOG=str(log))
    result = run_make("images-mirror", f"IMAGE_TAG={tag}", env=env)
    assert result.returncode == 0, result.stderr
    expected = [
        f"image mirror ghcr.io/validatedpatterns-sandbox/openshell-gateway:{tag} "
        f"registry.example/openshell-agents/openshell-gateway:{tag} --insecure=true"]
    destinations = f"openshell-gateway:{tag}"
    if tag != "latest":
        expected.append(f"tag openshell-agents/openshell-gateway:{tag} openshell-agents/openshell-gateway:latest")
        destinations += " and openshell-gateway:latest"
    assert log.read_text().splitlines() == expected
    assert f"Mirrored openshell-gateway:{tag} as {destinations}." in result.stdout
    log.unlink()
    result = run_make("images-mirror", "IMAGE_TAG=sha-missing", env=dict(env, FAIL_MIRROR="1"))
    assert result.returncode != 0
    assert len(log.read_text().splitlines()) == 1
    assert ":latest" not in log.read_text()


def test_public_image_check_ignores_login_and_reports_private_packages(tmp_path):
    import yaml

    action = yaml.safe_load((ROOT / ".github/actions/verify-public-image/action.yml").read_text())
    bindir = tmp_path / "bin"
    bindir.mkdir()
    executable(bindir / "docker", r'''[[ "$1" == --config ]]
[[ -d "$2" && ! -e "$2/config.json" ]]
[[ "$3 $4" == "manifest inspect" ]]
[[ "$5" == "$IMAGE" ]]
printf '%s' "$2" > "$AUTH_LOG"
exit "${DOCKER_STATUS:-0}"
''')
    log = tmp_path / "auth.log"
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", AUTH_LOG=str(log),
               IMAGE="ghcr.io/example/image@sha256:" + "a" * 64)
    for status in ("0", "1"):
        result = subprocess.run(["bash", "-c", action["runs"]["steps"][0]["run"]],
                                env=dict(env, DOCKER_STATUS=status), capture_output=True, text=True)
        assert result.returncode == int(status), result.stderr
        assert not Path(log.read_text()).exists()
        if status == "1":
            assert "visibility to Public" in result.stdout


@pytest.mark.parametrize("target", ["sandbox-build", "cli-build", "gateway-build-podman",
                                    "gateway-build-docker", "gateway-build", "build-nemoclaw",
                                    "governance-interceptor-build"])
@pytest.mark.parametrize("repo", [None, "ghcr.io/validatedpatterns-sandbox", "ghcr.io/VALIDATEDPATTERNS-SANDBOX/", "ghcr.io/example"])
def test_manual_builds_keep_images_local_unless_safe_destination_is_explicit(tmp_path, target, repo):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls"
    executable(bindir / "oc", r'''echo "oc $*" >> "$CALLS"
case "$*" in
  "start-build nemoclaw-discovery-runtime "*) echo build.build.openshift.io/nemoclaw-discovery-runtime-1 ;;
  "get build.build.openshift.io/nemoclaw-discovery-runtime-1 "*)
    case "$*" in
      *status.phase*) printf Complete ;;
      *imageDigest*) printf 'sha256:%064d' 0 ;;
    esac ;;
esac
''')
    executable(bindir / "helm", 'echo "helm $*" >> "$CALLS"\n')
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy2(ROOT / "scripts/check-build-repo.sh", scripts / "check-build-repo.sh")
    shutil.copytree(ROOT / "scripts/lib", scripts / "lib")
    executable(scripts / "push-image.sh", 'echo "push $*" >> "$CALLS"\n')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", CALLS=str(log))
    env.pop("IMAGE_REPO", None)
    env.pop("PUSH_IMAGE_REPO", None)
    args = [target, f"SCRIPTS_DIR={scripts}"]
    if repo is not None:
        args.append(f"IMAGE_REPO={repo}")
    result = run_make(*args, env=env)
    if repo and repo.lower().rstrip("/") == "ghcr.io/validatedpatterns-sandbox":
        assert result.returncode != 0
        assert "CI" in result.stderr
        assert not log.exists(), "reject before any cluster mutations"
    else:
        assert result.returncode == 0, result.stderr
        calls = log.read_text()
        if repo is None:
            assert "push " not in calls
            assert "output.externalImage=ghcr.io" not in calls
        elif target == "governance-interceptor-build":
            assert "output.externalImage=ghcr.io/example/governance-interceptor:v0.1.2" in calls
        else:
            assert "push " in calls and "ghcr.io/example" in calls


def test_public_image_check_targets_the_published_tag():
    import yaml
    action = yaml.safe_load((ROOT / ".github/actions/build-push-image/action.yml").read_text())
    verify = next(s for s in action["runs"]["steps"]
                  if s.get("uses") == "./.github/actions/verify-public-image")
    assert verify["with"]["image"] == "ghcr.io/${{ steps.meta.outputs.owner }}/${{ inputs.image_name }}:sha-${{ github.sha }}"


@pytest.mark.parametrize("phase,digest", [("Complete", "sha256:" + "a" * 64), ("Failed", "sha256:" + "b" * 64), ("Complete", ""), ("Complete", "sha256:")])
def test_sandbox_build_consumes_only_its_completed_discovery_build(tmp_path, phase, digest):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls"
    executable(bindir / "oc", r'''echo "oc $*" >> "$CALLS"
case "$*" in
  "start-build nemoclaw-discovery-runtime "*) echo build.build.openshift.io/nemoclaw-discovery-runtime-7 ;;
  "get build.build.openshift.io/nemoclaw-discovery-runtime-7 "*)
    case "$*" in
      *status.phase*) printf '%s' "$DISCOVERY_PHASE" ;;
      *imageDigest*) printf '%s' "$DISCOVERY_DIGEST" ;;
    esac ;;
esac
''')
    executable(bindir / "helm", 'echo "helm $*" >> "$CALLS"\n')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", CALLS=str(log),
               DISCOVERY_PHASE=phase, DISCOVERY_DIGEST=digest)
    env.pop("PUSH_IMAGE_REPO", None)
    result = run_make("sandbox-build", "IMAGE_REPO=", "BUILD_NS=test-build", env=env)
    calls = log.read_text().splitlines()
    if phase != "Complete" or len(digest) != 71:
        assert result.returncode != 0
        assert not any("start-build nemoclaw-sandbox " in line for line in calls)
        assert not any("source.discoveryImage=image-registry." in line for line in calls)
    else:
        assert result.returncode == 0, result.stderr
        pinned = next(i for i, line in enumerate(calls) if "source.discoveryImage=image-registry." in line)
        start = next(i for i, line in enumerate(calls) if "start-build nemoclaw-sandbox " in line)
        assert pinned < start
        assert f"source.discoveryImage=image-registry.openshift-image-registry.svc:5000/test-build/nemoclaw-discovery-runtime@{digest}" in calls[pinned]
        assert any("get build.build.openshift.io/nemoclaw-discovery-runtime-7 " in line and "imageDigest" in line for line in calls)
        assert not any("get bc/" in line for line in calls)


@pytest.mark.parametrize("terminal", ["Complete", "Failed", "Cancelled", "Error"])
def test_discovery_log_error_does_not_hide_build_phase(tmp_path, terminal):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls"
    executable(bindir / "oc", r'''echo "oc $*" >> "$CALLS"
case "$*" in
  "start-build nemoclaw-discovery-runtime "*) echo build.build.openshift.io/nemoclaw-discovery-runtime-8 ;;
  "logs "*) echo 'build is pending' >&2; exit 1 ;;
  "get build.build.openshift.io/nemoclaw-discovery-runtime-8 "*)
    case "$*" in
      *status.phase*)
        if [ -e "$PHASE_COUNT" ]; then printf '%s' "$TERMINAL_PHASE";
        else touch "$PHASE_COUNT"; printf Pending; fi ;;
      *imageDigest*) printf 'sha256:%064d' 0 ;;
    esac ;;
  "wait "*) echo 'terminal-phase polling required' >&2; exit 99 ;;
esac
''')
    executable(bindir / "helm", 'echo "helm $*" >> "$CALLS"\n')
    executable(bindir / "sleep", 'echo "sleep $*" >> "$CALLS"\n')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", CALLS=str(log),
               TERMINAL_PHASE=terminal, PHASE_COUNT=str(tmp_path / "phase-count"))
    env.pop("PUSH_IMAGE_REPO", None)
    result = run_make("sandbox-build", "IMAGE_REPO=", "BUILD_NS=test-build", env=env)
    calls = log.read_text().splitlines()
    assert sum("status.phase" in line for line in calls) >= 2
    assert not any("oc wait " in line for line in calls)
    if terminal == "Complete":
        assert result.returncode == 0, result.stderr
        assert any("start-build nemoclaw-sandbox " in line for line in calls)
    else:
        assert result.returncode != 0
        assert terminal in result.stderr
        assert not any("start-build nemoclaw-sandbox " in line for line in calls)
        assert not any("imageDigest" in line for line in calls)


def fake_cluster(tmp_path, vms):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (tmp_path / "vms.json").write_text(vms)
    executable(bin_dir / "oc", f'cat "{tmp_path}/vms.json"\n')
    executable(bin_dir / "virtctl", f'echo "$*" >> "{tmp_path}/restarted"\n')
    return dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")


PENDING_VMS = """{"items": [
  {"metadata": {"name": "alice", "namespace": "saw-alice"},
   "status": {"conditions": [{"type": "Ready", "status": "True"},
                             {"type": "RestartRequired", "status": "True"}]}},
  {"metadata": {"name": "bob", "namespace": "saw-bob"},
   "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
]}"""


def test_saw_restart_pending_lists_without_confirm(tmp_path):
    """Switching the governance engine changes each VM's gateway.toml, but
    KubeVirt only marks running VMs RestartRequired (PR #52 review)."""
    env = fake_cluster(tmp_path, PENDING_VMS)
    result = run_make("saw-restart-pending", env=env)
    assert result.returncode == 0, result.stderr
    assert "alice" in result.stdout and "bob" not in result.stdout
    assert "CONFIRM=yes" in result.stdout
    assert not (tmp_path / "restarted").exists()


def test_saw_restart_pending_restarts_only_pending_vms(tmp_path):
    env = fake_cluster(tmp_path, PENDING_VMS)
    result = run_make("saw-restart-pending", "CONFIRM=yes", env=env)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "restarted").read_text() == "-n saw-alice restart alice\n"


def test_saw_restart_pending_with_nothing_pending(tmp_path):
    env = fake_cluster(tmp_path, '{"items": []}')
    result = run_make("saw-restart-pending", "CONFIRM=yes", env=env)
    assert result.returncode == 0, result.stderr
    assert "No SAW VM" in result.stdout


def install_opts(*args, env=None):
    """EXTRA_HELM_OPTS as `make install` hands it to the pattern framework."""
    return run_make("--eval", 'probe-install-opts:\n\t@printf "%s" "$$EXTRA_HELM_OPTS"',
                    "probe-install-opts", *args, env=env)


def test_governance_engine_selects_the_engine_at_install():
    """`./pattern.sh make install GOVERNANCE_ENGINE=apf`: a Pattern
    extraParameter, which the operator passes to every application."""
    result = install_opts("GOVERNANCE_ENGINE=apf")
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [
        "--set", "main.extraParameters[0].name=global.governance.engine",
        "--set", "main.extraParameters[0].value=apf"]


def test_values_global_decides_without_an_explicit_engine():
    env = {k: v for k, v in os.environ.items() if k not in ("GOVERNANCE_ENGINE", "EXTRA_HELM_OPTS")}
    result = install_opts(env=env)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_the_engine_switch_keeps_other_helm_options():
    env = {**os.environ, "EXTRA_HELM_OPTS": "--set main.foo=bar"}
    result = install_opts("GOVERNANCE_ENGINE=interceptor", env=env)
    assert result.stdout.split()[:2] == ["--set", "main.foo=bar"]
    assert result.stdout.endswith("main.extraParameters[0].value=interceptor")


def test_an_unknown_engine_stops_the_install():
    result = install_opts("GOVERNANCE_ENGINE=opa")
    assert result.returncode != 0
    assert "GOVERNANCE_ENGINE must be interceptor or apf" in result.stderr
