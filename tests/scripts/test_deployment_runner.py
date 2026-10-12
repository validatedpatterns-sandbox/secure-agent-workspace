"""Safe local checks for the live runner's preflight and status parsing."""

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 40


def executable(path, body):
    path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body)
    path.chmod(0o755)


@pytest.fixture
def runner_env(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    executable(bindir / "oc", '''
case "$*" in
  "config current-context") printf 'test-context\\n' ;;
  "get namespaces -o json"|"get patterns -A -o json"|"get vm -A -o json"|"get csv -A -o json")
    printf '{"items":[]}\\n' ;;
  "version --client") printf 'oc test version\\n' ;;
  "get secret "*) printf 'Forbidden\\n' >&2; exit 3 ;;
  *) printf 'unexpected oc call: %s\\n' "$*" >&2; exit 9 ;;
esac
''')
    executable(bindir / "git", '''
case "$1" in
  rev-parse) printf '%s\\n' "$TEST_SHA" ;;
  diff) exit 0 ;;
  ls-remote) printf '%s\\trefs/heads/review\\n' "$TEST_SHA" ;;
  *) printf 'unexpected git call\\n' >&2; exit 9 ;;
esac
''')
    executable(bindir / "helm", '''
case "$*" in
  "version --short") printf 'v3.test\\n' ;;
  *) printf 'unexpected helm call\\n' >&2; exit 9 ;;
esac
''')
    executable(bindir / "make", '''
printf '%s %s %s\\n' "$1" "$SAW_NS" "$OPENSHELL_SAW_NAME" >> "$MAKE_LOG"
if [[ "$1" == quickstart-prereqs-check && "${RUNNER_STOP_AT}" == prereqs ]]; then exit 17; fi
if [[ "$1" == saw-status ]]; then
  if [[ -n "${RUNNER_STATUS_ERROR:-}" ]]; then
    printf '%s\\n' "$RUNNER_STATUS_ERROR" >&2
    exit 3
  fi
  printf '%s\\n' "$STATUS_OUTPUT"
fi
''')
    check = tmp_path / "check.sh"
    executable(check, 'printf \'{"result":"accepted","status_code":200}\\n\'\n')
    second = tmp_path / "second"
    second.mkdir()
    (second / "token.json").write_text("{}")
    evidence = tmp_path / "new" / "evidence.tsv"
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}",
               TEST_CLUSTER_CONTEXT="test-context", TEST_SAW_NAME="review-01",
               TEST_PATTERN_SAW_NAME="alice", TEST_OWNER="alice",
               TEST_OWNER_SUBJECT="subject", TEST_SECOND_TOKEN_DIR=str(second),
               PROVIDER="build", MODEL="test-model", API_KEY="dummy",
               WEB_SEARCH_API_KEY="dummy", TARGET_BRANCH="review", TARGET_ORIGIN="origin",
               TEST_INFERENCE_CHECK=str(check), TEST_OWNER_ACCESS_CHECK=str(check),
               TEST_SECOND_USER_DENIED_CHECK=str(check), TEST_EVIDENCE_FILE=str(evidence),
               TEST_SHA=SHA, MAKE_LOG=str(tmp_path / "make.log"),
               RUNNER_STOP_AT="prereqs", STATUS_OUTPUT="", SAW_NS="saw-")
    return env, evidence


def run_runner(env):
    return subprocess.run(["bash", str(ROOT / "scripts/test-deployment.sh")],
                          cwd=ROOT, env=env, input="yes\n", capture_output=True, text=True)


def test_make_exported_empty_name_does_not_set_wrong_namespace(runner_env):
    env, evidence = runner_env
    result = run_runner(env)
    assert result.returncode == 17
    assert evidence.exists()
    assert Path(env["MAKE_LOG"]).read_text().splitlines()[0] == \
        "quickstart-prereqs-check saw-review-01 review-01"


def test_status_progress_output_cannot_pass_as_json(runner_env):
    env, evidence = runner_env
    env["RUNNER_STOP_AT"] = "status"
    env["STATUS_OUTPUT"] = 'Key synced.\n{"install":{"phase":"Done"},"apply":{"phase":"Done"}}'
    result = run_runner(env)
    assert result.returncode != 0
    assert "did not return JSON" in result.stderr
    assert "saw-status saw-review-01 review-01" in Path(env["MAKE_LOG"]).read_text()
    assert "manual.installer\t1\tstatus output was not JSON" in evidence.read_text()


def test_status_json_records_both_completed_phases(runner_env):
    env, evidence = runner_env
    env["RUNNER_STOP_AT"] = "status"
    env["STATUS_OUTPUT"] = '{"install":{"phase":"Done"},"apply":{"phase":"Done"}}'
    result = run_runner(env)
    assert result.returncode != 0  # The fake denies the next Secret read.
    assert "Forbidden" in result.stderr
    assert "manual.installer\t0\t" in evidence.read_text()


def test_status_permission_error_stops_without_retry(runner_env):
    env, evidence = runner_env
    env["RUNNER_STOP_AT"] = "status"
    env["RUNNER_STATUS_ERROR"] = "Forbidden: cannot get Secret"
    result = run_runner(env)
    assert result.returncode != 0
    assert "status access failed" in evidence.read_text()
    assert Path(env["MAKE_LOG"]).read_text().count("saw-status") == 1
