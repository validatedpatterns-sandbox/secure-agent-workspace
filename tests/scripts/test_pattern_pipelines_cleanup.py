"""Pipelines cleanup needs explicit pattern ownership and no subscriber."""

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CSV_NAME = "openshift-pipelines-operator-rh.v1.24.1"
TRACKING = (
    "secure-agent-workspace-prod:operators.coreos.com/Subscription:"
    "openshift-operators/openshift-pipelines-operator-rh"
)


def run_script(tmp_path, script, subscription, csv):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    for name, data in {
        "subscription": subscription,
        "subscriptions": {"items": [subscription] if subscription else []},
        "csv": csv,
        "csvs": {"items": [csv] if csv else []},
    }.items():
        (fixtures / f"{name}.json").write_text(json.dumps(data))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    oc = bindir / "oc"
    oc.write_text("""#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "get subscription") cat "${FIXTURES}/subscription.json" ;;
  "get subscriptions.operators.coreos.com") cat "${FIXTURES}/subscriptions.json" ;;
  "get csv")
    if [[ "${3:-}" == "-n" ]]; then
      cat "${FIXTURES}/csvs.json"
    else
      cat "${FIXTURES}/csv.json"
    fi ;;
  "annotate csv"|"delete csv") printf '%s\\n' "$*" >> "${OC_LOG}" ;;
  *) echo "unexpected oc call: $*" >&2; exit 9 ;;
esac
""")
    oc.chmod(0o755)
    log = tmp_path / "oc.log"
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}",
               FIXTURES=str(fixtures), OC_LOG=str(log))
    result = subprocess.run(["bash", str(ROOT / "scripts" / script)],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return log.read_text().splitlines() if log.exists() else []


def subscription(tracked=True):
    return {
        "metadata": {"annotations": {"argocd.argoproj.io/tracking-id":
                                     TRACKING if tracked else "other"}},
        "spec": {"name": "openshift-pipelines-operator-rh"},
        "status": {"installedCSV": CSV_NAME},
    }


def csv(marked=False):
    return {
        "metadata": {
            "name": CSV_NAME,
            "annotations": {"openshell.pattern/cleanup-on-uninstall":
                            "secure-agent-workspace-prod"} if marked else {},
            "labels": {
                "olm.managed": "true",
                "operators.coreos.com/openshift-pipelines-operator-rh.openshift-operators": "",
            },
        },
    }


def test_mark_only_pattern_subscription(tmp_path):
    calls = run_script(tmp_path, "pattern-pipelines-mark.sh",
                       subscription(), csv())
    assert len(calls) == 1
    assert calls[0].startswith(f"annotate csv {CSV_NAME} ")


def test_do_not_mark_unowned_subscription(tmp_path):
    assert run_script(tmp_path, "pattern-pipelines-mark.sh",
                      subscription(tracked=False), csv()) == []


def test_cleanup_only_marked_csv_without_subscription(tmp_path):
    calls = run_script(tmp_path, "pattern-pipelines-cleanup.sh", None,
                       csv(marked=True))
    assert len(calls) == 1
    assert calls[0].startswith(f"delete csv {CSV_NAME} ")


def test_keep_csv_while_subscription_exists(tmp_path):
    assert run_script(tmp_path, "pattern-pipelines-cleanup.sh",
                      subscription(), csv(marked=True)) == []
