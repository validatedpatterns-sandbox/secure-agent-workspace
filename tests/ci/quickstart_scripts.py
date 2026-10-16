"""Run the quickstart team's shell scripts as-is, with pytest as the harness.

The scripts live in ``tests/*.sh`` (one level up from this ``tests/ci/``
package). We shell out to them unmodified and turn a non-zero exit into a
pytest failure, surfacing the script's own output in the failure message.

These run as part of ``make run-ci-tests`` against a live cluster, so the
scripts run in full (live phases included). Each script is paired with any
env it needs to target this pattern's deployed resources.
"""

import os
import pathlib
import subprocess

# tests/ -- parent of this tests/ci/ package, where the *.sh scripts live.
SCRIPTS_DIR = pathlib.Path(__file__).resolve().parents[1]

# Quickstart shell tests, run as-is against the live cluster. Each entry maps a
# script to any env it needs to target this pattern's deployed resources
# (namespaces / VM names come from overrides/saw-users.yaml). Add new scripts
# here; each becomes its own parametrized test case.
QUICKSTART_SCRIPTS = {
    "test-oidc-templates.sh": {},
    "test-egress-firewall.sh": {},  # defaults already target saw-alice / alice
}


def run_quickstart_script(script_name, extra_env=None):
    """Run a quickstart shell script and assert it exits 0.

    Invoked as ``bash <abs-path>`` so the executable bit is irrelevant while the
    script can still derive SCRIPT_DIR/REPO_ROOT from ``$0``. ``extra_env`` is
    merged over the current environment and passed to the script. On failure the
    captured stdout/stderr is included so the junit-xml report shows the
    script's own "N passed, M failed" summary.
    """
    script_path = SCRIPTS_DIR / script_name
    env = {**os.environ, **(extra_env or {})}
    result = subprocess.run(
        ["bash", str(script_path)],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, (
        f"{script_name} failed (exit {result.returncode})\n"
        f"--- stdout ---\n{result.stdout}\n"
        f"--- stderr ---\n{result.stderr}"
    )
