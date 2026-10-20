"""Shared environment and bounded runner for existing CI shell scripts."""

import os
from pathlib import Path
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def make_ci_environment(directory, environ=None):
    env = dict(os.environ if environ is None else environ)
    # CLI endpoint overrides take precedence over --gateway and would silently
    # test another deployment. The CI variant always targets alice/default.
    for name in ("OPENSHELL_GATEWAY_ENDPOINT", "OPENSHELL_GATEWAY_INSECURE",
                 "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CA_BUNDLE"):
        env.pop(name, None)
    env.update(XDG_CONFIG_HOME=str(directory / "config"),
               CI_BIN_DIR=str(directory / "bin"),
               PATH=str(directory / "bin") + os.pathsep + env.get("PATH", os.defpath),
               OIDC_TOKEN_DIR=str(directory / "config/openshell/oidc"),
               SSH_KEY_PATH=str(directory / "ssh-key"),
               OPENSHELL_SAW_NAME="alice", SAW_NS="saw-alice",
               KEYCLOAK_NS="saw-keycloak", KEYCLOAK_REALM="openshell",
               WORKSPACE="default", HARNESS_SANDBOX="notebook",
               HARNESS_BUNDLE_EXPECT="ds-default", KEY_NAME="vp-ci-harness")
    if env.get("VP_HUBCONFIG"):
        env["KUBECONFIG"] = env["VP_HUBCONFIG"]
    return env


def run_script(script, env, timeout):
    """Run a repo-relative shell script and expose its output in pytest/JUnit."""
    with subprocess.Popen(["bash", str(ROOT / script)], cwd=ROOT, env=env,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True,
                          start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            raise AssertionError(
                f"{script} timed out after {timeout}s\nstdout:\n{stdout}\nstderr:\n{stderr}"
            ) from None
    assert process.returncode == 0, (
        f"{script} failed (exit {process.returncode})\nstdout:\n{stdout}\nstderr:\n{stderr}"
    )
    print(stdout, end="")
    print(stderr, end="")
