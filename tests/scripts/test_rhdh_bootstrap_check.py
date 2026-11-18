import os
import subprocess
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/check-rhdh-bootstrap.sh"


@pytest.mark.parametrize(("available", "replicas"), [(True, 1), (False, 1), (True, 0)])
def test_check_requires_available_portal_even_when_argo_is_healthy(tmp_path, available, replicas):
    calls = tmp_path / "calls"
    oc = tmp_path / "oc"
    oc.write_text("""#!/bin/sh
echo "$*" >> "$CALLS"
case "$*" in
  'get applications.argoproj.io/'*) echo '{"status":{"sync":{"status":"Synced"},"health":{"status":"Healthy"}}}' ;;
  'get deployment/'*) printf '{"metadata":{"generation":2},"spec":{"replicas":%s},"status":{"observedGeneration":2,"updatedReplicas":%s,"availableReplicas":%s}}' "$REPLICAS" "$REPLICAS" "$REPLICAS" ;;
  'wait --for=condition=Available deployment/'*) exit "$AVAILABLE_RC" ;;
esac
""")
    oc.chmod(0o755)
    env = dict(os.environ, CALLS=str(calls), AVAILABLE_RC="0" if available else "1",
               REPLICAS=str(replicas), RHDH_NAME="demo", RHDH_NAMESPACE="test-rhdh",
               PATH=f"{tmp_path}:{os.environ['PATH']}")
    result = subprocess.run([str(SCRIPT), "after"], env=env, capture_output=True, text=True)
    log = calls.read_text().splitlines()
    assert "wait --for=condition=Available deployment/backstage-demo -n test-rhdh --timeout=30m" in log
    assert ("rollout status deployment/backstage-demo -n test-rhdh --timeout=30m" in log) == available
    assert (result.returncode == 0) == (available and replicas > 0)
