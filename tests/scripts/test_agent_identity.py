"""Compatibility gate reporting must never masquerade as full acceptance."""
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ready_requires_true_ready_condition():
    live = load("test-agent-identity-live")
    assert not live.ready({})
    assert not live.ready({"status": {"conditions": [{"type": "Ready", "status": "False"}]}})
    assert live.ready({"status": {"conditions": [{"type": "Ready", "status": "True"}]}})


def test_both_transports_remain_blocked():
    live = load("test-agent-identity-live")
    cases = live.blocked_cases("both")
    assert len(cases) == 2 * len(live.SCENARIOS)
    assert {c["status"] for c in cases} == {"blocked"}
    assert {c["name"].split("/")[0] for c in cases} == {"tcp", "vsock"}


def test_preflight_failure_writes_report_without_cleanup(monkeypatch, tmp_path):
    live = load("test-agent-identity-live")
    calls = []

    def command(args, stdin=None):
        calls.append(args)
        if args[0] == "git":
            return "abc" if "rev-parse" in args else ""
        raise subprocess.CalledProcessError(1, args, stderr="potentially sensitive diagnostic")

    monkeypatch.setattr(live, "command", command)
    assert live.run(SimpleNamespace(context="test", namespace_prefix="saw-test",
                                    artifact_dir=tmp_path, transport="both")) == 1
    report = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert report["acceptanceComplete"] is False
    assert report["status"] == "fail"
    assert "potentially sensitive" not in json.dumps(report)
    assert not any("delete" in c for c in calls)


def test_empty_context_is_refused(tmp_path):
    for script, extra in (
        ("deploy-spire-identity.py", ["--values", str(tmp_path)]),
        ("test-agent-identity-live.py", ["--namespace-prefix", "test", "--transport", "both",
                                         "--artifact-dir", str(tmp_path)]),
    ):
        import sys
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / script),
                                 "--context", "", *extra], capture_output=True, text=True)
        assert result.returncode == 2
