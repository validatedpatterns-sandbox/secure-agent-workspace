import importlib.util
import json
from pathlib import Path

import pytest


path = Path(__file__).resolve().parents[2] / "scripts/kata_worker_check.py"
spec = importlib.util.spec_from_file_location("kata_worker_check", path)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def node(*roles):
    labels = {"kubernetes.io/arch": "amd64"}
    labels.update({"node-role.kubernetes.io/" + role: "" for role in roles})
    return {"metadata": {"name": "worker-1", "labels": labels}, "spec": {},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}}


@pytest.mark.parametrize("items", [[], [node("worker", "control-plane")],
                                   [node("worker", "master")], [node()]])
def test_reject_unsafe_target(items):
    with pytest.raises(ValueError):
        check.workers(items)


@pytest.mark.parametrize("facts, passes", [("legacy-BIOS\nKVM", True), ("UEFI\nmissing-KVM", False),
                                           ("", False), ("UEFI\nKVM", True)])
def test_probe(monkeypatch, facts, passes):
    monkeypatch.setenv("KATA_NODE_SELECTOR", "role=dedicated")
    monkeypatch.setenv("KATA_API_SERVER", "https://cluster")
    pod = {"metadata": {"name": "mcd"}, "status": {"containerStatuses": [
        {"name": "machine-config-daemon", "ready": True}]}}
    replies = iter(["https://cluster", json.dumps({"items": [node("worker")]}),
                    json.dumps({"items": [pod]}), facts])
    monkeypatch.setattr(check, "oc", lambda *args: next(replies))
    if passes:
        check.main()
    else:
        with pytest.raises(ValueError, match="must expose /dev/kvm"):
            check.main()
