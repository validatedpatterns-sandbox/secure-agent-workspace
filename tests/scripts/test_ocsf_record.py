"""W6 must reject shared-collector traffic without this sandbox's fresh body."""
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "check_ocsf_record", Path(__file__).resolve().parents[2] / "scripts/check-ocsf-record.py")
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)
SANDBOX = "11111111-1111-4111-8111-111111111111"


def event(sandbox=SANDBOX, time=2000):
    return {"class_uid": 4002, "activity_id": 1, "time": time,
            "device": {"container": {"uid": sandbox}}, "message": "network decision"}


def record(body, sandbox=SANDBOX):
    return ("ResourceLogs #0\nScopeLogs #0\nLogRecord #0\n"
            "Body: Str(" + json.dumps(body) + ")\nAttributes:\n"
            "     -> openshell.sandbox.id: Str(" + sandbox + ")\n")


def test_accepts_a_fresh_complete_ocsf_body_for_the_exact_sandbox():
    body = event()
    assert check.find_record(record(event("another-sandbox"), "another-sandbox") + record(body), SANDBOX, 1000) == body
    body["unmapped"] = {"sandbox_id": body.pop("device")["container"]["uid"]}
    assert check.find_record(record(body), SANDBOX, 1000) == body


@pytest.mark.parametrize("text", [
    'Logs {"resource logs": 1, "log records": 80}\n',
    record(event("another-sandbox"), "another-sandbox"),
    record(event("another-sandbox")),
    record(event(), "another-sandbox"),
    record(event(time=999)),
    record({**event("another-sandbox"), "resources": [{"uid": SANDBOX}]}),
    record({"message": "unstructured text", "container": {"uid": SANDBOX}}),
    record(event()).replace("Body: Str(", "Body: Str(broken-json"),
    record(event()).replace("LogRecord #0", "Span #0"),
    record(event()).split("Attributes:")[0] + record(event("another-sandbox")),
])
def test_rejects_summaries_other_sandboxes_stale_and_incomplete_records(text):
    assert check.find_record(text, SANDBOX, 1000) is None
