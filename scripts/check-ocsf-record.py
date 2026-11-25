#!/usr/bin/env python3
"""Find a fresh sandbox OCSF body in the demo collector's detailed debug log.

The debug exporter is a demonstration output, not a stable ingestion API. Fail
closed if its format changes or only batch summaries/trace records are present.
"""
import argparse
from datetime import datetime
import json
import re
import sys


def find_record(text, sandbox_id, since_ms):
    for block in re.split(r"(?m)^LogRecord #\d+\s*$", text)[1:]:
        # Never borrow an attribute from the next resource/signal's header.
        block = re.split(r"(?m)^(?:Resource|Scope)(?:Logs|Spans) #", block)[0]
        identity = re.search(r"(?m)^\s*-> openshell\.sandbox\.id: Str\(([^\n]*)\)\s*$", block)
        body = re.search(r"(?m)^Body: Str\(([^\n]*)\)\s*$", block)
        if not identity or identity[1] != sandbox_id or not body:
            continue
        try:
            event = json.loads(body[1])
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        # OpenShell attributes identity from device.container, never from
        # request-supplied resources that may name a different sandbox.
        device = event.get("device") or {}
        container = device.get("container") if isinstance(device, dict) else None
        container = container if isinstance(container, dict) else {}
        unmapped = event.get("unmapped") or {}
        body_id = (container.get("uid") if isinstance(container, dict) else None)
        if body_id is None and isinstance(unmapped, dict):
            body_id = unmapped.get("sandbox_id")
        if (body_id != sandbox_id or type(event.get("class_uid")) is not int
                or event["class_uid"] <= 0 or type(event.get("activity_id")) is not int
                or type(event.get("time")) is not int or event["time"] < since_ms):
            continue
        return event
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sandbox-id", required=True)
    parser.add_argument("--since", required=True, help="UTC RFC3339 test start")
    args = parser.parse_args()
    since_ms = int(datetime.fromisoformat(args.since.replace("Z", "+00:00")).timestamp() * 1000)
    event = find_record(sys.stdin.read(), args.sandbox_id, since_ms)
    if event is None:
        return 1
    # Only structural evidence is printed; request data remains in the collector.
    print(f"sandbox={args.sandbox_id} class_uid={event['class_uid']} "
          f"activity_id={event['activity_id']} time={event['time']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
