"""Emit candidate boundary hashes for administrator review using the active oc login."""
import argparse
import json
import subprocess
from pathlib import Path

from .boundary import fingerprint, objects, verify


def capture(config, get):
    approved = {}
    for key, (path, field) in objects(config).items():
        obj = get(path)
        approved[key] = {"uid": obj["metadata"]["uid"], "sha256": fingerprint(obj[field])}
    result = dict(config, approved=approved)
    verify(result, result, get)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("configuration", type=Path)
    args = parser.parse_args()

    def get(path):
        return json.loads(subprocess.check_output(["oc", "get", "--raw", path, "--request-timeout=20s"]))
    print(json.dumps(capture(json.loads(args.configuration.read_text()), get), indent=2))


if __name__ == "__main__":
    main()
