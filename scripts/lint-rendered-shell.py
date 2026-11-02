"""Parse shell scripts after Helm has rendered their template values."""

import subprocess
import sys

import yaml


def check_mode(mode) -> int:
    command = ["helm", "template", "saw-lint", "charts/openshell-saw",
         "--namespace", "saw-lint", "-f", "tests/fixtures/saw-network-topology.yaml",
         "--set", "sandboxName=saw-lint"]
    command += (["-f", "tests/fixtures/credential-proxy-values.yaml"] if mode == "proxy" else
                ["--set", "credentialProxy.enabled=false"])
    rendered = subprocess.run(command, capture_output=True, text=True, check=False)
    if rendered.returncode:
        sys.stderr.write(rendered.stderr)
        return rendered.returncode

    checked = 0
    for document in yaml.safe_load_all(rendered.stdout):
        if not isinstance(document, dict) or document.get("kind") != "ConfigMap":
            continue
        for name, source in (document.get("data") or {}).items():
            if not name.endswith(".sh"):
                continue
            checked += 1
            result = subprocess.run(
                ["bash", "-n"], input=source, capture_output=True,
                text=True, check=False,
            )
            if result.returncode:
                config_map = document.get("metadata", {}).get("name", "unknown")
                sys.stderr.write(f"Invalid rendered shell: {config_map}/{name}\n")
                sys.stderr.write(result.stderr)
                return result.returncode
    if checked == 0:
        sys.stderr.write("No rendered ConfigMap shell scripts were found.\n")
        return 1
    print(f"Checked {checked} rendered shell scripts (mode: {mode}).")
    return 0


def main() -> int:
    return check_mode("proxy") or check_mode("direct")


if __name__ == "__main__":
    raise SystemExit(main())
