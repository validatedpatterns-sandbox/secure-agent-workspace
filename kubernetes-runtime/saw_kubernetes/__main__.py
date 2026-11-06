"""Compile only: no credentials, gateway connection or Kubernetes operations."""

import argparse
import json
from pathlib import Path
import sys

import yaml

from .compiler import ContractError, compile_profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--bindings", required=True, help="Administrator YAML/JSON bindings file")
    args = parser.parse_args()
    try:
        config = yaml.safe_load(Path(args.bindings).read_text())
        result = compile_profile(args.profile, config)
    except (ContractError, OSError, yaml.YAMLError) as exc:
        message = str(exc) if isinstance(exc, ContractError) else "cannot read input documents"
        print(message, file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
