#!/usr/bin/env python3
"""Generate the pinned stock SDK in scratch and test its real wire contracts.

No network, cluster, package installation, source modification or image build.
Install the pinned grpcio-tools dependency separately in an isolated environment.
"""

import argparse
import importlib.metadata
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


PIN = "305c8b3d7bbdb97a6f2f7264c3ad43b0087c307f"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openshell-source", required=True, type=Path)
    parser.add_argument("--scratch-parent", type=Path)
    args = parser.parse_args()
    source = args.openshell_source.resolve()
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if revision != PIN:
        parser.error(f"OpenShell source must be pinned at {PIN}")
    subprocess.run(["git", "-C", str(source), "diff", "--exit-code", "HEAD", "--",
                    "proto", "python/openshell", "tasks/scripts/generate_python_proto.py"],
                   check=True, stdout=subprocess.DEVNULL)
    if importlib.util.find_spec("grpc_tools") is None:
        parser.error("grpcio-tools==1.80.0 is required in the isolated test environment")
    if importlib.metadata.version("grpcio-tools") != "1.80.0":
        parser.error("use grpcio-tools==1.80.0 for repeatable generated-SDK tests")
    repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="saw-stock-protobuf-", dir=args.scratch_parent) as temporary:
        scratch = Path(temporary)
        shutil.copytree(source / "proto", scratch / "proto")
        shutil.copytree(source / "python/openshell", scratch / "python/openshell",
                        ignore=shutil.ignore_patterns("__pycache__", "*_test.py"))
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        subprocess.run([sys.executable, str(source / "tasks/scripts/generate_python_proto.py")],
                       cwd=scratch, env=env, check=True)
        env["PYTHONPATH"] = os.pathsep.join([str(scratch / "python"), str(repo / "kubernetes-runtime"),
                                            env.get("PYTHONPATH", "")])
        env["SAW_STOCK_SDK_TESTS"] = "1"
        command = [sys.executable, "-c", "import pytest,sys; sys.exit(pytest.main(sys.argv[1:]))",
                   "-q", "-p", "no:cacheprovider", f"--basetemp={scratch / 'pytest'}",
                   str(repo / "tests/kubernetes_runtime")]
        return subprocess.call(command, cwd=repo, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
