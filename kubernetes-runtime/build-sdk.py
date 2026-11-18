"""Generate wire bindings from verified stock OpenShell source."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.request import urlopen

revision = "305c8b3d7bbdb97a6f2f7264c3ad43b0087c307f"
for name, expected in json.loads(Path("/build/sdk-lock.json").read_text()).items():
    with urlopen(f"https://raw.githubusercontent.com/opendatahub-io/openshell/{revision}/{name}", timeout=30) as response:
        content = response.read()
    if hashlib.sha256(content).hexdigest() != expected:
        raise ValueError("stock protobuf source checksum mismatch")
    path = Path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
Path("python/openshell/_proto").mkdir(parents=True)
subprocess.run([sys.executable, "tasks/scripts/generate_python_proto.py"], check=True)
