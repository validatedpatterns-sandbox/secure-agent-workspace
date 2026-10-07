#!/bin/sh
# Build saw_spire.pp.b64 inside a Fedora container pinned to the golden-image
# policy RPMs. The guest installer never runs this script.
set -eu
cd "$(dirname "$0")"
runtime=podman
if ! command -v podman >/dev/null 2>&1; then
    runtime=docker
fi
if ! command -v "$runtime" >/dev/null 2>&1; then
    echo "podman or docker is required to build against selinux-policy 43.3-1.fc44" >&2
    exit 1
fi

$runtime run --rm -v "$PWD:/src:Z" -w /src fedora:44 bash -eux /src/container-build.sh

python3 -c '
import base64, pathlib
raw = pathlib.Path("saw_spire.pp").read_bytes()
text = base64.b64encode(raw).decode()
wrapped = "\n".join(text[i:i+76] for i in range(0, len(text), 76)) + "\n"
pathlib.Path("saw_spire.pp.b64").write_text(wrapped)
pathlib.Path("saw_spire.pp").unlink()
'
