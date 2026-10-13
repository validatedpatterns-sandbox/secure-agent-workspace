#!/usr/bin/env python3
"""Add live NVIDIA capability device numbers to a generated CDI YAML file."""
import os
import stat
import sys
from pathlib import Path


def patch_cdi(text: str, caps: list[Path]) -> str:
    lines = text.splitlines(keepends=True)
    candidates = [(i, line) for i, line in enumerate(lines)
                  if line.lstrip().startswith("- path: /dev/nvidiactl")]
    if len(candidates) != 1:
        raise ValueError("expected one /dev/nvidiactl device node in CDI spec")
    index, line = candidates[0]
    indent = line[:len(line) - len(line.lstrip())]
    end = index + 1
    while end < len(lines):
        current = lines[end]
        if current.startswith(indent + "- "):
            break
        if current.strip() and len(current) - len(current.lstrip()) < len(indent):
            break
        end += 1
    additions = []
    for cap in sorted(caps):
        path = str(cap)
        if f"- path: {path}" in text:
            continue
        info = cap.stat()
        if not stat.S_ISCHR(info.st_mode):
            raise ValueError(f"{path} is not a character device")
        additions.extend([
            f"{indent}- path: {path}\n",
            f"{indent}  major: {os.major(info.st_rdev)}\n",
            f"{indent}  minor: {os.minor(info.st_rdev)}\n",
            f"{indent}  fileMode: 438\n",
            f"{indent}  permissions: rwm\n",
        ])
    return "".join(lines[:end] + additions + lines[end:])


if __name__ == "__main__":
    spec = Path(sys.argv[1])
    caps = list(Path("/dev/nvidia-caps").glob("nvidia-cap*"))
    if not caps:
        raise SystemExit("No NVIDIA capability devices found")
    spec.write_text(patch_cdi(spec.read_text(), caps))
