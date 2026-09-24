"""Boot-only mount helper. Names/paths come from enrollment, never BOM content."""

import json
import os
import subprocess
from pathlib import Path

from .inputs import validate_settings


def mount_plan(settings):
    validate_settings(settings)
    result = [("saw-intent", "/run/saw/intent"), ("saw-installer-bom", "/run/saw/installer")]
    result += [(f"saw-profile-{i}", f"/run/saw/profiles/{cm}")
               for i, cm in enumerate(settings["profileConfigMaps"])]
    result += [(f"saw-secret-{i}", f"/run/saw/credentials/{sn}")
               for i, sn in enumerate(sorted(settings["providerSecrets"]))]
    return result


def main():
    os.umask(0o077)
    try:
        settings = json.loads(Path("/etc/saw/guest.json").read_text())
        paths = mount_plan(settings)
        root = Path("/run/saw")
        if root.is_symlink():
            return 1
        root.mkdir(mode=0o700, exist_ok=True)
        root.chmod(0o700)
        for tag, target in paths:
            destination = Path(target)
            destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            if destination.resolve() != destination:
                return 1
            mounted = subprocess.run(["/usr/bin/findmnt", "--json", "--mountpoint", target,
                                      "--output", "SOURCE,FSTYPE,OPTIONS"],
                                     capture_output=True, text=True, check=False, timeout=10)
            if mounted.returncode == 0:
                entry = json.loads(mounted.stdout)["filesystems"][0]
                if (entry["source"] != tag or entry["fstype"] != "virtiofs" or
                        not {"ro", "nodev", "nosuid", "noexec"} <= set(entry["options"].split(","))):
                    return 1
                continue
            subprocess.run(["/usr/bin/mount", "-t", "virtiofs", "-o", "ro,nodev,nosuid,noexec", tag, target],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        return 0
    except Exception:
        return 1  # No raw filesystem/config/command error text enters logs.


if __name__ == "__main__":
    raise SystemExit(main())
