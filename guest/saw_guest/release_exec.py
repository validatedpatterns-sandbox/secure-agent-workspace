"""Systemd bridge that activates and executes the verified current release."""

import os
import sys

sys.path.insert(0, "/opt/saw/guest")
from saw_guest.release import ensure_release


if __name__ == "__main__":
    target = ensure_release()
    os.execv(sys.executable, [sys.executable, "-I", str(target / "apply_bom.py"), *sys.argv[1:]])
