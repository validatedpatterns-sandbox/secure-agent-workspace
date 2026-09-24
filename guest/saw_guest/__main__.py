"""systemd guest entry point. Never reads kubeconfig or calls the Kubernetes API."""

import argparse
import json
import logging
import signal
import threading
from pathlib import Path

from .installer import BomInstaller
from .health import server
from .inputs import MountedInputs
from .reconcile import Busy, Reconciler, State


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", default="/etc/saw/guest.json")
    parser.add_argument("--inputs", default="/run/saw")
    parser.add_argument("--state-dir", default="/var/lib/saw/reconciler")
    parser.add_argument("--check-inputs", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        settings = json.loads(Path(args.settings).read_text())
        inputs = MountedInputs(args.inputs, settings)
        if args.check_inputs:
            inputs.capture()
            print("Mounted inputs valid; runtime application has NOT been verified")
            return 0
        reconciler = Reconciler(inputs, State(args.state_dir), BomInstaller())
    except Exception:
        logging.error("guest settings or inputs unavailable")
        return 1
    stopping = threading.Event()
    try:
        http = None if args.once else server(reconciler.state.directory)
    except OSError:
        logging.error("guest readiness listener unavailable")
        return 1
    if http:
        threading.Thread(target=http.serve_forever, daemon=True).start()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopping.set())
    while not stopping.is_set():
        try:
            ready = reconciler.run()
        except Busy:
            ready = False
        except Exception:
            # Disk/permission failures may prevent status writes; don't claim success.
            ready = False
        logging.info("guest reconciled" if ready else "guest reconciliation blocked; inspect local status")
        if args.once:
            return 0 if ready else 1
        stopping.wait(10)
    if http:
        http.shutdown()
        http.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
