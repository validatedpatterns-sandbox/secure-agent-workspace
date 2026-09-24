"""Read-only, credential-free readiness for the VM probe; no configuration API."""

import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer


def ready(state_directory):
    try:
        with (state_directory / "status.json").open() as source:
            status = json.load(source)
        checked = datetime.fromisoformat(status["checkedAt"])
        age = (datetime.now(timezone.utc) - checked).total_seconds()
        return status["phase"] == "Converged" and 0 <= age <= 30
    except Exception:
        return False


def server(state_directory):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(2)

        def do_GET(self):
            self.send_response(200 if self.path == "/readyz" and ready(state_directory) else 503)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    return HTTPServer(("0.0.0.0", 9080), Handler)
