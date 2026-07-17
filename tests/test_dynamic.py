"""Exercise frapsec.dynamic.verify against a local mock HTTP server --
no real Frappe site needed, but a real socket/request round-trip."""
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from frapsec import dynamic  # noqa: E402
from frapsec.model import Finding  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if "reachable_method" in self.path:
            self.send_response(200)
        elif "blocked_method" in self.path:
            self.send_response(403)
        else:
            self.send_response(404)
        self.end_headers()

    def log_message(self, *a):
        pass  # quiet test output


def test():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        findings = [
            Finding(rule_id="FRAP-API-001", severity="high", message="m", file="x",
                    endpoint="app.api.reachable_method"),
            Finding(rule_id="FRAP-API-002", severity="medium", message="m", file="x",
                    endpoint="app.api.blocked_method"),
            Finding(rule_id="FRAP-API-003", severity="high", message="m", file="x",
                    endpoint="app.api.unknown_method"),
            Finding(rule_id="FRAP-HOOK-001", severity="medium", message="m", file="x"),  # no endpoint
        ]
        dynamic.verify(findings, f"http://127.0.0.1:{port}", "key", "secret")
        assert findings[0].verified == "reachable"
        assert findings[1].verified == "blocked"
        assert findings[2].verified.startswith("error")
        assert findings[3].verified == ""  # untouched -- no endpoint
    finally:
        server.shutdown()
    print("OK")


if __name__ == "__main__":
    test()
