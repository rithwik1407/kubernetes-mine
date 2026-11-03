"""Generic decoy HTTP service for the deception lab.

Responses are static synthetic documents read from profiles.json (selected by
the PROFILE environment variable). Request content is never interpreted: the
server only looks up the request path in the profile's static route table.
Each request is logged to stdout as one JSON line, which the monitoring backend
collects through the Kubernetes API. Health checks use a separate, unlogged port.
"""
import json
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PROFILE = os.environ.get("PROFILE", "http-recon")
DECOY_NAME = os.environ.get("DECOY_NAME", "decoy")
PORT = int(os.environ.get("PORT", "8080"))
HEALTH_PORT = int(os.environ.get("HEALTH_PORT", "8081"))
PROFILES_FILE = os.environ.get("PROFILES_FILE", "/app/profiles.json")
MAX_BODY = 16 * 1024

with open(PROFILES_FILE, encoding="utf-8") as fh:
    SPEC = json.load(fh)[PROFILE]
ROUTES = SPEC["routes"]
SERVER_HEADER = SPEC.get("server_header", "nginx")


def interaction_type(method, known):
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return "data_submission"
    return "page_request" if known else "unknown_path"


class DecoyHandler(BaseHTTPRequestHandler):
    server_version = SERVER_HEADER
    sys_version = ""
    timeout = 10

    def _serve(self):
        parts = urlsplit(self.path)
        length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
        if length:
            self.rfile.read(length)  # drained and discarded, never parsed
        route = ROUTES.get(parts.path)
        status, ctype, body = (route["status"], route["type"], route["body"]) if route else \
            (404, "application/json", SPEC.get("not_found", '{"error":"not found"}'))
        payload = body.encode() if self.command != "HEAD" else b""
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(payload)
        print(json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(), "decoy": DECOY_NAME, "profile": PROFILE,
            "src_ip": self.client_address[0], "src_port": self.client_address[1],
            "method": self.command, "path": parts.path[:512], "query": parts.query[:512],
            "user_agent": (self.headers.get("User-Agent") or "")[:256], "status": status,
            "type": interaction_type(self.command, route is not None), "body_bytes": length,
        }), flush=True)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _serve

    def log_message(self, *args):  # default access log replaced by the JSON line above
        pass


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    health = ThreadingHTTPServer(("0.0.0.0", HEALTH_PORT), HealthHandler)
    threading.Thread(target=health.serve_forever, daemon=True).start()
    print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "decoy": DECOY_NAME,
                      "profile": PROFILE, "event": "started", "port": PORT}), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), DecoyHandler).serve_forever()
