"""Lab traffic generator for IDS validation (runs inside the ids-traffic namespace).

This is a test harness for the intrusion-detection pipeline. It produces labelled
traffic against the lab's OWN services so the detector can be measured on known
ground truth. It runs only inside an isolated Kubernetes namespace whose
NetworkPolicy allows egress to the lab targets and DNS and nothing else, so it
cannot reach anything outside the lab. Every request is written to stdout as one
JSON line, which is the ground truth for the captured window.

MODE (env) selects the scenario:
  benign       low-rate browsing and health checks against the lab services
  web_recon    bounded HTTP path enumeration of one service (no exploits)
  port_scan    TCP connect scan across a bounded port range on one target host
  slow_dos     many slow, partial HTTP connections held open against one target
  brute_force  repeated login attempts against a test login endpoint / SSH port
  web_attack   HTTP requests carrying SQLi / XSS-style strings in query params

Everything is bounded (request counts, a port range, a time budget) and aimed at
lab targets only. No payload is executed; brute_force and web_attack send
signature-like strings to a test endpoint, never real credentials or exploits.
"""
from __future__ import annotations

import json
import os
import random
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

MODE = os.environ.get("MODE", "benign")
NODERED = os.environ.get("NODERED_URL", "http://nodered.target-apps.svc.cluster.local:1880")
GRAFANA = os.environ.get("GRAFANA_URL", "http://grafana.target-apps.svc.cluster.local:3000")
INFLUXDB = os.environ.get("INFLUXDB_URL", "http://influxdb.target-apps.svc.cluster.local:8086")
# The single target for the attack-style scenarios (host[:port]); defaults to Node-RED.
TARGET = os.environ.get("TARGET", "nodered.target-apps.svc.cluster.local:1880")
TIMEOUT = float(os.environ.get("TIMEOUT", "5"))

# Bounds (all overridable by env, all with safe defaults).
COUNT = int(os.environ.get("COUNT", "300"))          # requests / attempts for bounded modes
DELAY = float(os.environ.get("DELAY", "0.1"))        # seconds between actions in bounded modes
MIN_DELAY = float(os.environ.get("MIN_DELAY", "1.0"))
MAX_DELAY = float(os.environ.get("MAX_DELAY", "4.0"))
PORT_START = int(os.environ.get("PORT_START", "1"))
PORT_END = int(os.environ.get("PORT_END", "1024"))
SLOW_CONNS = int(os.environ.get("SLOW_CONNS", "200"))
SLOW_HOLD_S = float(os.environ.get("SLOW_HOLD_S", "25"))


def emit(**fields) -> None:
    fields["ts"] = datetime.now(timezone.utc).isoformat()
    fields["mode"] = MODE
    print(json.dumps(fields), flush=True)


def host_port(target: str, default_port: int) -> tuple[str, int]:
    if ":" in target:
        host, port = target.rsplit(":", 1)
        return host, int(port)
    return target, default_port


def http_get(url: str, path: str = "") -> None:
    full = url.rstrip("/") + path
    req = urllib.request.Request(full, headers={"User-Agent": "ids-lab/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            emit(action="http", url=full, status=resp.status)
    except urllib.error.HTTPError as e:
        emit(action="http", url=full, status=e.code)
    except Exception as e:  # noqa: BLE001
        emit(action="http", url=full, error=type(e).__name__)


# --- benign -------------------------------------------------------------------------
BENIGN_REQUESTS = [
    (NODERED, "/"), (NODERED, "/settings"), (NODERED, "/flows"),
    (GRAFANA, "/api/health"), (GRAFANA, "/login"),
    (INFLUXDB, "/health"), (INFLUXDB, "/ping"),
]


def run_benign() -> None:
    emit(action="start", scenario="benign")
    while True:
        url, path = random.choice(BENIGN_REQUESTS)
        http_get(url, path)
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))


# --- web_recon ----------------------------------------------------------------------
RECON_PATHS = ["/", "/admin", "/login", "/settings", "/flows", "/api", "/api/status",
               "/robots.txt", "/.git/config", "/backup", "/debug", "/metrics", "/health",
               "/config", "/dashboard", "/users", "/console", "/.env", "/server-status"]


def run_web_recon() -> None:
    emit(action="start", scenario="web_recon", target=NODERED, count=COUNT)
    for i in range(COUNT):
        http_get(NODERED, random.choice(RECON_PATHS) + (f"?{i}" if random.random() < 0.3 else ""))
        time.sleep(DELAY)
    emit(action="done", scenario="web_recon")


# --- port_scan ----------------------------------------------------------------------
def run_port_scan() -> None:
    host, _ = host_port(TARGET, 0)
    lo, hi = max(1, PORT_START), min(65535, PORT_END)
    emit(action="start", scenario="port_scan", host=host, port_start=lo, port_end=hi)
    opened = 0
    for port in range(lo, hi + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        try:
            rc = s.connect_ex((host, port))
            if rc == 0:
                opened += 1
                emit(action="port_open", host=host, port=port)
        except Exception as e:  # noqa: BLE001
            emit(action="port_error", host=host, port=port, error=type(e).__name__)
        finally:
            s.close()
        time.sleep(DELAY)
    emit(action="done", scenario="port_scan", open_ports=opened)


# --- slow_dos -----------------------------------------------------------------------
def run_slow_dos() -> None:
    """Open many connections and send a partial HTTP request header, then hold them.

    This is the slowloris-style pattern the CIC 'DoS' class covers. It is bounded
    by SLOW_CONNS and SLOW_HOLD_S and targets one lab service only.
    """
    host, port = host_port(TARGET, 1880)
    emit(action="start", scenario="slow_dos", host=host, port=port, conns=SLOW_CONNS, hold_s=SLOW_HOLD_S)
    socks = []
    for i in range(SLOW_CONNS):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        try:
            s.connect((host, port))
            s.sendall(f"GET /?{i} HTTP/1.1\r\nHost: {host}\r\n".encode())  # headers never completed
            socks.append(s)
        except Exception:  # noqa: BLE001
            s.close()
        time.sleep(DELAY)
    emit(action="slow_established", host=host, established=len(socks))
    deadline = time.monotonic() + SLOW_HOLD_S
    while time.monotonic() < deadline:
        for s in socks:
            try:
                s.sendall(b"X-a: b\r\n")   # drip one header line to keep the connection alive
            except Exception:  # noqa: BLE001
                pass
        time.sleep(2)
    for s in socks:
        s.close()
    emit(action="done", scenario="slow_dos")


# --- brute_force --------------------------------------------------------------------
def run_brute_force() -> None:
    """Repeated login attempts against a test endpoint, or TCP connects to an SSH port.

    No real credentials: the usernames/passwords are obvious placeholders. The point
    is the burst of many short authentication connections from one source, which the
    CIC 'BruteForce' class and the flow-burst detector are meant to catch.
    """
    host, port = host_port(TARGET, 22)
    emit(action="start", scenario="brute_force", host=host, port=port, attempts=COUNT)
    USERS = ["admin", "root", "test", "user", "guest"]
    if port in (22, 2222):                       # SSH-style: repeated TCP connects to the SSH port
        for i in range(COUNT):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            try:
                if s.connect_ex((host, port)) == 0:
                    s.recv(64)                   # read the banner, then drop (no auth performed)
                emit(action="ssh_attempt", host=host, port=port, user=random.choice(USERS), n=i)
            except Exception as e:  # noqa: BLE001
                emit(action="ssh_error", host=host, port=port, error=type(e).__name__)
            finally:
                s.close()
            time.sleep(DELAY)
    else:                                        # HTTP form login attempts to a test URL
        base = f"http://{host}:{port}"
        for i in range(COUNT):
            data = urllib.parse.urlencode({"username": random.choice(USERS),
                                           "password": f"wrong-{i}"}).encode()
            req = urllib.request.Request(base + "/login", data=data, headers={"User-Agent": "ids-lab/1.0"})
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                    emit(action="login_attempt", url=base + "/login", status=resp.status, n=i)
            except urllib.error.HTTPError as e:
                emit(action="login_attempt", url=base + "/login", status=e.code, n=i)
            except Exception as e:  # noqa: BLE001
                emit(action="login_error", url=base + "/login", error=type(e).__name__)
            time.sleep(DELAY)
    emit(action="done", scenario="brute_force")


# --- web_attack ---------------------------------------------------------------------
# Signature-like strings sent as query parameters to a test endpoint. They are not
# executed anywhere; they exist so the captured flows resemble the CIC WebAttack class.
WEB_PAYLOADS = [
    "/?q=1' OR '1'='1", "/?id=1 UNION SELECT null--", "/search?q=<script>alert(1)</script>",
    "/?name=<img src=x onerror=1>", "/?file=../../etc/passwd", "/?cmd=;id",
    "/login?user=admin'--", "/?q=%27%20OR%201=1--", "/comment?text=<svg/onload=1>",
]


def run_web_attack() -> None:
    host, port = host_port(TARGET, 1880)
    base = f"http://{host}:{port}"
    emit(action="start", scenario="web_attack", target=base, count=COUNT)
    for i in range(COUNT):
        http_get(base, random.choice(WEB_PAYLOADS))
        time.sleep(DELAY)
    emit(action="done", scenario="web_attack")


RUNNERS = {
    "benign": run_benign, "web_recon": run_web_recon, "port_scan": run_port_scan,
    "slow_dos": run_slow_dos, "brute_force": run_brute_force, "web_attack": run_web_attack,
}


def main() -> None:
    runner = RUNNERS.get(MODE)
    if runner is None:
        sys.exit(f"unknown MODE {MODE!r}; one of {sorted(RUNNERS)}")
    try:
        runner()
    except KeyboardInterrupt:
        emit(action="interrupted", scenario=MODE)


if __name__ == "__main__":
    main()
