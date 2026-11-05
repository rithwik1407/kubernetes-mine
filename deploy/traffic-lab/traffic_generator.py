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
  decoy_probe  HTTP requests to the deployed decoy services (exercises deception)

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
SCAN_TIMEOUT = float(os.environ.get("SCAN_TIMEOUT", "1"))   # per-port connect timeout for port_scan

# Bounds (all overridable by env, all with safe defaults).
COUNT = int(os.environ.get("COUNT", "300"))          # requests / attempts for bounded modes
DELAY = float(os.environ.get("DELAY", "0.1"))        # seconds between actions in bounded modes
MIN_DELAY = float(os.environ.get("MIN_DELAY", "1.0"))
MAX_DELAY = float(os.environ.get("MAX_DELAY", "4.0"))
PORT_START = int(os.environ.get("PORT_START", "1"))
PORT_END = int(os.environ.get("PORT_END", "1024"))
SLOW_CONNS = int(os.environ.get("SLOW_CONNS", "200"))
SLOW_HOLD_S = float(os.environ.get("SLOW_HOLD_S", "25"))
LOGIN_PATH = os.environ.get("LOGIN_PATH", "/login")
# Stop cleanly before the Job's activeDeadlineSeconds. Without this, a run that is
# slower than expected (targets not answering, every connect waiting for its timeout)
# is killed by Kubernetes, its pod is deleted and the only trace is "DeadlineExceeded".
TIME_BUDGET_S = float(os.environ.get("TIME_BUDGET_S", "0"))   # 0 = unlimited
_T0 = time.monotonic()
_COUNTS = {"ok": 0, "errors": 0}
_NOT_COUNTED = {"start", "done", "interrupted", "slow_established", "budget_exhausted", "fatal", "redirected"}
# Deception redirect. The pod's own annotations are mounted here through the downward
# API (Kubernetes refreshes the file within seconds of a change). When the deception
# controller has engaged this pod, it sets ids-deception/redirect-to=<decoy host:port>
# and quarantines the pod (NetworkPolicy: decoys and DNS only). From then on every new
# connection goes to the decoy, as a transparent DNAT on the node would do it. That
# needs root on the node, which the lab does not have.
REDIRECT_FILE = os.environ.get("REDIRECT_FILE", "")
REDIRECT_KEY = "ids-deception/redirect-to"
_REDIRECT = {"checked": 0.0, "to": None}


def emit(**fields) -> None:
    fields["ts"] = datetime.now(timezone.utc).isoformat()
    fields["mode"] = MODE
    if fields.get("action") not in _NOT_COUNTED:
        _COUNTS["errors" if fields.get("error") else "ok"] += 1
    print(json.dumps(fields), flush=True)


def out_of_time() -> bool:
    """True (and logged once) when the time budget is used up; callers stop their loop."""
    if TIME_BUDGET_S <= 0 or time.monotonic() - _T0 < TIME_BUDGET_S:
        return False
    if not _COUNTS.get("budget_logged"):
        _COUNTS["budget_logged"] = 1
        emit(action="budget_exhausted", note=f"stopped after {TIME_BUDGET_S:.0f}s time budget",
             answered=_COUNTS["ok"], failed=_COUNTS["errors"])
    return True


def redirect_target() -> tuple[str, int] | None:
    """The decoy this pod was redirected to, or None (file re-read at most once a second)."""
    if not REDIRECT_FILE or time.monotonic() - _REDIRECT["checked"] < 1.0:
        return _REDIRECT["to"]
    _REDIRECT["checked"] = time.monotonic()
    to = None
    try:
        with open(REDIRECT_FILE, encoding="utf-8") as f:
            for line in f:
                key, _, val = line.strip().partition("=")
                if key == REDIRECT_KEY and val.strip('"'):
                    to = host_port(val.strip('"'), 80)
    except (OSError, ValueError):
        to = None
    if to != _REDIRECT["to"]:
        emit(action="redirected", to=f"{to[0]}:{to[1]}" if to else None,
             note="deception redirect: new connections go to the decoy" if to else "redirect removed")
        _REDIRECT["to"] = to
    return to


def aim(host: str, port: int) -> tuple[str, int]:
    """Where a new connection to host:port actually goes (the decoy while redirected)."""
    return redirect_target() or (host, port)


def aim_url(url: str) -> str:
    to = redirect_target()
    if not to:
        return url
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, f"{to[0]}:{to[1]}", parts.path, parts.query, parts.fragment))


def host_port(target: str, default_port: int) -> tuple[str, int]:
    if ":" in target:
        host, port = target.rsplit(":", 1)
        return host, int(port)
    return target, default_port


def http_get(url: str, path: str = "") -> None:
    # percent-encode spaces/quotes in the path+query (urllib refuses raw spaces, which made
    # a third of the web_attack requests fail locally without ever reaching the target)
    full = aim_url(url.rstrip("/")) + urllib.parse.quote(path, safe="/?=&%:@!$'()*+,;-._~")
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
    """Continuous when COUNT is unset (the traffic-benign Deployment); bounded to COUNT
    requests when launched as a Job, so the Job completes instead of hitting its deadline."""
    bounded = "COUNT" in os.environ
    emit(action="start", scenario="benign", count=COUNT if bounded else None)
    i = 0
    while (not bounded or i < COUNT) and not out_of_time():
        url, path = random.choice(BENIGN_REQUESTS)
        http_get(url, path)
        i += 1
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    emit(action="done", scenario="benign")


# --- web_recon ----------------------------------------------------------------------
RECON_PATHS = ["/", "/admin", "/login", "/settings", "/flows", "/api", "/api/status",
               "/robots.txt", "/.git/config", "/backup", "/debug", "/metrics", "/health",
               "/config", "/dashboard", "/users", "/console", "/.env", "/server-status"]


def run_web_recon() -> None:
    emit(action="start", scenario="web_recon", target=NODERED, count=COUNT)
    for i in range(COUNT):
        if out_of_time():
            break
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
        if out_of_time():
            break
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SCAN_TIMEOUT)
        dest = aim(host, port)                 # (decoy host, decoy port) once redirected
        extra = {"redirected_to": f"{dest[0]}:{dest[1]}"} if dest != (host, port) else {}
        try:
            rc = s.connect_ex(dest)
            if rc == 0:
                opened += 1
                if extra:                      # redirected: grab a banner, as nmap -sV would, so the decoy logs it
                    try:
                        s.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nX-Scan-Port: {port}\r\n\r\n".encode())
                        s.recv(256)
                    except OSError:
                        pass
                emit(action="port_open", host=host, port=port, **extra)
            elif rc in (111, 61):          # ECONNREFUSED (Linux, BSD): the host answered with RST
                emit(action="port_closed", host=host, port=port, **extra)
            else:                          # no answer (filtered / timeout)
                emit(action="port_filtered", host=host, port=port, error=f"errno{rc}", **extra)
        except Exception as e:  # noqa: BLE001
            emit(action="port_error", host=host, port=port, error=type(e).__name__, **extra)
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
        if out_of_time():
            break
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        dhost, dport = aim(host, port)
        try:
            s.connect((dhost, dport))
            s.sendall(f"GET /?{i} HTTP/1.1\r\nHost: {dhost}\r\n".encode())  # headers never completed
            socks.append(s)
            emit(action="slow_conn", host=dhost, port=dport, n=i)
        except Exception as e:  # noqa: BLE001
            emit(action="slow_conn", host=dhost, port=dport, n=i, error=type(e).__name__)
            s.close()
        time.sleep(DELAY)
    emit(action="slow_established", host=host, established=len(socks))
    deadline = time.monotonic() + SLOW_HOLD_S
    while time.monotonic() < deadline and not out_of_time():
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
            if out_of_time():
                break
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            try:
                if s.connect_ex(aim(host, port)) == 0:
                    s.recv(64)                   # read the banner, then drop (no auth performed)
                emit(action="ssh_attempt", host=host, port=port, user=random.choice(USERS), n=i)
            except Exception as e:  # noqa: BLE001
                emit(action="ssh_error", host=host, port=port, error=type(e).__name__)
            finally:
                s.close()
            time.sleep(DELAY)
    else:                                        # HTTP login attempts (Grafana-style JSON /login)
        base = f"http://{host}:{port}"
        for i in range(COUNT):
            if out_of_time():
                break
            user = random.choice(USERS)
            data = json.dumps({"user": user, "username": user, "password": f"wrong-{i}"}).encode()
            url = aim_url(base) + LOGIN_PATH
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"User-Agent": "ids-lab/1.0", "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                    emit(action="login_attempt", url=url, status=resp.status, n=i)
            except urllib.error.HTTPError as e:
                emit(action="login_attempt", url=url, status=e.code, n=i)
            except Exception as e:  # noqa: BLE001
                emit(action="login_error", url=url, error=type(e).__name__)
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
        if out_of_time():
            break
        http_get(base, random.choice(WEB_PAYLOADS))
        time.sleep(DELAY)
    emit(action="done", scenario="web_attack")


# --- decoy_probe --------------------------------------------------------------------
DECOY_PATHS = ["/", "/login", "/admin", "/api", "/api/v1/namespaces", "/flows", "/settings",
               "/api/health", "/health", "/.env", "/robots.txt", "/metrics"]


def run_decoy_probe() -> None:
    """Interact with the deployed decoys (TARGET = comma-separated host:port list).

    This is how the lab exercises the deception layer: the requests land in the
    decoys' own JSON request logs, which the controller collects as interactions.
    """
    targets = [t.strip() for t in TARGET.split(",") if t.strip()]
    emit(action="start", scenario="decoy_probe", targets=targets, count=COUNT)
    for i in range(COUNT):
        if out_of_time():
            break
        host, port = host_port(random.choice(targets), 8080)
        http_get(f"http://{host}:{port}", random.choice(DECOY_PATHS))
        time.sleep(DELAY)
    emit(action="done", scenario="decoy_probe")


RUNNERS = {
    "benign": run_benign, "web_recon": run_web_recon, "port_scan": run_port_scan,
    "slow_dos": run_slow_dos, "brute_force": run_brute_force, "web_attack": run_web_attack,
    "decoy_probe": run_decoy_probe,
}


def main() -> None:
    runner = RUNNERS.get(MODE)
    if runner is None:
        sys.exit(f"unknown MODE {MODE!r}; one of {sorted(RUNNERS)}")
    try:
        runner()
    except KeyboardInterrupt:
        emit(action="interrupted", scenario=MODE)
        return
    # Partial failures are normal for attack traffic (closed ports, 4xx), so the Job only
    # fails when NOTHING was answered: then the target is unreachable and the run is useless.
    if _COUNTS["ok"] == 0:
        emit(action="fatal", error="no request was answered by the target",
             failed=_COUNTS["errors"], target=TARGET)
        sys.exit(2)


if __name__ == "__main__":
    main()
