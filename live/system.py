"""Component health, resource usage and log access for the System page.

Everything here is measured, never assumed: a component is "ok" only when its
check actually succeeded, "unavailable" when a prerequisite is missing, and
"error" when the check itself failed. Nothing is cached across requests except
the backend process start time.
"""
from __future__ import annotations

import os
import re
import shutil
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from live import db
from live.config import REPO_ROOT, get_path, load_config
from live.logging_setup import LOG_DIR

STARTED = time.time()
_LOG_FILES = {"backend": "backend.log", "capture": "capture_service.log"}
_LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} [\d:,]+) (DEBUG|INFO|WARNING|ERROR|CRITICAL) ([\w.]+): (.*)$")
_COMPONENT = [  # logger-name prefix -> component shown in the UI
    ("live.capture", "capture"), ("live.tcpdump", "capture"), ("live.cicflowmeter", "cicflowmeter"),
    ("live.process_pcap", "detection"), ("live.predictor", "detection"), ("live.behavior", "detection"),
    ("live.trafficlab", "traffic"), ("live.pipeline", "traffic"), ("live.controller", "deception"),
    ("live.k8s_decoys", "deception"), ("live.kube", "kubernetes"), ("live.k8s_status", "kubernetes"),
    ("uvicorn.access", "api"), ("uvicorn", "api"), ("dashboard", "api"), ("api", "api"),
]


def _rel(p: Path) -> str:
    try:
        return str(p.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def component_of(logger: str) -> str:
    return next((c for p, c in _COMPONENT if logger.startswith(p)), "backend")


# --- logs --------------------------------------------------------------------------------
def _tail(path: Path, n: int) -> list[str]:
    if not path.is_file():
        return []
    with open(path, encoding="utf-8", errors="replace") as fh:
        return list(deque(fh, maxlen=n))


def read_logs(limit: int = 300, level: str | None = None, component: str | None = None,
              search: str | None = None, source: str | None = None) -> dict[str, Any]:
    """Newest-first parsed log records from the backend and capture-service log files."""
    order = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
    min_level = order.get((level or "").upper(), 0)
    records: list[dict[str, Any]] = []
    files = {}
    for src, name in _LOG_FILES.items():
        if source and src != source:
            continue
        path = LOG_DIR / name
        files[src] = {"path": _rel(path), "exists": path.is_file(),
                      "bytes": path.stat().st_size if path.is_file() else 0}
        current = None
        for raw in _tail(path, 4000):
            line = raw.rstrip("\n")
            m = _LINE_RE.match(line)
            if m:
                ts, lvl, logger, msg = m.groups()
                current = {"ts": ts.replace(",", "."), "level": lvl, "logger": logger,
                           "component": component_of(logger), "message": msg, "source": src}
                records.append(current)
            elif current is not None and line.strip():   # traceback / continuation line
                current["message"] += "\n" + line
            elif line.strip():                            # unformatted output (e.g. a crash before logging)
                records.append({"ts": None, "level": "INFO", "logger": src, "component": src if src == "capture" else "backend",
                                "message": line, "source": src})
    out = [r for r in records
           if order.get(r["level"], 0) >= min_level
           and (not component or r["component"] == component)
           and (not search or search.lower() in r["message"].lower())]
    out.reverse()
    counts = {lv: sum(1 for r in records if r["level"] == lv) for lv in ("WARNING", "ERROR", "CRITICAL")}
    return {"records": out[:limit], "total_matching": len(out), "files": files, "counts": counts}


# --- resources -----------------------------------------------------------------------------
def _proc_stat(pid: int) -> tuple[float, int] | None:
    """(cpu seconds, rss bytes) of one process from /proc, or None off Linux."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        tick = os.sysconf("SC_CLK_TCK")
        cpu = (int(fields[11]) + int(fields[12])) / tick
        rss = int(fields[21]) * os.sysconf("SC_PAGE_SIZE")
        return cpu, rss
    except (OSError, ValueError, IndexError, AttributeError):
        return None


_last_cpu: dict[int, tuple[float, float]] = {}


def process_usage(pid: int) -> dict[str, Any] | None:
    st = _proc_stat(pid)
    if st is None:
        return None
    cpu_s, rss = st
    now = time.monotonic()
    prev = _last_cpu.get(pid)
    _last_cpu[pid] = (now, cpu_s)
    pct = None
    if prev and now > prev[0]:
        pct = round(100 * (cpu_s - prev[1]) / (now - prev[0]), 1)
    return {"pid": pid, "cpu_percent": pct, "cpu_seconds": round(cpu_s, 2), "rss_mb": round(rss / 2**20, 1)}


def host_usage() -> dict[str, Any] | None:
    try:
        mem = dict(ln.split(":", 1) for ln in Path("/proc/meminfo").read_text().splitlines())
        total = int(mem["MemTotal"].split()[0]) * 1024
        avail = int(mem["MemAvailable"].split()[0]) * 1024
        load1, load5, _ = os.getloadavg()
    except (OSError, KeyError, ValueError, AttributeError):
        return None
    return {"cpus": os.cpu_count(), "load_1m": round(load1, 2), "load_5m": round(load5, 2),
            "memory_total_mb": round(total / 2**20), "memory_used_mb": round((total - avail) / 2**20),
            "memory_percent": round(100 * (total - avail) / total, 1)}


def resources(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    from live import capture as cap
    from live.k8s_status import cluster_metrics
    cfg = cfg or load_config()
    state = cap.read_state(cfg)
    disk = shutil.disk_usage(REPO_ROOT)
    pcap_dir = get_path("pcap_dir", cfg)
    pcaps = list(pcap_dir.glob("*.pcap")) if pcap_dir.is_dir() else []
    return {
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "host": host_usage(),
        "backend": process_usage(os.getpid()),
        "capture_service": process_usage(state["pid"]) if state.get("pid") else None,
        "disk": {"free_gb": round(disk.free / 2**30, 1), "used_percent": round(100 * disk.used / disk.total, 1),
                 "pcap_files": len(pcaps), "pcap_mb": round(sum(p.stat().st_size for p in pcaps) / 2**20, 1)},
        "cluster": cluster_metrics(cfg),
    }


# --- health --------------------------------------------------------------------------------
def _check(name: str, fn) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        status, detail = fn()
    except Exception as e:  # noqa: BLE001  the check itself failed; report it, do not hide it
        status, detail = "error", f"{type(e).__name__}: {str(e)[:300]}"
    return {"component": name, "status": status, "detail": detail, "ms": round((time.perf_counter() - t0) * 1000, 1)}


def health(cfg: dict[str, Any] | None = None, predictor_factory=None, controller=None) -> dict[str, Any]:
    from live import capture as cap
    from live.cicflowmeter import support as cfm_support
    from live.k8s_status import targets_status
    from live.trafficlab import check_ready
    cfg = cfg or load_config()

    def database():
        with db.connect(db.db_path(cfg)) as c:
            n = c.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        return "ok", f"SQLite {_rel(db.db_path(cfg))} reachable, {n:,} detections stored"

    def model():
        p = predictor_factory() if predictor_factory else None
        if p is None:
            return "error", "model not loaded"
        return "ok", f"{p.name}: {type(p.model).__name__}, {len(p.features)} features, {len(p.classes)} classes"

    def kubernetes():
        t = targets_status(cfg)
        if not t["connected"]:
            return "unavailable", t.get("error")
        return ("ok" if t["all_running"] else "degraded"), \
            f"{t.get('identity')}; target pods {t['running']}/{t['total']} running"

    def traffic():
        r = check_ready(cfg)
        return ("ok" if r["ready"] else "unavailable"), r.get("reason") or r.get("note") or "generator script deployed"

    def tcpdump():
        s = cap.support(cfg)
        return ("ok" if s["supported"] else "unavailable"), s["reason"] or f"{cfg['capture']['tcpdump']} on {cfg['capture']['interface']}"

    def capture_service():
        s = cap.read_state(cfg)
        if s.get("running"):
            return "ok", f"running (pid {s['pid']}), {s.get('windows', 0)} windows, window {s.get('current_window_s')}s"
        if s.get("status") in ("error", "stopped_unexpectedly"):
            return "error", s.get("error") or s.get("status")
        return "idle", s.get("status")

    def cicflowmeter():
        s = cfm_support(cfg)
        return ("ok" if s["supported"] else "unavailable"), s["reason"] or s.get("jar")

    def deception():
        if controller is None:
            return "idle", "controller not started"
        st = controller()
        if not st.status()["loop_running"]:
            return "error", "MAPE-K loop thread is not running"
        k = st.status()
        if not k["kubernetes_available"]:
            return "unavailable", f"loop running; Kubernetes unavailable: {k['kubernetes_error']}"
        return "ok", f"loop running; automatic deception {'enabled' if k['enabled'] else 'disabled'}"

    checks = [_check("api", lambda: ("ok", f"up {int(time.time() - STARTED)}s, pid {os.getpid()}")),
              _check("database", database), _check("model", model), _check("kubernetes", kubernetes),
              _check("traffic_lab", traffic), _check("tcpdump", tcpdump), _check("capture_service", capture_service),
              _check("cicflowmeter", cicflowmeter), _check("deception", deception)]
    worst = "ok"
    for c in checks:
        if c["status"] == "error":
            worst = "error"
        elif c["status"] in ("unavailable", "degraded") and worst == "ok":
            worst = "degraded"
    return {"status": worst, "checked_at": datetime.now(timezone.utc).isoformat(), "components": checks}
