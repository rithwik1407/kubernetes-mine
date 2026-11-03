"""Continuous windowed capture + classification service.

    python -m live.capture start [--windows N] [--no-process]   # background
    python -m live.capture stop
    python -m live.capture status
    python -m live.capture run   [--windows N] [--no-process]   # foreground

Each window: tcpdump on the configured interface -> PCAP -> (worker thread)
CICFlowMeter -> model -> SQLite. The next window length is chosen from the
packet rate of the previous one. Processing is file-based and therefore lags
the traffic by at least one window plus conversion time; it is not
packet-by-packet real-time detection.
"""
from __future__ import annotations

import argparse
import json
import platform
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from live.process_pcap import DONE_STATUSES, process_pcap
from live.tcpdump import CaptureError, capture_window, choose_next_window, validate_interface
from live import db
from live.config import REPO_ROOT as PROJECT_ROOT, get_path, load_config, project_path
from live.logging_setup import get_logger

try:  # POSIX only; capture itself needs Linux, but importing this module must never fail
    import fcntl
except ImportError:  # Windows
    fcntl = None

log = get_logger(__name__)
LOCK_NAME = "capture.lock"


class ServiceError(RuntimeError):
    pass


def support(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Can packet capture run on this machine? Never raises."""
    cfg = cfg or load_config()
    c = cfg["capture"]
    if platform.system() != "Linux":
        return {"supported": False, "reason": f"live capture needs Linux (this is {platform.system()}). "
                "Run the dashboard inside WSL2 / on the K3s host — see docs/live-system.md"}
    if not Path(c["tcpdump"]).exists():
        return {"supported": False, "reason": f"tcpdump not found at {c['tcpdump']} (sudo apt install tcpdump)"}
    if not Path("/sys/class/net", c["interface"]).exists():
        return {"supported": False, "reason": f"network interface {c['interface']} not found "
                "(K3s pod bridge; set capture.interface in config/live.yaml)"}
    return {"supported": True, "reason": None}


def _lock(fh) -> bool:
    if fcntl is None:
        return True
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


def _paths(cfg: dict[str, Any]) -> tuple[Path, Path, Path]:
    c = cfg["capture"]
    pid = project_path(c["pid_file"])
    return pid, project_path(c["state_file"]), pid.parent / LOCK_NAME


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_state(cfg: dict[str, Any], **state) -> None:
    _, state_file, _ = _paths(cfg)
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = _now()
    tmp = state_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, default=str))
    tmp.replace(state_file)


def read_state(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    pid_file, state_file, _ = _paths(cfg)
    state = json.loads(state_file.read_text()) if state_file.exists() else {"status": "never_started"}
    pid = _service_pid(pid_file)
    state["running"] = pid is not None
    state["pid"] = pid
    if state.get("status") == "running" and pid is None:
        state["status"] = "stopped_unexpectedly"
    return state


def _service_pid(pid_file: Path) -> int | None:
    """PID from the pid file, only if that process really is this service."""
    try:
        pid = int(pid_file.read_text().strip())
        proc = Path(f"/proc/{pid}/cmdline")
        if not proc.exists():
            return None
        cmdline = proc.read_bytes().replace(b"\0", b" ").decode()
    except (OSError, ValueError):
        return None
    return pid if "live.capture" in cmdline else None


def _enforce_retention(cfg: dict[str, Any]) -> None:
    keep = cfg["capture"]["retain_pcaps"]
    files = sorted(get_path("pcap_dir", cfg).glob("*.pcap"), key=lambda p: p.stat().st_mtime)
    if len(files) <= keep:
        return
    with db.connect(db.db_path(cfg)) as conn:
        done = {r["pcap_file"] for r in conn.execute(
            f"SELECT pcap_file FROM captures WHERE status IN ({','.join('?' * len(DONE_STATUSES))})", DONE_STATUSES)}
    for f in files[: len(files) - keep]:
        if f.name in done:
            f.unlink(missing_ok=True)


def run(windows: int | None = None, process: bool = True, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    validate_interface(cfg["capture"]["interface"])
    pid_file, _, lock_file = _paths(cfg)
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    lock_fh = open(lock_file, "w")
    if not _lock(lock_fh):
        lock_fh.close()
        raise ServiceError("another capture process is already running")

    stop = threading.Event()
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: stop.set())
    pid_file.write_text(str(os.getpid()))
    wcfg = cfg["capture"]["window"]
    work: queue.Queue = queue.Queue()
    stats: dict[str, Any] = {"windows": 0, "processed": 0, "failed": 0, "last_window": None, "last_result": None}
    lock = threading.Lock()
    predictor = None
    if process:
        from live.predictor import FlowPredictor
        predictor = FlowPredictor.from_config(cfg=cfg)

    def worker():
        while True:
            item = work.get()
            if item is None:
                return
            pcap, end_mono, fields = item
            try:
                res = process_pcap(Path(pcap), predictor, cfg, window_end_monotonic=end_mono, capture_fields=fields)
            except Exception as e:  # keep the service alive; the failure is recorded
                log.exception("processing %s failed", pcap)
                res = {"pcap": Path(pcap).name, "status": "failed", "error": str(e)}
            with lock:
                stats["processed"] += 1
                stats["failed"] += res.get("status") == "failed"
                stats["last_result"] = res
            _enforce_retention(cfg)

    thread = threading.Thread(target=worker, daemon=True) if process else None
    if thread:
        thread.start()

    window = float(wcfg["default_seconds"])
    base = {"status": "running", "pid": os.getpid(), "interface": cfg["capture"]["interface"],
            "started_at": _now(), "processing": process, "window_limit": windows}
    final: dict[str, Any] = {"status": "stopped"}
    try:
        while not stop.is_set() and (windows is None or stats["windows"] < windows):
            with lock:
                write_state(cfg, **base, current_window_s=window, **stats)
            res = capture_window(window, cfg, stop_event=stop)
            end_mono = time.monotonic()
            if res.error:
                log.error("capture failed: %s", res.error)
                final = {"status": "error", "error": res.error}
                raise CaptureError(res.error)
            next_window = choose_next_window(res.packets, res.duration_s, wcfg)
            fields = {"interface": res.interface, "started_at": res.started_at, "ended_at": res.ended_at,
                      "duration_s": res.duration_s, "packets": res.packets, "bytes": res.bytes,
                      "next_window_s": next_window, "status": "captured"}
            with db.connect(db.db_path(cfg)) as conn:
                db.upsert_capture(conn, Path(res.pcap).name, **fields)
            with lock:
                stats["windows"] += 1
                stats["last_window"] = res.to_dict()
            log.info("window %d: %s %.1fs %s packets -> next window %.0fs", stats["windows"],
                     Path(res.pcap).name, res.duration_s, res.packets, next_window)
            if process:
                work.put((res.pcap, end_mono, {k: v for k, v in fields.items() if k != "status"}))
            window = next_window
    finally:
        if thread:
            work.put(None)
            thread.join()
        with lock:
            write_state(cfg, **{**base, **final}, stopped_at=_now(), **stats)
        pid_file.unlink(missing_ok=True)
        if fcntl:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)
        lock_fh.close()
    return stats


def start(windows: int | None = None, process: bool = True, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    pid_file, _, _ = _paths(cfg)
    sup = support(cfg)
    if not sup["supported"]:
        raise ServiceError(sup["reason"])
    if _service_pid(pid_file):
        raise ServiceError("capture service is already running")
    validate_interface(cfg["capture"]["interface"])
    cmd = [sys.executable, "-m", "live.capture", "run"]
    if windows:
        cmd += ["--windows", str(int(windows))]
    if not process:
        cmd.append("--no-process")
    log_dir = PROJECT_ROOT / "logs"
    log_dir.mkdir(exist_ok=True)
    with open(log_dir / "capture_service.log", "a") as out:
        proc = subprocess.Popen(cmd, cwd=PROJECT_ROOT, stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
    for _ in range(100):  # wait until the child holds the lock and has published its state
        if proc.poll() is not None:
            raise ServiceError(f"capture service exited immediately (code {proc.returncode}); see logs/capture_service.log")
        state = read_state(cfg)
        if state["pid"] == proc.pid and state.get("status") == "running":
            return state
        time.sleep(0.1)
    raise ServiceError("capture service did not report running state within 10 s")


def stop(cfg: dict[str, Any] | None = None, timeout: float = 120) -> dict[str, Any]:
    cfg = cfg or load_config()
    pid_file, _, _ = _paths(cfg)
    pid = _service_pid(pid_file)
    if pid is None:
        return {**read_state(cfg), "message": "capture service was not running"}
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and _service_pid(pid_file) == pid:
        time.sleep(0.2)
    return read_state(cfg)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=("start", "stop", "status", "run"))
    ap.add_argument("--windows", type=int, help="stop after N windows")
    ap.add_argument("--no-process", action="store_true", help="capture only; process later with process_pcap --pending")
    args = ap.parse_args(argv)
    try:
        if args.command == "run":
            out = run(args.windows, not args.no_process)
        elif args.command == "start":
            out = start(args.windows, not args.no_process)
        elif args.command == "stop":
            out = stop()
        else:
            out = read_state()
    except (ServiceError, CaptureError) as e:
        sys.exit(f"error: {e}")
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
