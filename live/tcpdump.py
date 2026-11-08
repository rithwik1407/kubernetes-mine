"""Windowed packet capture with tcpdump.

One tcpdump process is run per observation window and stopped with SIGINT when
the window ends, so each window becomes one complete PCAP file. Files are written
as <name>.pcap.part and renamed to .pcap only once tcpdump has flushed and exited.
tcpdump needs CAP_NET_RAW/CAP_NET_ADMIN (granted with setcap on this host).
"""
from __future__ import annotations

import re
import signal
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from live.config import get_path, load_config
from live.logging_setup import get_logger

log = get_logger(__name__)
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}$")


class CaptureError(RuntimeError):
    pass


@dataclass
class WindowResult:
    pcap: str | None
    interface: str
    started_at: str
    ended_at: str
    duration_s: float
    packets: int | None
    dropped: int | None
    bytes: int | None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_interface(name: str) -> str:
    if not _IFACE_RE.match(name or ""):
        raise CaptureError(f"invalid interface name: {name!r}")
    if not Path("/sys/class/net", name).exists():
        raise CaptureError(f"interface {name} does not exist")
    return name


def build_command(tcpdump: str, interface: str, out_path: Path, snaplen: int = 0, bpf: str = "") -> list[str]:
    cmd = [tcpdump, "-i", validate_interface(interface), "-nn", "-s", str(int(snaplen)), "-U", "-w", str(out_path)]
    if bpf:
        cmd.append(bpf)  # one argument; tcpdump parses the filter expression itself
    return cmd


def choose_next_window(packets: int | None, duration_s: float, wcfg: dict[str, Any]) -> float:
    """Rate-only window choice (no threat evidence). Kept for callers of the old API;
    the capture service uses live.window.decide with threat evidence."""
    from live.window import Evidence, decide, initial_window
    return decide(initial_window(wcfg), Evidence(packets=packets, duration_s=duration_s), wcfg).next_s


def _parse_counts(stderr: str) -> tuple[int | None, int | None]:
    cap = re.search(r"(\d+) packets? captured", stderr)
    drop = re.search(r"(\d+) packets? dropped by kernel", stderr)
    return (int(cap.group(1)) if cap else None, int(drop.group(1)) if drop else None)


def capture_window(duration_s: float, cfg: dict[str, Any] | None = None, out_dir: Path | None = None,
                   stop_event: threading.Event | None = None, prefix: str = "win") -> WindowResult:
    cfg = cfg or load_config()
    c = cfg["capture"]
    out_dir = out_dir or get_path("pcap_dir", cfg)
    out_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc)
    name = f"{prefix}_{c['interface']}_{started.strftime('%Y%m%dT%H%M%S_%f')}.pcap"
    part = out_dir / f"{name}.part"
    cmd = build_command(c["tcpdump"], c["interface"], part, c.get("snaplen", 0), c.get("bpf_filter", ""))

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    t0 = time.monotonic()
    while time.monotonic() - t0 < duration_s and proc.poll() is None:
        if stop_event is not None and stop_event.is_set():
            break
        time.sleep(0.1)
    early_exit = proc.poll() is not None
    if not early_exit:
        proc.send_signal(signal.SIGINT)
    try:
        _, stderr = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, stderr = proc.communicate()
    elapsed = time.monotonic() - t0
    ended = datetime.now(timezone.utc).isoformat()
    packets, dropped = _parse_counts(stderr or "")

    if early_exit or not part.exists():
        part.unlink(missing_ok=True)
        msg = (stderr or "").strip().splitlines()[-1:] or ["tcpdump exited early"]
        return WindowResult(None, c["interface"], started.isoformat(), ended, elapsed, None, None, None, msg[0])
    final = out_dir / name
    part.rename(final)
    return WindowResult(str(final), c["interface"], started.isoformat(), ended, elapsed,
                        packets, dropped, final.stat().st_size)
