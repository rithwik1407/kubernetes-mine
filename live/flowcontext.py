"""Score each capture window with the preceding seconds of traffic as context.

CICFlowMeter converts one PCAP at a time, so before this every window boundary cut
every TCP connection that crossed it into separate "flows". Measured on the lab
database (15,003 TCP flow records): 3.1 % of connections were split across windows,
but they produced 19 % of all records. A single API-server watch connection showed
up as 211 fragments of 2-4 packets each, which is exactly what the model then called
"DoS" at 0.52 confidence. A slow_dos connection held for 20 s became 7-20 fragments.

Fix: the window's PCAP is converted together with the previous windows that fall
inside `capture.flow_context_seconds` (classic pcap files are concatenated, same
link type), and only flows that are still active in the current window (flow
start + duration >= first packet of the window) are kept. A connection that crosses
a boundary is therefore scored with its history instead of as a short fragment.
"""
from __future__ import annotations

import struct
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from live.schema import TIMESTAMP, parse_timestamps

_MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
          b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}


def _header(path: Path) -> tuple[bytes, str, float]:
    with open(path, "rb") as fh:
        head = fh.read(24)
    if len(head) < 24 or head[:4] not in _MAGIC:
        raise ValueError(f"{path.name} is not a classic pcap")
    endian, unit = _MAGIC[head[:4]]
    return head, endian, unit


def first_packet_time(path: Path) -> float | None:
    """Epoch seconds of the first packet, or None for an empty capture."""
    _, endian, unit = _header(path)
    with open(path, "rb") as fh:
        fh.seek(24)
        rec = fh.read(16)
    if len(rec) < 16:
        return None
    sec, frac, _, _ = struct.unpack(endian + "IIII", rec)
    return sec + frac * unit


def concat_pcaps(files: list[Path], out: Path) -> int:
    """Concatenate classic pcaps with identical global headers (magic, link type, snaplen). Returns files used."""
    base, _, _ = _header(files[-1])
    used = 0
    with open(out, "wb") as dst:
        dst.write(base)
        for f in files:
            head, _, _ = _header(f)
            if head[:4] != base[:4] or head[20:24] != base[20:24]:
                continue                       # different byte order / link type: skip, never corrupt
            with open(f, "rb") as src:
                src.seek(24)
                while chunk := src.read(1 << 20):
                    dst.write(chunk)
            used += 1
    return used


def context_files(pcap: Path, context_s: float) -> list[Path]:
    """Earlier window files (same directory, name-ordered) whose first packet is within context_s."""
    if context_s <= 0:
        return []
    t0 = first_packet_time(pcap)
    if t0 is None:
        return []
    prefix = pcap.name.split("_")[0] + "_"
    earlier = sorted(p for p in pcap.parent.glob(prefix + "*.pcap") if p.name < pcap.name)
    out = []
    for p in reversed(earlier[-50:]):
        try:
            t = first_packet_time(p)
        except (OSError, ValueError):
            continue
        if t is None:
            continue
        if t < t0 - context_s:
            break
        out.append(p)
    return list(reversed(out))


def keep_active_flows(df: pd.DataFrame, window_start_epoch: float | None) -> tuple[pd.DataFrame, int]:
    """Keep flows whose last packet is at or after the window start (CICFlowMeter writes local time)."""
    if window_start_epoch is None or TIMESTAMP not in df.columns or df.empty:
        return df, 0
    start = pd.Timestamp(datetime.fromtimestamp(window_start_epoch))
    begin = parse_timestamps(df[TIMESTAMP])
    dur = pd.to_numeric(df.get("Flow Duration"), errors="coerce").fillna(0)
    end = begin + pd.to_timedelta(dur, unit="us")
    keep = end.isna() | (end >= start - pd.Timedelta(milliseconds=1))
    return df.loc[keep].reset_index(drop=True), int((~keep).sum())


def describe(cfg: dict[str, Any]) -> dict[str, Any]:
    return {"flow_context_seconds": float(cfg["capture"].get("flow_context_seconds", 0) or 0)}
