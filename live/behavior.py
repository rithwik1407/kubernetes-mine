"""Per-source flow-burst detector for one capture window.

A single reconnaissance request looks exactly like a benign request to the same
service, so the ML model cannot separate them per flow (confirmed on the lab
recon captures: our CIC model classifies every recon flow BENIGN). What gives a
scan away is volume: many short flows from one source to one service in a
window. A flow burst is reported when one source opens at least `min_flows`
flows to one destination service and the rate reaches `min_rate_per_s`.
"""
from __future__ import annotations

import json
from typing import Any

import pandas as pd

from live.config import load_config

BURST_COLUMNS = ["alert_type", "src_ip", "dst_ip", "dst_port", "protocol", "flows", "rate_per_s",
                 "ml_malicious_flows", "ml_classes", "window_s", "distinct_ports"]


def flow_bursts(pred: pd.DataFrame, window_s: float | None,
                cfg: dict[str, Any] | None = None) -> pd.DataFrame:
    b = (cfg or load_config())["behavior"]
    if pred.empty or not window_s or window_s <= 0:
        return pd.DataFrame(columns=BURST_COLUMNS)
    df = pred[pred["src_ip"].notna() & pred["dst_ip"].notna() & pred["dst_port"].notna()]
    df = df[df["protocol"].isin(b["protocols"]) & ~df["src_ip"].isin(b.get("ignore_sources", []))]
    if "allowlisted" in df.columns:          # control-plane traffic never forms a burst
        df = df[df["allowlisted"].isna()]
    if df.empty:
        return pd.DataFrame(columns=BURST_COLUMNS)
    rows = []
    for (src, dst, port, proto), g in df.groupby(["src_ip", "dst_ip", "dst_port", "protocol"]):
        n = len(g)
        rate = n / window_s
        if n < b["min_flows"] or rate < b["min_rate_per_s"]:
            continue
        mal = g[g["is_malicious"].astype(bool)]
        rows.append({
            "alert_type": "flow_burst", "distinct_ports": 1,
            "src_ip": src, "dst_ip": dst, "dst_port": int(port), "protocol": int(proto),
            "flows": int(n), "rate_per_s": round(rate, 3), "ml_malicious_flows": int(len(mal)),
            "ml_classes": json.dumps(mal["predicted_class"].value_counts().to_dict()),
            "window_s": float(window_s),
        })
    rows += _port_sweeps(df, window_s, b)
    return pd.DataFrame(rows, columns=BURST_COLUMNS)


def _port_sweeps(df: pd.DataFrame, window_s: float, b: dict[str, Any]) -> list[dict[str, Any]]:
    """One source touching many *different* ports of one host in a window (a port scan).

    The per-port burst rule above never sees a scan, because each port gets only one
    flow. Measured in the K3s lab: a TCP connect scan of 1024 ports is classified
    BENIGN flow by flow by the CIC model (its PortScan class learned nmap's raw-SYN
    fingerprint, not a Linux connect() scan), so this rule is what catches it.
    """
    min_ports = int(b.get("sweep_min_ports", 10))
    rows = []
    for (src, dst, proto), g in df.groupby(["src_ip", "dst_ip", "protocol"]):
        ports = g["dst_port"].nunique()
        rate = ports / window_s
        if ports < min_ports or rate < b["min_rate_per_s"]:
            continue
        mal = g[g["is_malicious"].astype(bool)]
        rows.append({
            "alert_type": "port_sweep", "src_ip": src, "dst_ip": dst, "dst_port": None, "protocol": int(proto),
            "flows": int(len(g)), "rate_per_s": round(rate, 3), "ml_malicious_flows": int(len(mal)),
            "ml_classes": json.dumps(mal["predicted_class"].value_counts().to_dict()),
            "window_s": float(window_s), "distinct_ports": int(ports),
        })
    return rows
