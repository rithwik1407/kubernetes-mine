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

BURST_COLUMNS = ["src_ip", "dst_ip", "dst_port", "protocol", "flows", "rate_per_s",
                 "ml_malicious_flows", "ml_classes", "window_s"]


def flow_bursts(pred: pd.DataFrame, window_s: float | None,
                cfg: dict[str, Any] | None = None) -> pd.DataFrame:
    b = (cfg or load_config())["behavior"]
    if pred.empty or not window_s or window_s <= 0:
        return pd.DataFrame(columns=BURST_COLUMNS)
    df = pred[pred["src_ip"].notna() & pred["dst_ip"].notna() & pred["dst_port"].notna()]
    df = df[df["protocol"].isin(b["protocols"]) & ~df["src_ip"].isin(b.get("ignore_sources", []))]
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
            "src_ip": src, "dst_ip": dst, "dst_port": int(port), "protocol": int(proto),
            "flows": int(n), "rate_per_s": round(rate, 3), "ml_malicious_flows": int(len(mal)),
            "ml_classes": json.dumps(mal["predicted_class"].value_counts().to_dict()),
            "window_s": float(window_s),
        })
    return pd.DataFrame(rows, columns=BURST_COLUMNS)
