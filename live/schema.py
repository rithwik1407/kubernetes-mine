"""Read CICFlowMeter CSV files and align them to the CIC-IDS2017 model features.

Handles the quirks of real CICFlowMeter output: a header row repeated mid-file,
stray whitespace in column names, and the slightly different column names
between CICFlowMeter builds. Column matching reuses ml/prepare.py's `canon`,
so the same alias table that trained the model maps live captures too.
"""
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from live.config import get_path, load_config

# Network-metadata columns, kept for the detection record, never used as features.
FLOW_ID = "Flow ID"
SRC_IP = "Src IP"
SRC_PORT = "Src Port"
DST_IP = "Dst IP"
DST_PORT = "Dst Port"
PROTOCOL = "Protocol"
TIMESTAMP = "Timestamp"
LABEL = "Label"
TEXT_COLUMNS = {FLOW_ID, SRC_IP, DST_IP, TIMESTAMP, LABEL}


class SchemaError(ValueError):
    """A CSV could not be read as a CICFlowMeter flow file."""


def _canon():
    """ml/prepare.py's canonicaliser (same column aliases used in training)."""
    cfg = load_config()
    sys.path.insert(0, str(get_path("pipeline_dir", cfg)))
    from prepare import canon  # noqa: E402
    return canon


def normalize_column_name(name: str) -> str:
    return re.sub(r"\s+", " ", str(name)).strip()


def read_flow_csv(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    df = pd.read_csv(path, low_memory=False, skipinitialspace=True, encoding_errors="replace")
    if len(df.columns) == 0:
        raise SchemaError(f"{path} has no header")
    df.columns = [normalize_column_name(c) for c in df.columns]
    df = df.drop(columns=[c for c in df.columns if c.startswith("Unnamed:") and df[c].isna().all()])
    if FLOW_ID not in df.columns and SRC_IP not in df.columns:
        raise SchemaError(f"{path} is not a CICFlowMeter flow file (no '{FLOW_ID}'/'{SRC_IP}' column)")
    first = df.columns[0]                                   # drop repeated header rows
    df = df.loc[df[first].astype(str).str.strip() != first]
    for col in df.columns:
        if col not in TEXT_COLUMNS:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df.reset_index(drop=True)


def align_features(df: pd.DataFrame, features: list[str]) -> tuple[pd.DataFrame, list[str]]:
    """Return df restricted to the model's features (canonical names) plus the missing ones.

    Missing features become NaN columns; the caller decides whether too many are missing.
    """
    canon = _canon()
    by_canon: dict[str, str] = {}
    for c in df.columns:
        by_canon.setdefault(canon(c), c)
    out, missing = {}, []
    for feat in features:
        if feat in by_canon:
            out[feat] = pd.to_numeric(df[by_canon[feat]], errors="coerce")
        else:
            missing.append(feat)
            out[feat] = pd.Series(np.nan, index=df.index)
    return pd.DataFrame(out, index=df.index), missing


def parse_timestamps(series: pd.Series) -> pd.Series:
    """CICFlowMeter writes day-first timestamps, e.g. 30/10/2026 12:19:24 PM."""
    return pd.to_datetime(series, format="mixed", dayfirst=True, errors="coerce")


def _valid_ip(v) -> bool:
    try:
        ipaddress.ip_address(str(v).strip())
        return True
    except ValueError:
        return False


def drop_non_ip_flows(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Remove rows that are not IP flows.

    CICFlowMeter turns ARP frames into flows: it reads the ARP header bytes as the IP
    addresses, so a who-has/is-at pair becomes "8.6.0.1:0 -> 8.0.6.4:0, protocol 0"
    (08 06 = ARP EtherType, 00 01 = hardware type, 08 00 06 04 = IPv4/MAC sizes).
    Only applies when the CSV carries network columns (CIC MachineLearningCVE CSVs do not).
    """
    if PROTOCOL not in df.columns or SRC_IP not in df.columns or DST_IP not in df.columns or df.empty:
        return df, 0
    proto = pd.to_numeric(df[PROTOCOL], errors="coerce")
    ok = proto.isin([1, 6, 17, 58]) & df[SRC_IP].map(_valid_ip) & df[DST_IP].map(_valid_ip)
    return df.loc[ok].reset_index(drop=True), int((~ok).sum())
