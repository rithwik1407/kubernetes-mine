"""Read CICFlowMeter CSV files and align them to the CIC-IDS2017 model features.

Handles the quirks of real CICFlowMeter output: a header row repeated mid-file,
stray whitespace in column names, and the slightly different column names
between CICFlowMeter builds. Column matching reuses ml/prepare.py's `canon`,
so the same alias table that trained the model maps live captures too.
"""
from __future__ import annotations

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
