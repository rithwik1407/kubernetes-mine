"""Score CICFlowMeter flows with the saved CIC-IDS2017 model."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from live.config import get_path, load_config
from live.schema import (
    DST_IP, DST_PORT, FLOW_ID, LABEL, PROTOCOL, SRC_IP, SRC_PORT, TIMESTAMP,
    SchemaError, align_features, parse_timestamps, read_flow_csv,
)

PREDICTION_COLUMNS = [
    "flow_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "predicted_class", "confidence", "is_malicious",
    "capture_file", "source", "processing_time_ms", "detected_at", "true_label", "model",
    "flow_duration_us", "packets", "bytes",
]


def _num(df: pd.DataFrame, canon_names: tuple[str, ...]) -> pd.Series:
    """First column whose canonical name matches (CICFlowMeter builds name them differently)."""
    from live.schema import _canon
    canon = _canon()
    for c in df.columns:
        if canon(c) in canon_names:
            return pd.to_numeric(df[c], errors="coerce")
    return pd.Series(np.nan, index=df.index)
VALID_SOURCES = ("upload", "pcap", "live", "unknown")


def _col(df: pd.DataFrame, name: str, dtype: str) -> pd.Series:
    if name not in df.columns:
        return pd.Series(pd.NA, index=df.index, dtype=dtype)
    if dtype == "Int64":
        return pd.to_numeric(df[name], errors="coerce").round().astype("Int64")
    s = df[name].astype("string").str.strip()
    return s.mask(s == "", pd.NA)


class FlowPredictor:
    """Loads models/<dir>/best_model.joblib (a dict of model, features, classes)."""

    def __init__(self, model_dir: str | Path, cfg: dict[str, Any] | None = None):
        self.cfg = cfg or load_config()
        self.model_dir = Path(model_dir)
        bundle_path = self.model_dir / "best_model.joblib"
        if not bundle_path.is_file():
            raise FileNotFoundError(f"no best_model.joblib in {self.model_dir}")
        bundle = joblib.load(bundle_path)
        self.model = bundle["model"]
        self.features: list[str] = list(bundle["features"])
        self.classes = np.asarray(bundle["classes"])
        self.benign_class: str = self.cfg["detection"]["benign_class"]
        self.max_missing = self.cfg["detection"]["max_missing_feature_fraction"]
        self.name = self.model_dir.name
        self.last_report: dict[str, Any] = {}

    @classmethod
    def from_config(cls, cfg: dict[str, Any] | None = None) -> "FlowPredictor":
        cfg = cfg or load_config()
        return cls(get_path("model_dir", cfg), cfg)

    def predict_frame(self, df: pd.DataFrame, capture_file: str | None = None,
                      source: str = "unknown") -> pd.DataFrame:
        if source not in VALID_SOURCES:
            raise ValueError(f"source must be one of {VALID_SOURCES}")
        if df.empty:
            self.last_report = {"rows": 0, "missing_features": [], "batch_ms": 0.0}
            return pd.DataFrame(columns=PREDICTION_COLUMNS)

        X, missing = align_features(df, self.features)
        if len(missing) / len(self.features) > self.max_missing:
            raise SchemaError(f"{len(missing)}/{len(self.features)} model features missing: {missing[:10]}")
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)

        t0 = time.perf_counter()
        proba = self.model.predict_proba(X.to_numpy(np.float32))
        batch_ms = (time.perf_counter() - t0) * 1000
        idx = proba.argmax(axis=1)
        classes = self.classes[idx]

        ts = parse_timestamps(df[TIMESTAMP]) if TIMESTAMP in df.columns else pd.Series(pd.NaT, index=df.index)
        out = pd.DataFrame({
            "flow_id": _col(df, FLOW_ID, "string"),
            "timestamp": ts.dt.strftime("%Y-%m-%dT%H:%M:%S.%f").astype("string"),
            "src_ip": _col(df, SRC_IP, "string"),
            "src_port": _col(df, SRC_PORT, "Int64"),
            "dst_ip": _col(df, DST_IP, "string"),
            "dst_port": _col(df, DST_PORT, "Int64"),
            "protocol": _col(df, PROTOCOL, "Int64"),
            "predicted_class": classes.astype(str),
            "confidence": proba.max(axis=1).round(6),
            "is_malicious": classes != self.benign_class,
            "capture_file": capture_file,
            "source": source,
            "processing_time_ms": batch_ms / len(df),
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "true_label": _col(df, LABEL, "string"),
            "model": self.name,
            # flow facts kept for the dashboard only (identifiers and these are never model inputs here)
            "flow_duration_us": _num(df, ("flowduration",)),
            "packets": _num(df, ("totalfwdpackets",)).fillna(0) + _num(df, ("totalbackwardpackets",)).fillna(0),
            "bytes": _num(df, ("totallengthoffwdpackets",)).fillna(0) + _num(df, ("totallengthofbwdpackets",)).fillna(0),
        }, index=df.index)
        self.last_report = {"rows": int(len(df)), "missing_features": missing, "batch_ms": batch_ms}
        return out.reset_index(drop=True)

    def predict_csv(self, path: str | Path, source: str = "unknown") -> pd.DataFrame:
        path = Path(path)
        return self.predict_frame(read_flow_csv(path), capture_file=path.name, source=source)


def to_records(pred: pd.DataFrame) -> list[dict[str, Any]]:
    records = pred.astype(object).where(pred.notna(), None).to_dict(orient="records")
    for r in records:
        for k, v in r.items():
            if isinstance(v, np.generic):
                r[k] = v.item()
    return records
