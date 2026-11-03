"""SQLite knowledge base: captures, detections, flow bursts, decoys, interactions.

Shared by the FastAPI backend and, when the backend is down, by read-only
queries so stored records stay viewable.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pandas as pd

from live.config import get_path, load_config

SCHEMA = """
CREATE TABLE IF NOT EXISTS captures (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    pcap_file     TEXT UNIQUE NOT NULL,
    interface     TEXT,
    started_at    TEXT,
    ended_at      TEXT,
    duration_s    REAL,
    packets       INTEGER,
    bytes         INTEGER,
    status        TEXT NOT NULL,          -- captured|converted|empty|classified|failed
    csv_file      TEXT,
    flows         INTEGER,
    conversion_s  REAL,
    prediction_ms REAL,
    pipeline_s    REAL,
    next_window_s REAL,
    error         TEXT,
    updated_at    TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS detections (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id         INTEGER REFERENCES captures(id),
    flow_id            TEXT, timestamp TEXT,
    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, protocol INTEGER,
    predicted_class    TEXT NOT NULL,
    confidence         REAL NOT NULL,
    is_malicious       INTEGER NOT NULL,
    capture_file       TEXT,
    source             TEXT NOT NULL,     -- upload|pcap|live
    processing_time_ms REAL,
    detected_at        TEXT NOT NULL,
    true_label         TEXT,
    model              TEXT,
    simulated          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_det_detected_at ON detections(detected_at);
CREATE INDEX IF NOT EXISTS idx_det_malicious   ON detections(is_malicious);
CREATE INDEX IF NOT EXISTS idx_det_capture     ON detections(capture_id);

CREATE TABLE IF NOT EXISTS behavior_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER REFERENCES captures(id),
    capture_file TEXT,
    alert_type TEXT NOT NULL DEFAULT 'flow_burst',
    src_ip TEXT NOT NULL, dst_ip TEXT, dst_port INTEGER, protocol INTEGER,
    flows INTEGER, rate_per_s REAL, window_s REAL,
    ml_malicious_flows INTEGER, ml_classes TEXT,
    detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS simulated_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_class TEXT NOT NULL, confidence REAL NOT NULL,
    src_ip TEXT, count INTEGER NOT NULL DEFAULT 1, note TEXT,
    created_at TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_id INTEGER, created_at TEXT NOT NULL,
    trigger TEXT, src_ip TEXT, attack_class TEXT, assessment TEXT,
    max_confidence REAL, action TEXT, profile TEXT, decoy_name TEXT,
    result TEXT, reason TEXT, evidence TEXT, simulated INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS decoys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, profile TEXT NOT NULL, port INTEGER,
    status TEXT NOT NULL,                 -- deploying|active|expired|removed|failed
    replicas INTEGER DEFAULT 1,
    decision_id INTEGER, detection_id INTEGER,
    deployed_at TEXT, deploy_seconds REAL, expires_at TEXT, removed_at TEXT,
    simulated INTEGER NOT NULL DEFAULT 0, error TEXT
);

CREATE TABLE IF NOT EXISTS interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decoy_name TEXT NOT NULL, ts TEXT NOT NULL,
    src_ip TEXT, src_port INTEGER, method TEXT, path TEXT, status INTEGER,
    interaction_type TEXT, decision_id INTEGER, detection_id INTEGER,
    UNIQUE(decoy_name, ts, src_ip, path)
);

CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT);
"""


def db_path(cfg: dict[str, Any] | None = None) -> Path:
    return get_path("database", cfg or load_config())


@contextmanager
def connect(path: str | Path | None = None) -> Iterator[sqlite3.Connection]:
    path = Path(path or db_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def query_df(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> pd.DataFrame:
    return pd.read_sql_query(sql, conn, params=params)


def insert_row(conn: sqlite3.Connection, table: str, **fields: Any) -> int:
    cols = ", ".join(fields)
    marks = ", ".join("?" * len(fields))
    cur = conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", tuple(fields.values()))
    return cur.lastrowid


def upsert_capture(conn: sqlite3.Connection, pcap_file: str, **fields: Any) -> int:
    row = conn.execute("SELECT id FROM captures WHERE pcap_file = ?", (pcap_file,)).fetchone()
    if row is None:
        fields.setdefault("status", "captured")
        return insert_row(conn, "captures", pcap_file=pcap_file, **fields)
    if fields:
        sets = ", ".join(f"{k} = ?" for k in fields) + ", updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')"
        conn.execute(f"UPDATE captures SET {sets} WHERE id = ?", (*fields.values(), row["id"]))
    return row["id"]


def insert_detections(conn: sqlite3.Connection, pred: pd.DataFrame,
                      capture_id: int | None = None, simulated: int = 0) -> int:
    if pred.empty:
        return 0
    cols = ["flow_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
            "predicted_class", "confidence", "is_malicious", "capture_file", "source",
            "processing_time_ms", "detected_at", "true_label", "model"]
    frame = pred.reindex(columns=cols).astype(object).where(pred.reindex(columns=cols).notna(), None)
    frame.insert(0, "capture_id", capture_id)
    frame["is_malicious"] = [int(bool(v)) for v in frame["is_malicious"]]
    frame["simulated"] = simulated
    conn.executemany(
        f"INSERT INTO detections ({', '.join(frame.columns)}) VALUES ({', '.join('?' * len(frame.columns))})",
        [tuple(r) for r in frame.itertuples(index=False)])
    return len(frame)


def kv_get(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def kv_set(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO kv (key, value) VALUES (?, ?) "
                 "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
