"""SQLite knowledge base: captures, detections, flow bursts, decoys, interactions.

Detections carry the CIC-IDS2017 string class (no integer label). The deception
tables mirror the k8s-adaptive-ids schema so the MAPE-K controller runs unchanged.
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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pcap_file TEXT UNIQUE NOT NULL, interface TEXT, started_at TEXT, ended_at TEXT,
    duration_s REAL, window_s REAL, packets INTEGER, bytes INTEGER,
    status TEXT NOT NULL, csv_file TEXT, flows INTEGER,
    conversion_s REAL, prediction_ms REAL, pipeline_s REAL, next_window_s REAL, error TEXT,
    updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER REFERENCES captures(id),
    flow_id TEXT, timestamp TEXT,
    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, protocol INTEGER,
    predicted_class TEXT NOT NULL, confidence REAL NOT NULL, is_malicious INTEGER NOT NULL,
    capture_file TEXT, source TEXT NOT NULL, processing_time_ms REAL, detected_at TEXT NOT NULL,
    true_label TEXT, model TEXT, simulated INTEGER NOT NULL DEFAULT 0,
    flow_duration_us REAL, packets INTEGER, bytes INTEGER, allowlisted TEXT,
    lab_scenario TEXT, lab_job TEXT
);
CREATE INDEX IF NOT EXISTS idx_det_detected_at ON detections(detected_at);
CREATE INDEX IF NOT EXISTS idx_det_malicious   ON detections(is_malicious);
CREATE INDEX IF NOT EXISTS idx_det_capture     ON detections(capture_id);

CREATE TABLE IF NOT EXISTS behavior_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id INTEGER REFERENCES captures(id), capture_file TEXT,
    alert_type TEXT NOT NULL DEFAULT 'flow_burst',
    src_ip TEXT NOT NULL, dst_ip TEXT, dst_port INTEGER, protocol INTEGER,
    flows INTEGER, rate_per_s REAL, window_s REAL,
    ml_malicious_flows INTEGER, ml_classes TEXT, detected_at TEXT NOT NULL, distinct_ports INTEGER
);

CREATE TABLE IF NOT EXISTS simulated_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
    src_ip TEXT, attack_class TEXT NOT NULL, confidence REAL NOT NULL,
    count INTEGER NOT NULL DEFAULT 1, note TEXT
);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, cycle_id INTEGER, created_at TEXT NOT NULL,
    trigger TEXT NOT NULL, src_ip TEXT, attack_class TEXT, assessment TEXT,
    max_confidence REAL, evidence_count INTEGER, action TEXT NOT NULL,
    decoy_profile TEXT, decoy_name TEXT, result TEXT, reason TEXT NOT NULL,
    evidence TEXT, simulated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_dec_created ON decisions(created_at);

CREATE TABLE IF NOT EXISTS decoys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, profile TEXT NOT NULL, namespace TEXT NOT NULL,
    status TEXT NOT NULL, replicas INTEGER NOT NULL DEFAULT 1, port INTEGER, service_ip TEXT,
    created_at TEXT NOT NULL, ready_at TEXT, deploy_seconds REAL, expires_at TEXT, removed_at TEXT,
    decision_id INTEGER REFERENCES decisions(id), detection_id INTEGER,
    simulated INTEGER NOT NULL DEFAULT 0, error TEXT
);

CREATE TABLE IF NOT EXISTS interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
    decoy_name TEXT NOT NULL, decoy_profile TEXT, pod TEXT,
    src_ip TEXT, src_port INTEGER, method TEXT, path TEXT, query TEXT, user_agent TEXT,
    status INTEGER, interaction_type TEXT, body_bytes INTEGER,
    decoy_id INTEGER REFERENCES decoys(id), decision_id INTEGER, detection_id INTEGER,
    collected_at TEXT NOT NULL,
    UNIQUE (pod, ts, src_ip, src_port, path)
);
CREATE INDEX IF NOT EXISTS idx_int_ts ON interactions(ts);

CREATE TABLE IF NOT EXISTS window_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, pcap_file TEXT,
    previous_s REAL, next_s REAL NOT NULL, rule TEXT NOT NULL, reason TEXT NOT NULL,
    changed INTEGER NOT NULL DEFAULT 0, evidence TEXT
);
CREATE INDEX IF NOT EXISTS idx_win_created ON window_transitions(created_at);

CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT, src_ip TEXT NOT NULL, attack_class TEXT, trigger TEXT,
    state TEXT NOT NULL, started_at TEXT NOT NULL, last_evidence_at TEXT NOT NULL, released_at TEXT,
    decoys TEXT, redirect TEXT, reason TEXT, decision_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_eng_src ON engagements(src_ip, state);

CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT);
"""

DETECTION_COLUMNS = [
    "flow_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "predicted_class", "confidence", "is_malicious", "capture_file", "source",
    "processing_time_ms", "detected_at", "true_label", "model",
    "flow_duration_us", "packets", "bytes", "allowlisted", "lab_scenario", "lab_job",
]


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
    conn.executescript(SCHEMA)
    _migrate(conn)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


_MIGRATIONS = {"captures": {"window_s": "REAL"}, "behavior_alerts": {"distinct_ports": "INTEGER"},
               "detections": {"flow_duration_us": "REAL", "packets": "INTEGER", "bytes": "INTEGER",
                              "allowlisted": "TEXT", "lab_scenario": "TEXT", "lab_job": "TEXT"}}


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after a database was first created (SQLite has no IF NOT EXISTS for columns)."""
    for table, cols in _MIGRATIONS.items():
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        for col, typ in cols.items():
            if col not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")


def _clean(v):
    if v is None or v is pd.NA or (isinstance(v, float) and v != v):
        return None
    if isinstance(v, bool):
        return int(v)
    if hasattr(v, "item"):
        return v.item()
    return v


def query_df(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> pd.DataFrame:
    return pd.read_sql_query(sql, conn, params=params)


def insert_row(conn: sqlite3.Connection, table: str, **fields) -> int:
    fields = {k: _clean(v) for k, v in fields.items()}
    conn.execute(f"INSERT INTO {table} ({', '.join(fields)}) VALUES ({', '.join('?' * len(fields))})",
                 list(fields.values()))
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


def update_row(conn: sqlite3.Connection, table: str, row_id: int, **fields) -> None:
    fields = {k: _clean(v) for k, v in fields.items()}
    conn.execute(f"UPDATE {table} SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?",
                 [*fields.values(), row_id])


def upsert_capture(conn: sqlite3.Connection, pcap_file: str, **fields) -> int:
    fields = {k: _clean(v) for k, v in fields.items()}
    row = conn.execute("SELECT id FROM captures WHERE pcap_file = ?", (pcap_file,)).fetchone()
    if row is None:
        fields.setdefault("status", "captured")
        cols = ["pcap_file", *fields]
        conn.execute(f"INSERT INTO captures ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                     [pcap_file, *fields.values()])
        return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    if fields:
        sets = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(f"UPDATE captures SET {sets}, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
                     [*fields.values(), row["id"]])
    return int(row["id"])


def insert_detections(conn: sqlite3.Connection, pred: pd.DataFrame, capture_id: int | None = None,
                      simulated: bool = False) -> int:
    if pred.empty:
        return 0
    rows = [(capture_id, *(_clean(r.get(c)) for c in DETECTION_COLUMNS), int(simulated))
            for r in pred.reindex(columns=DETECTION_COLUMNS).to_dict(orient="records")]
    cols = ["capture_id", *DETECTION_COLUMNS, "simulated"]
    conn.executemany(f"INSERT INTO detections ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", rows)
    return len(rows)


def kv_get(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def kv_set(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                 (key, value))
