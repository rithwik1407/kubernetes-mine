"""Read-only queries over the SQLite knowledge base for the dashboard backend."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd

from live import db
from live.config import load_config


def _records(df: pd.DataFrame) -> list[dict[str, Any]]:
    return df.astype(object).where(df.notna(), None).to_dict(orient="records")


def _q(sql: str, params: tuple = (), cfg=None) -> list[dict[str, Any]]:
    with db.connect(db.db_path(cfg)) as c:
        return _records(db.query_df(c, sql, params))


def detections(limit=200, offset=0, source=None, predicted_class=None, src_ip=None,
               malicious=None, cfg=None) -> list[dict[str, Any]]:
    where, params = ["simulated = 0"], []
    for col, val in (("source", source), ("predicted_class", predicted_class), ("src_ip", src_ip)):
        if val:
            where.append(f"{col} = ?")
            params.append(val)
    if malicious is not None:
        where.append("is_malicious = ?")
        params.append(int(malicious))
    sql = f"SELECT * FROM detections WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ? OFFSET ?"
    return _q(sql, (*params, int(limit), int(offset)), cfg)


def detection_stats(cfg=None) -> dict[str, Any]:
    with db.connect(db.db_path(cfg)) as c:
        by_class = db.query_df(c, "SELECT source, predicted_class, is_malicious, COUNT(*) n, AVG(confidence) mean_conf "
                                  "FROM detections WHERE simulated = 0 GROUP BY 1,2,3")
        timeline = db.query_df(c, "SELECT substr(detected_at,1,16) minute, "
                                  "SUM(is_malicious) malicious, COUNT(*)-SUM(is_malicious) benign "
                                  "FROM detections WHERE simulated = 0 GROUP BY 1 ORDER BY 1")
    return {"by_class": _records(by_class), "timeline": _records(timeline)}


def metrics(cfg=None) -> dict[str, Any]:
    cfg = cfg or load_config()
    since = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
    medium = cfg["deception"]["thresholds"]["medium_confidence"]
    with db.connect(db.db_path(cfg)) as c:
        one = lambda sql, p=(): c.execute(sql, p).fetchone()[0]
        return {
            "total_flows": one("SELECT COUNT(*) FROM detections WHERE simulated = 0"),
            "benign_flows": one("SELECT COUNT(*) FROM detections WHERE simulated = 0 AND is_malicious = 0"),
            "malicious_flows": one("SELECT COUNT(*) FROM detections WHERE simulated = 0 AND is_malicious = 1"),
            "flows_by_source": dict(c.execute("SELECT source, COUNT(*) FROM detections WHERE simulated = 0 GROUP BY 1").fetchall()),
            "flows_by_class": dict(c.execute("SELECT predicted_class, COUNT(*) FROM detections WHERE simulated = 0 GROUP BY 1").fetchall()),
            "flow_bursts": one("SELECT COUNT(*) FROM behavior_alerts"),
            "active_threats": one(
                "SELECT COUNT(DISTINCT src_ip) FROM (SELECT src_ip FROM detections WHERE simulated = 0 AND is_malicious = 1 "
                "AND source IN ('pcap','live') AND confidence >= ? AND detected_at >= ? "
                "UNION SELECT src_ip FROM behavior_alerts WHERE detected_at >= ?)", (medium, since, since)),
            "active_decoys": one("SELECT COUNT(*) FROM decoys WHERE status IN ('deploying','active')"),
            "total_interactions": one("SELECT COUNT(*) FROM interactions"),
            "decisions": one("SELECT COUNT(*) FROM decisions"),
            "simulated_events": one("SELECT COUNT(*) FROM simulated_events"),
            "captures": one("SELECT COUNT(*) FROM captures"),
        }


def behavior_alerts(limit=200, cfg=None) -> list[dict[str, Any]]:
    return _q("SELECT * FROM behavior_alerts ORDER BY id DESC LIMIT ?", (int(limit),), cfg)


def captures(limit=100, cfg=None) -> list[dict[str, Any]]:
    return _q("SELECT * FROM captures ORDER BY id DESC LIMIT ?", (int(limit),), cfg)


def decisions(limit=200, cfg=None) -> list[dict[str, Any]]:
    rows = _q("SELECT * FROM decisions ORDER BY id DESC LIMIT ?", (int(limit),), cfg)
    for r in rows:
        r["evidence"] = json.loads(r["evidence"]) if r.get("evidence") else None
    return rows


def decoys(limit=200, cfg=None) -> list[dict[str, Any]]:
    return _q("SELECT * FROM decoys ORDER BY id DESC LIMIT ?", (int(limit),), cfg)


def interactions(limit=200, decoy=None, cfg=None) -> list[dict[str, Any]]:
    if decoy:
        return _q("SELECT * FROM interactions WHERE decoy_name = ? ORDER BY ts DESC LIMIT ?", (decoy, int(limit)), cfg)
    return _q("SELECT * FROM interactions ORDER BY ts DESC LIMIT ?", (int(limit),), cfg)


def simulated_events(limit=100, cfg=None) -> list[dict[str, Any]]:
    return _q("SELECT * FROM simulated_events ORDER BY id DESC LIMIT ?", (int(limit),), cfg)


def policy(cfg=None) -> dict[str, Any]:
    d = (cfg or load_config())["deception"]
    return {k: d[k] for k in ("attack_policy", "behavior_policy", "profiles", "thresholds", "scale_on_repeat",
                              "max_active_decoys", "max_replicas", "decoy_ttl_seconds", "act_on_sources", "engagement")}
