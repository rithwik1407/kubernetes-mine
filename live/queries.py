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
               malicious=None, cfg=None, lab_scenario=None) -> list[dict[str, Any]]:
    where, params = ["simulated = 0"], []
    if lab_scenario == "any":
        where.append("lab_scenario IS NOT NULL")
    elif lab_scenario:
        where.append("lab_scenario = ?")
        params.append(lab_scenario)
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
            "captures_failed": one("SELECT COUNT(*) FROM captures WHERE status = 'failed'"),
            "packets_captured": one("SELECT COALESCE(SUM(packets), 0) FROM captures"),
            "bytes_captured": one("SELECT COALESCE(SUM(bytes), 0) FROM captures"),
            # time from the end of a capture window to its detections being stored
            "detection_latency_s": _latency(c),
            "malicious_rate": (lambda t, m: round(m / t, 4) if t else None)(
                one("SELECT COUNT(*) FROM detections WHERE simulated = 0"),
                one("SELECT COUNT(*) FROM detections WHERE simulated = 0 AND is_malicious = 1")),
            "window_transitions": one("SELECT COUNT(*) FROM window_transitions WHERE changed = 1"),
        }


def _latency(c) -> dict[str, Any]:
    rows = [r[0] for r in c.execute("SELECT pipeline_s FROM captures WHERE pipeline_s IS NOT NULL ORDER BY id DESC LIMIT 50")]
    pred = [r[0] for r in c.execute("SELECT prediction_ms FROM captures WHERE prediction_ms IS NOT NULL ORDER BY id DESC LIMIT 50")]
    if not rows:
        return {"last_s": None, "mean_s": None, "samples": 0, "model_ms_mean": None}
    return {"last_s": round(rows[0], 3), "mean_s": round(sum(rows) / len(rows), 3), "samples": len(rows),
            "model_ms_mean": round(sum(pred) / len(pred), 2) if pred else None}


def window_transitions(limit=200, changed_only=False, cfg=None) -> list[dict[str, Any]]:
    where = "WHERE changed = 1" if changed_only else ""
    rows = _q(f"SELECT * FROM window_transitions {where} ORDER BY id DESC LIMIT ?", (int(limit),), cfg)
    for r in rows:
        r["evidence"] = json.loads(r["evidence"]) if r.get("evidence") else None
    return rows


def recent_events(limit=50, cfg=None) -> list[dict[str, Any]]:
    """Security event feed: malicious detections (grouped per window+source+class), bursts, decoy actions."""
    with db.connect(db.db_path(cfg)) as c:
        det = _records(db.query_df(c, (
            "SELECT MAX(detected_at) ts, 'detection' kind, predicted_class title, src_ip, dst_ip, MAX(dst_port) dst_port, "
            "COUNT(*) n, MAX(confidence) confidence, capture_file FROM detections "
            "WHERE simulated = 0 AND is_malicious = 1 GROUP BY capture_file, src_ip, dst_ip, predicted_class "
            "ORDER BY ts DESC LIMIT ?"), (int(limit),)))
        bursts = _records(db.query_df(c, (
            "SELECT detected_at ts, alert_type kind, CASE alert_type WHEN 'port_sweep' THEN 'Port sweep (' || distinct_ports || ' ports)' ELSE 'Flow burst' END title, src_ip, dst_ip, dst_port, flows n, "
            "NULL confidence, capture_file FROM behavior_alerts ORDER BY id DESC LIMIT ?"), (int(limit),)))
        # every deception decision that changes something or is refused: trigger, evidence, confidence, action
        dec = _records(db.query_df(c, (
            "SELECT created_at ts, 'deception' kind, action || ' ' || COALESCE(decoy_name, '') title, src_ip, NULL dst_ip, "
            "NULL dst_port, evidence_count n, max_confidence confidence, result capture_file, trigger, action, "
            "attack_class, reason, evidence FROM decisions "
            "WHERE action IN ('deploy','scale','remove','engage','redirect','release','suppress_limit','suppress_cooldown') "
            "ORDER BY id DESC LIMIT ?"), (int(limit),)))
    for d in dec:
        try:
            e = json.loads(d.pop("evidence") or "{}")
        except ValueError:
            e = {}
        d["evidence_flows"] = (e.get("detection_ids") or [])[:10]
        d["mean_confidence"] = e.get("mean_confidence")
    ev = sorted(det + bursts + dec, key=lambda r: r["ts"] or "", reverse=True)
    return ev[:limit]


def traffic_timeline(minutes=30, cfg=None) -> list[dict[str, Any]]:
    """Packets and flows per capture window over the last N minutes (real-time activity chart)."""
    since = (datetime.now(timezone.utc) - timedelta(minutes=int(minutes))).isoformat()
    return _q("SELECT c.started_at, c.ended_at, c.window_s, c.duration_s, c.packets, c.bytes, c.flows, c.status, "
              "(SELECT COUNT(*) FROM detections d WHERE d.capture_id = c.id AND d.is_malicious = 1) malicious "
              "FROM captures c WHERE c.started_at >= ? ORDER BY c.id", (since,), cfg)


def activity(minutes: int = 15, bucket_s: int = 30, cfg=None) -> dict[str, Any]:
    """Overview chart data: benign / malicious flows per fixed time bucket, capture coverage
    per bucket (so gaps show as "capture off", not as zero traffic) and malicious events."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=int(minutes))
    start = start - timedelta(seconds=start.timestamp() % bucket_s)          # align to bucket edges
    n = int((now - start).total_seconds() // bucket_s) + 1
    edges = [start + timedelta(seconds=i * bucket_s) for i in range(n)]
    since = start.isoformat()
    with db.connect(db.db_path(cfg)) as c:
        caps = [dict(r) for r in c.execute(
            "SELECT id, started_at, ended_at, packets FROM captures WHERE ended_at >= ? ORDER BY id", (since,))]
        det = [dict(r) for r in c.execute(
            "SELECT d.capture_id, d.is_malicious, COUNT(*) n FROM detections d JOIN captures c ON c.id = d.capture_id "
            "WHERE d.simulated = 0 AND c.ended_at >= ? GROUP BY d.capture_id, d.is_malicious", (since,))]
        mal = _records(db.query_df(c, (
            "SELECT c.started_at, c.ended_at, d.predicted_class, d.src_ip, d.dst_ip, d.dst_port, COUNT(*) n, "
            "MAX(d.confidence) confidence FROM detections d JOIN captures c ON c.id = d.capture_id "
            "WHERE d.simulated = 0 AND d.is_malicious = 1 AND c.ended_at >= ? "
            "GROUP BY d.capture_id, d.src_ip, d.dst_ip, d.predicted_class ORDER BY c.ended_at"), (since,)))
        alerts = _records(db.query_df(c, (
            "SELECT detected_at, alert_type, src_ip, dst_ip, dst_port, flows, distinct_ports FROM behavior_alerts "
            "WHERE detected_at >= ? ORDER BY id"), (since,)))
    per_cap = {}
    for d in det:
        per_cap.setdefault(d["capture_id"], [0, 0])[1 if d["is_malicious"] else 0] += d["n"]
    benign = [0] * n
    malicious = [0] * n
    covered = [0.0] * n
    packets = [0] * n

    def idx(t: datetime) -> int:
        return max(0, min(n - 1, int((t - start).total_seconds() // bucket_s)))

    for cp in caps:
        try:
            t0 = datetime.fromisoformat(cp["started_at"])
            t1 = datetime.fromisoformat(cp["ended_at"])
        except (TypeError, ValueError):
            continue
        b, m = per_cap.get(cp["id"], [0, 0])
        k = idx(t1)                                   # flows are attributed to the bucket the window closed in
        benign[k] += b
        malicious[k] += m
        packets[k] += cp["packets"] or 0
        for i in range(idx(t0), idx(t1) + 1):         # capture coverage, seconds per bucket
            lo, hi = edges[i], edges[i] + timedelta(seconds=bucket_s)
            covered[i] += max(0.0, (min(hi, t1) - max(lo, t0)).total_seconds())
    buckets = [{"t": edges[i].isoformat(), "benign": benign[i], "malicious": malicious[i], "packets": packets[i],
                "capture_on": covered[i] >= 0.2 * bucket_s or bool(benign[i] or malicious[i])} for i in range(n)]
    if buckets and not buckets[-1]["capture_on"] and (now - edges[-1]).total_seconds() < bucket_s:
        buckets[-1]["capture_on"] = None              # current, still filling: unknown rather than off
    return {"minutes": int(minutes), "bucket_seconds": int(bucket_s), "start": start.isoformat(), "end": now.isoformat(),
            "buckets": buckets, "events": [{**e, "t": e["ended_at"]} for e in mal],
            "alerts": [{**a, "t": a["detected_at"]} for a in alerts]}


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
