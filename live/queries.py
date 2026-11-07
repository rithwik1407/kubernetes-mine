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
            "flow_bursts": one("SELECT COUNT(*) FROM behavior_alerts WHERE dismissed_at IS NULL"),
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
            "WHERE action IN ('deploy','scale','remove','engage','redirect','release','decoy_ready','deploy_failed','suppress_limit','suppress_cooldown') "
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
    """Open behaviour alerts (dismissed ones stay in the database and in the event feed)."""
    return _q("SELECT * FROM behavior_alerts WHERE dismissed_at IS NULL ORDER BY id DESC LIMIT ?", (int(limit),), cfg)


def behavior_alert_count(cfg=None) -> int:
    with db.connect(db.db_path(cfg)) as c:
        return c.execute("SELECT COUNT(*) FROM behavior_alerts WHERE dismissed_at IS NULL").fetchone()[0]


def dismiss_behavior_alert(alert_id: int, cfg=None) -> dict[str, Any] | None:
    """Soft delete: the alert leaves the Behaviour alerts table but keeps its row, so the
    security-event history, deception decisions and run breakdowns that cite it are intact."""
    now = datetime.now(timezone.utc).isoformat()
    with db.connect(db.db_path(cfg)) as c:
        row = c.execute("SELECT id, dismissed_at FROM behavior_alerts WHERE id = ?", (int(alert_id),)).fetchone()
        if row is None:
            return None
        if row["dismissed_at"] is None:
            c.execute("UPDATE behavior_alerts SET dismissed_at = ? WHERE id = ?", (now, int(alert_id)))
        remaining = c.execute("SELECT COUNT(*) FROM behavior_alerts WHERE dismissed_at IS NULL").fetchone()[0]
    return {"id": int(alert_id), "dismissed_at": row["dismissed_at"] or now, "remaining": remaining}


def sessions(limit=50, cfg=None) -> list[dict[str, Any]]:
    """Capture sessions, newest first, with their flow counts."""
    with db.connect(db.db_path(cfg)) as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM capture_sessions ORDER BY id DESC LIMIT ?", (int(limit),))]
        counts = dict(c.execute("SELECT session_id, COUNT(*) FROM detections WHERE session_id IS NOT NULL "
                                "GROUP BY 1").fetchall())
    for r in rows:
        for k in ("scenarios", "jobs", "run_ids"):
            r[k] = json.loads(r[k] or "[]")
        r["flows"] = counts.get(r["id"], 0)
    return rows


def flows_page(session="current", page=1, page_size=20, predicted_class=None, malicious=None, src_ip=None,
               lab_scenario=None, cfg=None) -> dict[str, Any]:
    """Live traffic, one page at a time, for one capture session (default: the newest)."""
    with db.connect(db.db_path(cfg)) as c:
        if session == "current":
            sid = c.execute("SELECT MAX(id) FROM capture_sessions").fetchone()[0]
        elif session == "all":
            sid = None
        else:
            sid = int(session)
            if c.execute("SELECT 1 FROM capture_sessions WHERE id = ?", (sid,)).fetchone() is None:
                raise LookupError(f"capture session {sid} does not exist")
        where, params = ["simulated = 0"], []
        if session != "all":
            # "current" with no session yet -> nothing (never fall back to old flows)
            where.append("session_id = ?")
            params.append(sid if sid is not None else -1)
        if predicted_class:
            where.append("predicted_class = ?")
            params.append(predicted_class)
        if malicious is not None:
            where.append("is_malicious = ?")
            params.append(int(malicious))
        if src_ip:
            where.append("src_ip = ?")
            params.append(src_ip)
        if lab_scenario == "any":
            where.append("lab_scenario IS NOT NULL")
        elif lab_scenario == "UNKNOWN":
            where.append("lab_scenario IS NULL")
        elif lab_scenario:
            where.append("lab_scenario = ?")
            params.append(lab_scenario)
        w = " AND ".join(where)
        total = c.execute(f"SELECT COUNT(*) FROM detections WHERE {w}", params).fetchone()[0]
        pages = max(1, -(-total // page_size))
        page = min(max(1, int(page)), pages)
        rows = _records(db.query_df(c, f"SELECT * FROM detections WHERE {w} ORDER BY id DESC LIMIT ? OFFSET ?",
                                    (*params, int(page_size), (page - 1) * int(page_size))))
        sess = dict(c.execute("SELECT * FROM capture_sessions WHERE id = ?", (sid,)).fetchone() or {}) if sid else None
    if sess:
        for k in ("scenarios", "jobs", "run_ids"):
            sess[k] = json.loads(sess[k] or "[]")
    for r in rows:
        r["scenario"] = r.get("lab_scenario") or ("control-plane" if r.get("allowlisted") else "UNKNOWN")
    return {"session_id": sid, "session": sess, "total": total, "page": page, "pages": pages,
            "page_size": int(page_size), "rows": rows}


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


ACTIVE_RUN_STATES = ("waiting for Jobs", "draining")


def threat_counter(cfg=None) -> dict[str, Any]:
    """Sidebar counter. `run`: malicious flows of the Traffic-lab run in progress (None when
    no run is in progress, so the live number clears when a run finishes). `total`: every
    malicious flow so far, per class. Allowlisted and simulated flows never count."""
    cfg = cfg or load_config()
    with db.connect(db.db_path(cfg)) as c:
        row = c.execute("SELECT value FROM kv WHERE key = 'pipeline_runs'").fetchone()
        runs = json.loads(row[0]) if row else []
        run = runs[0] if runs else None
        active = False
        if run:
            st = (run.get("auto_stop") or {}).get("state")
            if st in ACTIVE_RUN_STATES:
                active = True
            elif st in (None, "off") and not run.get("finished_at"):
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(run["started_at"])).total_seconds()
                active = age < float(cfg["traffic_lab"].get("job_deadline_seconds", 300))
        live = None
        if active:
            where, params = "is_malicious = 1 AND simulated = 0 AND detected_at >= ?", [run["started_at"]]
            if run.get("session_id"):
                where += " AND session_id = ?"
                params.append(run["session_id"])
            by = {r[0]: r[1] for r in c.execute(
                f"SELECT predicted_class, COUNT(*) FROM detections WHERE {where} GROUP BY predicted_class", params)}
            live = {"run_id": run["id"], "scenario": run.get("scenario"), "session_id": run.get("session_id"),
                    "started_at": run["started_at"], "malicious": sum(by.values()), "by_class": by}
        tot = {r[0]: r[1] for r in c.execute(
            "SELECT predicted_class, COUNT(*) FROM detections WHERE is_malicious = 1 AND simulated = 0 GROUP BY predicted_class")}
    return {"run": live, "total": {"malicious": sum(tot.values()), "by_class": tot}}


def not_engaged(minutes: int = 15, cfg=None) -> list[dict[str, Any]]:
    """Sources with recent detections that are NOT engaged, with the controller's last reason
    (below the severity/flow threshold, cooldown, decoy limit, allowlisted, decoy pod ...)."""
    cfg = cfg or load_config()
    since = (datetime.now(timezone.utc) - timedelta(minutes=int(minutes))).isoformat()
    with db.connect(db.db_path(cfg)) as c:
        rows = [dict(r) for r in c.execute(
            "SELECT d.* FROM decisions d JOIN (SELECT src_ip, MAX(id) mid FROM decisions WHERE created_at >= ? "
            "AND src_ip IS NOT NULL AND trigger IN ('ml', 'behavior') GROUP BY src_ip) m ON d.id = m.mid "
            "WHERE d.src_ip NOT IN (SELECT src_ip FROM engagements WHERE state = 'active') ORDER BY d.id DESC",
            (since,))]
    keep = ("id", "created_at", "src_ip", "trigger", "attack_class", "assessment", "max_confidence",
            "evidence_count", "action", "result", "reason")
    return [{k: r.get(k) for k in keep} for r in rows if r.get("action") not in ("engage", "redirect")]


def detection_matrix(cfg=None, max_runs: int = 200) -> dict[str, Any]:
    """Per scenario x target: how many of the attack pod's flows the model put in the
    expected class (detection rate) and in any attack class, from this lab's own runs.
    Ground truth = the Traffic-lab Job's pod IP in its capture session; DNS is left out."""
    cfg = cfg or load_config()
    cells: dict[tuple[str, str], dict[str, Any]] = {}
    with db.connect(db.db_path(cfg)) as c:
        row = c.execute("SELECT value FROM kv WHERE key = 'pipeline_runs'").fetchone()
        runs = json.loads(row[0]) if row else []
        for run in runs[:max_runs]:
            sid = run.get("session_id")
            for j in run.get("jobs", []):
                ip, sc, exp = j.get("pod_ip"), j.get("scenario"), j.get("expect_class")
                if not (sid and ip and sc):
                    continue
                r = c.execute(
                    "SELECT COUNT(*) n, SUM(predicted_class = ?) hit, SUM(predicted_class != 'BENIGN') mal, "
                    "GROUP_CONCAT(DISTINCT model) models FROM detections WHERE session_id = ? AND lab_scenario = ? "
                    "AND (src_ip = ? OR dst_ip = ?) AND COALESCE(src_port, 0) != 53 AND COALESCE(dst_port, 0) != 53",
                    (exp or "BENIGN", sid, sc, ip, ip)).fetchone()
                if not r["n"]:
                    continue
                tgt = (j.get("target_label") or j.get("target") or "?").split(".")[0].split(":")[0]
                cell = cells.setdefault((sc, tgt), {"scenario": sc, "target": tgt, "expect_class": exp, "runs": 0,
                                                     "flows": 0, "detected": 0, "malicious": 0, "models": set(),
                                                     "last_run": None, "last_rate": None})
                cell["runs"] += 1
                cell["flows"] += r["n"]
                cell["detected"] += r["hit"] or 0
                cell["malicious"] += r["mal"] or 0
                cell["models"] |= set((r["models"] or "").split(",")) - {""}
                if cell["last_run"] is None:              # runs are newest first
                    cell["last_run"], cell["last_rate"] = run["started_at"], (r["hit"] or 0) / r["n"]
    out = []
    for cell in cells.values():
        n = cell["flows"]
        out.append({**cell, "models": sorted(cell["models"]),
                    "detection_rate": cell["detected"] / n if n else None,
                    "attack_rate": cell["malicious"] / n if n else None})
    out.sort(key=lambda x: (x["scenario"], x["target"]))
    return {"cells": out, "model_in_use": cfg["paths"]["model_dir"].rstrip("/").split("/")[-1]}


def _severity(conf: float | None, malicious: bool, th: dict[str, Any]) -> str:
    if not malicious:
        return "benign"
    if conf is not None and conf >= float(th.get("high_confidence", 0.9)):
        return "high"
    if conf is not None and conf >= float(th.get("medium_confidence", 0.6)):
        return "medium"
    return "low"


def flow_graph(seconds: int = 60, max_edges: int = 14, cfg=None, pods: dict | None = None,
               engagements: list[dict] | None = None) -> dict[str, Any]:
    """Who talked to whom in the last `seconds`: nodes (pod, namespace, node, role) and
    edges (flows, packets, malicious flows, class, severity), for the flow diagrams.
    Roles: attacker (source of malicious flows), client, target, decoy. Control-plane
    (allowlisted) and DNS flows are left out; edges always point attacker/client ->
    target -> decoy."""
    cfg = cfg or load_config()
    th = cfg["deception"].get("thresholds", {})
    since = (datetime.now(timezone.utc) - timedelta(seconds=int(seconds))).isoformat()
    with db.connect(db.db_path(cfg)) as c:
        rows = [dict(r) for r in c.execute(
            "SELECT src_ip, dst_ip, COUNT(*) flows, COALESCE(SUM(packets), 0) packets, SUM(is_malicious) mal, "
            "MAX(CASE WHEN is_malicious = 1 THEN confidence END) conf, MAX(detected_at) last, "
            "(SELECT predicted_class FROM detections d2 WHERE d2.src_ip = d.src_ip AND d2.dst_ip = d.dst_ip "
            " AND d2.is_malicious = 1 AND d2.detected_at >= ? GROUP BY predicted_class ORDER BY COUNT(*) DESC LIMIT 1) cls "
            "FROM detections d WHERE detected_at >= ? AND simulated = 0 AND allowlisted IS NULL "
            "AND COALESCE(src_port, 0) != 53 AND COALESCE(dst_port, 0) != 53 AND src_ip IS NOT NULL AND dst_ip IS NOT NULL "
            "GROUP BY src_ip, dst_ip", (since, since))]
    if pods is None:
        from live import podinfo
        pods = podinfo.get(cfg)
    decoy_ns = cfg["deception"]["namespace"]
    # an "attacker" is a source with a real share of malicious flows (or an engaged one); a
    # client with a stray misclassified flow stays a client (its edge still shows the severity)
    per_src: dict[str, list[int]] = {}
    for r in rows:
        t = per_src.setdefault(r["src_ip"], [0, 0])
        t[0] += r["mal"] or 0
        t[1] += r["flows"]
    attackers = {ip for ip, (m, n) in per_src.items() if m >= 5 and m >= 0.2 * n}
    for e in engagements or []:
        if e.get("state") == "active":
            attackers.add(e["src_ip"])

    def role(ip: str) -> str:
        p = pods.get(ip)
        if p and p["namespace"] == decoy_ns:
            return "decoy"
        return "attacker" if ip in attackers else None

    rank = {"attacker": 0, "client": 0, "target": 1, "decoy": 2}
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        a, b = r["src_ip"], r["dst_ip"]
        ra, rb = role(a) or "client", role(b) or "target"
        if rank[ra] > rank[rb]:                     # a reply recorded backwards: point it forward
            a, b, ra, rb = b, a, rb, ra
        e = edges.setdefault((a, b), {"src": a, "dst": b, "flows": 0, "packets": 0, "malicious": 0, "conf": None,
                                      "class": None, "last": None})
        e["flows"] += r["flows"]
        e["packets"] += r["packets"]
        e["malicious"] += r["mal"] or 0
        if r["conf"] is not None and (e["conf"] is None or r["conf"] > e["conf"]):
            e["conf"], e["class"] = r["conf"], r["cls"]
        e["last"] = max(filter(None, [e["last"], r["last"]]))
    for e in engagements or []:                      # the redirect path, even before flows arrive
        rd = e.get("redirect") or {}
        if e.get("state") != "active" or not rd.get("applied"):
            continue
        for dip in e.get("decoy_pod_ips") or []:
            if (e["src_ip"], dip) not in edges and dip in pods:
                edges[(e["src_ip"], dip)] = {"src": e["src_ip"], "dst": dip, "flows": 0, "packets": 0, "malicious": 0,
                                             "conf": None, "class": None, "last": None, "redirect": True}
                break
    chosen = sorted(edges.values(), key=lambda e: (-(e["malicious"] > 0), -e["flows"]))[:max_edges]
    for e in chosen:
        e["severity"] = _severity(e["conf"], e["malicious"] > 0, th)
        e["redirect"] = e.get("redirect") or (pods.get(e["dst"], {}).get("namespace") == decoy_ns)
    ips = {x for e in chosen for x in (e["src"], e["dst"])}
    nodes = []
    for ip in sorted(ips):
        p = pods.get(ip)
        r = role(ip) or ("target" if any(e["dst"] == ip for e in chosen) else "client")
        sev = max((e["severity"] for e in chosen if ip in (e["src"], e["dst"])),
                  key=["benign", "low", "medium", "high"].index, default="benign")
        nodes.append({"id": ip, "ip": ip, "role": r, "severity": sev,
                      "label": p["pod"] if p else ip, "namespace": p["namespace"] if p else None,
                      "node": p["node"] if p else None,
                      "scenario": (p.get("labels") or {}).get("scenario") if p else None})
    return {"seconds": int(seconds), "since": since, "nodes": nodes, "edges": chosen,
            "truncated": max(0, len(edges) - len(chosen))}


def engagement_replay(eng: dict[str, Any], cfg=None, frames: int = 24, pods: dict | None = None) -> dict[str, Any]:
    """The whole traffic of one engaged attacker, in time steps, for the replay on the
    Deception page: attacker -> target before the redirect, attacker -> decoy after it.

    `eng` is one row of controller.engagement_details(). Flows are placed by their own
    start time (CICFlowMeter timestamp, UTC); the engagement, decoy-ready, redirect and
    release moments come from the controller. Each frame holds the cumulative edges up to
    its time, so the diagram grows as the attack did."""
    cfg = cfg or load_config()
    th = cfg["deception"].get("thresholds", {})
    src = eng["src_ip"]
    decoy_ips = set(eng.get("decoy_pod_ips") or [])
    t_eng = datetime.fromisoformat(eng["started_at"]).astimezone(timezone.utc).replace(tzinfo=None)
    t_end = (datetime.fromisoformat(eng["released_at"]).astimezone(timezone.utc).replace(tzinfo=None)
             if eng.get("released_at") else datetime.utcnow())
    lo = (t_eng - timedelta(seconds=600)).isoformat()
    with db.connect(db.db_path(cfg)) as c:
        rows = [dict(r) for r in c.execute(
            "SELECT timestamp ts, src_ip, dst_ip, packets, is_malicious mal, confidence conf, predicted_class cls "
            "FROM detections WHERE (src_ip = ? OR dst_ip = ?) AND timestamp >= ? AND timestamp <= ? AND simulated = 0 "
            "AND allowlisted IS NULL "
            "AND COALESCE(src_port, 0) != 53 AND COALESCE(dst_port, 0) != 53 ORDER BY timestamp",
            (src, src, lo, t_end.isoformat()))]
    # the attack itself: from the first malicious flow of this source in the 10 minutes before
    # the engagement (or 60 s before it), to its last flow
    first_mal = next((r["ts"] for r in rows if r["mal"]), None)
    start = min(datetime.fromisoformat(first_mal) if first_mal else t_eng, t_eng) - timedelta(seconds=5)
    start = max(start, t_eng - timedelta(seconds=600))
    rows = [r for r in rows if r["ts"] >= start.isoformat()]
    end = max([datetime.fromisoformat(rows[-1]["ts"]) if rows else t_eng, t_eng]) + timedelta(seconds=2)
    span = max(1.0, (end - start).total_seconds())
    if pods is None:
        from live import podinfo
        pods = podinfo.get(cfg)
    tgt = eng.get("target") or {}
    att = eng.get("attacker") or {}
    decoy_ns = cfg["deception"]["namespace"]

    def peer_role(ip: str) -> str:
        if ip in decoy_ips or (pods.get(ip) or {}).get("namespace") == decoy_ns:
            return "decoy"
        return "target"

    n = max(4, min(int(frames), 60))
    step = span / n
    edges: dict[str, dict[str, Any]] = {}
    out_frames = []
    k = 0
    for i in range(1, n + 1):
        t_i = (start + timedelta(seconds=step * i)).isoformat()
        while k < len(rows) and rows[k]["ts"] <= t_i:
            r = rows[k]
            k += 1
            peer = r["dst_ip"] if r["src_ip"] == src else r["src_ip"]
            e = edges.setdefault(peer, {"src": src, "dst": peer, "flows": 0, "packets": 0, "malicious": 0,
                                        "conf": None, "class": None, "redirect": peer_role(peer) == "decoy"})
            e["flows"] += 1
            e["packets"] += r["packets"] or 0
            if r["mal"]:
                e["malicious"] += 1
                if r["conf"] is not None and (e["conf"] is None or r["conf"] > e["conf"]):
                    e["conf"], e["class"] = r["conf"], r["cls"]
        snap = []
        for e in edges.values():
            snap.append({**e, "severity": _severity(e["conf"], e["malicious"] > 0, th)})
        out_frames.append({"t": t_i, "offset_s": round(step * i, 1), "edges": snap})

    def node(ip: str, role: str) -> dict[str, Any]:
        p = pods.get(ip) or {}
        info = att if role == "attacker" else tgt if ip == tgt.get("ip") else {}
        fallback = f"{rd.get('decoy')} pod" if role == "decoy" and rd.get("decoy") else ip
        return {"id": ip, "ip": ip, "role": role, "label": info.get("pod") or p.get("pod") or fallback,
                "namespace": info.get("namespace") or p.get("namespace"), "node": info.get("node") or p.get("node")}

    rd = eng.get("redirect") or {}
    nodes = [node(src, "attacker")] + [node(ip, peer_role(ip)) for ip in edges]

    def offset(ts: str | None) -> float | None:
        if not ts:
            return None
        t = datetime.fromisoformat(ts)
        t = t.astimezone(timezone.utc).replace(tzinfo=None) if t.tzinfo else t
        return round((t - start).total_seconds(), 1)

    ready = min((d.get("ready_at") for d in eng.get("decoy_rows") or [] if d.get("ready_at")), default=None)
    events = [e for e in (
        {"kind": "engaged", "label": "attacker engaged", "offset_s": offset(eng["started_at"])},
        {"kind": "decoy_ready", "label": "decoy ready" if (offset(ready) or 0) >= 0 else "decoy already running",
         "offset_s": max(0.0, offset(ready)) if ready else None},
        {"kind": "redirect", "label": "redirected to decoy", "offset_s": offset(rd.get("at")) if rd.get("applied") else None},
        {"kind": "released", "label": "released", "offset_s": offset(eng.get("released_at"))},
    ) if e["offset_s"] is not None]
    return {"id": eng["id"], "src_ip": src, "attack_class": eng.get("attack_class"), "state": eng.get("state"),
            "start": start.isoformat(), "end": end.isoformat(), "span_s": round(span, 1), "frames": out_frames,
            "nodes": nodes, "events": events, "flows": len(rows),
            "to_decoy": sum(e["flows"] for e in edges.values() if e["redirect"]),
            "to_target": sum(e["flows"] for e in edges.values() if not e["redirect"])}
