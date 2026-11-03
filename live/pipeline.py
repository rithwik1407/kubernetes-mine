"""End-to-end automation: pods check -> capture -> traffic Job -> scored windows -> detections.

`run_scenario` is what the dashboard's "Run" button calls. It makes sure capture is
running (starting it if this machine can), launches the traffic-lab Job, and records
the run. `run_status` then reports, for the latest run, how far the traffic has made
it through the pipeline: Job state, PCAP windows captured, windows scored, flows
scored, detections by class and flow bursts since the run started.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from live import capture as cap
from live import db
from live.config import load_config
from live.k8s_status import targets_status
from live.trafficlab import TrafficLabError, check_ready, launch, list_jobs

KV_KEY = "pipeline_runs"
KEEP = 20


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def preflight(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Everything that must be true for traffic -> detection to work, in one place."""
    cfg = cfg or load_config()
    tg = targets_status(cfg)
    lab = check_ready(cfg) if tg["connected"] else {"ready": False, "reason": tg.get("error", "cluster unreachable")}
    sup = cap.support(cfg)
    state = cap.read_state(cfg)
    steps = [
        {"id": "cluster", "label": "Kubernetes reachable", "ok": tg["connected"],
         "detail": tg.get("identity") or tg.get("error")},
        {"id": "targets", "label": f"Target apps running ({tg['running']}/{tg['total']})", "ok": tg["all_running"],
         "detail": ", ".join(f"{a['key']}: {a['state']}" for a in tg["apps"])},
        {"id": "lab", "label": "Traffic lab deployed", "ok": bool(lab.get("ready")),
         "detail": lab.get("reason"), "fix": lab.get("fix")},
        {"id": "capture", "label": "Capture available on this machine", "ok": sup["supported"], "detail": sup["reason"]},
        {"id": "running", "label": "Capture running", "ok": bool(state.get("running")), "detail": state.get("status")},
    ]
    return {"steps": steps, "targets": tg, "capture_supported": sup["supported"],
            "capture_running": bool(state.get("running")),
            "can_generate": tg["connected"] and bool(lab.get("ready"))}


def _runs(conn) -> list[dict[str, Any]]:
    try:
        return json.loads(db.kv_get(conn, KV_KEY, "[]") or "[]")
    except ValueError:
        return []


def run_scenario(scenario: str, target: str | None = None, count: int = 300, delay: float = 0.1,
                 auto_capture: bool = True, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    started = _now()
    notes: list[str] = []
    capture_state = cap.read_state(cfg)
    capture_started = False
    if auto_capture and not capture_state.get("running"):
        try:
            capture_state = cap.start(None, True, cfg)
            capture_started = True
            notes.append("capture started automatically")
        except (cap.ServiceError, cap.CaptureError) as e:
            notes.append(f"capture not started: {e}")
    elif capture_state.get("running"):
        notes.append("capture already running")
    job = launch(scenario, target, count, delay, cfg)   # TrafficLabError propagates to the API
    run = {"id": job["job"], "scenario": scenario, "job": job["job"], "target": job["target"],
           "started_at": started, "capture_started": capture_started, "capture_running": bool(capture_state.get("running")),
           "notes": notes, "expect_class": cfg["traffic_lab"]["scenarios"][scenario].get("expect_class")}
    with db.connect(db.db_path(cfg)) as conn:
        runs = [run] + _runs(conn)
        db.kv_set(conn, KV_KEY, json.dumps(runs[:KEEP]))
    return run


def run_status(run_id: str | None = None, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    with db.connect(db.db_path(cfg)) as conn:
        runs = _runs(conn)
        if not runs:
            return {"run": None}
        run = next((r for r in runs if r["id"] == run_id), runs[0]) if run_id else runs[0]
        t0 = run["started_at"]
        caps = [dict(r) for r in conn.execute(
            "SELECT status, packets FROM captures WHERE started_at >= ? OR ended_at >= ?", (t0, t0))]
        det = [dict(r) for r in conn.execute(
            "SELECT predicted_class, COUNT(*) n, SUM(is_malicious) mal FROM detections WHERE detected_at >= ? "
            "GROUP BY predicted_class", (t0,))]
        bursts = conn.execute("SELECT COUNT(*) FROM behavior_alerts WHERE detected_at >= ?", (t0,)).fetchone()[0]
        decisions = conn.execute("SELECT COUNT(*) FROM decisions WHERE created_at >= ? AND action!='none'", (t0,)).fetchone()[0] \
            if _has(conn, "decisions") else 0
    jobs = {j.get("name"): j for j in list_jobs(cfg) if "name" in j}
    job = jobs.get(run["job"], {})
    scored = [c for c in caps if c["status"] in cap.DONE_STATUSES]
    flows = sum(d["n"] for d in det)
    svc = cap.read_state(cfg)
    stages = [
        {"id": "job", "label": "Traffic generated", "state": _job_stage(job.get("state")), "detail": job.get("state", "unknown")},
        {"id": "capture", "label": "Packets captured", "state": "done" if caps else ("active" if svc.get("running") else "idle"),
         "detail": f"{len(caps)} window(s), {sum(c['packets'] or 0 for c in caps):,} packets"},
        {"id": "score", "label": "Flows scored", "state": "done" if flows else ("active" if caps else "idle"),
         "detail": f"{len(scored)} window(s) processed, {flows:,} flows"},
        {"id": "detect", "label": "Detections", "state": "done" if (bursts or any(d["mal"] for d in det)) else ("active" if flows else "idle"),
         "detail": f"{sum(d['mal'] or 0 for d in det):,} malicious flows, {bursts} flow burst(s)"},
    ]
    return {"run": run, "job": job, "stages": stages, "capture_running": bool(svc.get("running")),
            "by_class": {d["predicted_class"]: d["n"] for d in det}, "bursts": bursts, "decisions": decisions,
            "hint": _hint(run, stages, svc)}


def _has(conn, table: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone())


def _job_stage(state: str | None) -> str:
    return {"succeeded": "done", "failed": "error", "running": "active", "pending": "active"}.get(state or "", "idle")


def _hint(run, stages, svc) -> str:
    if not svc.get("running") and not stages[1]["detail"].startswith(("1", "2", "3", "4", "5", "6", "7", "8", "9")):
        return "Capture is not running on this machine, so no packets are being recorded. Start it from a Linux/WSL dashboard."
    if stages[2]["state"] != "done":
        return "Waiting for the next capture window to close (5–30 s) and be scored."
    return "Pipeline complete for this run." if stages[3]["state"] == "done" else \
        "Flows scored. This scenario is benign-like or below the burst threshold, so no alert was raised."
