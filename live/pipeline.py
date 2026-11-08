"""End-to-end automation: pods check -> capture -> traffic Job -> scored windows -> detections.

`run_scenario` is what the dashboard's "Run" button calls. It makes sure capture is
running (starting it if this machine can), launches the traffic-lab Job, and records
the run. `run_status` then reports, for the latest run, how far the traffic has made
it through the pipeline: Job state, PCAP windows captured, windows scored, flows
scored, detections by class and flow bursts since the run started.
"""
from __future__ import annotations

import json
from collections import Counter
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from live import capture as cap
from live import db
from live.config import load_config
from live.k8s_status import targets_status
from live.cicflowmeter import support as cfm_support
from live.logging_setup import get_logger
from live.trafficlab import TrafficLabError, check_ready, job_detail, launch, list_jobs

log = get_logger(__name__)

KV_KEY = "pipeline_runs"
KEEP = 100                                # runs kept in the history (the detection matrix reads them; retraining also rebuilds older ones from scored flows)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def preflight(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Everything that must be true for traffic -> detection to work, in one place."""
    cfg = cfg or load_config()
    tg = targets_status(cfg)
    lab = check_ready(cfg) if tg["connected"] else {"ready": False, "reason": tg.get("error", "cluster unreachable")}
    sup = cap.support(cfg)
    cfm = cfm_support(cfg)
    state = cap.read_state(cfg)
    steps = [
        {"id": "cluster", "label": "Kubernetes reachable", "ok": tg["connected"],
         "detail": tg.get("identity") or tg.get("error")},
        {"id": "targets", "label": f"Target apps running ({tg['running']}/{tg['total']})", "ok": tg["all_running"],
         "detail": ", ".join(f"{a['key']}: {a['state']}" for a in tg["apps"])},
        {"id": "lab", "label": "Traffic lab deployed", "ok": bool(lab.get("ready")),
         "detail": lab.get("reason"), "fix": None if lab.get("ready") else lab.get("fix")},
        {"id": "generator", "label": "Generator script up to date in the cluster",
         "ok": lab.get("generator_current") is not False,
         "detail": lab.get("warning") or ("same as this checkout" if lab.get("generator_current") else "not checked"),
         "fix": lab.get("fix") if lab.get("generator_current") is False else None},
        {"id": "capture", "label": "Capture available on this machine", "ok": sup["supported"], "detail": sup["reason"]},
        {"id": "cicflowmeter", "label": "CICFlowMeter ready", "ok": cfm["supported"], "detail": cfm["reason"]},
        {"id": "running", "label": "Capture running", "ok": bool(state.get("running")), "detail": state.get("status")},
    ]
    return {"steps": steps, "targets": tg, "capture_supported": sup["supported"],
            "capture_running": bool(state.get("running")),
            "can_generate": tg["connected"] and bool(lab.get("ready")),
            "can_detect": sup["supported"] and cfm["supported"]}


def _runs(conn) -> list[dict[str, Any]]:
    try:
        runs = json.loads(db.kv_get(conn, KV_KEY, "[]") or "[]")
    except ValueError:
        return []
    for r in runs:                       # runs stored before multi-job support had one "job"
        if "jobs" not in r and r.get("job"):
            r["jobs"] = [{"job": r["job"], "scenario": r.get("scenario"), "target": r.get("target"),
                          "expect_class": r.get("expect_class")}]
    return runs


def _save_run(run: dict[str, Any], cfg: dict[str, Any]) -> None:
    with _RUN_LOCK, db.connect(db.db_path(cfg)) as conn:
        runs = [r for r in _runs(conn) if r["id"] != run["id"]]
        db.kv_set(conn, KV_KEY, json.dumps(([run] + runs)[:KEEP], default=str))


def _update_run(run_id: str, cfg: dict[str, Any], **fields) -> dict[str, Any] | None:
    with _RUN_LOCK, db.connect(db.db_path(cfg)) as conn:
        runs = _runs(conn)
        for r in runs:
            if r["id"] == run_id:
                for k, v in fields.items():
                    if isinstance(v, dict) and isinstance(r.get(k), dict):
                        r[k] = {**r[k], **v}
                    else:
                        r[k] = v
                db.kv_set(conn, KV_KEY, json.dumps(runs[:KEEP], default=str))
                return r
    return None


def run_scenarios(scenarios: list[str], targets: list[str] | None = None, count: int | None = None,
                  delay: float | None = None, auto_capture: bool = True, auto_stop: bool = True,
                  cfg: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Launch one bounded Job per (scenario, target) at the same time, each labelled with its
    expected class, and (by default) stop capture once they have all finished and been scored."""
    cfg = cfg or load_config()
    from live.trafficlab import GEN_PARAMS, check_params
    params = check_params(params)            # refuse bad parameters before capture starts
    started = _now()
    run_id = "run-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
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
    # the target apps must be up (and reachable on localhost) before traffic is aimed at them
    if cfg.get("target_apps") is not None:
        try:
            from live import targetaccess
            from live.k8s_status import targets_status
            tg = targets_status(cfg)
            if tg["connected"] and not tg["all_running"]:
                res = targetaccess.start(cfg, wait=True)
                notes.append("target apps started: " + "; ".join(res["steps"]))
            elif tg["connected"]:
                targetaccess.ensure_forwards(cfg)
        except Exception as e:  # noqa: BLE001
            notes.append(f"WARNING: could not bring the target apps up: {str(e)[:200]}")
    try:
        from live.trafficlab import ensure_generator_current
        note = ensure_generator_current(cfg)
        if note:
            notes.append(note)
    except Exception:  # noqa: BLE001
        pass
    pairs = []
    for sc in dict.fromkeys(scenarios):
        if cfg["traffic_lab"]["scenarios"][sc]["mode"] == "decoy_probe" or not targets:
            pairs.append((sc, None))
        else:
            pairs += [(sc, t) for t in dict.fromkeys(targets)]
    jobs, errors = [], []
    for sc, tgt in pairs:
        try:
            mode = cfg["traffic_lab"]["scenarios"][sc]["mode"]
            mine = {k: v for k, v in params.items()
                    if GEN_PARAMS[k]["modes"] is None or mode in GEN_PARAMS[k]["modes"]}
            j = launch(sc, tgt, count, delay, cfg, run_id=run_id, params=mine)
            jobs.append({"job": j["job"], "scenario": sc, "target": j["target"], "target_label": j.get("target_label", tgt),
                         "expect_class": j.get("expect_class", cfg["traffic_lab"]["scenarios"][sc].get("expect_class")),
                         "count": j.get("count"), "delay": j.get("delay"), "params": mine, "note": j.get("note")})
        except TrafficLabError as e:
            errors.append({"scenario": sc, "target": tgt, "error": str(e)})
    if not jobs:   # nothing launched: surface the first error to the API (400/503)
        if capture_started:      # and do not leave a capture running for a run that never started
            try:
                cap.stop(cfg)
            except Exception:  # noqa: BLE001
                log.warning("could not stop the capture started for a run that launched no Job")
        raise TrafficLabError(errors[0]["error"] if errors else "nothing to launch")
    first = jobs[0]
    run = {"id": run_id, "started_at": started, "jobs": jobs, "launch_errors": errors,
           "scenario": ", ".join(dict.fromkeys(j["scenario"] for j in jobs)),
           "target": ", ".join(dict.fromkeys(j["target_label"] or j["target"] for j in jobs)),
           "job": first["job"], "expect_class": first["expect_class"] if len(jobs) == 1 else "per job",
           "capture_started": capture_started, "capture_running": bool(capture_state.get("running")),
           "notes": notes, "auto_stop": {"enabled": bool(auto_stop), "state": "waiting for Jobs" if auto_stop else "off"},
           "session_id": capture_state.get("session_id") if capture_state.get("running") else None}
    if run["session_id"]:
        _tag_session(run["session_id"], run, cfg)
    _save_run(run, cfg)
    if auto_stop:
        start_watcher(run_id, cfg)
    return run


def _tag_session(session_id: int, run: dict[str, Any], cfg: dict[str, Any]) -> None:
    """Record which scenarios and Jobs ran during a capture session (shown in its selector)."""
    with db.connect(db.db_path(cfg)) as conn:
        row = conn.execute("SELECT scenarios, jobs, run_ids FROM capture_sessions WHERE id = ?", (session_id,)).fetchone()
        if row is None:
            return
        sc = json.loads(row["scenarios"] or "[]")
        jb = json.loads(row["jobs"] or "[]")
        rid = json.loads(row["run_ids"] or "[]")
        sc += [j["scenario"] for j in run["jobs"] if j["scenario"] not in sc]
        jb += [j["job"] for j in run["jobs"]]
        rid.append(run["id"])
        conn.execute("UPDATE capture_sessions SET scenarios = ?, jobs = ?, run_ids = ? WHERE id = ?",
                     (json.dumps(sc), json.dumps(jb), json.dumps(rid), session_id))


def run_scenario(scenario: str, target: str | None = None, count: int | None = None, delay: float | None = None,
                 auto_capture: bool = True, cfg: dict[str, Any] | None = None, auto_stop: bool = True) -> dict[str, Any]:
    return run_scenarios([scenario], [target] if target else None, count, delay, auto_capture, auto_stop, cfg)


# --- auto-stop ----------------------------------------------------------------------------
_WATCHERS: dict[str, threading.Thread] = {}
_RUN_LOCK = threading.RLock()
FINISHED = ("succeeded", "failed", "deleted")


def start_watcher(run_id: str, cfg: dict[str, Any]) -> None:
    t = _WATCHERS.get(run_id)
    if t and t.is_alive():
        return
    t = threading.Thread(target=_watch, args=(run_id, cfg), name=f"autostop-{run_id}", daemon=True)
    _WATCHERS[run_id] = t
    t.start()


def _job_states(run: dict[str, Any], cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    try:
        live = {j["name"]: j for j in list_jobs(cfg)}
    except TrafficLabError:
        return {}
    return {j["job"]: live.get(j["job"], {"state": "deleted"}) for j in run["jobs"]}


def _remember_pod_ips(run: dict[str, Any], cfg: dict[str, Any]) -> None:
    """Pod IPs are needed for the expected-vs-predicted breakdown and vanish when a Job is cleaned up."""
    changed = False
    for j in run["jobs"]:
        if j.get("pod_ip"):
            continue
        try:
            d = job_detail(j["job"], cfg, tail=1)
        except Exception:  # noqa: BLE001
            continue
        ip = next((p["ip"] for p in d["pods"] if p.get("ip")), None)
        if ip:
            j["pod_ip"] = ip
            changed = True
    if changed:
        _update_run(run["id"], cfg, jobs=run["jobs"])


def _keep_final_counts(run: dict[str, Any], cfg: dict[str, Any]) -> None:
    """Store each Job's answered / failed request counts in the run, so the per-target
    request counts survive the Job's cleanup (ttlSecondsAfterFinished)."""
    for j in run["jobs"]:
        try:
            v = job_detail(j["job"], cfg, tail=200000)["verification"]
        except Exception:  # noqa: BLE001
            v = (j.get("log_snapshot") or {}).get("verification")
        if v and v.get("lines"):
            j["answered"], j["failed"] = v.get("ok", 0), v.get("errors", 0)
    _update_run(run["id"], cfg, jobs=run["jobs"])


def _snapshot_logs(run: dict[str, Any], states: dict[str, dict[str, Any]], cfg: dict[str, Any]) -> None:
    """Keep a summary of each running generator's log in the run record. Kubernetes deletes
    the pod when a Job hits activeDeadlineSeconds, and with it the log, so without this a
    deadline failure could not say what the generator had done."""
    changed = False
    for j in run["jobs"]:
        if (states.get(j["job"]) or {}).get("state") not in ("running", "pending"):
            continue
        try:
            d = job_detail(j["job"], cfg, tail=5000)
        except Exception:  # noqa: BLE001
            continue
        if not d.get("verification", {}).get("lines"):
            continue
        j["log_snapshot"] = {"at": _now(), "verification": d["verification"],
                             "last_lines": (d.get("log_tail") or [])[-3:]}
        changed = True
    if changed:
        _update_run(run["id"], cfg, jobs=run["jobs"])


def _watch(run_id: str, cfg: dict[str, Any], poll_s: float = 3.0) -> None:
    """Wait for every Job of the run, drain the last window(s), then stop capture."""
    drain = float(cfg["traffic_lab"].get("auto_stop_drain_seconds", 15))
    max_window = max(cfg["capture"]["window"].get("sizes", [10]))
    last_snap = 0.0
    try:
        while True:
            with db.connect(db.db_path(cfg)) as conn:
                run = next((r for r in _runs(conn) if r["id"] == run_id), None)
            if run is None or not run.get("auto_stop", {}).get("enabled"):
                return
            _remember_pod_ips(run, cfg)
            states = _job_states(run, cfg)
            if time.monotonic() - last_snap >= 10:
                _snapshot_logs(run, states, cfg)
                last_snap = time.monotonic()
            if states and all(s.get("state") in FINISHED for s in states.values()):
                break
            time.sleep(poll_s)
        _keep_final_counts(run, cfg)
        finished_at = _now()
        _update_run(run_id, cfg, finished_at=finished_at,
                    auto_stop={"state": "draining", "detail": f"all Jobs finished; waiting {drain:g}s + last window"})
        time.sleep(drain + max_window)
        # wait (bounded) until every window that started before the drain ended has been scored
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            with db.connect(db.db_path(cfg)) as conn:
                pending = conn.execute("SELECT COUNT(*) FROM captures WHERE status = 'captured' AND started_at >= ?",
                                       (run["started_at"],)).fetchone()[0]
            if not pending:
                break
            time.sleep(2)
        if not cap.read_state(cfg).get("running"):
            _update_run(run_id, cfg, auto_stop={"state": "done", "detail": "capture was already stopped"})
            return
        with db.connect(db.db_path(cfg)) as conn:     # a newer run still generating traffic keeps capture on
            newer = [r for r in _runs(conn) if r["started_at"] > run["started_at"] and r.get("auto_stop", {}).get("state") not in ("stopped", "done", "skipped", "off")]
        if newer:
            _update_run(run_id, cfg, auto_stop={"state": "skipped", "detail": f"newer run {newer[0]['id']} is still active"})
            return
        cap.stop(cfg)
        log.info("auto-stop: capture stopped after run %s", run_id)
        _update_run(run_id, cfg, auto_stop={"state": "stopped", "at": _now(),
                                            "detail": f"capture stopped automatically {drain:g}s after the last Job finished"})
        _maybe_auto_retrain(run, cfg)
    except Exception as e:  # noqa: BLE001
        log.exception("auto-stop watcher for %s failed", run_id)
        _update_run(run_id, cfg, auto_stop={"state": "error", "detail": str(e)[:200]})


ATTACKS = {"port_scan", "brute_force", "web_attack", "slow_dos"}


def _maybe_auto_retrain(run: dict[str, Any], cfg: dict[str, Any]) -> None:
    """After every `retrain.auto_after_attack_jobs` new labelled attack Jobs, retrain on this
    machine's runs in the background. The new model only goes live if per-class recall
    improves on the same held-out flows (scripts/train_lab_model.py gate)."""
    n_after = int((cfg.get("retrain") or {}).get("auto_after_attack_jobs", 6) or 0)
    if n_after <= 0:
        return
    new = sum(1 for j in run.get("jobs", []) if j.get("scenario") in ATTACKS and j.get("pod_ip"))
    if not new:
        return
    with db.connect(db.db_path(cfg)) as conn:
        count = int(db.kv_get(conn, "retrain_new_attack_jobs", "0") or 0) + new
        db.kv_set(conn, "retrain_new_attack_jobs", str(count))
    if count < n_after:
        return
    from live import retrain
    try:
        retrain.start(cfg, reason=f"automatic: {count} new labelled attack Jobs since the last training")
        with db.connect(db.db_path(cfg)) as conn:
            db.kv_set(conn, "retrain_new_attack_jobs", "0")
        log.info("automatic retraining started after %d new attack Jobs", count)
    except Exception as e:  # noqa: BLE001 - already running, or no runs: try again after the next run
        log.info("automatic retraining not started: %s", e)


def cancel_auto_stop(cfg: dict[str, Any]) -> None:
    """Manual Stop overrides any pending auto-stop."""
    with db.connect(db.db_path(cfg)) as conn:
        runs = _runs(conn)
    for r in runs:
        if r.get("auto_stop", {}).get("state") in ("waiting for Jobs", "draining"):
            _update_run(r["id"], cfg, auto_stop={"enabled": False, "state": "done", "detail": "capture stopped manually"})


# --- status -------------------------------------------------------------------------------
def _breakdown(conn, job: dict[str, Any], since: str, until: str | None) -> dict[str, Any]:
    """Expected vs predicted for one Job: flows to/from its generator pod during the run."""
    ip = job.get("pod_ip")
    if not ip:
        return {"pod_ip": None, "flows": 0, "by_class": {}, "accuracy": None,
                "note": "generator pod IP unknown (pod not seen yet or already deleted)"}
    until = until or "9999"
    from live.trafficlab import benign_src_ports
    lo, hi = benign_src_ports()
    mixed = "(COALESCE(src_port, 0) BETWEEN ? AND ? OR COALESCE(dst_port, 0) BETWEEN ? AND ?)"
    dns = "(COALESCE(src_port, 0) = 53 OR COALESCE(dst_port, 0) = 53)"
    # the attack's own flows: DNS lookups (the generator resolves the service name before
    # each connection, so there are about as many as attack flows) and the benign requests
    # mixed into the run are counted apart, not as missed detections
    rows = conn.execute(
        "SELECT predicted_class, COUNT(*) n, SUM(is_malicious) mal, AVG(confidence) conf, "
        "SUM(CASE WHEN allowlisted IS NOT NULL THEN 1 ELSE 0 END) allow FROM detections "
        "WHERE simulated = 0 AND (src_ip = ? OR dst_ip = ?) AND detected_at >= ? AND detected_at <= ? "
        f"AND NOT {mixed} AND NOT {dns} GROUP BY predicted_class", (ip, ip, since, until, lo, hi, lo, hi)).fetchall()
    dns_n = conn.execute(
        "SELECT COUNT(*) FROM detections WHERE simulated = 0 AND (src_ip = ? OR dst_ip = ?) AND detected_at >= ? "
        f"AND detected_at <= ? AND {dns}", (ip, ip, since, until)).fetchone()[0]
    # the benign requests mixed into the attack: they should be scored BENIGN and keep going
    # to the real target (never to the decoy)
    bm = conn.execute(
        "SELECT predicted_class, dst_ip, COUNT(*) n FROM detections WHERE simulated = 0 AND src_ip = ? "
        f"AND detected_at >= ? AND detected_at <= ? AND {mixed} GROUP BY 1, 2",
        (ip, since, until, lo, hi, lo, hi)).fetchall()
    by = {r["predicted_class"]: r["n"] for r in rows}
    total = sum(by.values())
    exp = job.get("expect_class")
    alerts = conn.execute("SELECT alert_type, COUNT(*) FROM behavior_alerts WHERE src_ip = ? AND detected_at >= ? "
                          "AND detected_at <= ? GROUP BY 1", (ip, since, until)).fetchall()
    return {"pod_ip": ip, "flows": total, "by_class": by, "expected": exp,
            "matched": by.get(exp, 0) if exp else None,
            "accuracy": round(by.get(exp, 0) / total, 4) if exp and total else None,
            "mean_confidence": {r["predicted_class"]: round(r["conf"], 3) for r in rows},
            "behaviour_alerts": {a: n for a, n in alerts}, "dns_flows": int(dns_n),
            "benign_mix": {"flows": sum(r["n"] for r in bm),
                           "by_class": dict(Counter(r["predicted_class"] for r in bm for _ in range(r["n"]))),
                           "by_dst": dict(Counter(r["dst_ip"] for r in bm for _ in range(r["n"])))} if bm else None}


def _outcome(pj: dict[str, Any]) -> dict[str, Any]:
    """A Job counts as successful only when it ran, its generator got answers from the
    target AND the capture scored flows of its pod. Creating the Job proves nothing."""
    v = pj.get("verification") or {}
    flows = (pj.get("breakdown") or {}).get("flows") or 0
    base = {"started_at": v.get("first_ts"), "ended_at": v.get("last_ts") if v.get("finished") else None,
            "answered": v.get("ok", 0), "failed": v.get("errors", 0), "captured_flows": flows}
    st = pj.get("state")
    if pj.get("failure") and st == "failed":
        return {**base, "result": "failed", "detail": pj["failure"].get("summary")}
    if st in ("pending", "running") and not flows:
        return {**base, "result": st, "detail": "generator running" if st == "running" else "pod not started yet"}
    if not v.get("ok"):
        return {**base, "result": "no traffic", "detail": "the generator got no answer from the target"
                + (f" ({', '.join(f'{k} x{n}' for k, n in (v.get('error_types') or {}).items())})" if v.get("error_types") else "")}
    if not flows:
        return {**base, "result": "not captured",
                "detail": "traffic reached the target but no flow of this pod was scored (capture off, or still processing)"}
    return {**base, "result": "verified" if st == "succeeded" else st,
            "detail": f"{v.get('ok', 0):,} answered by the target, {flows:,} attack flows captured and scored"}


def run_status(run_id: str | None = None, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    with db.connect(db.db_path(cfg)) as conn:
        runs = _runs(conn)
    if not runs:
        return {"run": None}
    run = next((r for r in runs if r["id"] == run_id), runs[0]) if run_id else runs[0]
    if run.get("auto_stop", {}).get("state") in ("waiting for Jobs", "draining"):
        start_watcher(run["id"], cfg)       # resume after a backend restart
    t0 = run["started_at"]
    try:
        live = {j["name"]: j for j in list_jobs(cfg)}
        jobs_err = None
    except TrafficLabError as e:
        live, jobs_err = {}, str(e)
    per_job = []
    for j in run["jobs"]:
        lj = live.get(j["job"])
        state = lj["state"] if lj else ("unknown" if jobs_err else "deleted or expired")
        detail = None
        if lj:
            try:
                detail = job_detail(j["job"], cfg)
            except Exception as e:  # noqa: BLE001
                detail = {"verification": {"verified": False, "error": str(e)[:200]}, "failure": None, "pods": []}
            if not j.get("pod_ip"):
                j["pod_ip"] = next((p["ip"] for p in detail.get("pods", []) if p.get("ip")), None)
        snap = j.get("log_snapshot")
        if snap and not ((detail or {}).get("verification") or {}).get("lines"):
            # the pod (and its log) is gone: use the last summary taken while it ran
            detail = {**(detail or {}), "verification": {**snap["verification"], "from_snapshot": snap["at"]}}
            if (detail.get("failure") or {}).get("summary") or (lj and lj.get("failure")):
                f = dict(detail.get("failure") or {"summary": lj["failure"]})
                f["summary"] = f["summary"].replace("; no pod left to read (deleted with the Job's deadline)", "") \
                    + ". " + snapshot_diagnosis(snap)
                detail["failure"] = f
        per_job.append({**j, "state": state, "verification": (detail or {}).get("verification"),
                        "failure": (detail or {}).get("failure") or ({"summary": lj["failure"]} if lj and lj.get("failure") else None)})
    with db.connect(db.db_path(cfg)) as conn:
        caps = [dict(r) for r in conn.execute(
            "SELECT pcap_file, status, packets, error FROM captures WHERE started_at >= ? OR ended_at >= ?", (t0, t0))]
        det = [dict(r) for r in conn.execute(
            "SELECT predicted_class, COUNT(*) n, SUM(is_malicious) mal FROM detections WHERE detected_at >= ? "
            "AND simulated = 0 GROUP BY predicted_class", (t0,))]
        bursts = conn.execute("SELECT COUNT(*) FROM behavior_alerts WHERE detected_at >= ?", (t0,)).fetchone()[0]
        decisions = conn.execute("SELECT COUNT(*) FROM decisions WHERE created_at >= ? AND action!='none'", (t0,)).fetchone()[0] \
            if _has(conn, "decisions") else 0
        until = None
        if run.get("finished_at"):
            until = (datetime.fromisoformat(run["finished_at"]) + timedelta(seconds=60)).isoformat()
        for pj in per_job:
            pj["breakdown"] = _breakdown(conn, pj, t0, until)
            pj["outcome"] = _outcome(pj)
    scored = [c for c in caps if c["status"] in cap.DONE_STATUSES]
    failed = [c for c in caps if c["status"] == "failed"]
    flows = sum(d["n"] for d in det)
    svc = cap.read_state(cfg)
    vs = [pj["verification"] or {} for pj in per_job]
    ok = sum(v.get("ok", 0) for v in vs)
    errs = sum(v.get("errors", 0) for v in vs)
    states = [pj["state"] for pj in per_job]
    failures = [f"{pj['job']}: {pj['failure']['summary']}" for pj in per_job if pj.get("failure")]
    job_state = ("failed" if "failed" in states and all(s in FINISHED or s.startswith("deleted") for s in states)
                 else "running" if any(s in ("running", "pending") for s in states)
                 else "succeeded" if all(s == "succeeded" for s in states) else (states[0] if len(states) == 1 else "mixed"))
    verified = any(v.get("verified") for v in vs)
    stages = [
        {"id": "job", "label": "Traffic generated (verified from generator log)",
         "state": "error" if failures and not verified else _traffic_stage(job_state, {"verified": verified}),
         "detail": f"{len(per_job)} Job(s): " + ", ".join(f"{s} {states.count(s)}" for s in dict.fromkeys(states))
                   + f"; {ok:,} answered, {errs:,} failed" + (f". FAILED: {failures[0]}" if failures else "")},
        {"id": "capture", "label": "Packets captured", "state": "done" if caps else ("active" if svc.get("running") else "idle"),
         "detail": f"{len(caps)} window(s), {sum(c['packets'] or 0 for c in caps):,} packets"},
        {"id": "score", "label": "Flows scored",
         "state": "done" if flows else ("error" if failed and not scored else ("active" if caps else "idle")),
         "detail": f"{len(scored)} window(s) processed, {flows:,} flows"
                   + (f"; {len(failed)} window(s) FAILED: {failed[-1]['error']}" if failed else "")},
        {"id": "detect", "label": "Detections", "state": "done" if (bursts or any(d["mal"] for d in det)) else ("active" if flows else "idle"),
         "detail": f"{sum(d['mal'] or 0 for d in det):,} malicious flows, {bursts} flow burst(s)"},
    ]
    job0 = per_job[0] if per_job else {}
    return {"run": run, "jobs": per_job, "job": {"name": job0.get("job"), "state": job_state}, "stages": stages,
            "capture_running": bool(svc.get("running")), "failures": failures, "jobs_error": jobs_err,
            "by_class": {d["predicted_class"]: d["n"] for d in det}, "bursts": bursts, "decisions": decisions,
            "failed_windows": len(failed), "verification": job0.get("verification"),
            "auto_stop": run.get("auto_stop"), "hint": _hint(run, stages, svc)}


def snapshot_diagnosis(snap: dict[str, Any]) -> str:
    """One sentence on what the generator had done before its pod was deleted."""
    v = snap.get("verification") or {}
    acts = v.get("actions") or {}
    text = f"Last log summary ({snap.get('at', '')[11:19]} UTC): {v.get('ok', 0):,} answered, {v.get('errors', 0):,} failed"
    if acts.get("redirected"):
        text += ", redirected to a decoy"
    filt = acts.get("port_filtered", 0)
    if filt and filt >= 0.3 * max(1, sum(n for a, n in acts.items() if a.startswith("port_"))):
        text += (f"; {filt:,} ports timed out (filtered). Many timeouts after an engagement mean the pod was "
                 "quarantined but its generator did not follow the redirect: update the generator script")
    if v.get("error_types"):
        top = max(v["error_types"].items(), key=lambda kv: kv[1])
        text += f"; most common error: {top[0]} ({top[1]:,})"
    return text


def _has(conn, table: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone())


def _traffic_stage(state: str | None, v: dict | None) -> str:
    """'done' only when the generator log shows answered connections, never just because the Job exists."""
    if state == "failed":
        return "error"
    if v and v.get("verified"):
        return "done" if state == "succeeded" else "active"
    if state == "succeeded":
        return "error"          # finished without a single answered connection
    return _job_stage(state)


def _job_stage(state: str | None) -> str:
    return {"succeeded": "done", "failed": "error", "running": "active", "pending": "active"}.get(state or "", "idle")


def _hint(run, stages, svc) -> str:
    if stages[2]["state"] == "error":
        return "Captured windows could not be converted or scored; see the error above and the System page."
    if stages[0]["state"] == "error":
        return "The traffic Job failed; the reason is shown below and in the Job's Details."
    if not svc.get("running") and stages[1]["state"] != "done":
        return "Capture is not running on this machine, so no packets are being recorded. Start it from a Linux/WSL dashboard."
    if stages[2]["state"] != "done":
        return "Waiting for the next capture window to close and be scored (window length is adaptive, 1–10 s)."
    return "Pipeline complete for this run." if stages[3]["state"] == "done" else \
        "Flows scored. This scenario is benign-like or below the burst threshold, so no alert was raised."
