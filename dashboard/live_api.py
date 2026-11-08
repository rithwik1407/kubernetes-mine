"""Live-pipeline, traffic-lab, deception, Kubernetes and system endpoints.

Mounted by app.py. Conventions used by every route:
  * success                  2xx with the resource as JSON
  * bad input                400 / 422 (FastAPI validation) with {"detail": "..."}
  * unknown resource         404
  * conflicting state        409 (e.g. capture already running, decoy already active)
  * dependency unavailable   503 (cluster unreachable, tcpdump / CICFlowMeter missing)
Failures are never reported as 200. Read endpoints that only touch the local
SQLite store always work, even with no cluster.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from live import queries  # noqa: E402
from live.config import load_config  # noqa: E402
from live.logging_setup import get_logger  # noqa: E402

CFG = load_config()
router = APIRouter()
log = get_logger("api.live")
_STATE: dict[str, Any] = {}
_lock = threading.Lock()


def controller():
    """Lazily create and start the MAPE-K controller (no cluster needed to construct it)."""
    with _lock:
        if "controller" not in _STATE:
            from live.controller import MapeKController
            ctl = MapeKController(CFG)
            ctl.start()
            _STATE["controller"] = ctl
        return _STATE["controller"]


def predictor():
    with _lock:
        if "predictor" not in _STATE:
            from live.predictor import FlowPredictor
            _STATE["predictor"] = FlowPredictor.from_config(CFG)
        return _STATE["predictor"]


# --- schemas --------------------------------------------------------------------------
class CaptureStart(BaseModel):
    windows: int | None = Field(None, ge=1, le=10000)
    process: bool = True


class LaunchRequest(BaseModel):
    scenario: str = Field(..., max_length=64)
    target: str | None = Field(None, max_length=256, description="target key (nodered/grafana/influxdb) or decoy name")
    count: int | None = Field(None, ge=1, le=5000, description="requests/attempts; default per scenario")
    delay: float | None = Field(None, ge=0.0, le=10.0, description="seconds between requests; default per scenario")


class RunRequest(BaseModel):
    """One scenario (`scenario`/`target`) or several at once (`scenarios` x `targets`)."""
    scenario: str | None = Field(None, max_length=64)
    target: str | None = Field(None, max_length=256)
    scenarios: list[str] | None = Field(None, max_length=10)
    targets: list[str] | None = Field(None, max_length=10)
    count: int | None = Field(None, ge=1, le=5000)
    delay: float | None = Field(None, ge=0.0, le=10.0)
    minutes: float | None = Field(None, ge=0.5, le=60, description="run each Job for this many minutes (time-based run)")
    params: dict[str, str | int | float | None] | None = Field(
        None, description="generator parameters (see /api/trafficlab/scenarios -> params); validated server side")
    auto_capture: bool = True
    auto_stop: bool = True


class TestEvent(BaseModel):
    attack_class: str = Field(..., max_length=64)
    confidence: float = Field(0.95, ge=0, le=1)
    src_ip: str | None = Field(None, max_length=64)
    count: int = Field(1, ge=1, le=100)
    note: str = Field("", max_length=200)


class DecoyRequest(BaseModel):
    profile: str = Field(..., max_length=64)


class BaselineRequest(BaseModel):
    running: bool


class PredictRequest(BaseModel):
    records: list[dict[str, Any]] = Field(..., min_length=1, max_length=5000,
                                          description="CICFlowMeter rows (column name -> value)")


def _unavailable(e: Exception, what: str) -> HTTPException:
    log.warning("%s unavailable: %s", what, e)
    return HTTPException(503, f"{what}: {e}")


# --- live detections ------------------------------------------------------------------
@router.get("/api/live/metrics")
def live_metrics():
    out = queries.metrics(CFG)
    from live import capture as cap
    st = cap.read_state(CFG)
    out["capture_running"] = bool(st.get("running"))
    out["current_window_s"] = st.get("current_window_s") if st.get("running") else None
    return out


@router.get("/api/live/detections")
def live_detections(limit: int = Query(200, ge=1, le=5000), offset: int = Query(0, ge=0),
                    source: Literal["upload", "pcap", "live"] | None = None,
                    predicted_class: str | None = Query(None, max_length=64),
                    src_ip: str | None = Query(None, max_length=64),
                    malicious: bool | None = None,
                    lab_scenario: str | None = Query(None, max_length=64, pattern=r"^[a-z_]+$")):
    """lab_scenario: a Traffic-lab scenario (port_scan, ...) or "any" for flows of any lab pod."""
    return _with_nodes(queries.detections(limit, offset, source, predicted_class, src_ip, malicious, CFG, lab_scenario))


@router.get("/api/live/stats")
def live_stats():
    return queries.detection_stats(CFG)


@router.get("/api/live/events")
def live_events(limit: int = Query(50, ge=1, le=500)):
    return queries.recent_events(limit, CFG)


@router.get("/api/live/timeline")
def live_timeline(minutes: int = Query(30, ge=1, le=1440)):
    return queries.traffic_timeline(minutes, CFG)


@router.get("/api/live/activity")
def live_activity(minutes: int = Query(15, ge=1, le=180), bucket: int = Query(30, ge=5, le=600)):
    """Overview chart: flows per fixed bucket, capture-off periods and malicious events."""
    return queries.activity(minutes, bucket, CFG)


@router.get("/api/live/bursts")
def live_bursts(limit: int = Query(200, ge=1, le=5000)):
    return _with_nodes(queries.behavior_alerts(limit, CFG))


def _with_nodes(rows: list[dict]) -> list[dict]:
    """Add src_node / dst_node (and the pod names) for lab pods, from the live pod map."""
    from live import podinfo
    pods = podinfo.get(CFG)
    for r in rows:
        for end in ("src", "dst"):
            hit = pods.get(str(r.get(f"{end}_ip")))
            r[f"{end}_node"] = hit["node"] if hit else None
            r[f"{end}_pod"] = f"{hit['namespace']}/{hit['pod']}" if hit else None
    return rows


@router.get("/api/live/flow-graph")
def live_flow_graph(seconds: int = Query(60, ge=5, le=3600), max_edges: int = Query(14, ge=1, le=40),
                    recent: int = Query(10, ge=2, le=120)):
    """Attacker/client -> target -> decoy graph of the last `seconds` (for the flow diagrams)."""
    engs = []
    try:
        engs = [e for e in controller().engagement_details(10)["engagements"] if e["state"] == "active"]
    except Exception:  # noqa: BLE001 - the graph still works without deception
        pass
    return queries.flow_graph(seconds, max_edges, CFG, engagements=engs, recent_seconds=recent)


@router.get("/api/live/threat-counter")
def live_threat_counter():
    """Malicious flows of the Traffic-lab run in progress (null when none) and the total per class."""
    return queries.threat_counter(CFG)


@router.get("/api/live/bursts/count")
def live_bursts_count():
    return {"open": queries.behavior_alert_count(CFG)}


@router.delete("/api/live/bursts/{alert_id}")
def live_burst_dismiss(alert_id: int):
    """Remove one alert from the Behaviour alerts table (soft delete; history is kept)."""
    res = queries.dismiss_behavior_alert(alert_id, CFG)
    if res is None:
        raise HTTPException(404, f"behaviour alert {alert_id} not found")
    log.info("behaviour alert %s dismissed (%s still open)", alert_id, res["remaining"])
    return res


@router.get("/api/live/sessions")
def live_sessions(limit: int = Query(50, ge=1, le=500)):
    return queries.sessions(limit, CFG)


@router.get("/api/live/flows")
def live_flows(session: str = Query("current", pattern=r"^(current|all|[0-9]{1,9})$"),
               page: int = Query(1, ge=1, le=1_000_000), page_size: int = Query(20, ge=5, le=200),
               predicted_class: str | None = Query(None, max_length=64),
               malicious: bool | None = None, src_ip: str | None = Query(None, max_length=64),
               lab_scenario: str | None = Query(None, max_length=64, pattern=r"^([a-z_]+|UNKNOWN)$")):
    """Live traffic for one capture session (default: the newest), paginated on the server."""
    try:
        return queries.flows_page(session, page, page_size, predicted_class, malicious, src_ip, lab_scenario, CFG)
    except LookupError as e:
        raise HTTPException(404, str(e))


@router.get("/api/live/captures")
def live_captures(limit: int = Query(100, ge=1, le=2000)):
    return queries.captures(limit, CFG)


@router.get("/api/live/capture/status")
def capture_status():
    from live import capture as cap
    from live.cicflowmeter import support as cfm_support
    from live.process_pcap import pending_pcaps
    return {"service": cap.read_state(CFG), "support": cap.support(CFG), "cicflowmeter": cfm_support(CFG),
            "recent": queries.captures(20, CFG), "pending": [p.name for p in pending_pcaps(CFG)]}


@router.post("/api/live/capture/start")
def capture_start(req: CaptureStart):
    from live import capture as cap
    sup = cap.support(CFG)
    if not sup["supported"]:
        raise HTTPException(503, f"capture unavailable: {sup['reason']}")
    try:
        return cap.start(req.windows, req.process, CFG)
    except cap.ServiceError as e:
        raise HTTPException(409 if "already running" in str(e) else 503, str(e))
    except cap.CaptureError as e:
        raise HTTPException(400, str(e))


@router.post("/api/live/capture/stop")
def capture_stop():
    from live import capture as cap
    from live import pipeline
    pipeline.cancel_auto_stop(CFG)          # manual Stop overrides a pending auto-stop
    try:
        return cap.stop(CFG)
    except OSError as e:
        raise HTTPException(409, f"could not stop capture: {e}")


@router.post("/api/live/process")
def live_process(limit: int = Query(20, ge=1, le=200)):
    """Convert + score PCAPs that have not been processed yet (e.g. captured with --no-process)."""
    from live.cicflowmeter import support as cfm_support
    from live.process_pcap import pending_pcaps, process_pcap
    sup = cfm_support(CFG)
    if not sup["supported"]:
        raise HTTPException(503, f"CICFlowMeter unavailable: {sup['reason']}")
    targets = pending_pcaps(CFG)[:limit]
    return {"processed": [process_pcap(p, predictor(), CFG) for p in targets]}


# --- adaptive window ------------------------------------------------------------------
@router.get("/api/window/status")
def window_status():
    from live import capture as cap
    from live.window import policy_description
    st = cap.read_state(CFG)
    last = (st.get("last_decision") or {}) if st.get("running") else {}
    return {"running": bool(st.get("running")), "current_window_s": st.get("current_window_s") if st.get("running") else None,
            "last_decision": last or None, "policy": policy_description(CFG["capture"]["window"]),
            "history": queries.window_transitions(30, True, CFG)}


@router.get("/api/window/history")
def window_history(limit: int = Query(200, ge=1, le=5000), changed_only: bool = False):
    return queries.window_transitions(limit, changed_only, CFG)


# --- model / inference ----------------------------------------------------------------
@router.post("/api/predict")
def predict(req: PredictRequest):
    """Score CICFlowMeter rows with the live model (nothing is stored)."""
    import pandas as pd
    from live.predictor import to_records
    from live.schema import SchemaError, normalize_column_name
    df = pd.DataFrame(req.records)
    df.columns = [normalize_column_name(c) for c in df.columns]
    p = predictor()
    try:
        out = p.predict_frame(df, source="upload")
    except SchemaError as e:
        raise HTTPException(422, f"unsupported feature schema: {e}")
    return {"model": p.name, "missing_features": p.last_report.get("missing_features", []),
            "predictions": to_records(out)}


def _reload_predictor() -> None:
    """A retrained model went live: the next scored window loads it."""
    with _lock:
        _STATE.pop("predictor", None)


def _register_retrain_hook() -> None:
    from live import retrain
    if _reload_predictor not in retrain._ON_DONE:
        retrain._ON_DONE.append(_reload_predictor)


_register_retrain_hook()


@router.get("/api/model/retrain-lab")
def model_retrain_status():
    from live import retrain
    return {**retrain.status(), "labelled_sessions": len(retrain.labelled_sessions(CFG))}


@router.post("/api/model/retrain-lab", status_code=202)
def model_retrain_start():
    """Retrain the live model on this lab's own labelled runs (background; the previous
    model is copied to <model_dir>/history/ first). New captures use the new model."""
    from live import retrain

    try:
        return retrain.start(CFG, on_done=_reload_predictor)
    except RuntimeError as e:
        raise HTTPException(409, str(e))


@router.get("/api/model/evaluate-sample")
def evaluate_sample():
    """Score bundled *labelled* held-out rows with the live model and compare to the labels.

    The rows are the ones that match the live model: its metrics.json names them in
    eval_sample (the lab model: flows from capture sessions it was never trained on);
    otherwise the CIC-IDS2017 test mix.

    This is the labelled check for benign vs malicious classification; it does not
    touch the database and every number comes from this run.
    """
    import numpy as np
    import pandas as pd
    import json
    p = predictor()
    mpath = p.model_dir / "metrics.json"
    rel = (json.loads(mpath.read_text()).get("eval_sample") if mpath.is_file() else None) or "dashboard/sample_cic2017_test_mix.csv"
    path = REPO_ROOT / rel
    if not path.is_file():
        raise HTTPException(404, f"{path.name} is missing")
    df = pd.read_csv(path)
    df = df[df["Label"].astype(str) != "Label"].reset_index(drop=True)
    out = p.predict_frame(df.drop(columns=["Label"]), source="upload")
    truth = df["Label"].astype(str).to_numpy()
    pred = out["predicted_class"].astype(str).to_numpy()
    classes = [str(c) for c in p.classes]
    cm = [[int(((truth == t) & (pred == q)).sum()) for q in classes] for t in classes]
    per = {}
    for c in classes:
        tp = int(((truth == c) & (pred == c)).sum())
        fp = int(((truth != c) & (pred == c)).sum())
        fn = int(((truth == c) & (pred != c)).sum())
        prec = tp / (tp + fp) if tp + fp else None
        rec = tp / (tp + fn) if tp + fn else None
        per[c] = {"support": int((truth == c).sum()), "precision": prec, "recall": rec,
                  "f1": (2 * prec * rec / (prec + rec)) if prec and rec else 0.0}
    benign = p.benign_class
    att_t, att_p = truth != benign, pred != benign
    return {"model": p.name, "sample": path.name, "rows": int(len(df)), "accuracy": float((truth == pred).mean()), "classes": classes,
            "confusion_matrix": cm, "per_class": per,
            "binary": {"attack_detection_rate": float(att_p[att_t].mean()) if att_t.any() else None,
                       "false_alarm_rate": float(att_p[~att_t].mean()) if (~att_t).any() else None},
            "mean_confidence": float(np.mean(out["confidence"]))}


# --- traffic lab ----------------------------------------------------------------------
@router.get("/api/trafficlab/scenarios")
def trafficlab_scenarios():
    from live.trafficlab import GEN_PARAMS, scenarios, targets
    params = {k: {kk: (vv.__name__ if kk == "type" else vv) for kk, vv in v.items() if kk != "env"}
              for k, v in GEN_PARAMS.items()}
    return {"scenarios": scenarios(CFG), "targets": targets(CFG), "params": params}


@router.get("/api/trafficlab/detection-matrix")
def trafficlab_detection_matrix(all_models: bool = False):
    """Detection rate per scenario x target, measured from this lab's own runs (by default
    only flows scored by the live model; all_models=true mixes in earlier models too)."""
    return queries.detection_matrix(CFG, model=None if all_models else "live")


@router.post("/api/trafficlab/launch", status_code=201)
def trafficlab_launch(req: LaunchRequest):
    from live.trafficlab import TrafficLabError, launch
    if req.scenario not in CFG["traffic_lab"]["scenarios"]:
        raise HTTPException(400, f"unknown scenario {req.scenario!r}")
    try:
        return launch(req.scenario, req.target, req.count, req.delay, CFG)
    except TrafficLabError as e:
        msg = str(e)
        raise HTTPException(400 if msg.startswith(("target must", "unknown decoy", "no decoy")) else 503, msg)


@router.get("/api/trafficlab/jobs")
def trafficlab_jobs():
    from live.trafficlab import TrafficLabError, list_jobs
    try:
        return list_jobs(CFG)
    except TrafficLabError as e:
        raise _unavailable(e, "Kubernetes")


@router.get("/api/trafficlab/jobs/{name}")
def trafficlab_job(name: str):
    from live.trafficlab import TrafficLabError, job_detail
    try:
        return job_detail(name, CFG)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except KeyError:
        raise HTTPException(404, f"job {name} not found")
    except TrafficLabError as e:
        raise _unavailable(e, "Kubernetes")


@router.delete("/api/trafficlab/jobs/{name}")
def trafficlab_delete(name: str):
    from live.trafficlab import TrafficLabError, delete_job
    try:
        return delete_job(name, CFG)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except KeyError:
        raise HTTPException(404, f"job {name} not found")
    except TrafficLabError as e:
        raise _unavailable(e, "Kubernetes")


@router.get("/api/trafficlab/baseline")
def trafficlab_baseline():
    from live.trafficlab import baseline_status
    return baseline_status(CFG)


@router.put("/api/trafficlab/baseline")
def trafficlab_baseline_set(req: BaselineRequest):
    from live.trafficlab import TrafficLabError, set_baseline
    try:
        return set_baseline(req.running, CFG)
    except TrafficLabError as e:
        raise _unavailable(e, "Kubernetes")


@router.get("/api/targets")
def targets():
    """Are the Node-RED / Grafana / InfluxDB pods running?"""
    from live.k8s_status import targets_status
    return targets_status(CFG)


@router.get("/api/pipeline/preflight")
def pipeline_preflight():
    from live import pipeline
    return pipeline.preflight(CFG)


GEN_PARAM_NAMES = ("concurrency", "duration_s", "target_port", "port_start", "port_end", "scan_timeout",
                   "slow_conns", "slow_hold_s", "login_path", "payload_set")


@router.post("/api/pipeline/run", status_code=201)
def pipeline_run(req: RunRequest):
    """Generate traffic and make sure it is captured and processed automatically."""
    from live import pipeline
    from live.trafficlab import TrafficLabError
    scen = list(req.scenarios or ([req.scenario] if req.scenario else []))
    if not scen:
        raise HTTPException(422, "give `scenario` or a non-empty `scenarios` list")
    bad = [x for x in scen if x not in CFG["traffic_lab"]["scenarios"]]
    if bad:
        raise HTTPException(400, f"unknown scenario {bad[0]!r}")
    tg = list(req.targets or ([req.target] if req.target else []))
    if len(scen) * max(1, len(tg)) > 20:
        raise HTTPException(400, "at most 20 Jobs per run")
    try:
        params = dict(req.params or {})
        if req.minutes is not None:
            params["minutes"] = req.minutes
        return pipeline.run_scenarios(scen, tg or None, req.count, req.delay, req.auto_capture, req.auto_stop, CFG,
                                      params=params or None)
    except TrafficLabError as e:
        msg = str(e)
        bad_param = msg.startswith(("unknown generator parameter", "port_start must")) or \
            any(msg.startswith(k + " ") for k in GEN_PARAM_NAMES)
        raise HTTPException(400 if bad_param or msg.startswith(("target must", "unknown decoy", "no decoy")) else 503, msg)


@router.get("/api/pipeline/status")
def pipeline_status(run_id: str | None = Query(None, max_length=128)):
    from live import pipeline
    return pipeline.run_status(run_id, CFG)


# --- deception ------------------------------------------------------------------------
@router.get("/api/deception/status")
def deception_status():
    return controller().status()


@router.get("/api/deception/policy")
def deception_policy():
    return queries.policy(CFG)


class PolicyUpdate(BaseModel):
    classes: dict[str, dict[str, float]] | None = None
    hysteresis: dict[str, float] | None = None
    engage_severity: Literal["high", "medium", "custom"] | None = None
    reset: bool = False


@router.get("/api/deception/detection-policy")
def deception_detection_policy():
    """Per-class trigger thresholds + hysteresis actually in force (config + saved overrides)."""
    return controller().detection_policy()


@router.put("/api/deception/detection-policy")
def deception_detection_policy_set(req: PolicyUpdate):
    if not req.reset and not req.classes and not req.hysteresis and not req.engage_severity:
        raise HTTPException(422, "nothing to update: give classes, hysteresis, engage_severity or reset")
    try:
        return controller().set_detection_policy(req.classes, req.hysteresis, req.reset, req.engage_severity)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/api/deception/engagements")
def deception_engagements(limit: int = Query(100, ge=1, le=1000)):
    """Engaged sources: trigger, redirect state, linked decoys, release."""
    return controller().engagements(limit)


@router.get("/api/deception/not-engaged")
def deception_not_engaged(minutes: int = Query(60, ge=1, le=1440)):
    """Detected sources without a decoy, and the controller's reason for each."""
    from live import podinfo
    rows = queries.not_engaged(minutes, CFG)
    pods = podinfo.get(CFG)
    for r in rows:
        hit = pods.get(str(r["src_ip"]))
        r["src_pod"] = f"{hit['namespace']}/{hit['pod']}" if hit else None
    return rows


@router.get("/api/deception/live")
def deception_live(limit: int = Query(20, ge=1, le=200)):
    """What deception is doing right now: decoy pods (name, namespace, node, pod IP, phase,
    creation time) and per engagement the path attacker pod -> target pod -> decoy pod,
    with the flows/packets captured between the attacker and the decoy pods."""
    return controller().engagement_details(limit)


@router.get("/api/deception/recent-pods")
def deception_recent_pods(minutes: int = Query(60, ge=5, le=1440)):
    """Every attacker and decoy pod of the last `minutes`, including the ones already gone,
    in a stable order (first seen, newest on top)."""
    d = controller().engagement_details(200)
    return {"minutes": minutes, "pods": queries.recent_pods(d["engagements"], minutes, CFG, d["decoy_pods"]),
            "categories": [{"key": k, "label": lbl, "why": why} for k, lbl, why in queries.NOT_ENGAGED_REASONS]}


@router.get("/api/deception/engagements/{eid}/replay")
def deception_replay(eid: int, frames: int = Query(24, ge=4, le=60)):
    """The full traffic of one engagement in time steps (attacker -> target, then -> decoy),
    with the engaged / decoy ready / redirected / released moments, for the "View flow" replay."""
    engs = controller().engagement_details(200)["engagements"]
    eng = next((e for e in engs if e["id"] == eid), None)
    if eng is None:
        raise HTTPException(404, f"engagement {eid} not found (only the latest 200 are kept for replay)")
    return queries.engagement_replay(eng, CFG, frames)


@router.get("/api/live/allowlist")
def live_allowlist():
    from live import allowlist
    return allowlist.get(CFG).describe()


@router.get("/api/deception/decisions")
def deception_decisions(limit: int = Query(200, ge=1, le=5000)):
    return queries.decisions(limit, CFG)


@router.get("/api/deception/decoys")
def deception_decoys(limit: int = Query(200, ge=1, le=5000)):
    return queries.decoys(limit, CFG)


@router.get("/api/deception/interactions")
def deception_interactions(limit: int = Query(200, ge=1, le=5000), decoy: str | None = Query(None, max_length=64)):
    return queries.interactions(limit, decoy, CFG)


@router.get("/api/deception/test-events")
def deception_test_events(limit: int = Query(100, ge=1, le=1000)):
    return queries.simulated_events(limit, CFG)


@router.post("/api/deception/enable")
def deception_enable():
    controller().set_enabled(True)
    return controller().status()


@router.post("/api/deception/disable")
def deception_disable():
    controller().set_enabled(False)
    return controller().status()


@router.post("/api/deception/cycle")
def deception_cycle():
    return controller().run_cycle()


@router.post("/api/deception/test-event", status_code=201)
def deception_test_event(ev: TestEvent):
    try:
        eid = controller().submit_simulated_event(ev.attack_class, ev.confidence, ev.src_ip, ev.count, ev.note)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"simulated_event_id": eid, "simulated": True}


@router.post("/api/deception/decoys", status_code=201)
def deception_deploy(req: DecoyRequest):
    from live.k8s_decoys import DecoyError
    if req.profile not in CFG["deception"]["profiles"]:
        raise HTTPException(400, f"unknown profile {req.profile!r}")
    try:
        res = controller().manual_deploy(req.profile)
    except DecoyError as e:
        raise HTTPException(409 if "already" in str(e) else 400, str(e))
    if res["result"] != "ok":
        raise HTTPException(503, res.get("error") or "deployment failed")
    return res


@router.delete("/api/deception/decoys/{name}")
def deception_remove(name: str):
    from live.k8s_decoys import DecoyError
    try:
        res = controller().manual_remove(name)
    except DecoyError as e:
        raise HTTPException(400, str(e))
    if res["result"] == "not_found":
        raise HTTPException(404, f"{name} is not an active decoy")
    if res["result"] != "ok":
        raise HTTPException(503, f"could not remove {name}: {res.get('error') or 'Kubernetes unavailable'}")
    return res


# --- kubernetes -----------------------------------------------------------------------
@router.get("/api/kubernetes/status")
def kubernetes_status():
    from live.k8s_status import cluster_status
    return cluster_status(CFG)


@router.get("/api/targets/access")
def targets_access(minutes: int = Query(15, ge=1, le=240)):
    """Target apps on this machine: pod state, local URL (port-forward), whether the URL
    answers, and how much traffic reached each pod (captured flows, generator requests)."""
    from live import targetaccess
    from live.k8s_status import targets_status
    tg = targets_status(CFG)
    acc = targetaccess.status(CFG)
    traffic = queries.target_traffic(tg["apps"], minutes, CFG)
    by = {a["key"]: a for a in acc["apps"]}
    apps = [{**a, **by.get(a["key"], {}), "traffic": traffic.get(a["key"])} for a in tg["apps"]]
    return {"connected": tg["connected"], "error": tg.get("error"), "apps": apps, "minutes": minutes,
            "port_forward": acc["port_forward"], "all_reachable": acc["all_reachable"],
            "start": _STATE.get("targets_start")}


def _start_targets() -> None:
    from datetime import datetime, timezone
    from live import targetaccess
    _STATE["targets_start"] = {"state": "running", "at": datetime.now(timezone.utc).isoformat()}
    try:
        res = targetaccess.start(CFG)
        _STATE["targets_start"] = {"state": "done", "at": datetime.now(timezone.utc).isoformat(), "steps": res["steps"],
                                   "urls": {a["key"]: a["url"] for a in res["apps"]}}
    except Exception as e:  # noqa: BLE001
        log.warning("starting target apps failed: %s", e)
        _STATE["targets_start"] = {"state": "failed", "at": datetime.now(timezone.utc).isoformat(), "error": str(e)[:300]}


@router.post("/api/targets/start", status_code=202)
def targets_start():
    """Deploy missing target apps, wait for Ready pods, start the localhost port-forwards
    (in the background; poll GET /api/targets/access)."""
    if (_STATE.get("targets_start") or {}).get("state") == "running":
        raise HTTPException(409, "the target apps are already being started")
    threading.Thread(target=_start_targets, name="targets-start", daemon=True).start()
    return {"state": "running"}


def _autostart_loop() -> None:
    """Bring the target apps up when the dashboard starts; if the cluster is not up yet
    (K3s still starting), try again every 30 s for 15 minutes. Also updates an old
    generator script in the cluster."""
    import time as _time
    for _ in range(30):
        _start_targets()
        if (_STATE.get("targets_start") or {}).get("state") == "done":
            try:
                from live.trafficlab import ensure_generator_current
                note = ensure_generator_current(CFG)
                if note:
                    log.info("%s", note)
            except Exception as e:  # noqa: BLE001
                log.warning("could not check the generator script: %s", e)
        if (_STATE.get("targets_start") or {}).get("state") == "done":
            return
        _time.sleep(30)


@router.on_event("startup")
def _autostart_targets() -> None:
    # the hook can be registered on both the router and the app: start the loop only once
    if _STATE.get("targets_autostart"):
        return
    _STATE["targets_autostart"] = True
    if (CFG.get("target_apps") or {}).get("start_on_launch"):
        threading.Thread(target=_autostart_loop, name="targets-autostart", daemon=True).start()


@router.on_event("shutdown")
def _stop_targets() -> None:
    from live import targetaccess
    targetaccess.stop_forwards()


# --- system ---------------------------------------------------------------------------
@router.get("/api/system/health")
def system_health():
    from live.system import health
    return health(CFG, predictor_factory=predictor, controller=controller)


@router.get("/api/system/resources")
def system_resources():
    from live.system import resources
    return resources(CFG)


@router.get("/api/system/logs")
def system_logs(limit: int = Query(300, ge=1, le=5000),
                level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] | None = None,
                component: str | None = Query(None, max_length=32), search: str | None = Query(None, max_length=200),
                source: Literal["backend", "capture"] | None = None):
    from live.system import read_logs
    return read_logs(limit, level, component, search, source)


@router.get("/api/system/requests")
def system_requests(limit: int = Query(200, ge=1, le=1000)):
    """Recent API requests with status codes and latency (recorded by app.py's middleware)."""
    from app import REQUEST_LOG  # noqa: PLC0415
    rows = list(REQUEST_LOG)[-limit:]
    rows.reverse()
    by_status: dict[str, int] = {}
    for r in REQUEST_LOG:
        k = f"{r['status'] // 100}xx"
        by_status[k] = by_status.get(k, 0) + 1
    return {"requests": rows, "by_status": by_status, "kept": len(REQUEST_LOG)}
