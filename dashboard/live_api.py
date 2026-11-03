"""Live-pipeline, traffic-lab and deception endpoints for the dashboard.

Mounted by app.py as an APIRouter under /api/live, /api/trafficlab, /api/deception
and /api/kubernetes. Everything degrades gracefully: if the SQLite store is empty
or the cluster is unreachable, the read endpoints return empty data and the action
endpoints return a clear error instead of crashing the CSV scorer.
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

from live import db, queries  # noqa: E402
from live.config import load_config  # noqa: E402

CFG = load_config()
router = APIRouter()
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
    scenario: str
    target: str | None = Field(None, max_length=256)
    count: int = Field(300, ge=1, le=5000)
    delay: float = Field(0.1, ge=0.0, le=10.0)


class RunRequest(LaunchRequest):
    auto_capture: bool = True


class TestEvent(BaseModel):
    attack_class: str
    confidence: float = Field(0.95, ge=0, le=1)
    src_ip: str | None = Field(None, max_length=64)
    count: int = Field(1, ge=1, le=100)
    note: str = Field("", max_length=200)


class DecoyRequest(BaseModel):
    profile: str


# --- live detections ------------------------------------------------------------------
@router.get("/api/live/metrics")
def live_metrics():
    return queries.metrics(CFG)


@router.get("/api/live/detections")
def live_detections(limit: int = Query(200, ge=1, le=5000), offset: int = Query(0, ge=0),
                    source: Literal["upload", "pcap", "live"] | None = None,
                    predicted_class: str | None = None, src_ip: str | None = None,
                    malicious: bool | None = None):
    return queries.detections(limit, offset, source, predicted_class, src_ip, malicious, CFG)


@router.get("/api/live/stats")
def live_stats():
    return queries.detection_stats(CFG)


@router.get("/api/live/bursts")
def live_bursts(limit: int = Query(200, ge=1, le=5000)):
    return queries.behavior_alerts(limit, CFG)


@router.get("/api/live/captures")
def live_captures(limit: int = Query(100, ge=1, le=2000)):
    return queries.captures(limit, CFG)


@router.get("/api/live/capture/status")
def capture_status():
    from live import capture as cap
    from live.process_pcap import pending_pcaps
    return {"service": cap.read_state(CFG), "support": cap.support(CFG), "recent": queries.captures(20, CFG),
            "pending": [p.name for p in pending_pcaps(CFG)]}


@router.post("/api/live/capture/start")
def capture_start(req: CaptureStart):
    from live import capture as cap
    try:
        return cap.start(req.windows, req.process, CFG)
    except cap.ServiceError as e:
        raise HTTPException(409, str(e))
    except cap.CaptureError as e:
        raise HTTPException(400, str(e))


@router.post("/api/live/capture/stop")
def capture_stop():
    from live import capture as cap
    try:
        return cap.stop(CFG)
    except OSError as e:
        raise HTTPException(409, f"could not stop capture: {e}")


@router.post("/api/live/process")
def live_process(limit: int = Query(20, ge=1, le=200)):
    from live.process_pcap import pending_pcaps, process_pcap
    targets = pending_pcaps(CFG)[:limit]
    return {"processed": [process_pcap(p, predictor(), CFG) for p in targets]}


# --- traffic lab ----------------------------------------------------------------------
@router.get("/api/trafficlab/scenarios")
def trafficlab_scenarios():
    from live.trafficlab import scenarios
    return scenarios(CFG)


@router.post("/api/trafficlab/launch")
def trafficlab_launch(req: LaunchRequest):
    from live.trafficlab import TrafficLabError, launch
    try:
        return launch(req.scenario, req.target, req.count, req.delay, CFG)
    except TrafficLabError as e:
        raise HTTPException(503, str(e))


@router.get("/api/targets")
def targets():
    """Are the Node-RED / Grafana / InfluxDB pods running?"""
    from live.k8s_status import targets_status
    return targets_status(CFG)


@router.get("/api/pipeline/preflight")
def pipeline_preflight():
    from live import pipeline
    return pipeline.preflight(CFG)


@router.post("/api/pipeline/run")
def pipeline_run(req: RunRequest):
    """Generate traffic and make sure it is captured and processed automatically."""
    from live import pipeline
    from live.trafficlab import TrafficLabError
    try:
        return pipeline.run_scenario(req.scenario, req.target, req.count, req.delay, req.auto_capture, CFG)
    except TrafficLabError as e:
        raise HTTPException(503, str(e))


@router.get("/api/pipeline/status")
def pipeline_status(run_id: str | None = None):
    from live import pipeline
    return pipeline.run_status(run_id, CFG)


@router.get("/api/trafficlab/jobs")
def trafficlab_jobs():
    from live.trafficlab import list_jobs
    return list_jobs(CFG)


@router.delete("/api/trafficlab/jobs/{name}")
def trafficlab_delete(name: str):
    from live.trafficlab import TrafficLabError, delete_job
    try:
        return delete_job(name, CFG)
    except TrafficLabError as e:
        raise HTTPException(503, str(e))


# --- deception ------------------------------------------------------------------------
@router.get("/api/deception/status")
def deception_status():
    return controller().status()


@router.get("/api/deception/policy")
def deception_policy():
    return queries.policy(CFG)


@router.get("/api/deception/decisions")
def deception_decisions(limit: int = Query(200, ge=1, le=5000)):
    return queries.decisions(limit, CFG)


@router.get("/api/deception/decoys")
def deception_decoys(limit: int = Query(200, ge=1, le=5000)):
    return queries.decoys(limit, CFG)


@router.get("/api/deception/interactions")
def deception_interactions(limit: int = Query(200, ge=1, le=5000), decoy: str | None = None):
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


@router.post("/api/deception/test-event")
def deception_test_event(ev: TestEvent):
    try:
        eid = controller().submit_simulated_event(ev.attack_class, ev.confidence, ev.src_ip, ev.count, ev.note)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"simulated_event_id": eid, "simulated": True}


@router.post("/api/deception/decoys")
def deception_deploy(req: DecoyRequest):
    from live.k8s_decoys import DecoyError
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
    if res["result"] != "ok":
        raise HTTPException(503, f"could not remove {name}: Kubernetes unavailable")
    return res


# --- kubernetes -----------------------------------------------------------------------
@router.get("/api/kubernetes/status")
def kubernetes_status():
    from live.k8s_status import cluster_status
    return cluster_status(CFG)
