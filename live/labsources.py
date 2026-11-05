"""Which Traffic-lab scenario produced a flow (for the Live traffic page).

Every generator pod carries the labels app=traffic-lab and scenario=<slug>, and the
Job's pods also carry job-name. This module maps pod IPs in the traffic-lab namespace
to that scenario and Job, and tags each scored flow whose source or destination
is one of those pods. The model never sees these columns; they only label the result.

Pod IPs are reused once a pod has finished, so a running pod wins over a finished
one, and among finished pods the most recently started wins.
"""
from __future__ import annotations

import threading
import time
from typing import Any

import pandas as pd

from live.config import load_config
from live.logging_setup import get_logger

log = get_logger(__name__)
_CACHE: dict[str, Any] = {"at": 0.0, "value": None, "error": None}
_LOCK = threading.Lock()


def _list_pods(cfg: dict[str, Any]) -> list:
    from kubernetes import client
    from live.kube import api_client
    api, _ = api_client(cfg)
    ns = cfg["traffic_lab"]["namespace"]
    return client.CoreV1Api(api).list_namespaced_pod(ns, label_selector="app=traffic-lab", _request_timeout=5).items


def build_map(pods: list) -> dict[str, dict[str, Any]]:
    """{pod_ip: {"scenario", "job", "pod"}} with running pods preferred on IP reuse."""
    out: dict[str, tuple[tuple, dict[str, Any]]] = {}
    for p in pods:
        ip = p.status.pod_ip if p.status else None
        if not ip:
            continue
        labels = p.metadata.labels or {}
        scenario = (labels.get("scenario") or "unknown").replace("-", "_")
        job = labels.get("job-name") or labels.get("batch.kubernetes.io/job-name")
        running = p.status.phase in ("Running", "Pending")
        started = p.status.start_time.timestamp() if p.status.start_time else 0.0
        rank = (running, started)
        if ip not in out or rank > out[ip][0]:
            out[ip] = (rank, {"scenario": scenario, "job": job or p.metadata.name, "pod": p.metadata.name})
    return {ip: v for ip, (_, v) in out.items()}


def get(cfg: dict[str, Any] | None = None, refresh_s: float = 5) -> dict[str, dict[str, Any]]:
    """Cached pod-IP map. Empty (never raising) when the cluster cannot be reached."""
    cfg = cfg or load_config()
    with _LOCK:
        if _CACHE["value"] is None or time.monotonic() - _CACHE["at"] > refresh_s:
            try:
                _CACHE["value"], _CACHE["error"] = build_map(_list_pods(cfg)), None
            except Exception as e:  # noqa: BLE001
                if _CACHE["error"] is None:
                    log.warning("lab scenario tags unavailable: %s", e)
                _CACHE["value"], _CACHE["error"] = {}, str(e)
            _CACHE["at"] = time.monotonic()
        return _CACHE["value"]


def reset_cache() -> None:
    with _LOCK:
        _CACHE.update(at=0.0, value=None, error=None)


def tag(pred: pd.DataFrame, pods: dict[str, dict[str, Any]]) -> pd.DataFrame:
    """Add lab_scenario / lab_job to scored flows (the generator pod may be either end)."""
    pred = pred.copy()
    if not len(pred) or not pods:
        pred["lab_scenario"] = pd.Series(None, index=pred.index, dtype="object")
        pred["lab_job"] = pd.Series(None, index=pred.index, dtype="object")
        return pred
    hits = [pods.get(str(s)) or pods.get(str(d)) for s, d in zip(pred["src_ip"], pred["dst_ip"])]
    pred["lab_scenario"] = pd.Series([h["scenario"] if h else None for h in hits], index=pred.index, dtype="object")
    pred["lab_job"] = pd.Series([h["job"] if h else None for h in hits], index=pred.index, dtype="object")
    return pred


_DECOYS: dict[str, Any] = {"at": 0.0, "value": None}


def decoy_ips(cfg: dict[str, Any] | None = None, refresh_s: float = 5) -> set[str]:
    """IPs of the decoy pods. Their reply traffic can look like a sweep or a burst
    (CICFlowMeter sometimes records a mid-stream flow in reverse), so the deception
    controller must never treat a decoy as an attacker."""
    cfg = cfg or load_config()
    with _LOCK:
        if _DECOYS["value"] is None or time.monotonic() - _DECOYS["at"] > refresh_s:
            try:
                from kubernetes import client
                from live.kube import api_client
                api, _ = api_client(cfg)
                pods = client.CoreV1Api(api).list_namespaced_pod(
                    cfg["deception"]["namespace"], label_selector="app.kubernetes.io/component=decoy",
                    _request_timeout=5).items
                _DECOYS["value"] = {p.status.pod_ip for p in pods if p.status and p.status.pod_ip}
            except Exception:  # noqa: BLE001
                _DECOYS["value"] = set()
            _DECOYS["at"] = time.monotonic()
        return _DECOYS["value"]
