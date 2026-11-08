"""Pod IP -> pod, namespace, node (and the Services in front of it) for the lab namespaces.

Used by node-specific deception: the controller finds the pod an attack is hitting and
the node it runs on, places the decoy on that node and redirects only traffic aimed
at that pod. The dashboard uses the same map to show node names next to alerts.

Read-only, limited to the lab namespaces the ids-controller identity can read
(target-apps, ids-traffic, ids-deception). Cached for a few seconds; an empty map
(never an exception) when the cluster cannot be reached.
"""
from __future__ import annotations

import threading
import time
from typing import Any

from live.config import load_config
from live.logging_setup import get_logger

log = get_logger(__name__)
_CACHE: dict[str, Any] = {"at": 0.0, "value": None, "error": None}
_LOCK = threading.Lock()


def namespaces(cfg: dict[str, Any]) -> list[str]:
    targets = {str(t.get("host", "")).split(".")[1] for t in cfg["traffic_lab"]["targets"].values()
               if str(t.get("host", "")).count(".") >= 1}
    return sorted(targets | {cfg["traffic_lab"]["namespace"], cfg["deception"]["namespace"]})


def _matches(selector: dict[str, str] | None, labels: dict[str, str]) -> bool:
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def build(pods: list, services: list) -> dict[str, dict[str, Any]]:
    """{pod_ip: {pod, namespace, node, phase, ip, created, services: [{name, cluster_ip, ports, hosts}]}}.
    A running pod wins when an IP was reused by a finished one."""
    out: dict[str, dict[str, Any]] = {}
    for p in pods:
        ip = p.status.pod_ip if p.status else None
        if not ip:
            continue
        labels = p.metadata.labels or {}
        ns = p.metadata.namespace
        svcs = []
        for s in services:
            if s.metadata.namespace == ns and _matches(s.spec.selector, labels):
                n = s.metadata.name
                svcs.append({"name": n, "cluster_ip": s.spec.cluster_ip,
                             "ports": [x.port for x in (s.spec.ports or [])],
                             "hosts": [n, f"{n}.{ns}", f"{n}.{ns}.svc", f"{n}.{ns}.svc.cluster.local"]
                                      + ([s.spec.cluster_ip] if s.spec.cluster_ip not in (None, "None") else [])})
        rec = {"pod": p.metadata.name, "namespace": ns, "node": p.spec.node_name if p.spec else None,
               "phase": p.status.phase, "ip": ip, "labels": labels,
               "created": p.metadata.creation_timestamp.isoformat() if p.metadata.creation_timestamp else None,
               "services": svcs}
        old = out.get(ip)
        if old is None or (rec["phase"] in ("Running", "Pending")) >= (old["phase"] in ("Running", "Pending")):
            out[ip] = rec
    return out


def _fetch(cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    from kubernetes import client
    from live.kube import api_client
    api, _ = api_client(cfg)
    core = client.CoreV1Api(api)
    pods, svcs = [], []
    for ns in namespaces(cfg):
        pods += core.list_namespaced_pod(ns, _request_timeout=5).items
        svcs += core.list_namespaced_service(ns, _request_timeout=5).items
    return build(pods, svcs)


def get(cfg: dict[str, Any] | None = None, refresh_s: float = 5) -> dict[str, dict[str, Any]]:
    cfg = cfg or load_config()
    with _LOCK:
        if _CACHE["value"] is None or time.monotonic() - _CACHE["at"] > refresh_s:
            try:
                _CACHE["value"], _CACHE["error"] = _fetch(cfg), None
            except Exception as e:  # noqa: BLE001
                if _CACHE["error"] is None:
                    log.warning("pod/node map unavailable: %s", e)
                _CACHE["value"], _CACHE["error"] = {}, str(e)
            _CACHE["at"] = time.monotonic()
        return _CACHE["value"]


def lookup(ip: str | None, cfg: dict[str, Any] | None = None) -> dict[str, Any] | None:
    return get(cfg).get(str(ip)) if ip else None


def reset_cache() -> None:
    with _LOCK:
        _CACHE.update(at=0.0, value=None, error=None)
