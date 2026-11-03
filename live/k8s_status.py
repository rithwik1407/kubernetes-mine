"""Read-only cluster status through the least-privilege ids-controller identity."""
from __future__ import annotations

from typing import Any

from live.config import load_config, project_path

LAB_NAMESPACES = ("target-apps", "ids-traffic", "ids-deception")


def cluster_status(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    try:
        from kubernetes import client

        from live.kube import api_client
        api, identity = api_client(cfg)
        core, apps = client.CoreV1Api(api), client.AppsV1Api(api)
        nodes = [{
            "name": n.metadata.name,
            "ready": next((c.status for c in n.status.conditions if c.type == "Ready"), "Unknown"),
            "version": n.status.node_info.kubelet_version, "internal_ip": next(
                (a.address for a in n.status.addresses if a.type == "InternalIP"), None),
        } for n in core.list_node(_request_timeout=5).items]
    except Exception as e:
        return {"connected": False, "error": str(e)[:300]}

    out: dict[str, Any] = {"connected": True, "identity": identity, "nodes": nodes, "namespaces": {}}
    for ns in LAB_NAMESPACES:
        entry: dict[str, Any] = {}
        try:
            entry["status"] = core.read_namespace(ns).status.phase
            entry["pods"] = [{
                "name": p.metadata.name, "phase": p.status.phase, "ip": p.status.pod_ip,
                "ready": all(cs.ready for cs in (p.status.container_statuses or [])),
                "restarts": sum(cs.restart_count for cs in (p.status.container_statuses or [])),
                "labels": p.metadata.labels or {},
                "started": p.status.start_time.isoformat() if p.status.start_time else None,
            } for p in core.list_namespaced_pod(ns).items]
            entry["deployments"] = [{
                "name": d.metadata.name, "replicas": d.spec.replicas, "ready": d.status.ready_replicas or 0,
            } for d in apps.list_namespaced_deployment(ns).items]
            entry["services"] = [{
                "name": s.metadata.name, "type": s.spec.type, "cluster_ip": s.spec.cluster_ip,
                "ports": [p.port for p in s.spec.ports or []],
            } for s in core.list_namespaced_service(ns).items]
            evs = core.list_namespaced_event(ns).items
            evs.sort(key=lambda e: str(e.last_timestamp or e.event_time or e.metadata.creation_timestamp), reverse=True)
            entry["events"] = [{
                "time": str(e.last_timestamp or e.event_time or e.metadata.creation_timestamp), "type": e.type,
                "reason": e.reason, "object": f"{e.involved_object.kind}/{e.involved_object.name}",
                "message": (e.message or "")[:300],
            } for e in evs[:15]]
        except Exception as e:
            entry["error"] = str(e)[:300]
        out["namespaces"][ns] = entry
    return out



def _pod_state(p) -> str:
    if p.metadata.deletion_timestamp:
        return "terminating"
    for cs in p.status.container_statuses or []:
        w = cs.state.waiting if cs.state else None
        if w and w.reason:
            return w.reason            # CrashLoopBackOff, ImagePullBackOff, ...
    if p.status.phase == "Running" and all(cs.ready for cs in (p.status.container_statuses or [])):
        return "running"
    return (p.status.phase or "unknown").lower() if p.status.phase != "Running" else "not ready"


def targets_status(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Are the target apps (Node-RED, Grafana, InfluxDB) running? Never raises."""
    cfg = cfg or load_config()
    targets = cfg["traffic_lab"]["targets"]
    apps = [{"key": k, "port": t["port"], "host": t["host"], "state": "unknown", "pods": [], "service": None}
            for k, t in targets.items()]
    out: dict[str, Any] = {"connected": False, "namespace": "target-apps", "apps": apps,
                           "running": 0, "total": len(apps), "all_running": False}
    try:
        from live.kube import api_client
        from kubernetes import client
        api, identity = api_client(cfg)
        core = client.CoreV1Api(api)
        pods = core.list_namespaced_pod("target-apps", _request_timeout=6).items
        try:
            svcs = {s.metadata.name for s in core.list_namespaced_service("target-apps", _request_timeout=6).items}
        except Exception:
            svcs = set()
    except Exception as e:
        out["error"] = str(e)[:300]
        for a in apps:
            a["state"] = "cluster unreachable"
        return out
    out["connected"], out["identity"] = True, identity
    for a in apps:
        key = a["key"].lower()
        match = [p for p in pods if key in p.metadata.name.lower()
                 or any(key in str(v).lower() for v in (p.metadata.labels or {}).values())]
        a["pods"] = [{"name": p.metadata.name, "state": _pod_state(p), "ip": p.status.pod_ip,
                      "restarts": sum(cs.restart_count for cs in (p.status.container_statuses or []))} for p in match]
        a["service"] = any(key in s for s in svcs) if svcs else None
        states = [x["state"] for x in a["pods"]]
        a["state"] = ("running" if "running" in states else (states[0] if states else "not found"))
    out["running"] = sum(a["state"] == "running" for a in apps)
    out["all_running"] = out["running"] == out["total"]
    return out
