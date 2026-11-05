"""Read-only cluster status through the least-privilege ids-controller identity."""
from __future__ import annotations

from typing import Any

from live.config import load_config, project_path

LAB_NAMESPACES = ("target-apps", "ids-traffic", "ids-deception")


def _qty(v: str | None) -> float | None:
    """Kubernetes quantity -> number (CPU in cores, memory in MiB)."""
    if v is None:
        return None
    v = str(v)
    units = {"n": 1e-9, "u": 1e-6, "m": 1e-3, "Ki": 1 / 1024, "Mi": 1, "Gi": 1024, "Ti": 1024 ** 2,
             "k": 1e3 / 2**20, "M": 1e6 / 2**20, "G": 1e9 / 2**20}
    for u in sorted(units, key=len, reverse=True):
        if v.endswith(u):
            return float(v[: -len(u)]) * units[u]
    try:
        return float(v) / (2**20 if v.isdigit() and len(v) > 6 else 1)
    except ValueError:
        return None


def cluster_metrics(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """CPU / memory from metrics-server (metrics.k8s.io). Never raises."""
    cfg = cfg or load_config()
    try:
        from kubernetes import client
        from live.kube import api_client
        api, _ = api_client(cfg)
        co = client.CustomObjectsApi(api)
        nodes = co.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "nodes", _request_timeout=5)["items"]
    except Exception as e:  # noqa: BLE001
        return {"available": False, "error": f"metrics-server not reachable: {str(e)[:200]}"}
    out: dict[str, Any] = {"available": True, "nodes": [
        {"name": n["metadata"]["name"], "cpu_cores": round(_qty(n["usage"]["cpu"]) or 0, 3),
         "memory_mb": round(_qty(n["usage"]["memory"]) or 0)} for n in nodes], "pods": []}
    for ns in LAB_NAMESPACES:
        try:
            items = co.list_namespaced_custom_object("metrics.k8s.io", "v1beta1", ns, "pods", _request_timeout=5)["items"]
        except Exception:  # noqa: BLE001
            continue
        for p in items:
            out["pods"].append({"namespace": ns, "name": p["metadata"]["name"],
                                "cpu_cores": round(sum(_qty(c["usage"]["cpu"]) or 0 for c in p["containers"]), 4),
                                "memory_mb": round(sum(_qty(c["usage"]["memory"]) or 0 for c in p["containers"]), 1)})
    return out


def cluster_status(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Nodes, namespaces and, for the lab namespaces, pods / deployments / services / events."""
    cfg = cfg or load_config()
    try:
        from kubernetes import client

        from live.kube import api_client
        api, identity = api_client(cfg)
        core, apps = client.CoreV1Api(api), client.AppsV1Api(api)
        nodes = []
        for n in core.list_node(_request_timeout=5).items:
            conds = {c.type: c.status for c in (n.status.conditions or [])}
            nodes.append({
                "name": n.metadata.name, "ready": conds.get("Ready", "Unknown"),
                "pressure": [t for t in ("MemoryPressure", "DiskPressure", "PIDPressure") if conds.get(t) == "True"],
                "version": n.status.node_info.kubelet_version, "os": n.status.node_info.os_image,
                "runtime": n.status.node_info.container_runtime_version,
                "cpu_capacity": n.status.capacity.get("cpu"), "memory_capacity_mb": round(_qty(n.status.capacity.get("memory")) or 0),
                "internal_ip": next((a.address for a in n.status.addresses if a.type == "InternalIP"), None),
                "roles": sorted(k.split("/", 1)[1] for k in (n.metadata.labels or {}) if k.startswith("node-role.kubernetes.io/")),
            })
    except Exception as e:  # noqa: BLE001
        return {"connected": False, "error": str(e)[:300]}

    out: dict[str, Any] = {"connected": True, "identity": identity, "nodes": nodes, "namespaces": {},
                           "all_namespaces": None}
    try:
        out["all_namespaces"] = [{"name": n.metadata.name, "phase": n.status.phase}
                                 for n in core.list_namespace(_request_timeout=5).items]
    except Exception as e:  # noqa: BLE001
        out["all_namespaces_error"] = str(e)[:200]
    for ns in LAB_NAMESPACES:
        entry: dict[str, Any] = {}
        try:
            entry["status"] = core.read_namespace(ns, _request_timeout=5).status.phase
            entry["pods"] = [{
                "name": p.metadata.name, "phase": p.status.phase, "state": _pod_state(p), "ip": p.status.pod_ip,
                "ready": all(cs.ready for cs in (p.status.container_statuses or [])) and bool(p.status.container_statuses),
                "restarts": sum(cs.restart_count for cs in (p.status.container_statuses or [])),
                "labels": p.metadata.labels or {},
                "decoy": (p.metadata.labels or {}).get("app.kubernetes.io/component") == "decoy",
                "started": p.status.start_time.isoformat() if p.status.start_time else None,
            } for p in core.list_namespaced_pod(ns, _request_timeout=5).items]
            entry["deployments"] = [{
                "name": d.metadata.name, "replicas": d.spec.replicas, "ready": d.status.ready_replicas or 0,
                "decoy": (d.metadata.labels or {}).get("app.kubernetes.io/component") == "decoy",
            } for d in apps.list_namespaced_deployment(ns, _request_timeout=5).items]
            entry["services"] = [{
                "name": s.metadata.name, "type": s.spec.type, "cluster_ip": s.spec.cluster_ip,
                "ports": [p.port for p in s.spec.ports or []],
                "decoy": (s.metadata.labels or {}).get("app.kubernetes.io/component") == "decoy",
            } for s in core.list_namespaced_service(ns, _request_timeout=5).items]
            evs = core.list_namespaced_event(ns, _request_timeout=5).items
            evs.sort(key=lambda e: str(e.last_timestamp or e.event_time or e.metadata.creation_timestamp), reverse=True)
            entry["events"] = [{
                "time": str(e.last_timestamp or e.event_time or e.metadata.creation_timestamp), "type": e.type,
                "reason": e.reason, "object": f"{e.involved_object.kind}/{e.involved_object.name}",
                "message": (e.message or "")[:300], "count": e.count,
            } for e in evs[:25]]
        except Exception as e:  # noqa: BLE001
            entry["error"] = str(e)[:300]
        out["namespaces"][ns] = entry
    out["metrics"] = cluster_metrics(cfg)
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
