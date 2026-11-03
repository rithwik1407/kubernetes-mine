"""Read-only cluster status through the least-privilege ids-controller identity."""
from __future__ import annotations

from typing import Any

from live.config import load_config, project_path

LAB_NAMESPACES = ("target-apps", "ids-traffic", "ids-deception")


def cluster_status(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    try:
        from kubernetes import client, config as kconfig

        api = kconfig.new_client_from_config(config_file=str(project_path(cfg["deception"]["kubeconfig"])))
        core, apps = client.CoreV1Api(api), client.AppsV1Api(api)
        nodes = [{
            "name": n.metadata.name,
            "ready": next((c.status for c in n.status.conditions if c.type == "Ready"), "Unknown"),
            "version": n.status.node_info.kubelet_version, "internal_ip": next(
                (a.address for a in n.status.addresses if a.type == "InternalIP"), None),
        } for n in core.list_node(_request_timeout=5).items]
    except Exception as e:
        return {"connected": False, "error": str(e)[:300]}

    out: dict[str, Any] = {"connected": True, "nodes": nodes, "namespaces": {}}
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
