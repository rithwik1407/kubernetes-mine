"""Launch and track traffic-lab scenarios as Kubernetes Jobs.

The dashboard calls this to start a named scenario (benign, web_recon, port_scan,
slow_dos, brute_force, web_attack). Each scenario is one bounded Job in the
ids-traffic namespace, built from config/live.yaml. Jobs are created through the
Kubernetes API with the least-privilege ids-controller identity; nothing here
runs a shell or reaches outside the cluster.
"""
from __future__ import annotations

from typing import Any

from live.config import load_config, repo_path

SCENARIO_LABEL = "app=traffic-lab"


class TrafficLabError(RuntimeError):
    pass


def scenarios(cfg: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    return (cfg or load_config())["traffic_lab"]["scenarios"]


def _api(cfg: dict[str, Any]):
    try:
        from kubernetes import client, config as kconfig
    except ImportError as e:  # pragma: no cover
        raise TrafficLabError(f"kubernetes client not installed: {e}")
    kubeconfig = repo_path(cfg["deception"]["kubeconfig"])
    if not kubeconfig.is_file():
        raise TrafficLabError(f"kubeconfig {kubeconfig} missing; run deploy/rbac/create-kubeconfig.sh")
    api = kconfig.new_client_from_config(config_file=str(kubeconfig))
    return client, client.BatchV1Api(api), client.CoreV1Api(api)


def _target_for(scenario: str, cfg: dict[str, Any]) -> str:
    """Default target host:port for a scenario (the dashboard may override it)."""
    tl = cfg["traffic_lab"]
    nodered = tl["targets"]["nodered"]
    return f"{nodered['host']}:{nodered['port']}"


def build_job(scenario: str, cfg: dict[str, Any], target: str | None = None,
              count: int = 300, delay: float = 0.1) -> dict[str, Any]:
    tl = cfg["traffic_lab"]
    if scenario not in tl["scenarios"]:
        raise TrafficLabError(f"unknown scenario {scenario!r}; one of {sorted(tl['scenarios'])}")
    mode = tl["scenarios"][scenario]["mode"]
    target = target or _target_for(scenario, cfg)
    env = [
        {"name": "MODE", "value": mode},
        {"name": "TARGET", "value": target},
        {"name": "COUNT", "value": str(int(count))},
        {"name": "DELAY", "value": str(float(delay))},
        {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
    ]
    container = {
        "name": "generator", "image": "python:3.13-alpine",
        "command": ["python", "/app/traffic_generator.py"], "env": env,
        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                      "limits": {"cpu": "200m", "memory": "96Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
        "volumeMounts": [{"name": "script", "mountPath": "/app", "readOnly": True}],
    }
    pod = {
        "metadata": {"labels": {"app": "traffic-lab", "scenario": mode}},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container],
            "volumes": [{"name": "script", "configMap": {"name": "traffic-generator-script"}}],
        },
    }
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"generateName": f"traffic-{mode}-", "namespace": tl["namespace"],
                     "labels": {"app": "traffic-lab", "scenario": mode}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 300, "ttlSecondsAfterFinished": 3600,
                 "template": pod},
    }


def launch(scenario: str, target: str | None = None, count: int = 300, delay: float = 0.1,
           cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    body = build_job(scenario, cfg, target, count, delay)
    _, batch, _ = _api(cfg)
    created = batch.create_namespaced_job(cfg["traffic_lab"]["namespace"], body)
    return {"job": created.metadata.name, "scenario": scenario,
            "mode": body["spec"]["template"]["metadata"]["labels"]["scenario"],
            "target": body["spec"]["template"]["spec"]["containers"][0]["env"][1]["value"]}


def list_jobs(cfg: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    cfg = cfg or load_config()
    try:
        _, batch, _ = _api(cfg)
        jobs = batch.list_namespaced_job(cfg["traffic_lab"]["namespace"], label_selector=SCENARIO_LABEL).items
    except TrafficLabError as e:
        return [{"error": str(e)}]
    out = []
    for j in jobs:
        s = j.status
        state = "running"
        if s.succeeded:
            state = "succeeded"
        elif s.failed:
            state = "failed"
        elif not s.active:
            state = "pending"
        out.append({"name": j.metadata.name, "scenario": (j.metadata.labels or {}).get("scenario"),
                    "state": state, "active": s.active or 0, "succeeded": s.succeeded or 0,
                    "failed": s.failed or 0,
                    "started": s.start_time.isoformat() if s.start_time else None})
    return sorted(out, key=lambda r: r["started"] or "", reverse=True)


def delete_job(name: str, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    _, batch, _ = _api(cfg)
    batch.delete_namespaced_job(name, cfg["traffic_lab"]["namespace"], propagation_policy="Background")
    return {"deleted": name}
