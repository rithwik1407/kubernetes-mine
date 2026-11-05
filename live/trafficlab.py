"""Launch, track and verify traffic-lab scenarios as Kubernetes Jobs.

The dashboard calls this to start a named scenario (benign, web_recon, port_scan,
slow_dos, brute_force, web_attack, decoy_probe). Each scenario is one bounded Job
in the ids-traffic namespace, built from config/live.yaml, and created through the
Kubernetes API with the least-privilege ids-controller identity. Nothing here runs a
shell, and targets are restricted to the configured lab services (target-apps) and
the decoys in ids-deception: a free-form host is rejected, so the lab cannot be
pointed at anything outside the cluster.

"Verified" traffic means the generator pod's own log shows connections that got an
answer from the target (HTTP status or TCP connect result), not merely that the Job
object was created.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from live.config import load_config
from live.logging_setup import get_logger

log = get_logger(__name__)
SCENARIO_LABEL = "app=traffic-lab"
BENIGN_DEPLOYMENT = "traffic-benign"
_HOSTPORT_RE = re.compile(r"^[a-z0-9.-]{1,253}:\d{1,5}$")


class TrafficLabError(RuntimeError):
    pass


def scenarios(cfg: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    return (cfg or load_config())["traffic_lab"]["scenarios"]


def targets(cfg: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    return (cfg or load_config())["traffic_lab"]["targets"]


def _api(cfg: dict[str, Any]):
    from live.kube import KubeUnavailable, api_client
    try:
        from kubernetes import client
        api, _identity = api_client(cfg)
    except (ImportError, KubeUnavailable) as e:
        raise TrafficLabError(str(e))
    return client, client.BatchV1Api(api), client.CoreV1Api(api)


def _apps(cfg: dict[str, Any]):
    from kubernetes import client
    from live.kube import api_client
    api, _ = api_client(cfg)
    return client.AppsV1Api(api)


def _api_message(e) -> str:
    """The API server's own explanation (e.body), not just the HTTP reason phrase."""
    try:
        return str(json.loads(e.body).get("message"))[:400]
    except Exception:  # noqa: BLE001
        return (getattr(e, "reason", None) or str(e))[:200]


def slugify(mode: str) -> str:
    """Kubernetes object names must be RFC 1123: 'port_scan' -> 'port-scan'.

    Before this, every scenario with an underscore was rejected with HTTP 422, so
    only 'benign' could ever be launched from the dashboard.
    """
    return re.sub(r"[^a-z0-9-]+", "-", mode.lower()).strip("-")


def check_ready(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Is the traffic lab deployed (namespace + generator script)? Never raises."""
    cfg = cfg or load_config()
    ns = cfg["traffic_lab"]["namespace"]
    try:
        client, _, core = _api(cfg)
    except TrafficLabError as e:
        return {"ready": False, "reason": str(e)}
    try:
        core.read_namespaced_config_map("traffic-generator-script", ns, _request_timeout=5)
    except client.exceptions.ApiException as e:
        if e.status == 404:
            return {"ready": False, "reason": f"traffic lab not deployed in namespace {ns}",
                    "fix": "kubectl apply -f deploy/namespaces/ && kubectl apply -k deploy/traffic-lab"}
        if e.status == 403:  # older RBAC without configmap read: the Job create is the real test
            return {"ready": True, "note": "could not verify generator script (RBAC); re-apply deploy/rbac/ids-controller.yaml"}
        return {"ready": False, "reason": f"Kubernetes API error {e.status}: {_api_message(e)}"}
    except Exception as e:  # noqa: BLE001
        return {"ready": False, "reason": f"cluster unreachable: {str(e)[:160]}"}
    return {"ready": True}


# --- targets ---------------------------------------------------------------------------
def _decoy_targets(core, cfg: dict[str, Any]) -> dict[str, str]:
    """host:port of every managed decoy Service (for the decoy_probe scenario)."""
    ns = cfg["deception"]["namespace"]
    from live.k8s_decoys import SELECTOR
    out = {}
    for s in core.list_namespaced_service(ns, label_selector=SELECTOR, _request_timeout=5).items:
        if s.spec.ports:
            out[s.metadata.name] = f"{s.metadata.name}.{ns}.svc.cluster.local:{s.spec.ports[0].port}"
    return out


def _pod_ip_for(core, host: str) -> str | None:
    """Pod IP behind a target-apps service, so a port scan reaches a real host.

    A ClusterIP only forwards the service's own port; every other port is silently
    dropped, which made the old scan time out port after port and finish almost no
    probes inside the Job deadline.
    """
    m = re.match(r"^([a-z0-9-]+)\.([a-z0-9-]+)\.svc", host)
    if not m:
        return None
    name, ns = m.groups()
    try:
        ep = core.read_namespaced_endpoints(name, ns, _request_timeout=5)
    except Exception:  # noqa: BLE001
        ep = None
    for subset in (ep.subsets or []) if ep else []:
        for addr in subset.addresses or []:
            if addr.ip:
                return addr.ip
    try:
        pods = core.list_namespaced_pod(ns, _request_timeout=5).items
    except Exception:  # noqa: BLE001
        return None
    for p in pods:
        if p.status.phase == "Running" and p.status.pod_ip and name in p.metadata.name:
            return p.status.pod_ip
    return None


def resolve_target(scenario: str, target: str | None, cfg: dict[str, Any], core=None) -> dict[str, Any]:
    """Validate the requested target and turn it into what the generator needs."""
    tl = cfg["traffic_lab"]
    sc = tl["scenarios"][scenario]
    allowed = {k: f"{t['host']}:{t['port']}" for k, t in tl["targets"].items()}
    mode = sc["mode"]
    if mode == "decoy_probe":
        if core is None:
            raise TrafficLabError("decoy_probe needs the cluster to list decoys")
        decoys = _decoy_targets(core, cfg)
        if target and target not in decoys:
            raise TrafficLabError(f"unknown decoy {target!r}; active decoy services: {sorted(decoys) or 'none'}")
        chosen = [decoys[target]] if target else list(decoys.values())
        if not chosen:
            raise TrafficLabError("no decoy services exist yet: deploy a decoy first (Deception page)")
        return {"target": ",".join(chosen), "label": target or "all decoys"}
    key = target or sc.get("default_target") or next(iter(allowed))
    if key in allowed:
        hostport = allowed[key]
    elif _HOSTPORT_RE.match(key or "") and key in allowed.values():
        hostport = key
    else:
        raise TrafficLabError(f"target must be one of {sorted(allowed)} (lab services only); got {key!r}")
    out = {"target": hostport, "label": key}
    if mode == "port_scan" and core is not None:
        ip = _pod_ip_for(core, hostport.split(":")[0])
        if ip:
            out["target"] = f"{ip}:{hostport.split(':')[1]}"
            out["note"] = f"scanning pod {ip} behind {hostport.split(':')[0]}"
    return out


# --- jobs ------------------------------------------------------------------------------
def build_job(scenario: str, cfg: dict[str, Any], target: str | None = None,
              count: int = 300, delay: float = 0.1) -> dict[str, Any]:
    """The Job manifest. `target` must already be resolved (host:port[,host:port])."""
    tl = cfg["traffic_lab"]
    if scenario not in tl["scenarios"]:
        raise TrafficLabError(f"unknown scenario {scenario!r}; one of {sorted(tl['scenarios'])}")
    sc = tl["scenarios"][scenario]
    mode = sc["mode"]
    slug = slugify(mode)
    if target is None:
        t = tl["targets"][sc.get("default_target") or next(iter(tl["targets"]))]
        target = f"{t['host']}:{t['port']}"
    env = [
        {"name": "MODE", "value": mode},
        {"name": "TARGET", "value": target},
        {"name": "COUNT", "value": str(int(count))},
        {"name": "DELAY", "value": str(float(delay))},
        {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
        {"name": "PYTHONUNBUFFERED", "value": "1"},
    ]
    env += [{"name": str(k), "value": str(v)} for k, v in (sc.get("env") or {}).items()]
    container = {
        "name": "generator", "image": tl.get("image", "python:3.13-alpine"),
        "command": ["python", "/app/traffic_generator.py"], "env": env,
        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                      "limits": {"cpu": "200m", "memory": "96Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
        "volumeMounts": [{"name": "script", "mountPath": "/app", "readOnly": True}],
    }
    labels = {"app": "traffic-lab", "scenario": slug}
    pod = {
        "metadata": {"labels": labels},
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
        "metadata": {"generateName": f"traffic-{slug}-", "namespace": tl["namespace"], "labels": dict(labels),
                     "annotations": {"ids/scenario": scenario, "ids/mode": mode, "ids/target": target[:250]}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": int(tl.get("job_deadline_seconds", 300)),
                 "ttlSecondsAfterFinished": 3600, "template": pod},
    }


def launch(scenario: str, target: str | None = None, count: int = 300, delay: float = 0.1,
           cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    if scenario not in cfg["traffic_lab"]["scenarios"]:
        raise TrafficLabError(f"unknown scenario {scenario!r}; one of {sorted(cfg['traffic_lab']['scenarios'])}")
    client, batch, core = _api(cfg)
    ready = check_ready(cfg)
    if not ready["ready"]:
        raise TrafficLabError(ready["reason"] + (f" — run: {ready['fix']}" if ready.get("fix") else ""))
    resolved = resolve_target(scenario, target, cfg, core)
    body = build_job(scenario, cfg, resolved["target"], count, delay)
    try:
        created = batch.create_namespaced_job(cfg["traffic_lab"]["namespace"], body)
    except client.exceptions.ApiException as e:
        raise TrafficLabError(f"Kubernetes refused the Job ({e.status}): {_api_message(e)}")
    log.info("traffic lab: launched %s (%s) -> %s", created.metadata.name, scenario, resolved["target"])
    return {"job": created.metadata.name, "scenario": scenario, "mode": cfg["traffic_lab"]["scenarios"][scenario]["mode"],
            "target": resolved["target"], "target_label": resolved["label"], "note": resolved.get("note")}


def _job_state(s) -> str:
    if s.succeeded:
        return "succeeded"
    if s.failed:
        return "failed"
    return "running" if s.active else "pending"


def list_jobs(cfg: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Traffic-lab Jobs. Raises TrafficLabError when the cluster is unreachable."""
    cfg = cfg or load_config()
    _, batch, _ = _api(cfg)
    try:
        jobs = batch.list_namespaced_job(cfg["traffic_lab"]["namespace"], label_selector=SCENARIO_LABEL,
                                         _request_timeout=6).items
    except Exception as e:  # noqa: BLE001
        raise TrafficLabError(f"could not list Jobs: {_api_message(e)}")
    out = []
    for j in jobs:
        s, ann = j.status, (j.metadata.annotations or {})
        out.append({"name": j.metadata.name,
                    "scenario": ann.get("ids/scenario") or (j.metadata.labels or {}).get("scenario"),
                    "target": ann.get("ids/target"), "state": _job_state(s), "active": s.active or 0,
                    "succeeded": s.succeeded or 0, "failed": s.failed or 0,
                    "started": s.start_time.isoformat() if s.start_time else None,
                    "completed": s.completion_time.isoformat() if s.completion_time else None})
    return sorted(out, key=lambda r: r["started"] or "9999", reverse=True)


def summarize_log(text: str) -> dict[str, Any]:
    """Turn the generator's JSON-lines log into verified counts.

    ok        actions that got an answer from the target (an HTTP status, an open or
              refused port, a TCP connection)
    errors    actions that failed (timeouts, DNS errors, unreachable)
    """
    actions: Counter = Counter()
    statuses: Counter = Counter()
    errors: Counter = Counter()
    ok = err = lines = 0
    first = last = None
    for line in text.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict) or "action" not in rec:
            continue
        lines += 1
        first = first or rec.get("ts")
        last = rec.get("ts")
        a = rec["action"]
        actions[a] += 1
        if a in ("start", "done", "interrupted", "slow_established"):
            continue
        if rec.get("error"):
            err += 1
            errors[rec["error"]] += 1
        else:
            ok += 1
            if "status" in rec:
                statuses[str(rec["status"])] += 1
    done = actions.get("done", 0) > 0
    return {"lines": lines, "ok": ok, "errors": err, "actions": dict(actions), "http_status": dict(statuses),
            "error_types": dict(errors), "finished": done, "first_ts": first, "last_ts": last,
            "verified": ok > 0}


def job_detail(name: str, cfg: dict[str, Any] | None = None, tail: int = 2000) -> dict[str, Any]:
    """One Job with its pod state and a verification summary parsed from the generator log."""
    cfg = cfg or load_config()
    if not re.match(r"^[a-z0-9-]{1,63}$", name):
        raise ValueError(f"invalid job name {name!r}")
    client, batch, core = _api(cfg)
    ns = cfg["traffic_lab"]["namespace"]
    try:
        j = batch.read_namespaced_job(name, ns, _request_timeout=6)
    except client.exceptions.ApiException as e:
        if e.status == 404:
            raise KeyError(name)
        raise TrafficLabError(_api_message(e))
    pods = core.list_namespaced_pod(ns, label_selector=f"job-name={name}", _request_timeout=6).items
    pod_info, text, log_error = [], "", None
    for p in pods:
        waiting = next((cs.state.waiting.reason for cs in (p.status.container_statuses or [])
                        if cs.state and cs.state.waiting), None)
        pod_info.append({"name": p.metadata.name, "phase": p.status.phase, "waiting": waiting, "ip": p.status.pod_ip})
        if p.status.phase in ("Running", "Succeeded", "Failed"):
            try:
                text += core.read_namespaced_pod_log(p.metadata.name, ns, tail_lines=tail, _request_timeout=8)
            except Exception as e:  # noqa: BLE001
                log_error = _api_message(e)
    ann = j.metadata.annotations or {}
    summary = summarize_log(text)
    return {"name": name, "scenario": ann.get("ids/scenario"), "target": ann.get("ids/target"),
            "state": _job_state(j.status), "started": j.status.start_time.isoformat() if j.status.start_time else None,
            "completed": j.status.completion_time.isoformat() if j.status.completion_time else None,
            "pods": pod_info, "verification": summary, "log_error": log_error,
            "log_tail": text.splitlines()[-25:]}


def delete_job(name: str, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    if not re.match(r"^[a-z0-9-]{1,63}$", name):
        raise ValueError(f"invalid job name {name!r}")
    client, batch, _ = _api(cfg)
    try:
        batch.delete_namespaced_job(name, cfg["traffic_lab"]["namespace"], propagation_policy="Background")
    except client.exceptions.ApiException as e:
        if e.status == 404:
            raise KeyError(name)
        raise TrafficLabError(f"delete refused ({e.status}): {_api_message(e)}")
    return {"deleted": name}


# --- continuous benign baseline ------------------------------------------------------------
def baseline_status(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    try:
        d = _apps(cfg).read_namespaced_deployment(BENIGN_DEPLOYMENT, cfg["traffic_lab"]["namespace"], _request_timeout=5)
    except Exception as e:  # noqa: BLE001
        return {"available": False, "error": _api_message(e)}
    return {"available": True, "name": BENIGN_DEPLOYMENT, "replicas": d.spec.replicas or 0,
            "ready": d.status.ready_replicas or 0, "running": bool(d.status.ready_replicas)}


def set_baseline(running: bool, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Start (1 replica) or stop (0) the continuous benign generator."""
    cfg = cfg or load_config()
    try:
        _apps(cfg).patch_namespaced_deployment_scale(BENIGN_DEPLOYMENT, cfg["traffic_lab"]["namespace"],
                                                     {"spec": {"replicas": 1 if running else 0}})
    except Exception as e:  # noqa: BLE001
        raise TrafficLabError(f"could not scale {BENIGN_DEPLOYMENT}: {_api_message(e)}")
    return baseline_status(cfg)
