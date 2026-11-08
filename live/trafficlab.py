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
import time
from collections import Counter
from typing import Any

from live.config import load_config, repo_path
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
        cm = core.read_namespaced_config_map("traffic-generator-script", ns, _request_timeout=5)
    except client.exceptions.ApiException as e:
        if e.status == 404:
            return {"ready": False, "reason": f"traffic lab not deployed in namespace {ns}",
                    "fix": "kubectl apply -f deploy/namespaces/ && kubectl apply -k deploy/traffic-lab"}
        if e.status == 403:  # older RBAC without configmap read: the Job create is the real test
            return {"ready": True, "note": "could not verify generator script (RBAC); re-apply deploy/rbac/ids-controller.yaml"}
        return {"ready": False, "reason": f"Kubernetes API error {e.status}: {_api_message(e)}"}
    except Exception as e:  # noqa: BLE001
        return {"ready": False, "reason": f"cluster unreachable: {str(e)[:160]}"}
    return {"ready": True, **generator_freshness(cm)}


GENERATOR_FILE = repo_path("deploy/traffic-lab/traffic_generator.py")


def generator_freshness(cm) -> dict[str, Any]:
    """Is the generator script in the cluster the one in this checkout? An old copy keeps
    running old behaviour (for example no deception redirect) until it is re-applied."""
    try:
        live = ((cm.data or {}).get("traffic_generator.py") or "").replace("\r\n", "\n")
        local = GENERATOR_FILE.read_text().replace("\r\n", "\n")
    except Exception:  # noqa: BLE001
        return {}
    if live.strip() == local.strip():
        return {"generator_current": True}
    return {"generator_current": False,
            "warning": "the traffic generator script in the cluster is older than this checkout; "
                       "runs use the old behaviour until you update it",
            "fix": "kubectl apply -k deploy/traffic-lab"}


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
# Generator parameters the dashboard may set, each mapped to one env var of the generator
# and validated here (type, range, pattern): nothing else from a request reaches the pod.
def benign_src_ports(cfg: dict[str, Any] | None = None) -> tuple[int, int]:
    """Source ports of the benign requests mixed into attack runs (labelled BENIGN in training)."""
    r = ((cfg or load_config())["traffic_lab"].get("benign_src_ports") or [20000, 20999])
    return int(r[0]), int(r[1])


GEN_PARAMS: dict[str, dict[str, Any]] = {
    "concurrency":  {"env": "CONCURRENCY", "type": int, "min": 1, "max": 16, "modes": ["port_scan", "brute_force", "web_attack"],
                     "help": "parallel workers (rate is about concurrency / delay per second)"},
    "benign_mix_s": {"env": "BENIGN_MIX_S", "type": float, "min": 0, "max": 60, "modes": ["port_scan", "brute_force", "web_attack", "slow_dos"],
                     "help": "one ordinary request to the real target every N s during the attack (0 = off); never redirected to the decoy"},
    "minutes":      {"env": "RUN_SECONDS", "type": float, "min": 0.5, "max": 60, "modes": None,
                     "help": "run for this many minutes: the scenario repeats at its normal rate until the time is up"},
    "target_port":  {"env": None, "type": int, "min": 1, "max": 65535, "modes": ["port_scan", "brute_force", "web_attack", "slow_dos", "web_recon"],
                     "help": "port on the target (brute_force: 22/2222 = SSH-style connects)"},
    "port_start":   {"env": "PORT_START", "type": int, "min": 1, "max": 65535, "modes": ["port_scan"], "help": "first port to scan"},
    "port_end":     {"env": "PORT_END", "type": int, "min": 1, "max": 65535, "modes": ["port_scan"], "help": "last port to scan"},
    "scan_timeout": {"env": "SCAN_TIMEOUT", "type": float, "min": 0.1, "max": 5, "modes": ["port_scan"], "help": "connect timeout per port (s)"},
    "slow_conns":   {"env": "SLOW_CONNS", "type": int, "min": 1, "max": 1000, "modes": ["slow_dos"], "help": "connections held open"},
    "slow_hold_s":  {"env": "SLOW_HOLD_S", "type": float, "min": 1, "max": 240, "modes": ["slow_dos"], "help": "seconds the connections are held"},
    "login_path":   {"env": "LOGIN_PATH", "type": str, "pattern": r"^/[A-Za-z0-9/_.-]{0,63}$", "modes": ["brute_force"],
                     "help": "HTTP login endpoint"},
    "payload_set":  {"env": "PAYLOAD_SET", "type": str, "choices": ["mixed", "sqli", "xss", "traversal"], "modes": ["web_attack"],
                     "help": "attack strings sent"},
}


def check_params(params: dict[str, Any] | None) -> dict[str, Any]:
    """Validated generator parameters, or TrafficLabError naming the bad one."""
    out: dict[str, Any] = {}
    for k, v in (params or {}).items():
        spec = GEN_PARAMS.get(k)
        if spec is None:
            raise TrafficLabError(f"unknown generator parameter {k!r}; one of {sorted(GEN_PARAMS)}")
        if v is None or v == "":
            continue
        try:
            v = spec["type"](v)
        except (TypeError, ValueError):
            raise TrafficLabError(f"{k} must be a {spec['type'].__name__}")
        if "min" in spec and not spec["min"] <= v <= spec["max"]:
            raise TrafficLabError(f"{k} must be between {spec['min']} and {spec['max']}")
        if "pattern" in spec and not re.match(spec["pattern"], v):
            raise TrafficLabError(f"{k} has an invalid format")
        if "choices" in spec and v not in spec["choices"]:
            raise TrafficLabError(f"{k} must be one of {spec['choices']}")
        out[k] = v
    if "port_start" in out and "port_end" in out and out["port_start"] > out["port_end"]:
        raise TrafficLabError("port_start must be <= port_end")
    return out


def scenario_defaults(scenario: str, cfg: dict[str, Any]) -> tuple[int, float]:
    sc = cfg["traffic_lab"]["scenarios"][scenario]
    return int(sc.get("count", 300)), float(sc.get("delay", 0.05))


def build_job(scenario: str, cfg: dict[str, Any], target: str | None = None,
              count: int | None = None, delay: float | None = None, run_id: str | None = None,
              params: dict[str, Any] | None = None) -> dict[str, Any]:
    """The Job manifest. `target` must already be resolved (host:port[,host:port])."""
    tl = cfg["traffic_lab"]
    if scenario not in tl["scenarios"]:
        raise TrafficLabError(f"unknown scenario {scenario!r}; one of {sorted(tl['scenarios'])}")
    sc = tl["scenarios"][scenario]
    mode = sc["mode"]
    slug = slugify(mode)
    d_count, d_delay = scenario_defaults(scenario, cfg)
    count = d_count if count is None else count
    delay = d_delay if delay is None else delay
    deadline = int(tl.get("job_deadline_seconds", 300))
    params = check_params(params)
    run_s = int(round(params["minutes"] * 60)) if params.get("minutes") else 0
    if run_s:
        # time-based run: the Job's limit follows the chosen minutes, plus room for the pod to
        # start (image pull) and for the generator to finish its last action and log a summary
        deadline = run_s + int(tl.get("job_start_margin_seconds", 120))
    if target is None:
        t = tl["targets"][sc.get("default_target") or next(iter(tl["targets"]))]
        target = f"{t['host']}:{t['port']}"
    if params.get("target_port") and "," not in target:
        target = f"{target.rsplit(':', 1)[0]}:{params['target_port']}"
    env = [
        {"name": "MODE", "value": mode},
        {"name": "TARGET", "value": target},
        {"name": "COUNT", "value": str(int(count))},
        {"name": "DELAY", "value": str(float(delay))},
        {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
        {"name": "PYTHONUNBUFFERED", "value": "1"},
        # finish (and log why) before Kubernetes kills the pod at activeDeadlineSeconds
        {"name": "TIME_BUDGET_S", "value": str(run_s if run_s else max(10, deadline - 30))},
        # ... counted from the Job's creation, not from when the script started: a pod that
        # waits for an image pull or a slow node would otherwise run past the deadline
        {"name": "JOB_DEADLINE_EPOCH", "value": str(int(time.time()) + deadline - 25)},
        # the deception controller's redirect (live/redirect.py) arrives as a pod annotation
        {"name": "REDIRECT_FILE", "value": "/etc/podinfo/annotations"},
    ]
    if mode in ("port_scan", "brute_force", "web_attack", "slow_dos"):
        lo, hi = benign_src_ports(cfg)
        env += [{"name": "BENIGN_MIX_S", "value": str(float(tl.get("benign_mix_seconds", 3)))},
                {"name": "BENIGN_SRC_PORT_LO", "value": str(lo)}, {"name": "BENIGN_SRC_PORT_HI", "value": str(hi)}]
    env += [{"name": str(k), "value": str(v)} for k, v in (sc.get("env") or {}).items()]
    over = {GEN_PARAMS[k]["env"]: str(v) for k, v in params.items() if GEN_PARAMS[k]["env"] and k != "minutes"}
    if run_s:
        over["RUN_SECONDS"] = str(run_s)
    env = [e for e in env if e["name"] not in over] + [{"name": k, "value": v} for k, v in over.items()]
    container = {
        "name": "generator", "image": tl.get("image", "python:3.13-alpine"),
        "command": ["python", "/app/traffic_generator.py"], "env": env,
        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                      "limits": {"cpu": "200m", "memory": "96Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
        "volumeMounts": [{"name": "script", "mountPath": "/app", "readOnly": True},
                         {"name": "podinfo", "mountPath": "/etc/podinfo", "readOnly": True}],
    }
    expect = sc.get("expect_class")
    labels = {"app": "traffic-lab", "scenario": slug, "expect-class": slugify(expect or "none")}
    pod = {
        "metadata": {"labels": labels},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container],
            "volumes": [{"name": "script", "configMap": {"name": "traffic-generator-script"}},
                        {"name": "podinfo", "downwardAPI": {"items": [
                            {"path": "annotations", "fieldRef": {"fieldPath": "metadata.annotations"}}]}}],
        },
    }
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"generateName": f"traffic-{slug}-", "namespace": tl["namespace"], "labels": dict(labels),
                     "annotations": {"ids/scenario": scenario, "ids/mode": mode, "ids/target": target[:250],
                                     "ids/expect-class": expect or "", "ids/run": run_id or "",
                                     "ids/count": str(int(count)), "ids/delay": str(float(delay)),
                                     "ids/params": json.dumps(params, sort_keys=True)[:250]}},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": deadline,
                 "ttlSecondsAfterFinished": 3600, "template": pod},
    }


def launch(scenario: str, target: str | None = None, count: int | None = None, delay: float | None = None,
           cfg: dict[str, Any] | None = None, run_id: str | None = None,
           params: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    if scenario not in cfg["traffic_lab"]["scenarios"]:
        raise TrafficLabError(f"unknown scenario {scenario!r}; one of {sorted(cfg['traffic_lab']['scenarios'])}")
    client, batch, core = _api(cfg)
    ready = check_ready(cfg)
    if not ready["ready"]:
        raise TrafficLabError(ready["reason"] + (f" — run: {ready['fix']}" if ready.get("fix") else ""))
    resolved = resolve_target(scenario, target, cfg, core)
    body = build_job(scenario, cfg, resolved["target"], count, delay, run_id, params)
    try:
        created = batch.create_namespaced_job(cfg["traffic_lab"]["namespace"], body)
    except client.exceptions.ApiException as e:
        raise TrafficLabError(f"Kubernetes refused the Job ({e.status}): {_api_message(e)}")
    log.info("traffic lab: launched %s (%s) -> %s", created.metadata.name, scenario, resolved["target"])
    ann = created.metadata.annotations or {}
    return {"job": created.metadata.name, "scenario": scenario, "mode": cfg["traffic_lab"]["scenarios"][scenario]["mode"],
            "target": resolved["target"], "target_label": resolved["label"], "note": resolved.get("note"),
            "expect_class": cfg["traffic_lab"]["scenarios"][scenario].get("expect_class"),
            "count": int(ann.get("ids/count", 0)), "delay": float(ann.get("ids/delay", 0)),
            "params": json.loads(ann.get("ids/params") or "{}")}


def _conditions(j) -> list[dict[str, Any]]:
    return [{"type": c.type, "status": c.status, "reason": c.reason, "message": c.message,
             "time": c.last_transition_time.isoformat() if c.last_transition_time else None}
            for c in (j.status.conditions or [])]


_REASON_TEXT = {
    "DeadlineExceeded": "Kubernetes stopped the Job at its time limit (activeDeadlineSeconds) and deleted its pod",
    "BackoffLimitExceeded": "the generator container exited with an error",
    "PodFailurePolicy": "a pod failure policy matched",
}


def failure_reason(j, pods: list | None = None, log_lines: list[str] | None = None,
                   events: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    """Why a Job failed (or cannot start), from its conditions, the container's termination
    state, Warning events and the generator log tail."""
    stuck = [e for e in (events or []) if e["reason"] == "FailedCreate"]
    if not j.status.failed and not any(c.type == "Failed" and c.status == "True" for c in (j.status.conditions or [])):
        if stuck and not pods:
            return {"job_reason": "FailedCreate", "job_message": stuck[-1]["message"], "deadline_seconds":
                    j.spec.active_deadline_seconds, "summary": f"pod could not be created: {stuck[-1]['message'][:300]}",
                    "log_tail": []}
        return None
    cond = next((c for c in (j.status.conditions or []) if c.type in ("Failed", "FailureTarget") and c.status == "True"), None)
    out: dict[str, Any] = {"job_reason": cond.reason if cond else None, "job_message": cond.message if cond else None,
                           "deadline_seconds": j.spec.active_deadline_seconds}
    for p in pods or []:
        for cs in p.status.container_statuses or []:
            t = (cs.state and cs.state.terminated) or (cs.last_state and cs.last_state.terminated)
            if t:
                out.update(exit_code=t.exit_code, container_reason=t.reason, container_message=(t.message or "")[:300] or None)
    reason = out.get("job_reason")
    parts = [_REASON_TEXT.get(reason, reason or "failed")]
    if out.get("exit_code") is not None:
        parts.append(f"container {out.get('container_reason') or 'terminated'}, exit code {out['exit_code']}")
    elif reason == "DeadlineExceeded":
        parts.append("no pod left to read (deleted with the Job's deadline)")
    tail = [ln for ln in (log_lines or []) if ln.strip()][-5:]
    last = None
    for ln in reversed(tail):
        try:
            rec = json.loads(ln)
        except ValueError:
            last = ln[:200]
            break
        if rec.get("action") in ("fatal", "budget_exhausted") or rec.get("error"):
            last = f"{rec.get('action')}: {rec.get('error') or rec.get('note') or ''}".strip(": ")
            break
    if last:
        parts.append(f"last log: {last}")
    if stuck and not pods:
        parts.append(f"pod could not be created: {stuck[-1]['message'][:200]}")
    out["summary"] = "; ".join(parts)
    out["log_tail"] = tail
    return out


def _job_state(s) -> str:
    if s.succeeded:
        return "succeeded"
    # a Job killed at its deadline can have failed=0 (its pod was deleted): trust the condition
    if s.failed or any(c.type == "Failed" and c.status == "True" for c in (s.conditions or [])):
        return "failed"
    return "running" if s.active else "pending"


def _job_events(core, ns: str, name: str) -> list[dict[str, Any]]:
    """Warning events of a Job (e.g. FailedCreate when PodSecurity or a quota rejects its pod)."""
    try:
        evs = core.list_namespaced_event(ns, field_selector=f"involvedObject.name={name},type=Warning",
                                         _request_timeout=5).items
    except Exception:  # noqa: BLE001
        return []
    return [{"reason": e.reason, "message": (e.message or "")[:400], "count": e.count} for e in evs][-5:]


def list_jobs(cfg: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Traffic-lab Jobs. Raises TrafficLabError when the cluster is unreachable."""
    cfg = cfg or load_config()
    _, batch, core = _api(cfg)
    try:
        jobs = batch.list_namespaced_job(cfg["traffic_lab"]["namespace"], label_selector=SCENARIO_LABEL,
                                         _request_timeout=6).items
    except Exception as e:  # noqa: BLE001
        raise TrafficLabError(f"could not list Jobs: {_api_message(e)}")
    out = []
    for j in jobs:
        s, ann = j.status, (j.metadata.annotations or {})
        stuck = None
        if not (s.active or s.succeeded or s.failed or s.conditions):     # pending: was its pod refused?
            stuck = _job_events(core, cfg["traffic_lab"]["namespace"], j.metadata.name)
        fail = failure_reason(j, [], None, stuck) if (s.failed or s.conditions or stuck) else None
        out.append({"name": j.metadata.name,
                    "scenario": ann.get("ids/scenario") or (j.metadata.labels or {}).get("scenario"),
                    "expect_class": ann.get("ids/expect-class"), "run": ann.get("ids/run"),
                    "failure": fail["summary"] if fail else None,
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
    benign = {"answered": 0, "failed": 0, "while_redirected": 0}
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
        if a == "benign_mix":                # benign requests mixed into an attack run
            benign["failed" if rec.get("error") else "answered"] += 1
            benign["while_redirected"] += 1 if rec.get("redirected") and not rec.get("error") else 0
            continue
        if a in ("start", "done", "interrupted", "slow_established", "budget_exhausted", "run_complete", "redirected"):
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
            "verified": ok > 0, "benign_mix": benign if sum(benign.values()) else None}


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
        term = next((cs.state.terminated for cs in (p.status.container_statuses or [])
                     if cs.state and cs.state.terminated), None)
        pod_info.append({"name": p.metadata.name, "phase": p.status.phase, "waiting": waiting, "ip": p.status.pod_ip,
                         "exit_code": term.exit_code if term else None, "reason": term.reason if term else None})
        if p.status.phase in ("Running", "Succeeded", "Failed"):
            try:
                text += core.read_namespaced_pod_log(p.metadata.name, ns, tail_lines=tail, _request_timeout=8)
            except Exception as e:  # noqa: BLE001
                log_error = _api_message(e)
    ann = j.metadata.annotations or {}
    summary = summarize_log(text)
    lines = text.splitlines()
    return {"name": name, "scenario": ann.get("ids/scenario"), "target": ann.get("ids/target"),
            "expect_class": ann.get("ids/expect-class"), "run": ann.get("ids/run"),
            "state": _job_state(j.status), "started": j.status.start_time.isoformat() if j.status.start_time else None,
            "completed": j.status.completion_time.isoformat() if j.status.completion_time else None,
            "pods": pod_info, "verification": summary, "log_error": log_error,
            "conditions": _conditions(j), "failure": failure_reason(j, pods, lines, _job_events(core, ns, name)),
            "events": _job_events(core, ns, name),
            "log_tail": lines[-25:]}


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
