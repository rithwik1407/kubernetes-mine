"""Bring the lab's target apps up and make them reachable on this machine.

The target apps (Node-RED, Grafana, InfluxDB) run as ClusterIP Services in K3s, so nothing
listens on localhost:<port> until something forwards it. This module:

  * deploys deploy/target-apps/target-apps.yaml when an app's Deployment is missing,
  * waits until every app has a Ready pod,
  * runs one `kubectl port-forward` per app, bound to 127.0.0.1 only, and restarts it when it
    exits (a pod restart ends a port-forward), and
  * checks each local URL with an HTTP request.

Every command is a fixed argument list built from config/live.yaml (app names, namespace and
ports are validated here); nothing from a request reaches a command line. The forwards use the
default kubeconfig (KUBECONFIG or ~/.kube/config), because the least-privilege ids-controller
identity may not open port-forwards. WSL2 forwards Windows localhost to sockets listening in
WSL, so the URLs open in the Windows browser too.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from typing import Any

from live.config import load_config, repo_path
from live.logging_setup import get_logger

log = get_logger(__name__)
_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_LOCK = threading.RLock()
_FWD: dict[str, dict[str, Any]] = {}          # app -> {proc, port, started, restarts, error}
_SUPERVISOR: dict[str, Any] = {"thread": None, "stop": threading.Event()}


class TargetAccessError(RuntimeError):
    pass


def settings(cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    ta = cfg.get("target_apps") or {}
    ns = ta.get("namespace", "target-apps")
    apps = {}
    for key, t in cfg["traffic_lab"]["targets"].items():
        svc = t["host"].split(".")[0]
        local = int((ta.get("local_ports") or {}).get(key, t["port"]))
        if not (_NAME.match(key) and _NAME.match(svc) and 1 <= int(t["port"]) <= 65535 and 1024 <= local <= 65535):
            raise TargetAccessError(f"invalid target app config for {key!r}")
        apps[key] = {"service": svc, "port": int(t["port"]), "local_port": local, "deployment": svc,
                     "path": (ta.get("open_paths") or {}).get(key, "/")}
    if not _NAME.match(ns):
        raise TargetAccessError(f"invalid namespace {ns!r}")
    return {"namespace": ns, "apps": apps, "manifest": repo_path(ta.get("manifest", "deploy/target-apps/target-apps.yaml")),
            "kubectl": ta.get("kubectl", "kubectl"), "address": "127.0.0.1",
            "port_forward": bool(ta.get("port_forward", True)), "ready_timeout": int(ta.get("ready_timeout_seconds", 180))}


def _env() -> dict[str, str]:
    from live.kube import default_kubeconfigs
    env = dict(os.environ)
    for p in default_kubeconfigs():
        if p.is_file():
            env["KUBECONFIG"] = str(p)
            break
    return env


def _kubectl(st: dict[str, Any], *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    exe = shutil.which(st["kubectl"])
    if not exe:
        raise TargetAccessError(f"{st['kubectl']} not found on PATH")
    return subprocess.run([exe, *args], capture_output=True, text=True, timeout=timeout, env=_env())


def url(app: dict[str, Any]) -> str:
    return f"http://localhost:{app['local_port']}{app['path']}"


def probe(app: dict[str, Any], timeout: float = 3) -> dict[str, Any]:
    """GET the forwarded URL: any HTTP answer (even 401/404) means the app is reachable."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{app['local_port']}{app['path']}", timeout=timeout) as r:
            return {"reachable": True, "http_status": r.status}
    except urllib.error.HTTPError as e:
        return {"reachable": True, "http_status": e.code}
    except Exception as e:  # noqa: BLE001
        return {"reachable": False, "error": type(e).__name__ + (f": {e.reason}" if hasattr(e, "reason") else "")}


# --- port-forwards ------------------------------------------------------------------------
def _errlog(key: str):
    return repo_path(f"logs/port-forward-{key}.log")


def _start_forward(key: str, app: dict[str, Any], st: dict[str, Any]) -> None:
    exe = shutil.which(st["kubectl"])
    if not exe:
        _FWD[key] = {"proc": None, "port": app["local_port"], "error": f"{st['kubectl']} not found on PATH", "restarts": 0}
        return
    argv = [exe, "port-forward", "-n", st["namespace"], f"svc/{app['service']}",
            f"{app['local_port']}:{app['port']}", "--address", st["address"]]
    # kubectl prints a line per connection: send that to /dev/null (a full pipe would block
    # it) and keep only errors, in a small file, to explain an exit
    errlog = _errlog(key)
    errlog.parent.mkdir(parents=True, exist_ok=True)
    with open(errlog, "w") as fh:
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=fh, env=_env())  # same process group: Ctrl+C stops it too
    prev = _FWD.get(key) or {}
    _FWD[key] = {"proc": proc, "port": app["local_port"], "started": time.time(), "error": None,
                 "restarts": prev.get("restarts", -1) + 1}
    log.info("port-forward %s: %s -> svc/%s:%s (pid %s)", key, url(app), app["service"], app["port"], proc.pid)


def _check_forward(key: str) -> None:
    f = _FWD.get(key)
    if not f or not f.get("proc") or f["proc"].poll() is None:
        return
    err = ""
    try:
        lines = _errlog(key).read_text(errors="replace").strip().splitlines()
        err = lines[-1] if lines else ""
    except OSError:
        pass
    f["error"] = (err or f"kubectl port-forward exited with {f['proc'].returncode}")[:300]
    f["proc"] = None


def _supervise(cfg: dict[str, Any]) -> None:
    stop = _SUPERVISOR["stop"]
    while not stop.wait(5):
        try:
            st = settings(cfg)
            # kubectl port-forward can stay alive with a dead stream ("error creating forwarding
            # stream ... Timeout occurred") and never exit: probe each forward every 15 s (outside
            # the lock) and restart it after two failed probes in a row
            due = []
            with _LOCK:
                for key in st["apps"]:
                    _check_forward(key)
                    f = _FWD.get(key)
                    if f and f.get("proc") and time.time() - f.get("probed", 0) >= 15 \
                            and time.time() - f.get("started", 0) >= 10:
                        f["probed"] = time.time()
                        due.append(key)
            results = {key: probe(st["apps"][key], timeout=4)["reachable"] for key in due}
            with _LOCK:
                for key, ok in results.items():
                    f = _FWD.get(key)
                    if not f or not f.get("proc"):
                        continue
                    f["fails"] = 0 if ok else f.get("fails", 0) + 1
                    if f["fails"] >= 2:
                        log.warning("port-forward %s not answering, restarting it", key)
                        f["proc"].terminate()
                        f.update(proc=None, error="stopped answering; restarted", started=0, fails=0)
                for key, app in st["apps"].items():
                    f = _FWD.get(key)
                    # restart a dead forward (pod restarted, cluster back up), at most every 10 s
                    if f is not None and f.get("proc") is None and time.time() - f.get("started", 0) > 10:
                        _start_forward(key, app, st)
        except Exception:  # noqa: BLE001
            log.exception("port-forward supervisor")


def ensure_forwards(cfg: dict[str, Any] | None = None) -> None:
    cfg = cfg or load_config()
    st = settings(cfg)
    if not st["port_forward"]:
        return
    with _LOCK:
        for key, app in st["apps"].items():
            _check_forward(key)
            f = _FWD.get(key)
            if f is None or f.get("proc") is None:
                _start_forward(key, app, st)
        t = _SUPERVISOR["thread"]
        if t is None or not t.is_alive():
            _SUPERVISOR["stop"].clear()
            t = threading.Thread(target=_supervise, args=(cfg,), name="target-port-forward", daemon=True)
            _SUPERVISOR["thread"] = t
            t.start()


def stop_forwards() -> None:
    with _LOCK:
        _SUPERVISOR["stop"].set()
        for f in _FWD.values():
            p = f.get("proc")
            if p and p.poll() is None:
                p.terminate()
        _FWD.clear()


# --- deploy and wait ----------------------------------------------------------------------
def _deployments(st: dict[str, Any]) -> dict[str, dict[str, int]]:
    p = _kubectl(st, "get", "deploy", "-n", st["namespace"], "-o",
                 "jsonpath={range .items[*]}{.metadata.name} {.spec.replicas} {.status.readyReplicas}{\"\\n\"}{end}",
                 timeout=20)
    if p.returncode != 0:
        if "NotFound" in p.stderr or "not found" in p.stderr:
            return {}
        raise TargetAccessError((p.stderr.strip() or "kubectl get deploy failed")[:300])
    out = {}
    for line in p.stdout.splitlines():
        parts = line.split()
        if parts:
            out[parts[0]] = {"replicas": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                             "ready": int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0}
    return out


def start(cfg: dict[str, Any] | None = None, wait: bool = True) -> dict[str, Any]:
    """Deploy what is missing, wait for Ready pods, start the port-forwards, probe the URLs."""
    cfg = cfg or load_config()
    st = settings(cfg)
    steps: list[str] = []
    deps = _deployments(st)
    missing = [a["deployment"] for a in st["apps"].values() if a["deployment"] not in deps]
    if missing:
        p = _kubectl(st, "apply", "-f", str(st["manifest"]), timeout=60)
        if p.returncode != 0:
            raise TargetAccessError(f"kubectl apply failed: {(p.stderr or p.stdout).strip()[:300]}")
        steps.append(f"deployed {', '.join(missing)} from {st['manifest'].name}")
    scaled = [k for k, d in deps.items() if k in {a['deployment'] for a in st['apps'].values()} and d["replicas"] == 0]
    for name in scaled:                       # a Deployment scaled to 0 never gets Ready
        _kubectl(st, "scale", "deploy", name, "-n", st["namespace"], "--replicas=1", timeout=20)
        steps.append(f"scaled {name} to 1 replica")
    if wait:
        deadline = time.monotonic() + st["ready_timeout"]
        for a in st["apps"].values():
            left = max(5, int(deadline - time.monotonic()))
            p = _kubectl(st, "rollout", "status", f"deploy/{a['deployment']}", "-n", st["namespace"],
                         f"--timeout={left}s", timeout=left + 10)
            steps.append(f"{a['deployment']}: " + ("ready" if p.returncode == 0 else
                                                     f"not ready ({(p.stderr or p.stdout).strip()[:160]})"))
    ensure_forwards(cfg)
    if st["port_forward"]:
        steps.append("port-forwards started on 127.0.0.1")
        time.sleep(1.5)                       # let kubectl bind its ports before probing
    res = status(cfg)
    res["steps"] = steps
    for a in res["apps"]:
        log.info("target app %s: %s (%s)", a["key"], a["url"], "reachable" if a.get("reachable") else a.get("error"))
    return res


def status(cfg: dict[str, Any] | None = None, probe_urls: bool = True) -> dict[str, Any]:
    cfg = cfg or load_config()
    st = settings(cfg)
    apps = []
    with _LOCK:
        for key, app in st["apps"].items():
            _check_forward(key)
            f = _FWD.get(key) or {}
            row = {"key": key, "service": app["service"], "port": app["port"], "local_port": app["local_port"],
                   "url": url(app), "forwarding": bool(f.get("proc")), "forward_error": f.get("error"),
                   "forward_restarts": max(0, f.get("restarts", 0)), "forward_since": f.get("started")}
            apps.append(row)
    if probe_urls:
        for row in apps:
            res = probe(st["apps"][row["key"]])
            if not res["reachable"] and row["forwarding"]:
                # kubectl port-forward now and then hangs one connection and serves the next
                # one normally: try once more before showing the app as down
                res = probe(st["apps"][row["key"]])
            if not res["reachable"] and not row["forwarding"]:
                res["error"] = row["forward_error"] or "port-forward not started"
            row.update(res)
    return {"port_forward": st["port_forward"], "namespace": st["namespace"], "apps": apps,
            "all_reachable": all(a.get("reachable") for a in apps)}
