"""Pipeline orchestration and target-pod status with fake Kubernetes (no cluster needed)."""
from types import SimpleNamespace as NS

import pytest

from live import capture as cap
from live import k8s_status, pipeline, trafficlab


def _pod(name, phase="Running", ready=True, waiting=None):
    cs = NS(ready=ready, restart_count=0, state=NS(waiting=NS(reason=waiting) if waiting else None))
    return NS(metadata=NS(name=name, labels={"app": name.split("-")[0]}, deletion_timestamp=None),
              status=NS(phase=phase, pod_ip="10.42.0.5", container_statuses=[cs]))


class FakeCore:
    def __init__(self, pods): self.pods = pods
    def list_namespaced_pod(self, ns, **kw): return NS(items=self.pods)
    def list_namespaced_service(self, ns, **kw): return NS(items=[NS(metadata=NS(name="nodered"))])


def _patch_core(monkeypatch, pods):
    import kubernetes.client as kc
    monkeypatch.setattr("live.kube.api_client", lambda cfg=None: (object(), "test"))
    monkeypatch.setattr(kc, "CoreV1Api", lambda api: FakeCore(pods))


def test_targets_all_running(cfg, monkeypatch):
    _patch_core(monkeypatch, [_pod("nodered-1"), _pod("grafana-1"), _pod("influxdb-1")])
    t = k8s_status.targets_status(cfg)
    assert t["connected"] and t["all_running"] and t["running"] == 3


def test_targets_reports_crashloop_and_missing(cfg, monkeypatch):
    _patch_core(monkeypatch, [_pod("nodered-1"), _pod("grafana-1", ready=False, waiting="CrashLoopBackOff")])
    t = {a["key"]: a["state"] for a in k8s_status.targets_status(cfg)["apps"]}
    assert t == {"nodered": "running", "grafana": "CrashLoopBackOff", "influxdb": "not found"}


def test_targets_without_cluster_never_raises(cfg, monkeypatch):
    from live.kube import KubeUnavailable
    def boom(cfg=None): raise KubeUnavailable("no kubeconfig found")
    monkeypatch.setattr("live.kube.api_client", boom)
    t = k8s_status.targets_status(cfg)
    assert not t["connected"] and "no kubeconfig" in t["error"]


def test_capture_module_imports_without_fcntl_and_reports_support(cfg):
    assert "supported" in cap.support(cfg)


def test_run_scenario_auto_starts_capture_and_records_run(cfg, monkeypatch):
    started = []
    monkeypatch.setattr(pipeline.cap, "read_state", lambda c=None: {"running": False})
    monkeypatch.setattr(pipeline.cap, "start", lambda w, p, c: started.append(1) or {"running": True})
    monkeypatch.setattr(pipeline, "launch", lambda *a, **k: {"job": "traffic-port-scan-x", "target": "svc:1880"})
    run = pipeline.run_scenario("port_scan", cfg=cfg)
    assert started and run["capture_started"] and run["expect_class"] == "PortScan"
    monkeypatch.setattr(pipeline, "list_jobs", lambda c=None: [{"name": "traffic-port-scan-x", "state": "running"}])
    st = pipeline.run_status(cfg=cfg)
    assert st["run"]["job"] == "traffic-port-scan-x" and len(st["stages"]) == 4


def test_run_scenario_survives_unsupported_capture(cfg, monkeypatch):
    monkeypatch.setattr(pipeline.cap, "read_state", lambda c=None: {"running": False})
    def nope(*a): raise cap.ServiceError("live capture needs Linux")
    monkeypatch.setattr(pipeline.cap, "start", nope)
    monkeypatch.setattr(pipeline, "launch", lambda *a, **k: {"job": "j1", "target": "t"})
    run = pipeline.run_scenario("benign", cfg=cfg)
    assert not run["capture_started"] and any("needs Linux" in n for n in run["notes"])


def test_launch_error_propagates(cfg, monkeypatch):
    monkeypatch.setattr(pipeline.cap, "read_state", lambda c=None: {"running": True})
    def bad(*a, **k): raise trafficlab.TrafficLabError("traffic lab not deployed")
    monkeypatch.setattr(pipeline, "launch", bad)
    with pytest.raises(trafficlab.TrafficLabError):
        pipeline.run_scenario("benign", cfg=cfg)
