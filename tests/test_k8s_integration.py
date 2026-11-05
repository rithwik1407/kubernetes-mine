"""Kubernetes integration tests against a REAL cluster (opt-in).

    IDS_K8S_TESTS=1 python -m pytest tests/test_k8s_integration.py -v

Needs the lab deployed (bash scripts/setup_lab.sh) and the target apps running. They
create a real traffic Job and a real decoy, wait for them, and clean up afterwards.
"""
import os
import time

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("IDS_K8S_TESTS") != "1", reason="set IDS_K8S_TESTS=1 to run against a cluster")


@pytest.fixture(scope="module")
def cfg():
    from live.config import load_config
    return load_config()


def test_cluster_and_targets_reachable(cfg):
    from live.k8s_status import cluster_status, targets_status
    k = cluster_status(cfg)
    assert k["connected"], k.get("error")
    assert all(n["ready"] == "True" for n in k["nodes"])
    t = targets_status(cfg)
    assert t["all_running"], t


def test_traffic_job_runs_and_is_verified(cfg):
    from live.trafficlab import delete_job, job_detail, launch
    job = launch("web_recon", "nodered", count=20, delay=0.05, cfg=cfg)
    try:
        deadline = time.time() + 180
        d = None
        while time.time() < deadline:
            d = job_detail(job["job"], cfg)
            if d["state"] in ("succeeded", "failed"):
                break
            time.sleep(3)
        assert d["state"] == "succeeded", d
        assert d["verification"]["verified"] and d["verification"]["ok"] >= 20, d["verification"]
    finally:
        delete_job(job["job"], cfg)


def test_port_scan_targets_pod_ip(cfg):
    from live.trafficlab import _api, resolve_target
    _, _, core = _api(cfg)
    r = resolve_target("port_scan", "nodered", cfg, core)
    assert r["target"].startswith("10."), r


def test_decoy_deploy_ready_reachable_and_cleanup(cfg):
    from live.k8s_decoys import DecoyManager
    m = DecoyManager(cfg)
    name = "decoy-k8s-inventory"
    m.remove(name)
    info = m.deploy("k8s-inventory", 1)
    try:
        deadline = time.time() + 150
        d = {}
        while time.time() < deadline:
            d = m.list_decoys().get(name, {})
            if d.get("ready_replicas", 0) >= 1 and (d.get("endpoints") or 0) >= 1:
                break
            time.sleep(2)
        assert d.get("ready_replicas") == 1 and d.get("endpoints") == 1, d
        assert d["service_ip"] == info["service_ip"]
    finally:
        assert m.remove(name) is True
    time.sleep(2)
    assert name not in m.list_decoys()
