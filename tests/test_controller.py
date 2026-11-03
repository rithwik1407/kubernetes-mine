"""MAPE-K controller tests with a fake Kubernetes manager (no cluster needed)."""
from datetime import datetime, timezone

import pytest

from live import db
from live.controller import MapeKController


class FakeManager:
    def __init__(self):
        self.deployed = {}
    def deploy(self, profile, replicas):
        self.deployed[f"decoy-{profile}"] = replicas
        return {"port": 80, "service_ip": "10.0.0.1"}
    def scale(self, name, replicas):
        self.deployed[name] = replicas
    def remove(self, name):
        self.deployed.pop(name, None)
    def list_decoys(self):
        return {n: {"ready_replicas": 1} for n in self.deployed}
    def interaction_lines(self, name, since):
        return []


def _now():
    return datetime.now(timezone.utc).isoformat()


def test_high_confidence_portscan_deploys_decoy(cfg):
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    with db.connect(cfg["paths"]["database"]) as c:
        db.insert_row(c, "detections", predicted_class="PortScan", confidence=0.98, is_malicious=1,
                      source="live", detected_at=_now(), src_ip="10.42.0.9", dst_ip="10.43.0.5",
                      dst_port=1880, protocol=6, model="m")
    summary = ctl.run_cycle()
    assert summary["evidence"]["detections"] == 1
    assert any(a["action"] == "deploy" and a["result"] == "ok" for a in summary["actions"])
    assert "decoy-web-portal" in mgr.deployed


def test_benign_never_deploys(cfg):
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    with db.connect(cfg["paths"]["database"]) as c:
        # is_malicious=0 means it never enters the controller's monitor query
        db.insert_row(c, "detections", predicted_class="BENIGN", confidence=0.99, is_malicious=0,
                      source="live", detected_at=_now(), src_ip="10.42.0.3", model="m")
    ctl.run_cycle()
    assert mgr.deployed == {}


def test_flow_burst_triggers_decoy_by_port(cfg):
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    with db.connect(cfg["paths"]["database"]) as c:
        db.insert_row(c, "behavior_alerts", src_ip="10.42.0.7", dst_ip="10.43.0.5", dst_port=1880,
                      protocol=6, flows=40, rate_per_s=4.0, window_s=10.0, ml_malicious_flows=0,
                      ml_classes="{}", detected_at=_now())
    summary = ctl.run_cycle()
    assert summary["evidence"]["alerts"] == 1
    # port 1880 -> nodered decoy per behavior_policy
    assert "decoy-nodered" in mgr.deployed


def test_max_active_decoys_suppresses(cfg):
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    now = _now()
    with db.connect(cfg["paths"]["database"]) as c:
        for cls, port in [("PortScan", 1), ("BruteForce", 2), ("WebAttack", 3), ("DDoS", 4), ("DoS", 5)]:
            db.insert_row(c, "detections", predicted_class=cls, confidence=0.98, is_malicious=1,
                          source="live", detected_at=now, src_ip=f"10.42.0.{port}", dst_ip="10.43.0.5",
                          dst_port=1880, protocol=6, model="m")
    ctl.run_cycle()
    assert len(mgr.deployed) <= cfg["deception"]["max_active_decoys"]


def test_simulated_event_is_separate(cfg):
    ctl = MapeKController(cfg, manager=FakeManager())
    eid = ctl.submit_simulated_event("WebAttack", 0.99, "10.0.0.3", 1, "demo")
    assert eid > 0
    with db.connect(cfg["paths"]["database"]) as c:
        assert c.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM simulated_events").fetchone()[0] == 1


def test_unknown_simulated_class_rejected(cfg):
    ctl = MapeKController(cfg, manager=FakeManager())
    with pytest.raises(ValueError):
        ctl.submit_simulated_event("NotARealClass", 0.9)
