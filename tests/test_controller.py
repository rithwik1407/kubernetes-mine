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


def _flows(cls, n, conf, src="10.42.0.9", port=1880):
    with db.connect(DBP[0]) as c:
        for _ in range(n):
            db.insert_row(c, "detections", predicted_class=cls, confidence=conf, is_malicious=1,
                          source="live", detected_at=_now(), src_ip=src, dst_ip="10.43.0.5",
                          dst_port=port, protocol=6, model="m")


DBP = [None]


@pytest.fixture(autouse=True)
def _db(cfg):
    DBP[0] = cfg["paths"]["database"]


def test_single_confident_flow_never_triggers(cfg):
    """The old single-flow threshold is gone: one 0.98 PortScan flow is recorded, not acted on."""
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    _flows("PortScan", 1, 0.98)
    summary = ctl.run_cycle()
    assert summary["evidence"]["detections"] == 1
    assert mgr.deployed == {}
    with db.connect(DBP[0]) as c:
        reason = c.execute("SELECT reason FROM decisions ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert "below policy" in reason and "10 flows" in reason


def test_aggregated_portscan_deploys_decoy(cfg):
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    pol = ctl.class_policy("PortScan")
    _flows("PortScan", pol["min_flows"], 0.97)
    summary = ctl.run_cycle()
    assert any(a["action"] == "deploy" and a["result"] == "ok" for a in summary["actions"])
    assert "decoy-web-portal" in mgr.deployed
    eng = ctl.engagements()
    assert len(eng) == 1 and eng[0]["src_ip"] == "10.42.0.9" and eng[0]["state"] == "active"
    assert "decoy-web-portal" in eng[0]["decoys"]
    with db.connect(DBP[0]) as c:
        assert c.execute("SELECT COUNT(*) FROM decisions WHERE action = 'engage'").fetchone()[0] == 1
        # no redirect before the decoy is Ready
        assert c.execute("SELECT COUNT(*) FROM decisions WHERE action = 'redirect'").fetchone()[0] == 0


class FakeRedirector:
    def __init__(self):
        self.calls = []
    def quarantine(self, ip, cfg, redirect_to=None, only=None):
        self.calls.append((ip, redirect_to))
        return {"applied": True, "namespace": "ids-traffic", "pod": "p", "label": "l", "to": redirect_to,
                "reason": f"redirected to {redirect_to}"}
    def release(self, rd, cfg):
        self.calls.append(("release", rd.get("to")))
        return {"released": True, "reason": "released"}


def test_redirect_waits_for_ready_decoy_then_points_source_at_it(cfg):
    mgr, red = FakeManager(), FakeRedirector()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.redirector = red
    ctl.set_enabled(True)
    _flows("PortScan", ctl.class_policy("PortScan")["min_flows"], 0.97)
    ctl.run_cycle()                       # engage + deploy (decoy not Ready yet)
    assert red.calls == []
    assert ctl.engagements()[0]["redirect"]["pending"]
    ctl.run_cycle()                       # housekeeping sees the decoy Ready -> redirect
    assert red.calls == [("10.42.0.9", "decoy-web-portal.ids-deception.svc.cluster.local:80")]
    e = ctl.engagements()[0]
    assert e["redirect"]["applied"] and e["redirect"]["decoy"] == "decoy-web-portal"
    ctl.run_cycle()                       # applied once only
    assert len(red.calls) == 1
    with db.connect(DBP[0]) as c:
        r = c.execute("SELECT result, reason FROM decisions WHERE action = 'redirect'").fetchall()
    assert len(r) == 1 and r[0][0] == "ok" and "is Ready" in r[0][1]


def test_low_mean_confidence_does_not_trigger(cfg):
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    ctl.set_detection_policy(None, None, engage_severity="custom")   # per-class values
    _flows("DoS", 30, 0.81)          # enough flows, each >= 0.80, but mean 0.81 < 0.85
    ctl.run_cycle()
    assert mgr.deployed == {}


def test_medium_severity_engages_and_high_does_not(cfg):
    """Default engage_severity=medium: 10 PortScan flows at 0.70 (Threats page "medium")
    create a decoy; with engage_severity=high the same evidence does not."""
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    ctl.set_detection_policy(None, None, engage_severity="high")
    _flows("PortScan", 12, 0.70)
    ctl.run_cycle()
    assert mgr.deployed == {}
    ctl.set_detection_policy(None, None, engage_severity="medium")
    _flows("PortScan", 12, 0.70, src="10.42.0.10")
    ctl.run_cycle()
    assert mgr.deployed and ctl.engagements()[0]["src_ip"] == "10.42.0.10"
    assert ctl.class_policy("PortScan")["min_confidence"] == 0.6


def test_engagement_reuses_a_running_decoy_when_new_ones_are_blocked(cfg):
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    ctl.d["max_active_decoys"] = 1
    _flows("PortScan", 12, 0.97)
    ctl.run_cycle()
    assert len(mgr.deployed) == 1
    _flows("BruteForce", 12, 0.97, src="10.42.0.11")   # limit reached: no new decoy allowed
    ctl.run_cycle()
    e = next(x for x in ctl.engagements() if x["src_ip"] == "10.42.0.11")
    assert e["decoys"] == list(mgr.deployed)              # linked to the running decoy instead


def test_allowlisted_source_is_never_acted_on(cfg):
    """Even if control-plane flows were stored as malicious, the controller refuses them."""
    cfg["detection"]["allowlist"]["addresses"] = {"10.42.0.9": "test control plane"}
    from live import allowlist
    allowlist.reset_cache()
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    _flows("PortScan", 20, 0.99)
    ctl.run_cycle()
    assert mgr.deployed == {}


def test_release_after_quiet_period_and_cooldown(cfg):
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    ctl.set_detection_policy(None, {"quiet_seconds": 10, "reengage_cooldown_seconds": 600})
    _flows("WebAttack", ctl.class_policy("WebAttack")["min_flows"], 0.99)
    ctl.run_cycle()
    assert ctl.engagements()[0]["state"] == "active"
    with db.connect(DBP[0]) as c:          # pretend the last evidence was long ago
        c.execute("UPDATE engagements SET last_evidence_at = '2000-01-01T00:00:00+00:00'")
    ctl.run_cycle()
    e = ctl.engagements()[0]
    assert e["state"] == "released" and mgr.deployed == {}     # decoys torn down
    _flows("WebAttack", ctl.class_policy("WebAttack")["min_flows"], 0.99)                                # fresh evidence inside the cooldown
    ctl.run_cycle()
    assert len(ctl.engagements()) == 1 and mgr.deployed == {}
    with db.connect(DBP[0]) as c:
        assert "re-engage cooldown" in c.execute("SELECT reason FROM decisions ORDER BY id DESC LIMIT 1").fetchone()[0]


def test_detection_policy_override_and_validation(cfg):
    ctl = MapeKController(cfg, manager=FakeManager())
    ctl.set_detection_policy({"PortScan": {"min_flows": 2}}, None)
    assert ctl.class_policy("PortScan")["min_flows"] == 2
    assert ctl.detection_policy()["overridden"]
    with pytest.raises(ValueError):
        ctl.set_detection_policy({"PortScan": {"min_confidence": 1.5}}, None)
    with pytest.raises(ValueError):
        ctl.set_detection_policy({"NotAClass": {"min_flows": 2}}, None)
    ctl.set_detection_policy(None, None, reset=True)
    assert ctl.class_policy("PortScan")["min_flows"] == cfg["deception"]["detection_policy"]["PortScan"]["min_flows"]


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
    """A burst acts when the model also classified some of the source's flows as an attack
    (4 flows: below the ML policy's 10, above the burst rule's 3)."""
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    _flows("BruteForce", 4, 0.7, src="10.42.0.7")
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
    for cls, port in [("PortScan", 1), ("BruteForce", 2), ("WebAttack", 3), ("DDoS", 4), ("DoS", 5)]:
        _flows(cls, 25, 0.98, src=f"10.42.0.{port}")
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


def test_decoy_pod_is_never_engaged(cfg, monkeypatch):
    """Decoy replies can look like a sweep (reverse-direction flows); the decoy itself is not an attacker."""
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    monkeypatch.setattr(ctl, "decoy_ips", lambda: {"10.42.0.9"})
    ctl.set_enabled(True)
    _flows("PortScan", 20, 0.99)
    ctl.run_cycle()
    assert mgr.deployed == {} and ctl.engagements() == []


def test_one_decoy_per_engagement_and_no_scaling_by_default(cfg):
    """PortScan maps to [web-portal, k8s-inventory]; only the first (the one the redirect
    uses) is deployed, and repeated evidence never scales it past max_replicas 1."""
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    _flows("PortScan", 40, 0.98)
    ctl.run_cycle()
    _flows("PortScan", 40, 0.98)
    ctl.run_cycle()
    assert mgr.deployed == {"decoy-web-portal": 1}


class AckRedirector(FakeRedirector):
    def __init__(self):
        super().__init__()
        self.ack = False
    def annotate(self, ip, cfg, redirect_to=None, only=None):
        self.calls.append(("annotate", redirect_to))
        return {"annotated": True, "namespace": "ids-traffic", "pod": "p", "to": redirect_to}
    def acknowledged(self, pod, ns, to, since, cfg):
        return self.ack


def test_quarantine_label_waits_for_the_generator_to_confirm_the_redirect(cfg):
    mgr, red = FakeManager(), AckRedirector()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.redirector = red
    ctl.set_enabled(True)
    _flows("PortScan", 12, 0.97)
    ctl.run_cycle()                       # engage + deploy
    ctl.run_cycle()                       # decoy Ready -> annotations only
    to = "decoy-web-portal.ids-deception.svc.cluster.local:80"
    assert red.calls == [("annotate", to)]
    rd = ctl.engagements()[0]["redirect"]
    assert rd["pending"] and rd["phase"] == "annotated" and not rd.get("applied")
    ctl.run_cycle()                       # not confirmed yet, inside the timeout: no label
    assert red.calls == [("annotate", to)]
    red.ack = True
    ctl.run_cycle()                       # the generator confirmed: redirected, NOT quarantined
    assert red.calls == [("annotate", to)]
    rd = ctl.engagements()[0]["redirect"]
    assert rd["applied"] and rd["acknowledged"] and rd["quarantined"] is False and "confirmed" in rd["reason"]
    assert "benign requests keep reaching the real target" in rd["reason"]


def test_redirect_without_confirmation_is_quarantined(cfg):
    cfg["deception"]["redirect"]["ack_timeout_seconds"] = 0
    mgr, red = FakeManager(), AckRedirector()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.redirector = red
    ctl.set_enabled(True)
    _flows("PortScan", 12, 0.97)
    ctl.run_cycle(); ctl.run_cycle(); ctl.run_cycle()
    to = "decoy-web-portal.ids-deception.svc.cluster.local:80"
    assert red.calls[-1] == ("10.42.0.9", to)          # quarantine label applied
    assert "quarantined anyway" in ctl.engagements()[0]["redirect"]["reason"]


def test_quarantine_always_mode_labels_a_confirmed_pod(cfg):
    cfg["deception"]["redirect"]["quarantine"] = "always"
    mgr, red = FakeManager(), AckRedirector()
    red.ack = True
    ctl = MapeKController(cfg, manager=mgr)
    ctl.redirector = red
    ctl.set_enabled(True)
    _flows("PortScan", 12, 0.97)
    ctl.run_cycle(); ctl.run_cycle(); ctl.run_cycle()
    assert red.calls[-1] == ("10.42.0.9", "decoy-web-portal.ids-deception.svc.cluster.local:80")


def test_orphan_decoys_are_removed_after_the_grace_period(cfg):
    mgr = FakeManager()
    mgr.deployed["decoy-web-portal"] = 1          # left over from an older version
    old = "2020-01-01T00:00:00+00:00"
    mgr.list_decoys = lambda: {n: {"ready_replicas": 1, "created": old, "profile": "web-portal"} for n in mgr.deployed}
    ctl = MapeKController(cfg, manager=mgr)
    ctl.run_cycle()
    assert mgr.deployed == {}
    with db.connect(DBP[0]) as c:
        reason = c.execute("SELECT reason FROM decisions WHERE action = 'remove'").fetchone()[0]
    assert "left over" in reason


def test_second_trigger_on_an_engaged_source_adds_no_second_decoy(cfg):
    """Engagement #60 in the sandbox got two decoys: PortScan evidence engaged the source,
    then a second class (another trigger) planned its own profile. An engaged source keeps
    the one decoy it has; the second trigger only refreshes it."""
    cfg["deception"]["cooldown_seconds"] = 0
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    _flows("PortScan", 40, 0.98)
    ctl.run_cycle()
    _flows("BruteForce", 40, 0.98, port=3000)
    ctl.run_cycle()
    assert mgr.deployed == {"decoy-web-portal": 1}
    engs = ctl.engagements()
    assert len(engs) == 1 and engs[0]["decoys"] == ["decoy-web-portal"]


def test_ml_and_behaviour_triggers_in_one_cycle_plan_one_decoy(cfg):
    """Sandbox engagements #61/#62: the ML trigger and a flow-burst trigger for the same
    source arrived in the same cycle, before the first decoy was linked to the engagement."""
    from live import db as _db
    ctl = MapeKController(cfg, manager=FakeManager())
    with _db.connect(DBP[0]) as c:
        eid = _db.insert_row(c, "engagements", src_ip="10.42.0.9", state="active", started_at=_now(),
                             last_evidence_at=_now(), node="vm", decoys="[]", redirect="{}") \
            if "engagements" in [r[0] for r in c.execute("SELECT name FROM sqlite_master")] else None
        base = {"actionable": True, "assessment": "high", "src_ip": "10.42.0.9", "engagement_id": eid,
                "target_node": "vm", "evidence_count": 12, "reason": "r"}
        acts = ctl.plan(c, [{**base, "trigger": "ml", "attack_class": "BruteForce"},
                            {**base, "trigger": "behavior", "attack_class": "Reconnaissance (flow burst)",
                             "target_port": 3000}])
    deploys = [a["name"] for a in acts if a["action"] == "deploy"]
    assert len(deploys) == 1
    assert [a["action"] for a in acts if a["trigger"] == "behavior"] == ["refresh"]


def test_flow_burst_the_model_calls_benign_is_not_redirected(cfg):
    """web_recon: a crawler forms a flow burst, but the model scores its flows BENIGN.
    Only attack traffic is redirected, so no decoy and no engagement."""
    mgr = FakeManager()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.set_enabled(True)
    with db.connect(DBP[0]) as c:
        db.insert_row(c, "behavior_alerts", src_ip="10.42.0.8", dst_ip="10.43.0.5", dst_port=1880,
                      protocol=6, flows=60, rate_per_s=6.0, window_s=10.0, ml_malicious_flows=0,
                      ml_classes="{}", detected_at=_now())
    ctl.run_cycle()
    assert mgr.deployed == {}
    assert ctl.engagements() == []
    with db.connect(DBP[0]) as c:
        r = c.execute("SELECT action, reason FROM decisions WHERE src_ip = '10.42.0.8'").fetchone()
    assert r["action"] == "monitor" and "benign traffic is not redirected" in r["reason"]
    from live.queries import _not_engaged_category
    assert _not_engaged_category(r["action"], r["reason"]) == "benign_model"


def test_reused_decoy_counts_as_the_engagements_decoy(cfg):
    """Sandbox engagement #71: the ML trigger could not deploy (cooldown) and reused a
    running decoy; a flow burst in the same cycle then linked a second decoy."""
    from live import db as _db
    ctl = MapeKController(cfg, manager=FakeManager())
    with _db.connect(DBP[0]) as c:
        for name, prof in (("decoy-influxdb-vm", "influxdb"), ("decoy-web-portal-vm", "web-portal")):
            _db.insert_row(c, "decoys", name=name, profile=prof, namespace="ids-deception", status="active",
                           created_at=_now(), port=80)
        eid = _db.insert_row(c, "engagements", src_ip="10.42.0.18", state="active", started_at=_now(),
                             last_evidence_at=_now(), node="vm", decoys="[]", redirect="{}")
        base = {"actionable": True, "assessment": "high", "src_ip": "10.42.0.18", "engagement_id": eid,
                "target_node": "vm", "evidence_count": 13, "reason": "r"}
        acts = ctl.plan(c, [{**base, "trigger": "ml", "attack_class": "BruteForce"},
                            {**base, "trigger": "behavior", "attack_class": "Reconnaissance (flow burst)", "target_port": 1880}])
    names = {a["name"] for a in acts if a["action"] in ("deploy", "refresh", "reuse", "scale")}
    assert len(names) == 1, [(a["trigger"], a["action"], a.get("name")) for a in acts]
