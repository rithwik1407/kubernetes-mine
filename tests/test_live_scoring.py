"""Per-Job scoring without DNS, live-rate flow graph, automatic generator update and
automatic retraining counter (no cluster needed)."""
from datetime import datetime, timedelta, timezone

from live import db, pipeline, queries, trafficlab


def _det(c, when, src, dst, cls, sport=40000, dport=1880):
    db.insert_row(c, "detections", predicted_class=cls, confidence=0.9, is_malicious=int(cls != "BENIGN"),
                  source="live", detected_at=when, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, model="m")


def test_breakdown_leaves_dns_and_benign_mix_out_of_accuracy(cfg):
    now = datetime.now(timezone.utc).isoformat()
    with db.connect(db.db_path(cfg)) as c:
        for _ in range(9):
            _det(c, now, "10.42.0.77", "10.42.0.5", "BruteForce")
        _det(c, now, "10.42.0.77", "10.42.0.5", "BENIGN")
        for _ in range(12):                                   # DNS lookups before each connection
            _det(c, now, "10.42.0.77", "10.43.0.10", "BENIGN", sport=5353, dport=53)
        for _ in range(3):                                    # the mixed-in benign requests
            _det(c, now, "10.42.0.77", "10.42.0.5", "BENIGN", sport=20005)
        b = pipeline._breakdown(c, {"pod_ip": "10.42.0.77", "expect_class": "BruteForce"},
                                (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(), None)
    assert b["flows"] == 10 and b["accuracy"] == 0.9
    assert b["dns_flows"] == 12
    assert b["benign_mix"]["flows"] == 3 and b["benign_mix"]["by_class"] == {"BENIGN": 3}


def test_flow_graph_reports_live_rate_per_edge(cfg):
    now = datetime.now(timezone.utc)
    old = (now - timedelta(seconds=60)).isoformat()
    pods = {"10.42.0.50": {"pod": "atk", "namespace": "ids-traffic", "node": "n1", "labels": {}},
            "10.42.0.7": {"pod": "nodered-1", "namespace": "target-apps", "node": "n1", "labels": {}},
            "10.42.0.8": {"pod": "grafana-1", "namespace": "target-apps", "node": "n1", "labels": {}}}
    with db.connect(db.db_path(cfg)) as c:
        for _ in range(6):
            _det(c, old, "10.42.0.50", "10.42.0.7", "PortScan")
        for _ in range(20):
            _det(c, now.isoformat(), "10.42.0.50", "10.42.0.8", "PortScan")
    g = queries.flow_graph(120, 10, cfg, pods=pods, recent_seconds=10)
    e = {(x["src"], x["dst"]): x for x in g["edges"]}
    assert e[("10.42.0.50", "10.42.0.7")]["recent"] == 0          # idle path: shown dimmed
    assert e[("10.42.0.50", "10.42.0.8")]["recent"] == 20
    assert e[("10.42.0.50", "10.42.0.8")]["rate"] == 2.0          # 20 flows in 10 s
    assert g["recent_seconds"] == 10


def test_stale_generator_is_updated_automatically(cfg, monkeypatch):
    calls = []
    monkeypatch.setattr(trafficlab, "check_ready", lambda c=None: {"ready": True, "generator_current": False,
                                                                    "warning": "old", "fix": "kubectl apply -k deploy/traffic-lab"})
    monkeypatch.setattr(trafficlab, "update_generator", lambda c=None: calls.append(1) or {"updated": True})
    note = trafficlab.ensure_generator_current(cfg)
    assert calls == [1] and "updated it" in note
    cfg["traffic_lab"]["auto_update_generator"] = False
    assert trafficlab.ensure_generator_current(cfg).startswith("WARNING")
    assert calls == [1]                                           # not applied when turned off


def test_current_generator_is_left_alone(cfg, monkeypatch):
    monkeypatch.setattr(trafficlab, "check_ready", lambda c=None: {"ready": True, "generator_current": True})
    monkeypatch.setattr(trafficlab, "update_generator", lambda c=None: (_ for _ in ()).throw(AssertionError))
    assert trafficlab.ensure_generator_current(cfg) is None


def test_auto_retrain_starts_after_enough_attack_jobs(cfg, monkeypatch):
    from live import retrain
    started = []
    monkeypatch.setattr(retrain, "start", lambda c, reason="", **k: started.append(reason))
    cfg["retrain"] = {"auto_after_attack_jobs": 3}
    run = {"jobs": [{"scenario": "port_scan", "pod_ip": "10.42.0.1"}, {"scenario": "benign", "pod_ip": "10.42.0.2"}]}
    pipeline._maybe_auto_retrain(run, cfg)
    pipeline._maybe_auto_retrain(run, cfg)
    assert started == []                                          # 2 attack Jobs so far, benign not counted
    pipeline._maybe_auto_retrain(run, cfg)
    assert len(started) == 1 and "3 new labelled attack Jobs" in started[0]
    with db.connect(db.db_path(cfg)) as c:
        assert db.kv_get(c, "retrain_new_attack_jobs", "") == "0"
