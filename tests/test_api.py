"""API contract tests: status codes, validation and response shapes, with NO cluster.

The app is loaded against a temporary config (own SQLite, PCAP dirs, no kubeconfig), so
these tests are deterministic on any machine. Cluster-backed behaviour is covered by
tests/test_k8s_integration.py.
"""
import importlib
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("api")
    cfg = yaml.safe_load((REPO / "config" / "live.yaml").read_text())
    cfg["paths"].update(database=str(tmp / "ids.sqlite"), pcap_dir=str(tmp / "pcap"), flows_dir=str(tmp / "flows"))
    cfg["capture"].update(state_file=str(tmp / "state.json"), pid_file=str(tmp / "capture.pid"))
    cfg["deception"]["kubeconfig"] = str(tmp / "no.kubeconfig")
    (tmp / "live.yaml").write_text(yaml.safe_dump(cfg))
    mp = pytest.MonkeyPatch()
    mp.setenv("IDS_CONFIG", str(tmp / "live.yaml"))
    import live.config
    live.config.load_config.cache_clear()
    import live.kube
    mp.setattr(live.kube, "default_kubeconfigs", lambda: [])
    sys.path.insert(0, str(REPO / "dashboard"))
    for m in ("app", "live_api"):
        sys.modules.pop(m, None)
    app = importlib.import_module("app")
    from fastapi.testclient import TestClient
    assert app.LIVE_ENABLED, getattr(app, "_LIVE_IMPORT_ERROR", "")
    with TestClient(app.app) as c:
        yield c
    mp.undo()
    live.config.load_config.cache_clear()


GET_OK = ["/", "/scorer", "/api/features", "/api/metrics", "/api/model", "/api/model?which=scorer",
          "/api/live/metrics", "/api/live/detections?limit=5", "/api/live/stats", "/api/live/events",
          "/api/live/timeline", "/api/live/bursts", "/api/live/captures", "/api/live/capture/status",
          "/api/window/status", "/api/window/history", "/api/trafficlab/scenarios", "/api/targets",
          "/api/pipeline/preflight", "/api/pipeline/status", "/api/deception/status", "/api/deception/policy",
          "/api/deception/decisions", "/api/deception/decoys", "/api/deception/interactions",
          "/api/deception/test-events", "/api/kubernetes/status", "/api/system/health", "/api/system/resources",
          "/api/system/logs", "/api/system/requests", "/api/trafficlab/baseline",
          "/api/live/activity?minutes=5&bucket=10", "/api/deception/detection-policy", "/api/deception/engagements",
          "/api/live/allowlist"]


@pytest.mark.parametrize("path", GET_OK)
def test_read_endpoints_return_200_without_a_cluster(client, path):
    r = client.get(path)
    assert r.status_code == 200, (path, r.text[:300])


def test_no_cluster_is_reported_not_hidden(client):
    k = client.get("/api/kubernetes/status").json()
    assert k["connected"] is False and "kubeconfig" in k["error"]
    h = client.get("/api/system/health").json()
    comp = {c["component"]: c["status"] for c in h["components"]}
    assert comp["kubernetes"] == "unavailable" and comp["database"] == "ok" and comp["model"] == "ok"
    assert h["status"] in ("degraded", "error")


@pytest.mark.parametrize("method,path,body,status", [
    ("post", "/api/pipeline/run", {"scenario": "nope"}, 400),
    ("post", "/api/pipeline/run", {"scenario": "port_scan", "count": 0}, 422),
    ("post", "/api/pipeline/run", {"scenario": "port_scan", "delay": 99}, 422),
    ("post", "/api/pipeline/run", {"scenarios": ["port_scan", "nope"]}, 400),
    ("post", "/api/pipeline/run", {"scenarios": []}, 422),
    ("post", "/api/pipeline/run", {"scenarios": ["port_scan"], "targets": ["grafana"]}, 503),   # no cluster
    ("put", "/api/deception/detection-policy", {}, 422),
    ("put", "/api/deception/detection-policy", {"classes": {"PortScan": {"min_confidence": 2}}}, 400),
    ("put", "/api/deception/detection-policy", {"classes": {"Nope": {"min_flows": 3}}}, 400),
    ("get", "/api/live/activity?minutes=0", None, 422),
    ("post", "/api/trafficlab/launch", {"scenario": "port_scan"}, 503),       # no cluster
    ("get", "/api/trafficlab/jobs", None, 503),
    ("get", "/api/trafficlab/jobs/Bad_Name", None, 400),
    ("delete", "/api/trafficlab/jobs/bad_name!", None, 400),
    ("put", "/api/trafficlab/baseline", {"running": True}, 503),
    ("put", "/api/trafficlab/baseline", {}, 422),
    ("post", "/api/deception/decoys", {"profile": "nope"}, 400),
    ("post", "/api/deception/decoys", {"profile": "web-portal"}, 503),        # no cluster
    ("delete", "/api/deception/decoys/not-a-decoy", None, 400),
    ("post", "/api/deception/test-event", {"attack_class": "Nope"}, 400),
    ("post", "/api/deception/test-event", {"attack_class": "DoS", "confidence": 2}, 422),
    ("get", "/api/system/logs?level=LOUD", None, 422),
    ("get", "/api/live/detections?limit=0", None, 422),
    ("get", "/api/live/detections?source=x", None, 422),
    ("get", "/api/model?which=x", None, 400),
    ("get", "/api/nonexistent", None, 404),
    ("put", "/api/live/metrics", None, 405),
    ("post", "/api/predict", {"records": []}, 422),
    ("post", "/api/predict", {"records": [{"foo": 1}]}, 422),
])
def test_error_status_codes(client, method, path, body, status):
    r = getattr(client, method)(path, json=body) if body is not None else getattr(client, method)(path)
    assert r.status_code == status, (method, path, r.status_code, r.text[:300])
    assert "detail" in r.json()


def test_capture_start_unsupported_is_503_not_200(client, monkeypatch):
    import live.capture as cap
    monkeypatch.setattr(cap, "support", lambda cfg=None: {"supported": False, "reason": "no tcpdump"})
    r = client.post("/api/live/capture/start", json={})
    assert r.status_code == 503 and "no tcpdump" in r.json()["detail"]


def test_predict_and_labelled_evaluation(client):
    import pandas as pd
    # the live model is the lab model: score its own held-out lab flows
    rows = pd.read_csv(REPO / "dashboard" / "sample_lab_test_mix.csv").sample(20, random_state=1)
    labels = rows.pop("Label").tolist()
    r = client.post("/api/predict", json={"records": rows.to_dict(orient="records")})
    assert r.status_code == 200
    preds = r.json()["predictions"]
    assert len(preds) == 20 and all(0 <= p["confidence"] <= 1 for p in preds)
    assert {"predicted_class", "confidence", "is_malicious", "detected_at", "flow_id"} <= set(preds[0])
    assert sum(p["predicted_class"] == t for p, t in zip(preds, labels)) >= 18
    e = client.get("/api/model/evaluate-sample").json()
    assert e["sample"] == "sample_lab_test_mix.csv" and e["rows"] == 2366 and e["accuracy"] > 0.85
    assert len(e["confusion_matrix"]) == len(e["classes"])


def test_model_info_comes_from_artifacts(client):
    live = client.get("/api/model").json()               # trained on this lab's own CICFlowMeter flows
    assert live["name"] == "k8s-lab-live" and live["n_features"] == 68 and live["source"]
    assert set(live["classes"]) == {"BENIGN", "BruteForce", "DoS", "PortScan", "WebAttack"}
    assert live["test_samples"] > 0 and live["models"]["RandomForest"]["confusion_matrix"]
    m = client.get("/api/model?which=scorer").json()
    assert m["n_features"] == 68 and m["source"] is None
    assert set(m["classes"]) == {"BENIGN", "Bot", "BruteForce", "DDoS", "DoS", "PortScan", "WebAttack"}
    bot = next(x for x in m["reliability"] if x["class"] == "Bot")
    assert bot["reliable"] is False        # few samples, F1 0.72: never claimed reliable


def test_requests_are_recorded_with_status(client):
    client.get("/api/nonexistent")
    req = client.get("/api/system/requests").json()
    assert any(r["path"] == "/api/nonexistent" and r["status"] == 404 for r in req["requests"])


def test_simulated_event_is_stored_separately(client):
    r = client.post("/api/deception/test-event", json={"attack_class": "DoS", "confidence": 0.95})
    assert r.status_code == 201 and r.json()["simulated"] is True
    assert client.get("/api/live/metrics").json()["total_flows"] == 0


def test_detection_policy_roundtrip(client):
    r = client.put("/api/deception/detection-policy", json={"classes": {"WebAttack": {"min_flows": 4}},
                                                             "hysteresis": {"quiet_seconds": 90}})
    assert r.status_code == 200 and r.json()["classes"]["WebAttack"]["min_flows"] == 4
    assert r.json()["hysteresis"]["quiet_seconds"] == 90
    r = client.put("/api/deception/detection-policy", json={"reset": True})
    assert r.status_code == 200 and not r.json()["overridden"]


def _db_path(client):
    from live.config import load_config
    return load_config()["paths"]["database"]


def test_flows_are_isolated_per_capture_session_and_paginated(client):
    from live import db
    with db.connect(_db_path(client)) as c:
        old = db.insert_row(c, "capture_sessions", started_at="2026-11-05T10:00:00+00:00", scenarios='["slow_dos"]')
        new = db.insert_row(c, "capture_sessions", started_at="2026-11-05T11:00:00+00:00", scenarios='["port_scan"]')
        for sid, scen, n in ((old, "slow_dos", 7), (new, "port_scan", 23)):
            for i in range(n):
                db.insert_row(c, "detections", predicted_class="BENIGN", confidence=0.9, is_malicious=0, source="pcap",
                              detected_at="2026-11-05T11:00:01+00:00", src_ip="10.42.0.9", dst_ip="10.42.0.78",
                              dst_port=i, protocol=6, session_id=sid, lab_scenario=scen)
        db.insert_row(c, "detections", predicted_class="BENIGN", confidence=0.9, is_malicious=0, source="pcap",
                      detected_at="2026-11-05T11:00:02+00:00", src_ip="10.42.0.1", dst_ip="10.42.0.78",
                      protocol=6, session_id=new)
    r = client.get("/api/live/flows?page_size=10").json()          # default: the newest session only
    assert r["session_id"] == new and r["total"] == 24 and r["pages"] == 3 and len(r["rows"]) == 10
    assert {x["session_id"] for x in r["rows"]} == {new}
    assert client.get("/api/live/flows?page=3&page_size=10").json()["rows"].__len__() == 4
    assert client.get("/api/live/flows?page=99&page_size=10").json()["page"] == 3        # clamped
    r = client.get("/api/live/flows?lab_scenario=UNKNOWN").json()
    assert r["total"] == 1 and r["rows"][0]["scenario"] == "UNKNOWN"
    assert client.get(f"/api/live/flows?session={old}").json()["total"] == 7
    assert client.get("/api/live/flows?session=all").json()["total"] >= 31
    assert client.get("/api/live/flows?session=999999").status_code == 404
    assert client.get("/api/live/flows?session=x;1").status_code == 422
    s = client.get("/api/live/sessions").json()
    assert s[0]["id"] == new and s[0]["scenarios"] == ["port_scan"] and s[0]["flows"] == 24


def test_behaviour_alert_delete_is_a_soft_delete(client):
    from live import db
    with db.connect(_db_path(client)) as c:
        a = db.insert_row(c, "behavior_alerts", src_ip="10.42.0.9", dst_ip="10.42.0.78", dst_port=1880, protocol=6,
                          flows=40, rate_per_s=4.0, window_s=10.0, ml_malicious_flows=0, ml_classes="{}",
                          detected_at="2026-11-05T11:00:00+00:00")
    before = client.get("/api/live/bursts/count").json()["open"]
    r = client.delete(f"/api/live/bursts/{a}")
    assert r.status_code == 200 and r.json()["remaining"] == before - 1
    assert all(x["id"] != a for x in client.get("/api/live/bursts").json())
    assert client.delete("/api/live/bursts/987654").status_code == 404
    with db.connect(_db_path(client)) as c:      # row kept: history intact
        assert c.execute("SELECT dismissed_at FROM behavior_alerts WHERE id = ?", (a,)).fetchone()[0]
    assert any(e.get("kind") == "burst" or "burst" in str(e.get("title", "")).lower() or e.get("src_ip") == "10.42.0.9"
               for e in client.get("/api/live/events").json())
