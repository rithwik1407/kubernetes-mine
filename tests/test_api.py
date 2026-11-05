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
    rows = pd.read_csv(REPO / "dashboard" / "sample_cic2017_test_mix.csv", nrows=20)
    labels = rows.pop("Label")
    r = client.post("/api/predict", json={"records": rows.to_dict(orient="records")})
    assert r.status_code == 200
    preds = r.json()["predictions"]
    assert len(preds) == 20 and all(0 <= p["confidence"] <= 1 for p in preds)
    assert {"predicted_class", "confidence", "is_malicious", "detected_at", "flow_id"} <= set(preds[0])
    assert sum(p["predicted_class"] == t for p, t in zip(preds, labels)) >= 18
    e = client.get("/api/model/evaluate-sample").json()
    assert e["rows"] == 2230 and e["accuracy"] > 0.95
    assert len(e["confusion_matrix"]) == len(e["classes"])


def test_model_info_comes_from_artifacts(client):
    m = client.get("/api/model").json()
    assert m["name"] == "cic-ids2017-lab" and m["n_features"] == 68
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
