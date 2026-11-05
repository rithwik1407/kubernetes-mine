"""Regression tests for the issues found in the full-system audit (no cluster needed)."""
import json
import re
import struct

import numpy as np
import pandas as pd
import pytest

from live import window as W
from live.behavior import flow_bursts
from live.trafficlab import TrafficLabError, build_job, resolve_target, scenarios, slugify, summarize_log

WCFG = {"sizes": [1, 3, 5, 10], "default_seconds": 5, "min_seconds": 1, "max_seconds": 10,
        "high_rate_pps": 200, "low_rate_pps": 20, "calm_windows": 3, "threat_seconds": 3, "evidence_confidence": 0.6}
RFC1123 = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


# --- adaptive observation window -------------------------------------------------------
def test_window_sizes_and_initial():
    assert W.window_sizes(WCFG) == [1.0, 3.0, 5.0, 10.0]
    assert W.initial_window(WCFG) == 5.0
    assert W.window_sizes({**WCFG, "min_seconds": 3, "max_seconds": 5}) == [3.0, 5.0]


def test_window_threat_shrinks_to_threat_seconds():
    d = W.decide(10, W.Evidence(packets=100, duration_s=10, malicious_flows=4, top_class="DoS", max_confidence=0.97), WCFG)
    assert (d.rule, d.next_s, d.changed) == ("R1_threat", 3.0, True)
    assert "DoS" in d.reason
    # already shorter than threat_seconds -> stays
    assert W.decide(1, W.Evidence(packets=10, duration_s=1, bursts=1), WCFG).next_s == 1.0


def test_window_high_rate_steps_down_one_and_clamps():
    assert W.decide(5, W.Evidence(packets=5000, duration_s=5), WCFG).next_s == 3.0
    d = W.decide(1, W.Evidence(packets=5000, duration_s=1), WCFG)
    assert d.rule == "R2_high_rate" and d.next_s == 1.0 and not d.changed


def test_window_grows_only_after_calm_streak():
    quiet = dict(packets=20, duration_s=5)
    assert W.decide(5, W.Evidence(**quiet, calm_streak=2), WCFG).rule == "R4_hold"
    d = W.decide(5, W.Evidence(**quiet, calm_streak=3), WCFG)
    assert d.rule == "R3_calm" and d.next_s == 10.0
    assert W.decide(10, W.Evidence(**quiet, calm_streak=9), WCFG).next_s == 10.0   # max bound


def test_window_mid_rate_holds_and_is_deterministic():
    ev = W.Evidence(packets=500, duration_s=5, calm_streak=10)  # 100 pkt/s
    assert {W.decide(5, ev, WCFG).next_s for _ in range(20)} == {5.0}


def test_window_policy_description_lists_all_rules():
    p = W.policy_description(WCFG)
    assert [r["id"] for r in p["rules"]] == ["R1_threat", "R2_high_rate", "R3_calm", "R4_hold"]


def test_live_config_window_is_valid(cfg):
    w = cfg["capture"]["window"]
    assert W.window_sizes(w) == [1.0, 3.0, 5.0, 10.0]


# --- traffic lab -------------------------------------------------------------------------
def test_every_scenario_builds_a_valid_kubernetes_job_name(cfg):
    """The original bug: generateName 'traffic-port_scan-' -> HTTP 422 for every attack scenario."""
    for name in scenarios(cfg):
        job = build_job(name, cfg, target="nodered.target-apps.svc.cluster.local:1880")
        gen = job["metadata"]["generateName"]
        assert RFC1123.match(gen + "abcde"), gen
        for v in job["metadata"]["labels"].values():
            assert re.match(r"^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$", v)
        assert job["metadata"]["annotations"]["ids/scenario"] == name


def test_slugify():
    assert slugify("port_scan") == "port-scan" and slugify("Web_Attack!") == "web-attack"


def test_targets_are_restricted_to_lab_services(cfg):
    assert resolve_target("web_attack", "grafana", cfg)["target"] == "grafana.target-apps.svc.cluster.local:3000"
    assert resolve_target("web_attack", None, cfg)["label"] == "nodered"
    for bad in ("example.com:80", "8.8.8.8:53", "grafana.target-apps.svc.cluster.local:22"):
        with pytest.raises(TrafficLabError):
            resolve_target("web_attack", bad, cfg)


def test_generator_log_verification():
    log = "\n".join(json.dumps(x) for x in [
        {"action": "start", "ts": "t0"}, {"action": "http", "status": 200, "ts": "t1"},
        {"action": "http", "status": 404, "ts": "t2"}, {"action": "http", "error": "URLError", "ts": "t3"},
        {"action": "port_closed", "port": 2, "ts": "t4"}, {"action": "done", "ts": "t5"}]) + "\nnot json"
    s = summarize_log(log)
    assert s["verified"] and s["finished"]
    assert (s["ok"], s["errors"]) == (3, 1)
    assert s["http_status"] == {"200": 1, "404": 1}
    assert not summarize_log("")["verified"]
    assert not summarize_log(json.dumps({"action": "http", "error": "timeout"}))["verified"]


# --- behaviour rules ----------------------------------------------------------------------
def _flows(n_ports, src="10.42.0.9", dst="10.42.0.28"):
    return pd.DataFrame([{"src_ip": src, "dst_ip": dst, "dst_port": p, "protocol": 6,
                          "is_malicious": False, "predicted_class": "BENIGN"} for p in range(1, n_ports + 1)])


def test_port_sweep_is_detected_where_per_port_bursts_are_not(cfg):
    b = flow_bursts(_flows(60), 5.0, cfg)
    assert list(b["alert_type"]) == ["port_sweep"]
    assert int(b.iloc[0]["distinct_ports"]) == 60
    assert flow_bursts(_flows(4), 5.0, cfg).empty           # a few ports is normal


# --- feature schema ------------------------------------------------------------------------
def test_model_features_exclude_identifiers(cfg):
    from live.predictor import FlowPredictor
    p = FlowPredictor.from_config(cfg)
    banned = {"flowid", "srcip", "dstip", "srcport", "dstport", "sourceip", "destinationip", "sourceport",
              "destinationport", "timestamp", "protocol", "label"}
    assert not banned & set(p.features)
    metrics = json.loads((p.model_dir / "metrics.json").read_text())
    assert list(metrics["features"]) == p.features            # inference order == training order


def test_inference_schema_handles_cicflowmeter_names_and_bad_values(cfg):
    from live.predictor import FlowPredictor
    from live.schema import SchemaError
    p = FlowPredictor.from_config(cfg)
    sample = pd.read_csv(p.model_dir.parent.parent / "dashboard" / "sample_cic2017_test_mix.csv", nrows=50)
    X = sample.drop(columns=["Label"])
    X.iloc[0, 0] = np.inf
    out = p.predict_frame(X, source="upload")
    assert len(out) == 50 and set(out["predicted_class"]) <= set(map(str, p.classes))
    assert out["confidence"].between(0, 1).all()
    with pytest.raises(SchemaError):
        p.predict_frame(pd.DataFrame({"foo": [1, 2]}), source="upload")


# --- PCAP handling ------------------------------------------------------------------------
def test_conversion_rejects_missing_invalid_and_pcapng(tmp_path, cfg):
    from live.cicflowmeter import convert_pcap
    assert convert_pcap(tmp_path / "missing.pcap", cfg=cfg).status == "failed"
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a pcap at all, just text" * 3)
    r = convert_pcap(bad, cfg=cfg)
    assert r.status == "failed" and "not a pcap" in r.error
    ng = tmp_path / "ng.pcap"
    ng.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)
    assert "pcapng" in convert_pcap(ng, cfg=cfg).error
    sll = tmp_path / "sll.pcap"
    sll.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 113))
    assert "not supported" in convert_pcap(sll, cfg=cfg).error


def test_empty_pcap_is_reported_empty_or_failed_never_converted(tmp_path, cfg):
    from live.cicflowmeter import convert_pcap, support
    if not support(cfg)["supported"]:
        pytest.skip("CICFlowMeter not installed here")
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    r = convert_pcap(empty, out_dir=tmp_path / "flows", cfg=cfg)
    assert r.status in ("empty", "failed") and r.flows == 0


# --- database -----------------------------------------------------------------------------
def test_db_migrates_old_schema(tmp_path):
    import sqlite3
    from live import db
    path = tmp_path / "old.sqlite"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE captures (id INTEGER PRIMARY KEY, pcap_file TEXT UNIQUE NOT NULL, status TEXT NOT NULL)")
    con.commit()
    con.close()
    with db.connect(path) as c:
        cols = {r[1] for r in c.execute("PRAGMA table_info(captures)")}
        assert "window_s" in cols
        db.insert_row(c, "window_transitions", created_at="t", next_s=5, rule="start", reason="r", changed=1)
        assert c.execute("SELECT COUNT(*) FROM window_transitions").fetchone()[0] == 1
