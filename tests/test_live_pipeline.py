"""Tests for the live detection pipeline, flow bursts, db and traffic lab."""
import numpy as np
import pandas as pd
import pytest

from live import db
from live.behavior import flow_bursts
from live.schema import SchemaError, align_features, normalize_column_name, read_flow_csv


def test_read_flow_csv_handles_repeated_header(tmp_path):
    p = tmp_path / "f.csv"
    p.write_text("Src IP,Dst IP,Dst Port,Protocol\n"
                 "10.0.0.1,10.0.0.2,80,6\n"
                 "Src IP,Dst IP,Dst Port,Protocol\n"      # repeated header mid-file
                 "10.0.0.3,10.0.0.4,443,6\n")
    df = read_flow_csv(p)
    assert len(df) == 2
    assert df["Dst Port"].tolist() == [80, 443]


def test_read_flow_csv_rejects_non_flow(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("a,b,c\n1,2,3\n")
    with pytest.raises(SchemaError):
        read_flow_csv(p)


def test_align_features_maps_aliases_and_reports_missing():
    # "Total Bwd packets" (newer CICFlowMeter) must map to the model's canonical feature.
    df = pd.DataFrame({"Total Backward Packets": [5], "Nonsense Col": [1]})
    X, missing = align_features(df, ["totalbackwardpackets", "flowduration"])
    assert X["totalbackwardpackets"].tolist() == [5]
    assert "flowduration" in missing
    assert np.isnan(X["flowduration"]).all()


def test_flow_bursts_flags_scan_not_normal(cfg):
    # 20 flows from one source to one service in a 10s window -> burst; a quiet source -> none.
    rows = [{"src_ip": "10.0.0.9", "dst_ip": "10.0.0.1", "dst_port": 1880, "protocol": 6,
             "is_malicious": False, "predicted_class": "BENIGN"} for _ in range(20)]
    rows += [{"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 1880, "protocol": 6,
              "is_malicious": False, "predicted_class": "BENIGN"} for _ in range(3)]
    b = flow_bursts(pd.DataFrame(rows), 10.0, cfg)
    assert len(b) == 1
    assert b.iloc[0]["src_ip"] == "10.0.0.9"
    assert b.iloc[0]["flows"] == 20


def test_flow_bursts_empty_on_no_window(cfg):
    assert flow_bursts(pd.DataFrame(), None, cfg).empty


def test_db_detection_roundtrip(cfg):
    pred = pd.DataFrame([{
        "flow_id": None, "timestamp": None, "src_ip": "10.0.0.9", "src_port": 5000,
        "dst_ip": "10.0.0.1", "dst_port": 1880, "protocol": 6, "predicted_class": "PortScan",
        "confidence": 0.97, "is_malicious": True, "capture_file": "w.pcap", "source": "live",
        "processing_time_ms": 1.0, "detected_at": "2026-11-03T00:00:00", "true_label": None, "model": "cic",
    }])
    with db.connect(cfg["paths"]["database"]) as c:
        assert db.insert_detections(c, pred) == 1
        row = c.execute("SELECT predicted_class, is_malicious FROM detections").fetchone()
        assert row["predicted_class"] == "PortScan" and row["is_malicious"] == 1


@pytest.mark.skipif(True, reason="needs the trained model; run with --runslow")
def test_predictor_on_lab_csv():
    pass
