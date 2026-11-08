"""Retraining must not forget runs that fell out of the dashboard's short run history:
they are rebuilt from the scored flows (lab_job / lab_scenario + the capture's session)."""
import importlib.util
import sqlite3
from pathlib import Path

spec = importlib.util.spec_from_file_location("tlm2", Path(__file__).resolve().parents[1] / "scripts" / "train_lab_model.py")
tlm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tlm)


def test_runs_missing_from_history_are_rebuilt_from_flows():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE kv (key TEXT, value TEXT)")
    c.execute("INSERT INTO kv VALUES ('pipeline_runs', '[{\"session_id\": 9, \"jobs\": [{\"job\": \"traffic-port-scan-new\", \"scenario\": \"port_scan\", \"pod_ip\": \"10.42.0.50\"}]}]')")
    c.execute("CREATE TABLE captures (id INTEGER, session_id INTEGER)")
    c.execute("CREATE TABLE detections (lab_job TEXT, lab_scenario TEXT, session_id INTEGER, capture_id INTEGER, "
              "src_ip TEXT, dst_ip TEXT, simulated INTEGER)")
    c.execute("INSERT INTO captures VALUES (1, 3)")
    rows = [("traffic-brute-force-old", "brute_force", None, 1, "10.42.0.20", "10.42.0.5", 0)] * 5 + \
           [("traffic-brute-force-old", "brute_force", None, 1, "10.42.0.5", "10.42.0.20", 0)] * 5 + \
           [("traffic-web-attack-x", "web_attack", None, 1, "10.42.0.21", "10.42.0.5", 0)] * 4 + \
           [("traffic-benign-abc", "benign", None, 1, "10.42.0.3", "10.42.0.5", 0)] * 3
    c.executemany("INSERT INTO detections VALUES (?,?,?,?,?,?,?)", rows)
    runs = tlm.runs_by_session(c)
    assert runs[9] == [{"scenario": "port_scan", "pod_ip": "10.42.0.50", "job": "traffic-port-scan-new"}]
    # the pod IP is the address in every flow of the Job (not the target, which is in half)
    assert {"scenario": "brute_force", "pod_ip": "10.42.0.20", "job": "traffic-brute-force-old"} in runs[3]
    assert {"scenario": "web_attack", "pod_ip": "10.42.0.21", "job": "traffic-web-attack-x"} in runs[3]
    assert all(j["scenario"] != "benign" for j in runs[3])
