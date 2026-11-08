"""The lab retraining: every class is in the held-out test set, benign-mix flows are
labelled BENIGN, and a new model only replaces the live one when recall improves."""
import importlib.util
from pathlib import Path

import numpy as np
import pandas as pd

spec = importlib.util.spec_from_file_location("tlm", Path(__file__).resolve().parents[1] / "scripts" / "train_lab_model.py")
tlm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tlm)


def _X(rows):
    return pd.DataFrame({"f": 0.0, "_session": [r[0] for r in rows], "_t": [r[1] for r in rows],
                         "_scenario": [r[2] for r in rows]})


def test_every_scenario_is_held_out_even_with_one_run():
    # port_scan in runs 1 and 2 (newest held out whole, its benign flows too); brute_force
    # and web_recon in one run each (the old split left such classes out of the test set)
    rows = ([(1, t, "port_scan") for t in range(10)] + [(2, t, "port_scan") for t in range(10)]
            + [(3, t, "brute_force") for t in range(20)] + [(4, t, "web_recon") for t in range(8)])
    y = pd.Series(["PortScan"] * 8 + ["BENIGN"] * 2 + ["PortScan"] * 8 + ["BENIGN"] * 2 + ["BruteForce"] * 20 + ["BENIGN"] * 8)
    X = _X(rows)
    test = tlm.split_per_class(X, y, set())
    assert set(X[test & (X["_scenario"] == "port_scan").to_numpy()]["_session"]) == {2}
    held = y[test].value_counts().to_dict()
    assert held["PortScan"] == 8 and held["BruteForce"] == 5 and held["BENIGN"] == 2 + 2
    # the held-out part of a single-run scenario is its LATEST flows
    assert X[test & (X["_scenario"] == "brute_force").to_numpy()]["_t"].min() >= 15


def test_explicit_test_sessions_still_win():
    rows = [(1, 0, "a"), (2, 0, "b"), (3, 0, "c")]
    y = pd.Series(["BENIGN", "PortScan", "DoS"])
    assert list(tlm.split_per_class(_X(rows), y, {2})) == [False, True, False]


def test_benign_mix_flows_of_an_attack_pod_are_benign():
    df = pd.DataFrame({"Src IP": ["10.42.0.9", "10.42.0.9", "10.42.0.5", "10.42.0.9"],
                       "Dst IP": ["10.42.0.5", "10.42.0.5", "10.42.0.9", "10.43.0.10"],
                       "Src Port": [45000, 20017, 1880, 51000], "Dst Port": [1880, 1880, 20017, 53]})
    lab = tlm.label(df, [{"scenario": "brute_force", "pod_ip": "10.42.0.9"}], (20000, 20999))
    assert list(lab) == ["BruteForce", "BENIGN", "BENIGN", None]


def _m(**recall):
    return {"macro_f1": float(np.mean(list(recall.values()))), "per_class": {c: {"recall": r} for c, r in recall.items()}}


def test_gate_replaces_only_when_recall_improves():
    old = _m(BENIGN=0.99, DoS=0.65, PortScan=1.0)
    ok, why = tlm.gate(_m(BENIGN=0.995, DoS=0.99, PortScan=1.0), old)
    assert ok and "DoS 0.650 -> 0.990" in why
    ok, why = tlm.gate(_m(BENIGN=0.99, DoS=0.99, PortScan=0.90), old)
    assert not ok and "PortScan" in why
    ok, why = tlm.gate(_m(BENIGN=0.99, DoS=0.65, PortScan=1.0), old)
    assert not ok and "no class's recall improved" in why
    assert tlm.gate(_m(DoS=0.1), None)[0]
