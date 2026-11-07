"""Train the live-pipeline model on flows captured in THIS lab by the live CICFlowMeter.

    python scripts/train_lab_model.py --test-sessions 21,22,23,24,25      # held-out sessions
    python scripts/train_lab_model.py --list                               # labelled sessions found

Why: the CIC-IDS2017 model is accurate on CIC-IDS2017 rows (99.7 %), but the live
extractor (the CICFlowMeter fork used here) produces different values for the same
traffic (scripts/check_feature_parity.py, scripts/sanity_replay.py), so real lab
attacks were all scored BENIGN. This trains on the extractor's own output.

Ground truth comes from Traffic-lab runs, never from the model:
  * every run records its capture session and each Job's pod IP (live/pipeline.py)
  * a flow with the attack pod at either end is that scenario's class
        port_scan -> PortScan, brute_force -> BruteForce, web_attack -> WebAttack, slow_dos -> DoS
    (DNS flows of the attack pod are left out: they are not the attack)
  * pods of scenarios without an attack class (web_recon, decoy_probe) are left out
  * every other flow in the session is BENIGN (baseline generator, kubelet probes,
    control plane, DNS), plus the verified benign lab captures in data/k8s/lab-benign

Each window is converted with 20 s of context, so the same flow appears in several
CSVs; flows are de-duplicated per session (Flow ID + start time, longest kept).

Same 68 features, same preprocessing (inf/NaN -> 0) and same RandomForest settings as
the CIC model, so the predictor and the parity checks need no change. The model is
evaluated on WHOLE held-out sessions (other targets, other rates) that it never saw.
Writes models/<out>/best_model.joblib, metrics.json and README.md.
"""
from __future__ import annotations

import argparse
import glob
import json
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from live.config import get_path, load_config  # noqa: E402
from live.schema import align_features, drop_non_ip_flows, read_flow_csv  # noqa: E402

SCENARIO_CLASS = {"port_scan": "PortScan", "brute_force": "BruteForce", "web_attack": "WebAttack",
                  "slow_dos": "DoS", "benign": "BENIGN"}
NO_CLASS = {"web_recon", "decoy_probe"}       # their pods' flows are excluded


def runs_by_session(conn) -> dict[int, list[dict]]:
    """Traffic-lab Jobs (scenario, pod IP) per capture session, from the stored runs."""
    row = conn.execute("SELECT value FROM kv WHERE key = 'pipeline_runs'").fetchone()
    out: dict[int, list[dict]] = {}
    for r in json.loads(row[0]) if row else []:
        sid = r.get("session_id")
        if not sid:
            continue
        for j in r.get("jobs", []):
            if j.get("pod_ip") and j.get("scenario"):
                out.setdefault(int(sid), []).append({"scenario": j["scenario"], "pod_ip": j["pod_ip"], "job": j["job"]})
    return out


def session_flows(conn, sid: int, flows_dir: Path) -> pd.DataFrame:
    frames = []
    for (csv,) in conn.execute("SELECT csv_file FROM captures WHERE session_id = ? AND csv_file IS NOT NULL", (sid,)):
        p = flows_dir / csv
        if p.is_file():
            try:
                frames.append(read_flow_csv(p))
            except Exception:  # noqa: BLE001 - an unreadable window is skipped, not fatal
                continue
    if not frames:
        return pd.DataFrame()
    df, _ = drop_non_ip_flows(pd.concat(frames, ignore_index=True))
    dur = pd.to_numeric(df.get("Flow Duration"), errors="coerce").fillna(0)
    df = df.assign(_dur=dur).sort_values("_dur").drop_duplicates(["Flow ID", "Timestamp"], keep="last")
    return df.drop(columns="_dur").reset_index(drop=True)


def label(df: pd.DataFrame, jobs: list[dict]) -> pd.Series:
    lab = pd.Series("BENIGN", index=df.index, dtype="object")
    src, dst = df["Src IP"].astype(str), df["Dst IP"].astype(str)
    sport = pd.to_numeric(df["Src Port"], errors="coerce")
    dport = pd.to_numeric(df["Dst Port"], errors="coerce")
    dns = (sport == 53) | (dport == 53)
    for j in jobs:
        mine = (src == j["pod_ip"]) | (dst == j["pod_ip"])
        cls = SCENARIO_CLASS.get(j["scenario"])
        if j["scenario"] in NO_CLASS or cls is None:
            lab[mine] = None
        else:
            lab[mine & ~dns] = cls
            lab[mine & dns] = "BENIGN" if cls == "BENIGN" else None
    return lab


def build(conn, sessions: list[int], jobs: dict[int, list[dict]], flows_dir: Path, features: list[str]):
    X, y, meta = [], [], []
    for sid in sessions:
        df = session_flows(conn, sid, flows_dir)
        if df.empty:
            continue
        lab = label(df, jobs[sid])
        keep = lab.notna()
        Xs, _ = align_features(df[keep], features)
        X.append(Xs.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32))
        y.append(lab[keep].astype(str))
        meta.append({"session": sid, "jobs": [f"{j['scenario']} {j['job']}" for j in jobs[sid]],
                     "flows": int(keep.sum()), "labels": lab[keep].value_counts().to_dict()})
    if not X:
        return pd.DataFrame(columns=features), pd.Series(dtype=str), meta
    return pd.concat(X, ignore_index=True), pd.concat(y, ignore_index=True), meta


def lab_benign(features: list[str]) -> tuple[pd.DataFrame, pd.Series]:
    frames = []
    for f in sorted(glob.glob(str(REPO / "data" / "k8s" / "lab-benign" / "*.csv"))):
        df, _ = drop_non_ip_flows(read_flow_csv(f))
        Xs, _ = align_features(df, features)
        frames.append(Xs.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32))
    X = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=features)
    return X, pd.Series("BENIGN", index=X.index)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test-sessions", default="", help="comma-separated capture sessions held out for testing")
    ap.add_argument("--exclude-sessions", default="", help="sessions to ignore entirely")
    ap.add_argument("--base-model", default="models/cic-ids2017-lab", help="feature list is taken from this model")
    ap.add_argument("--out", default="models/k8s-lab-live")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--sample-out", default="dashboard/sample_lab_test_mix.csv",
                    help="labelled held-out flows for the dashboard's Labelled check ('' = none)")
    ap.add_argument("--sample-per-class", type=int, default=500)
    a = ap.parse_args(argv)
    cfg = load_config()
    conn = sqlite3.connect(str(get_path("database", cfg)))
    jobs = runs_by_session(conn)
    if a.list:
        for sid in sorted(jobs):
            print(sid, [(j["scenario"], j["pod_ip"]) for j in jobs[sid]])
        return 0
    test = {int(s) for s in a.test_sessions.split(",") if s.strip()}
    skip = {int(s) for s in a.exclude_sessions.split(",") if s.strip()}
    base = joblib.load(REPO / a.base_model / "best_model.joblib")
    features = list(base["features"])
    train_ids = [s for s in sorted(jobs) if s not in test and s not in skip]
    test_ids = [s for s in sorted(jobs) if s in test]
    Xtr, ytr, mtr = build(conn, train_ids, jobs, get_path("flows_dir", cfg), features)
    Xb, yb = lab_benign(features)
    Xtr, ytr = pd.concat([Xtr, Xb], ignore_index=True), pd.concat([ytr, yb], ignore_index=True)
    Xte, yte, mte = build(conn, test_ids, jobs, get_path("flows_dir", cfg), features)
    print("train", ytr.value_counts().to_dict(), "\ntest ", yte.value_counts().to_dict())
    model = RandomForestClassifier(n_estimators=200, class_weight="balanced_subsample", n_jobs=-1, random_state=42)
    t0 = time.perf_counter()
    model.fit(Xtr.to_numpy(np.float32), ytr.to_numpy())
    fit_s = time.perf_counter() - t0
    classes = list(model.classes_)
    # Same layout as the CIC metrics.json, so the dashboard's Model and Threats pages read it unchanged.
    metrics: dict = {"trained_at": datetime.now(timezone.utc).isoformat(), "features": features, "classes": classes,
                     "best_model": "RandomForest", "models": {},
                     "split_counts": {"train": ytr.value_counts().to_dict(), "test": yte.value_counts().to_dict()},
                     "source": "K3s lab flows from the live CICFlowMeter, labelled by Traffic-lab runs "
                               "(test = whole held-out capture sessions)",
                     "train_sessions": mtr, "test_sessions": mte, "lab_benign_flows": int(len(yb))}
    if len(yte):
        t0 = time.perf_counter()
        pred = model.predict(Xte.to_numpy(np.float32))
        pred_s = time.perf_counter() - t0
        rep = classification_report(yte, pred, labels=classes, output_dict=True, zero_division=0)
        present = sorted(set(yte))
        res = {
            "accuracy": float((pred == yte.to_numpy()).mean()),
            "macro_f1": float(f1_score(yte, pred, labels=present, average="macro")),
            "weighted_f1": float(f1_score(yte, pred, labels=present, average="weighted")),
            "attack_detection_rate": float(((pred != "BENIGN") & (yte != "BENIGN")).sum() / max(1, (yte != "BENIGN").sum())),
            "false_alarm_rate": float(((pred != "BENIGN") & (yte == "BENIGN")).sum() / max(1, (yte == "BENIGN").sum())),
            "per_class": {c: {"precision": rep[c]["precision"], "recall": rep[c]["recall"], "f1": rep[c]["f1-score"],
                              "support": int(rep[c]["support"])} for c in classes if c in rep},
            "fit_seconds": round(fit_s, 1), "predict_seconds": round(pred_s, 2),
            "confusion_matrix": confusion_matrix(yte, pred, labels=classes).tolist(),
        }
        metrics["models"]["RandomForest"] = res
        print(json.dumps({k: v for k, v in res.items() if k != "confusion_matrix"}, indent=1))
        print("confusion (rows true, cols predicted)", classes)
        for c, row in zip(classes, res["confusion_matrix"]):
            print(f"  {c:11s}", row)
    out = REPO / a.out
    out.mkdir(parents=True, exist_ok=True)
    if len(yte) and a.sample_out:
        # Held-out flows only (never trained on), up to N per class, for the Labelled check.
        s = Xte.assign(Label=yte.to_numpy())
        s = pd.concat([g.sample(min(len(g), a.sample_per_class), random_state=0) for _, g in s.groupby("Label")])
        (REPO / a.sample_out).parent.mkdir(parents=True, exist_ok=True)
        s.to_csv(REPO / a.sample_out, index=False)
        metrics["eval_sample"] = a.sample_out
        print(f"saved {a.sample_out} ({len(s)} labelled held-out flows)")
    joblib.dump({"model": model, "features": features, "classes": classes}, out / "best_model.joblib", compress=3)
    (out / "metrics.json").write_text(json.dumps(metrics, indent=1, default=str))
    print(f"saved {out}/best_model.joblib")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
