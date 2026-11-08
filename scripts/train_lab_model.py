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
  * web_recon (a crawler) is BENIGN; decoy_probe pods are left out
  * an attack pod's mixed-in benign requests (source ports traffic_lab.benign_src_ports) are BENIGN
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
from collections import Counter
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

# web_recon (a crawler requesting common paths) is benign traffic: the redirect must leave
# it alone, so the model learns it as BENIGN
SCENARIO_CLASS = {"port_scan": "PortScan", "brute_force": "BruteForce", "web_attack": "WebAttack",
                  "slow_dos": "DoS", "benign": "BENIGN", "web_recon": "BENIGN"}
NO_CLASS = {"decoy_probe"}                    # its pod's flows are excluded
BENIGN_PORTS = (20000, 20999)                 # traffic_lab.benign_src_ports
ATTACK = ["PortScan", "BruteForce", "WebAttack", "DoS"]
MIN_TRAIN_FLOWS = 200                         # below this a class is reported as "needs more runs"
CLASS_SCENARIO = {v: k for k, v in SCENARIO_CLASS.items()}


def runs_by_session(conn) -> dict[int, list[dict]]:
    """Traffic-lab Jobs (scenario, pod IP) per capture session.

    The dashboard's run history keeps only the latest runs, so older runs are also rebuilt
    from the scored flows themselves: each flow records the lab Job and scenario of its
    generator pod (live/labsources.py), and its capture records the session. The pod IP is
    the address that appears in every flow of that Job."""
    row = conn.execute("SELECT value FROM kv WHERE key = 'pipeline_runs'").fetchone()
    out: dict[int, list[dict]] = {}
    seen: set[str] = set()
    for r in json.loads(row[0]) if row else []:
        sid = r.get("session_id")
        if not sid:
            continue
        for j in r.get("jobs", []):
            if j.get("pod_ip") and j.get("scenario"):
                out.setdefault(int(sid), []).append({"scenario": j["scenario"], "pod_ip": j["pod_ip"], "job": j["job"]})
                seen.add(j["job"])
    for job, sc, sid, ip in archived_jobs(conn):
        if job not in seen and (sc in SCENARIO_CLASS or sc in NO_CLASS):
            out.setdefault(int(sid), []).append({"scenario": sc, "pod_ip": ip, "job": job})
            seen.add(job)
    return out


def archived_jobs(conn) -> list[tuple[str, str, int, str]]:
    """(job, scenario, session, pod IP) for every lab Job that has scored flows."""
    try:
        rows = conn.execute(
            "SELECT d.lab_job, d.lab_scenario, COALESCE(d.session_id, c.session_id) sid, "
            "d.src_ip, d.dst_ip FROM detections d LEFT JOIN captures c ON c.id = d.capture_id "
            "WHERE d.lab_job IS NOT NULL AND d.lab_scenario IS NOT NULL AND d.simulated = 0").fetchall()
    except sqlite3.Error:
        return []
    ips: dict[str, Counter] = {}
    meta: dict[str, tuple[str, Counter]] = {}
    nrows: Counter = Counter()
    for job, sc, sid, src, dst in rows:
        if not job.startswith("traffic-") or sc == "benign":      # the benign Deployment is background
            continue
        ips.setdefault(job, Counter()).update({src, dst})
        nrows[job] += 1
        m = meta.setdefault(job, (sc, Counter()))
        if sid:
            m[1][sid] += 1
    # how many Jobs each address appears in: a target app serves many Jobs, a generator pod one
    jobs_of: Counter = Counter(ip for cnt in ips.values() for ip in cnt)
    out = []
    for job, cnt in ips.items():
        sc, sids = meta[job]
        if not sids:
            continue
        cands = [ip for ip, n in cnt.items() if ip and n >= 0.9 * nrows[job]]   # in (nearly) every flow
        if cands:
            ip = min(cands, key=lambda a: (jobs_of[a], -cnt[a]))
            out.append((job, sc, sids.most_common(1)[0][0], ip))
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


def label(df: pd.DataFrame, jobs: list[dict], benign_ports: tuple[int, int] = BENIGN_PORTS) -> pd.Series:
    lab = pd.Series("BENIGN", index=df.index, dtype="object")
    src, dst = df["Src IP"].astype(str), df["Dst IP"].astype(str)
    sport = pd.to_numeric(df["Src Port"], errors="coerce")
    dport = pd.to_numeric(df["Dst Port"], errors="coerce")
    dns = (sport == 53) | (dport == 53)
    lo, hi = benign_ports
    # the ordinary requests an attack pod mixes in (fixed source ports, see the generator)
    mixed = sport.between(lo, hi) | dport.between(lo, hi)
    for j in jobs:
        mine = (src == j["pod_ip"]) | (dst == j["pod_ip"])
        cls = SCENARIO_CLASS.get(j["scenario"])
        if j["scenario"] in NO_CLASS or cls is None:
            lab[mine] = None
        else:
            lab[mine & ~dns] = cls
            lab[mine & dns] = "BENIGN" if cls == "BENIGN" else None
            lab[mine & mixed & ~dns] = "BENIGN"
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
        Xs = Xs.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32)
        ts = pd.to_datetime(df.loc[keep, "Timestamp"], errors="coerce", dayfirst=True)
        Xs["_session"] = sid
        Xs["_scenario"] = "+".join(sorted({j["scenario"] for j in jobs[sid]}))
        Xs["_t"] = ts.astype("int64").to_numpy() if len(ts) else []
        X.append(Xs)
        y.append(lab[keep].astype(str))
        meta.append({"session": sid, "jobs": [f"{j['scenario']} {j['job']}" for j in jobs[sid]],
                     "flows": int(keep.sum()), "labels": lab[keep].value_counts().to_dict()})
    if not X:
        return pd.DataFrame(columns=features + ["_session", "_scenario", "_t"]), pd.Series(dtype=str), meta
    return pd.concat(X, ignore_index=True), pd.concat(y, ignore_index=True), meta


def lab_benign(features: list[str]) -> tuple[pd.DataFrame, pd.Series]:
    frames = []
    for f in sorted(glob.glob(str(REPO / "data" / "k8s" / "lab-benign" / "*.csv"))):
        df, _ = drop_non_ip_flows(read_flow_csv(f))
        Xs, _ = align_features(df, features)
        frames.append(Xs.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32))
    X = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=features)
    return X, pd.Series("BENIGN", index=X.index)


def split_per_class(X: pd.DataFrame, y: pd.Series, test_sessions: set[int], frac: float = 0.25) -> np.ndarray:
    """Test mask such that EVERY class, and every kind of benign traffic, is in the test set.

    * explicit --test-sessions: those whole sessions are the test set (as before);
    * otherwise per scenario (port_scan, brute_force, web_recon, ...): with 2+ runs, its newest
      run is held out whole (all its flows: the attack, the benign requests mixed into it and
      the background traffic); with one run, the LAST `frac` of that run's flows (by time).
      The model is always tested on flows later than any it trained on, from every scenario,
      so a class with few runs no longer ends up with test support 0.
    """
    sess = X["_session"].to_numpy()
    if test_sessions:
        return np.isin(sess, list(test_sessions))
    key = X["_scenario"].to_numpy() if "_scenario" in X else y.to_numpy()
    t = X["_t"].to_numpy()
    test = np.zeros(len(X), dtype=bool)
    for k in sorted(set(key)):
        m = key == k
        ids = sorted(set(sess[m]))
        if len(ids) >= 2:
            test |= m & (sess == ids[-1])
        elif m.sum() >= 4:
            cut = np.quantile(t[m], 1 - frac)
            test |= m & (t >= cut)
    return test


def load_cic(path: Path, features: list[str], per_class: int, classes: list[str]) -> tuple[pd.DataFrame, pd.Series]:
    """Up to `per_class` CIC-IDS2017 rows of each class in `classes` (training only)."""
    sys.path.insert(0, str(REPO / "ml"))
    from prepare import group_label  # noqa: E402
    keep: dict[str, list[pd.DataFrame]] = {c: [] for c in classes}
    got = dict.fromkeys(classes, 0)
    for chunk in pd.read_csv(path, encoding="latin-1", low_memory=False, chunksize=200_000):
        chunk.columns = [c.strip() for c in chunk.columns]
        chunk = chunk.loc[:, ~chunk.columns.duplicated()]
        lab = chunk["Label"].map(group_label)
        for c in classes:
            if got[c] < per_class:
                part = chunk[lab == c]
                part = part.sample(min(len(part), per_class - got[c]), random_state=0)
                keep[c].append(part)
                got[c] += len(part)
    frames, labels = [], []
    for c, parts in keep.items():
        if parts:
            d = pd.concat(parts, ignore_index=True)
            Xs, _ = align_features(d, features)
            frames.append(Xs.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32))
            labels.append(pd.Series(c, index=range(len(d))))
    if not frames:
        return pd.DataFrame(columns=features), pd.Series(dtype=str)
    return pd.concat(frames, ignore_index=True), pd.concat(labels, ignore_index=True)


def evaluate(model_or_path, Xte: pd.DataFrame, yte: pd.Series, features: list[str]) -> dict | None:
    """Per-class metrics of a model on the held-out flows (the current live model for the gate)."""
    if isinstance(model_or_path, (str, Path)):
        p = Path(model_or_path) / "best_model.joblib"
        if not p.is_file():
            return None
        bundle = joblib.load(p)
        model, feats = bundle["model"], list(bundle["features"])
        if feats != features:
            Xte = Xte.reindex(columns=feats, fill_value=0.0)
    else:
        model = model_or_path
    pred = model.predict(Xte[features if not isinstance(model_or_path, (str, Path)) else Xte.columns].to_numpy(np.float32))
    labels = sorted(set(yte) | set(pred))
    rep = classification_report(yte, pred, labels=labels, output_dict=True, zero_division=0)
    present = sorted(set(yte))
    return {
        "accuracy": float((pred == yte.to_numpy()).mean()),
        "macro_f1": float(f1_score(yte, pred, labels=present, average="macro")),
        "weighted_f1": float(f1_score(yte, pred, labels=present, average="weighted")),
        "attack_detection_rate": float(((pred != "BENIGN") & (yte != "BENIGN")).sum() / max(1, (yte != "BENIGN").sum())),
        "false_alarm_rate": float(((pred != "BENIGN") & (yte == "BENIGN")).sum() / max(1, (yte == "BENIGN").sum())),
        "per_class": {c: {"precision": rep[c]["precision"], "recall": rep[c]["recall"], "f1": rep[c]["f1-score"],
                          "support": int(rep[c]["support"])} for c in present},
        "_pred": pred,
    }


def gate(new: dict, old: dict | None, tolerance: float = 0.02) -> tuple[bool, str]:
    """Replace the live model only if no class's recall drops and at least one improves
    (or there is no current model to compare with)."""
    if old is None:
        return True, "no current model to compare with"
    worse, better = [], []
    for c, m in new["per_class"].items():
        o = (old["per_class"].get(c) or {}).get("recall")
        if o is None:
            continue
        if m["recall"] < o - tolerance:
            worse.append(f"{c} {o:.3f} -> {m['recall']:.3f}")
        elif m["recall"] > o + 0.001:
            better.append(f"{c} {o:.3f} -> {m['recall']:.3f}")
    if worse:
        return False, "recall dropped for " + ", ".join(worse)
    if not better and new["macro_f1"] <= old["macro_f1"] + 0.001:
        return False, "no class's recall improved on the same held-out flows"
    return True, "recall improved for " + (", ".join(better) if better else "none (macro F1 improved)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test-sessions", default="", help="comma-separated capture sessions held out whole for testing "
                                                         "(default: per class, see split_per_class)")
    ap.add_argument("--exclude-sessions", default="", help="sessions to ignore entirely")
    ap.add_argument("--base-model", default="models/cic-ids2017-lab", help="feature list is taken from this model")
    ap.add_argument("--out", default="models/k8s-lab-live")
    ap.add_argument("--compare", default="", help="model dir to compare with (default: --out); the new model "
                                                  "replaces it only if per-class recall improves")
    ap.add_argument("--force", action="store_true", help="replace the model even if recall did not improve")
    ap.add_argument("--cic-csv", default="", help="CIC-IDS2017 merged CSV: add its rows of the lab's attack classes "
                                                  "to TRAINING (never to the test set)")
    ap.add_argument("--cic-per-class", type=int, default=5000)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--sample-out", default="dashboard/sample_lab_test_mix.csv",
                    help="labelled held-out flows for the dashboard's Labelled check ('' = none)")
    ap.add_argument("--sample-per-class", type=int, default=500)
    a = ap.parse_args(argv)
    cfg = load_config()
    global BENIGN_PORTS
    BENIGN_PORTS = tuple((cfg["traffic_lab"].get("benign_src_ports") or BENIGN_PORTS)[:2])
    conn = sqlite3.connect(str(get_path("database", cfg)))
    jobs = runs_by_session(conn)
    if a.list:
        for sid in sorted(jobs):
            print(sid, [(j["scenario"], j["pod_ip"]) for j in jobs[sid]])
        return 0
    test_ids = {int(s) for s in a.test_sessions.split(",") if s.strip()}
    skip = {int(s) for s in a.exclude_sessions.split(",") if s.strip()}
    base = joblib.load(REPO / a.base_model / "best_model.joblib")
    features = list(base["features"])
    sessions = [s for s in sorted(jobs) if s not in skip]
    X, y, meta = build(conn, sessions, jobs, get_path("flows_dir", cfg), features)
    test = split_per_class(X, y, test_ids)
    Xtr, ytr = X[~test][features], y[~test].reset_index(drop=True)
    Xte, yte = X[test][features].reset_index(drop=True), y[test].reset_index(drop=True)
    Xb, yb = lab_benign(features)
    Xtr, ytr = pd.concat([Xtr.reset_index(drop=True), Xb], ignore_index=True), pd.concat([ytr, yb], ignore_index=True)
    cic_counts = {}
    cic_error = None
    if a.cic_csv:
        try:
            Xc, yc = load_cic(Path(a.cic_csv), features, a.cic_per_class, ["BENIGN"] + ATTACK)
            cic_counts = yc.value_counts().to_dict()
            Xtr, ytr = pd.concat([Xtr, Xc], ignore_index=True), pd.concat([ytr, yc], ignore_index=True)
            print("CIC-IDS2017 rows added to training:", cic_counts)
        except Exception as e:  # noqa: BLE001 - lab-only training still works
            cic_error = f"CIC-IDS2017 rows not added ({type(e).__name__}: {e}); trained on lab flows only"
            print("WARNING:", cic_error)
    lab_train = y[~test].value_counts().to_dict()
    warnings = []
    for c in ATTACK:
        n = int(lab_train.get(c, 0))
        if n < MIN_TRAIN_FLOWS:
            warnings.append(f"{c}: only {n} lab flows for training (need {MIN_TRAIN_FLOWS}+): run "
                            f"{CLASS_SCENARIO.get(c, c)} from the Traffic lab for a few minutes and retrain")
        if c in lab_train and c not in set(yte):
            warnings.append(f"{c}: no held-out flows, so its test metrics are missing")
    if cic_error:
        warnings.append(cic_error)
    for w in warnings:
        print("WARNING:", w)
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
                     "source": "K3s lab flows from the live CICFlowMeter, labelled by Traffic-lab runs"
                               + (" + CIC-IDS2017 rows of the same classes (training only)" if cic_counts else "")
                               + "; test = per scenario, the newest run held out whole, or the last 25% of a "
                                 "scenario's flows when it has only one run",
                     "sessions": meta, "lab_benign_flows": int(len(yb)), "cic_rows": cic_counts,
                     "warnings": warnings}
    out = REPO / a.out
    decision = (True, "no held-out flows to compare on")
    if len(yte):
        t0 = time.perf_counter()
        res = evaluate(model, Xte, yte, features)
        pred = res.pop("_pred")
        res.update(fit_seconds=round(fit_s, 1), predict_seconds=round(time.perf_counter() - t0, 2),
                   confusion_matrix=confusion_matrix(yte, pred, labels=classes).tolist())
        metrics["models"]["RandomForest"] = res
        print(json.dumps({k: v for k, v in res.items() if k != "confusion_matrix"}, indent=1))
        print("confusion (rows true, cols predicted)", classes)
        for c, row in zip(classes, res["confusion_matrix"]):
            print(f"  {c:11s}", row)
        cmp_dir = REPO / (a.compare or a.out)
        old = evaluate(cmp_dir, Xte, yte, features)
        if old:
            old.pop("_pred")
            metrics["previous_model"] = {"dir": str(cmp_dir.relative_to(REPO)) if cmp_dir.is_relative_to(REPO) else str(cmp_dir),
                                         "on_same_test": old}
            print("current model on the same held-out flows:")
            for c, m in old["per_class"].items():
                print(f"  {c:11s} P {m['precision']:.3f} R {m['recall']:.3f} F1 {m['f1']:.3f} (n={m['support']})")
        decision = gate(res, old)
    replace = decision[0] or a.force
    metrics["replaced"] = replace
    metrics["decision"] = decision[1] + (" (forced)" if a.force and not decision[0] else "")
    print("DECISION:", "replace" if replace else "keep the current model", "-", metrics["decision"])
    if not replace:
        out = out / "candidate"            # kept for inspection, never loaded
    out.mkdir(parents=True, exist_ok=True)
    if len(yte) and a.sample_out and replace:
        # Held-out flows only (never trained on), up to N per class, for the Labelled check.
        smp = Xte.assign(Label=yte.to_numpy())
        smp = pd.concat([g.sample(min(len(g), a.sample_per_class), random_state=0) for _, g in smp.groupby("Label")])
        (REPO / a.sample_out).parent.mkdir(parents=True, exist_ok=True)
        smp.to_csv(REPO / a.sample_out, index=False)
        metrics["eval_sample"] = a.sample_out
        print(f"saved {a.sample_out} ({len(smp)} labelled held-out flows)")
    joblib.dump({"model": model, "features": features, "classes": classes}, out / "best_model.joblib", compress=3)
    (out / "metrics.json").write_text(json.dumps(metrics, indent=1, default=str))
    print(f"saved {out}/best_model.joblib")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
