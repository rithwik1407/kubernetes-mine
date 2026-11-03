"""Window/channel-level IDS experiment.

Aggregates CICFlowMeter flows into (time window, src IP, dst IP, dst port, proto) "channels"
and trains models on behaviour features that do not depend on IPs or port numbers.
"""
import glob, json, sys, time
from pathlib import Path
import numpy as np, pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score
import lightgbm as lgb, xgboost as xgb

KDS = Path(sys.argv[1]); LAB = Path(sys.argv[2]); OUT = Path(sys.argv[3])
NUM = ["Flow Duration", "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet",
       "Total Length of Bwd Packet", "SYN Flag Count", "FIN Flag Count", "RST Flag Count",
       "PSH Flag Count", "ACK Flag Count", "Flow IAT Mean", "FWD Init Win Bytes", "Bwd Init Win Bytes"]


def read(f):
    d = pd.read_csv(f, low_memory=False)
    d = d[d["Src IP"] != "Src IP"]
    for c in NUM + ["Dst Port", "Src Port", "Protocol"]:
        d[c] = pd.to_numeric(d[c], errors="coerce")
    d["ts"] = pd.to_datetime(d["Timestamp"], format="mixed")
    return d


def aggregate(d, win_col, win_len):
    """One row per (window, channel)."""
    d = d.copy()
    d["dur_s"] = d["Flow Duration"] / 1e6
    d["bytes"] = d["Total Length of Fwd Packet"] + d["Total Length of Bwd Packet"]
    d["pkts"] = d["Total Fwd Packet"] + d["Total Bwd packets"]
    d["short"] = (d["pkts"] <= 3).astype(int)
    d["rst"] = (d["RST Flag Count"] > 0).astype(int)
    d["noreply"] = (d["Total Bwd packets"] == 0).astype(int)
    keys = [win_col, "Src IP", "Dst IP", "Dst Port", "Protocol"]
    g = d.sort_values("ts").groupby(keys, sort=False)
    out = g.agg(n_flows=("ts", "size"), n_srcports=("Src Port", "nunique"),
                dur_mean=("dur_s", "mean"), dur_std=("dur_s", "std"), dur_max=("dur_s", "max"),
                pkts_mean=("pkts", "mean"), pkts_std=("pkts", "std"),
                fwd_bytes_mean=("Total Length of Fwd Packet", "mean"),
                bwd_bytes_mean=("Total Length of Bwd Packet", "mean"),
                bytes_sum=("bytes", "sum"), short_frac=("short", "mean"), rst_frac=("rst", "mean"),
                noreply_frac=("noreply", "mean"), syn_mean=("SYN Flag Count", "mean"),
                fin_mean=("FIN Flag Count", "mean"), psh_mean=("PSH Flag Count", "mean"),
                iat_in_flow=("Flow IAT Mean", "mean"),
                t0=("ts", "min"), t1=("ts", "max"), label=("y", "max"), amb=("amb", "max")).reset_index()
    gaps = g["ts"].apply(lambda s: s.diff().dt.total_seconds().dropna())
    gs = gaps.groupby(level=list(range(len(keys)))).agg(["mean", "std"]).reset_index()
    gs.columns = keys + ["gap_mean", "gap_std"]
    out = out.merge(gs, on=keys, how="left")
    out["rate"] = out.n_flows / win_len
    out["span_s"] = (out.t1 - out.t0).dt.total_seconds()
    out["gap_cv"] = out.gap_std / out.gap_mean
    out["bwd_fwd_ratio"] = out.bwd_bytes_mean / (out.fwd_bytes_mean + 1)
    out["is_tcp"] = (out.Protocol == 6).astype(int)
    # number of distinct destinations / ports this source touched in the same window (scan breadth)
    src = d.groupby([win_col, "Src IP"]).agg(src_dsts=("Dst IP", "nunique"), src_ports=("Dst Port", "nunique"),
                                             src_flows=("ts", "size")).reset_index()
    out = out.merge(src, on=[win_col, "Src IP"], how="left")
    return out.replace([np.inf, -np.inf], np.nan)


FEATS = ["n_flows", "rate", "n_srcports", "dur_mean", "dur_std", "dur_max", "pkts_mean", "pkts_std",
         "fwd_bytes_mean", "bwd_bytes_mean", "bytes_sum", "short_frac", "rst_frac", "noreply_frac",
         "syn_mean", "fin_mean", "psh_mean", "iat_in_flow", "gap_mean", "gap_std", "gap_cv", "span_s",
         "bwd_fwd_ratio", "is_tcp", "src_dsts", "src_ports", "src_flows"]


def dataset_windows(win=10):
    rows = []
    for f in sorted(KDS.glob("*/*.pcap_Flow.csv")):
        name = f.name.split("_")[0]
        d = read(f)
        d["y"] = 0; d["amb"] = 0
        if name == "reconnaissance":
            m = (d["Src IP"] == "100.64.0.2") & (d["Dst IP"] == "10.16.0.15") & (d["Dst Port"] == 1880)
            d.loc[m, "y"] = 1
        elif f.parent.name == "malicious":
            continue  # other attack captures: flows are ~95-100 % background; no reliable channel labels
        d["win"] = ((d.ts - d.ts.min()).dt.total_seconds() // win).astype(int)
        a = aggregate(d, "win", win); a["source"] = f"kds:{name}"; a["capture"] = f.stem
        rows.append(a)
    return pd.concat(rows, ignore_index=True)


def lab_windows(name):
    m = json.loads((LAB / name / "manifest.json").read_text())
    frames = []
    for f in m["files"]:
        d = read(LAB / name / f); d["file"] = f; frames.append(d)
    d = pd.concat(frames, ignore_index=True)
    d["y"] = 0; d["amb"] = 0
    if m["kind"] == "attack":
        ips = set(m["attacker_ips"])
        inv = d["Src IP"].isin(ips) | d["Dst IP"].isin(ips)
        onp = (d["Dst Port"] == m["target_port"]) | (d["Src Port"] == m["target_port"])
        d.loc[inv & onp, "y"] = 1
        d.loc[inv & ~onp, "amb"] = 1
    outs = []
    for f, g in d.groupby("file"):  # each capture file is one window
        wl = max((g.ts.max() - g.ts.min()).total_seconds(), 5.0)
        outs.append(aggregate(g, "file", min(wl, 10.0)))
    a = pd.concat(outs, ignore_index=True)
    a = a[a.amb == 0]
    a["source"] = f"lab:{name}"; a["capture"] = name
    return a


def models():
    return {
        "rule(min_flows>=15,rate>=1,tcp)": None,
        "LogReg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
        "RandomForest": RandomForestClassifier(300, min_samples_leaf=2, class_weight="balanced_subsample", n_jobs=-1, random_state=0),
        "ExtraTrees": ExtraTreesClassifier(300, min_samples_leaf=2, class_weight="balanced", n_jobs=-1, random_state=0),
        "LightGBM": lgb.LGBMClassifier(n_estimators=300, learning_rate=0.05, num_leaves=15, min_child_samples=5,
                                       class_weight="balanced", verbose=-1, random_state=0),
        "XGBoost": xgb.XGBClassifier(n_estimators=300, learning_rate=0.05, max_depth=4, subsample=0.8,
                                     colsample_bytree=0.8, eval_metric="logloss", random_state=0),
    }


def evaluate(train, tests, title):
    res = []
    X = train[FEATS].fillna(0); y = train.label
    for name, m in models().items():
        if m is not None:
            if name == "XGBoost":
                m.set_params(scale_pos_weight=(y == 0).sum() / max((y == 1).sum(), 1))
            t = time.time(); m.fit(X, y); fit_s = time.time() - t
        for tname, te in tests.items():
            Xt = te[FEATS].fillna(0)
            if m is None:
                p = ((te.n_flows >= 15) & (te.rate >= 1.0) & (te.is_tcp == 1)).astype(int).values
            else:
                p = (m.predict_proba(Xt)[:, 1] >= 0.5).astype(int)
            yt = te.label.values
            # flow-level recall: share of attack flows inside channels flagged
            att_flows = te.loc[yt == 1, "n_flows"].sum()
            caught = te.loc[(yt == 1) & (p == 1), "n_flows"].sum()
            fp_ch = int(((p == 1) & (yt == 0)).sum()); neg = int((yt == 0).sum())
            res.append(dict(setting=title, model=name, test=tname,
                            attack_windows=int((yt == 1).sum()),
                            recall=recall_score(yt, p, zero_division=0) if (yt == 1).any() else np.nan,
                            precision=precision_score(yt, p, zero_division=0) if p.any() else np.nan,
                            f1=f1_score(yt, p, zero_division=0) if (yt == 1).any() else np.nan,
                            attack_flow_coverage=caught / att_flows if att_flows else np.nan,
                            fp_channels=fp_ch, benign_channels=neg, fpr=fp_ch / neg if neg else np.nan))
    return res


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    kds = dataset_windows()
    lab = {n: lab_windows(n) for n in ["benign_train", "benign_eval_a", "benign_eval_b", "recon_run1", "recon_run2"]}
    print("dataset channel-windows", kds.shape, kds.label.value_counts().to_dict())
    for n, a in lab.items():
        print(n, a.shape, a.label.value_counts().to_dict())
    res = []
    # A: dataset only -> lab (does knowledge transfer to the live cluster?)
    res += evaluate(kds, {n: lab[n] for n in ["benign_eval_a", "benign_eval_b", "recon_run1", "recon_run2"]},
                    "A: train dataset only")
    # B: dataset + lab benign_train + recon_run1 -> held-out recon_run2 + benign evals
    trB = pd.concat([kds, lab["benign_train"], lab["recon_run1"]])
    res += evaluate(trB, {n: lab[n] for n in ["benign_eval_a", "benign_eval_b", "recon_run2"]},
                    "B: dataset+lab(benign_train,recon_run1)")
    # C: swap recon runs
    trC = pd.concat([kds, lab["benign_train"], lab["recon_run2"]])
    res += evaluate(trC, {n: lab[n] for n in ["benign_eval_a", "benign_eval_b", "recon_run1"]},
                    "C: dataset+lab(benign_train,recon_run2)")
    # D: lab only -> dataset (reverse transfer, harder: dataset recon is ~6x faster, other cluster)
    trD = pd.concat([lab["benign_train"], lab["recon_run1"], lab["recon_run2"]])
    res += evaluate(trD, {"kds:all": kds}, "D: train lab only -> test dataset")
    r = pd.DataFrame(res)
    r.to_csv(OUT / "window_results.csv", index=False)
    pd.set_option("display.width", 250); pd.set_option("display.max_rows", 500)
    print(r.round(3).to_string(index=False))
    # feature importances of LightGBM in setting B
    m = models()["LightGBM"].fit(trB[FEATS].fillna(0), trB.label)
    imp = pd.Series(m.booster_.feature_importance("gain"), FEATS).sort_values(ascending=False)
    print((imp / imp.sum()).round(3).head(12).to_string())
    kds.to_parquet(OUT / "kds_windows.parquet") if False else None
