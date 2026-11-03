"""Steps 4-7: stratified split, class balancing, train RF / Naive Bayes / LightGBM / XGBoost, evaluate.

Usage:
    python train.py <out_dir> [--own-csv path/to/k8s-lab-01.pcap_ISCX.csv] [--benign-cap 400000]

Reads <out_dir>/clean.parquet from prepare.py. Writes, into <out_dir>:
    metrics.json            per-model accuracy, macro F1, weighted F1, per-class P/R/F1
    report_<model>.txt      sklearn classification report
    cm_<model>.png          normalised confusion matrix
    best_model.joblib       best model by macro F1 + feature list + class names
"""
import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix, f1_score,
                             precision_recall_fscore_support)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight

sys.path.insert(0, str(Path(__file__).parent))
from prepare import canon  # noqa: E402

SEED = 42


def signed_log1p(X):
    return np.sign(X) * np.log1p(np.abs(X))


def build_models():
    import lightgbm as lgb
    import xgboost as xgb
    return {
        "RandomForest": RandomForestClassifier(
            n_estimators=200, min_samples_leaf=1, class_weight="balanced_subsample",
            n_jobs=-1, random_state=SEED),
        # NB assumes Gaussian features; flow stats are heavy-tailed, so log-transform + scale first.
        "NaiveBayes": make_pipeline(FunctionTransformer(signed_log1p), StandardScaler(), GaussianNB()),
        "LightGBM": lgb.LGBMClassifier(
            n_estimators=400, learning_rate=0.05, num_leaves=63, class_weight="balanced",
            # Balanced weights give rare classes ~400x weight; without a hessian floor and L2,
            # multiclass leaves blow up and the model diverges (macro F1 0.33 on CIC-IDS2017).
            min_child_weight=1.0, reg_lambda=1.0,
            subsample=0.8, subsample_freq=1, colsample_bytree=0.8, n_jobs=-1,
            random_state=SEED, verbose=-1),
        "XGBoost": xgb.XGBClassifier(
            n_estimators=400, learning_rate=0.1, max_depth=10, subsample=0.8,
            colsample_bytree=0.8, tree_method="hist", n_jobs=-1, random_state=SEED),
    }


def plot_cm(cm, classes, title, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    cmn = cm / cm.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(classes)), classes, rotation=45, ha="right")
    ax.set_yticks(range(len(classes)), classes)
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, f"{cmn[i, j]:.2f}\n({cm[i, j]})", ha="center", va="center", fontsize=7,
                    color="white" if cmn[i, j] > 0.5 else "black")
    ax.set_xlabel("Predicted"); ax.set_ylabel("True"); ax.set_title(title)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--own-csv", help="your CICFlowMeter CSV; keep only features it also has")
    ap.add_argument("--benign-cap", type=int, default=400_000,
                    help="max BENIGN rows in the TRAINING split (test split is never resampled)")
    ap.add_argument("--models", default="RandomForest,NaiveBayes,LightGBM,XGBoost")
    a = ap.parse_args()
    out = Path(a.out_dir)

    data = pd.read_parquet(out / "clean.parquet")
    feats = [c for c in data.columns if c != "label"]

    if a.own_csv:
        own = {canon(c) for c in pd.read_csv(a.own_csv, nrows=1).columns}
        missing = [f for f in feats if f not in own]
        feats = [f for f in feats if f in own]
        print(f"Keeping {len(feats)} features shared with {a.own_csv}; dropped {missing}")

    le = LabelEncoder().fit(data["label"])
    classes = list(le.classes_)
    X, y = data[feats].to_numpy(np.float32), le.transform(data["label"])
    del data

    # Step 4: 70/30 stratified split, done BEFORE any balancing so the test set stays realistic.
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.30, stratify=y, random_state=SEED)
    del X, y

    # Step 5: balance the training split only. Downsample BENIGN, then class weights for the rest.
    b = classes.index("BENIGN")
    rng = np.random.default_rng(SEED)
    idx_b = np.flatnonzero(ytr == b)
    if len(idx_b) > a.benign_cap:
        keep = np.concatenate([rng.choice(idx_b, a.benign_cap, replace=False), np.flatnonzero(ytr != b)])
        rng.shuffle(keep)
        Xtr, ytr = Xtr[keep], ytr[keep]
    sw = compute_sample_weight("balanced", ytr)

    split = {"train": dict(zip(classes, np.bincount(ytr, minlength=len(classes)).tolist())),
             "test": dict(zip(classes, np.bincount(yte, minlength=len(classes)).tolist()))}
    print("Train/test class counts:", json.dumps(split, indent=1))

    results, fitted = {"features": feats, "classes": classes, "split_counts": split, "models": {}}, {}
    for name, model in build_models().items():
        if name not in a.models.split(","):
            continue
        t = time.time()
        print(f"\n== {name}")
        if name == "XGBoost":
            model.fit(Xtr, ytr, sample_weight=sw)
        else:
            model.fit(Xtr, ytr)          # RF / LightGBM use class_weight; NB uses priors
        fit_s = time.time() - t
        t = time.time()
        pred = model.predict(Xte)
        pred_s = time.time() - t

        p, r, f, s = precision_recall_fscore_support(yte, pred, labels=range(len(classes)), zero_division=0)
        cm = confusion_matrix(yte, pred, labels=range(len(classes)))
        res = {
            "accuracy": accuracy_score(yte, pred),
            "macro_f1": f1_score(yte, pred, average="macro"),
            "weighted_f1": f1_score(yte, pred, average="weighted"),
            # Detection view: any attack class vs BENIGN.
            "attack_detection_rate": float((pred[yte != b] != b).mean()),
            "false_alarm_rate": float((pred[yte == b] != b).mean()),
            "per_class": {c: {"precision": p[i], "recall": r[i], "f1": f[i], "support": int(s[i])}
                          for i, c in enumerate(classes)},
            "fit_seconds": round(fit_s, 1), "predict_seconds": round(pred_s, 1),
            "confusion_matrix": cm.tolist(),
        }
        results["models"][name] = res
        fitted[name] = model
        rep = classification_report(yte, pred, target_names=classes, digits=4, zero_division=0)
        (out / f"report_{name}.txt").write_text(rep)
        plot_cm(cm, classes, f"{name}  macro F1={res['macro_f1']:.4f}", out / f"cm_{name}.png")
        print(rep)
        print(f"macro F1 {res['macro_f1']:.4f}  accuracy {res['accuracy']:.4f}  "
              f"false alarms {res['false_alarm_rate']:.4%}  fit {fit_s:.0f}s")

    best = max(results["models"], key=lambda m: results["models"][m]["macro_f1"])
    results["best_model"] = best
    joblib.dump({"model": fitted[best], "features": feats, "classes": classes}, out / "best_model.joblib",
                compress=3)
    (out / "metrics.json").write_text(json.dumps(results, indent=2, default=float))

    print("\nSummary (sorted by macro F1):")
    for m, r in sorted(results["models"].items(), key=lambda kv: -kv[1]["macro_f1"]):
        print(f"  {m:13s} macro F1 {r['macro_f1']:.4f}  acc {r['accuracy']:.4f}  "
              f"detect {r['attack_detection_rate']:.4f}  false alarm {r['false_alarm_rate']:.4%}")
    print(f"Saved {best} to {out / 'best_model.joblib'}")


if __name__ == "__main__":
    main()
