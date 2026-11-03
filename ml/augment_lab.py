"""Augment the CIC-IDS2017 training set with verified benign lab traffic, then
retrain so the model raises fewer false alarms on real K3s cluster traffic.

The CIC-IDS2017 dataset was recorded on a different network, so a few percent of
ordinary K3s flows (kubelet probes, CoreDNS, control plane) look unusual to a
dataset-only model. Adding captured benign flows from this cluster, all labelled
BENIGN, teaches it what normal looks like here without changing the attack classes.

    python ml/augment_lab.py <clean.parquet> <lab_benign_dir> [more_dirs...] [--out out_lab/]

<clean.parquet> is the output of prepare.py (features + 'label'). Each lab dir
holds CICFlowMeter CSVs of benign cluster traffic. Writes an augmented parquet and
then you run: python ml/train.py <out_dir>
"""
from __future__ import annotations

import argparse
import glob
import sys
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from prepare import canon  # noqa: E402


def load_lab_benign(dirs: list[str], features: list[str]) -> pd.DataFrame:
    """Read benign CICFlowMeter CSVs and align them to the model's 68 features."""
    frames = []
    for d in dirs:
        for f in sorted(glob.glob(str(Path(d) / "*.csv"))):
            df = pd.read_csv(f, low_memory=False, skipinitialspace=True)
            df.columns = [str(c).strip() for c in df.columns]
            df = df[df.get("Src IP", pd.Series(index=df.index)).astype(str) != "Src IP"] if "Src IP" in df else df
            by = {}
            for c in df.columns:
                by.setdefault(canon(c), c)
            cols = {feat: (pd.to_numeric(df[by[feat]], errors="coerce") if feat in by else np.nan) for feat in features}
            X = pd.DataFrame(cols).replace([np.inf, -np.inf], np.nan)
            X = X.dropna(how="all")
            frames.append(X)
    if not frames:
        return pd.DataFrame(columns=features)
    out = pd.concat(frames, ignore_index=True).fillna(0.0)
    out["label"] = "BENIGN"
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("clean_parquet", type=Path)
    ap.add_argument("lab_dirs", nargs="+")
    ap.add_argument("--out", type=Path, default=Path("out_lab"))
    a = ap.parse_args()

    data = pd.read_parquet(a.clean_parquet)
    features = [c for c in data.columns if c != "label"]
    lab = load_lab_benign(a.lab_dirs, features)
    print(f"dataset rows {len(data):,}; lab benign rows added {len(lab):,}")

    aug = pd.concat([data, lab[[*features, "label"]]], ignore_index=True)
    a.out.mkdir(parents=True, exist_ok=True)
    aug.to_parquet(a.out / "clean.parquet")
    print(f"wrote {a.out / 'clean.parquet'} ({len(aug):,} rows). Now run: python ml/train.py {a.out}/")


if __name__ == "__main__":
    main()
