"""Step 1-3: clean CIC-IDS2017 (MachineLearningCVE) CSVs, group labels, pick features.

Usage:
    python prepare.py <merged.csv | folder_of_csvs> <out_dir>

Writes <out_dir>/clean.parquet (features + 'label') and <out_dir>/prepare_report.json.
"""
import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# Columns that identify a flow or leak the answer. Ports are dropped because in
# CIC-IDS2017 the destination port alone nearly gives away the attack (e.g. 21/22
# for Patator, 80 for DoS), and our K3s NodePorts (31880, 30806, 30300) never appear
# in the training data, so a port-based model would not transfer to our cluster.
DROP = {"flowid", "srcip", "sourceip", "dstip", "destinationip", "srcport", "sourceport",
        "dstport", "destinationport", "timestamp", "protocol", "sourcefile", "fwdheaderlength1"}

# CIC-IDS2017 ships one duplicated column ("Fwd Header Length" appears twice).
# Old CICFlowMeter (CIC-IDS2017) and the newer CICFlowMeter we ran on our own PCAPs name
# the same feature slightly differently. We canonicalise both to one key.
ALIASES = {
    "totalfwdpacket": "totalfwdpackets",
    "totalbwdpacket": "totalbackwardpackets",   # CIC-IDS2017 says "Total Backward Packets"
    "totalbwdpackets": "totalbackwardpackets",
    "fwdsegmentsizeavg": "avgfwdsegmentsize",
    "bwdsegmentsizeavg": "avgbwdsegmentsize",
    "totallengthoffwdpacket": "totallengthoffwdpackets",
    "totallengthofbwdpacket": "totallengthofbwdpackets",
    "fwdinitwinbytes": "initwinbytesforward",
    "bwdinitwinbytes": "initwinbytesbackward",
    "fwdactdatapkts": "actdatapktfwd",
    "fwdactdatapackets": "actdatapktfwd",
    "fwdsegsizemin": "minsegsizeforward",
    "fwdminsegsize": "minsegsizeforward",
    "packetlengthmin": "minpacketlength",
    "packetlengthmax": "maxpacketlength",
    "cwrflagcount": "cweflagcount",
    "ecnflagcount": "eceflagcount",
    "fwdbytesbulkavg": "fwdavgbytesbulk",
    "fwdpacketbulkavg": "fwdavgpacketsbulk",
    "fwdbulkrateavg": "fwdavgbulkrate",
    "bwdbytesbulkavg": "bwdavgbytesbulk",
    "bwdpacketbulkavg": "bwdavgpacketsbulk",
    "bwdbulkrateavg": "bwdavgbulkrate",
}


def canon(name: str) -> str:
    k = re.sub(r"[^a-z0-9]", "", str(name).lower())
    return ALIASES.get(k, k)


def group_label(raw: str):
    s = str(raw).strip()
    u = s.upper()
    if u == "BENIGN":
        return "BENIGN"
    if u == "DDOS":
        return "DDoS"
    if u.startswith("DOS"):
        return "DoS"            # Hulk, GoldenEye, slowloris, Slowhttptest
    if u == "PORTSCAN":
        return "PortScan"
    if "PATATOR" in u:
        return "BruteForce"     # FTP-Patator, SSH-Patator
    if u.startswith("WEB ATTACK"):
        return "WebAttack"      # Brute Force, XSS, Sql Injection
    if u == "BOT":
        return "Bot"
    return None                 # Heartbleed (11 rows), Infiltration (36 rows): too few to learn


def load(src: Path) -> pd.DataFrame:
    files = sorted(src.glob("*.csv")) if src.is_dir() else [src]
    if not files:
        sys.exit(f"no CSV files found in {src}")
    parts = []
    for f in files:
        d = pd.read_csv(f, encoding="latin-1", low_memory=False)
        d.columns = [c.strip() for c in d.columns]
        d = d.loc[:, ~d.columns.duplicated()]      # drops the repeated Fwd Header Length
        print(f"  {f.name}: {len(d):,} rows")
        parts.append(d)
    return pd.concat(parts, ignore_index=True)


def main():
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    rep = {}

    print("Loading", src)
    df = load(src)
    rep["rows_loaded"] = len(df)

    label_col = next((c for c in df.columns if canon(c) == "label"), None)
    if label_col is None:
        sys.exit("no Label column found")
    df = df[df[label_col].astype(str).str.strip().str.upper() != "LABEL"]   # stray repeated headers
    rep["raw_label_counts"] = df[label_col].astype(str).str.strip().value_counts().to_dict()

    df["label"] = df[label_col].map(group_label)
    rep["dropped_rare_labels"] = int(df["label"].isna().sum())
    df = df[df["label"].notna()]

    # Feature columns: everything numeric except identifiers / ports / label.
    feats = {}
    for c in df.columns:
        k = canon(c)
        if c in ("label", label_col) or k in DROP or k in feats:
            continue
        feats[k] = c
    X = df[list(feats.values())].apply(pd.to_numeric, errors="coerce")
    X.columns = list(feats.keys())

    # Inf -> NaN, then drop those rows (a few thousand, mostly Flow Bytes/s with zero duration).
    X = X.replace([np.inf, -np.inf], np.nan)
    bad = X.isna().any(axis=1)
    rep["rows_with_nan_or_inf_dropped"] = int(bad.sum())
    X, y = X[~bad], df.loc[~bad, "label"]

    # Constant columns carry no information (8 bulk/flag columns are all zero in CIC-IDS2017).
    const = [c for c in X.columns if X[c].nunique() <= 1]
    X = X.drop(columns=const)
    rep["constant_columns_dropped"] = const

    # Keep valid zeros. Negative values in IAT / init-win columns are CICFlowMeter's "-1 = not seen";
    # we keep them as-is because trees handle them and they mean something.

    X = X.astype("float32")
    data = X.assign(label=y.values)

    # Exact duplicate rows inflate test scores (the same row lands in train and test).
    before = len(data)
    data = data.drop_duplicates()
    rep["duplicate_rows_dropped"] = before - len(data)

    # Identical features with different labels cannot be learned; drop the conflicting groups.
    fcols = [c for c in data.columns if c != "label"]
    n_lab = data.groupby(fcols, sort=False)["label"].transform("nunique")
    rep["conflicting_rows_dropped"] = int((n_lab > 1).sum())
    data = data[n_lab == 1]

    rep["final_rows"] = len(data)
    rep["n_features"] = len(fcols)
    rep["features"] = fcols
    rep["class_counts"] = data["label"].value_counts().to_dict()

    data.reset_index(drop=True).to_parquet(out / "clean.parquet", index=False)
    (out / "prepare_report.json").write_text(json.dumps(rep, indent=2, default=str))
    print(json.dumps({k: v for k, v in rep.items() if k not in ("features", "raw_label_counts")},
                     indent=2, default=str))


if __name__ == "__main__":
    main()
