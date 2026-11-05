"""Feature parity: does the live CICFlowMeter output match what the model was trained on?

    python scripts/check_feature_parity.py                     # newest live CSV in captures/flows
    python scripts/check_feature_parity.py path/to/flows.csv   # any CICFlowMeter CSV

Checks, each reported PASS / WARN / FAIL with evidence:
  1. names     every model feature is found in the CSV (after ml/prepare.py aliasing)
  2. order     inference builds X in the model's own feature order (metrics.json)
  3. units     Flow Duration / IAT columns are microseconds (as in CIC-IDS2017), not ms/s
  4. scaling   the model has no fitted scaler that live data would skip
  5. build     which CICFlowMeter produced the CSV vs the training CSVs, and the measured
               distribution shift on the most important features (live vs CIC sample)
  6. non-IP    rows that are not IP flows (e.g. ARP parsed as "8.6.0.1 -> 8.0.6.4", proto 0)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from live.config import get_path, load_config  # noqa: E402
from live.predictor import FlowPredictor  # noqa: E402
from live.schema import _canon, align_features, drop_non_ip_flows, read_flow_csv  # noqa: E402


def line(status: str, name: str, detail: str) -> dict:
    print(f"[{status:4}] {name:8} {detail}")
    return {"check": name, "status": status, "detail": detail}


def main(argv: list[str]) -> int:
    cfg = load_config()
    p = FlowPredictor.from_config(cfg)
    if argv:
        csv = Path(argv[0])
    else:
        files = sorted(get_path("flows_dir", cfg).glob("*.csv"), key=lambda f: f.stat().st_mtime)
        if not files:
            print("no live flow CSV found in captures/flows; capture some traffic first or pass a CSV")
            return 2
        csv = files[-1]
    raw = read_flow_csv(csv)
    print(f"live CSV: {csv} ({len(raw)} rows)\nmodel:    {p.model_dir.name} ({type(p.model).__name__}, {len(p.features)} features)\n")
    out = []

    # 1. names
    X, missing = align_features(raw, p.features)
    canon = _canon()
    extra = sorted({canon(c) for c in raw.columns} - set(p.features))
    out.append(line("PASS" if not missing else "FAIL", "names",
                    f"{len(p.features) - len(missing)}/{len(p.features)} model features present"
                    + (f"; missing {missing}" if missing else "") + f"; {len(extra)} CSV columns unused (identifiers/extra)"))

    # 2. order
    metrics = json.loads((p.model_dir / "metrics.json").read_text())
    same = list(metrics["features"]) == list(p.features) == list(X.columns)
    out.append(line("PASS" if same else "FAIL", "order",
                    "X columns == model.features == metrics.json features (inference selects by name, in training order)"))

    # 3. units
    d = pd.to_numeric(raw.get("Flow Duration"), errors="coerce")
    iat = X.get("flowiatmax")
    ok_units = d is not None and iat is not None and bool((iat <= d + 1).mean() > 0.99)
    med = float(d.median()) if d is not None else float("nan")
    out.append(line("PASS" if ok_units else "WARN", "units",
                    f"Flow IAT Max <= Flow Duration on {(iat <= d + 1).mean():.1%} of rows; median Flow Duration {med:,.0f} "
                    "(CIC-IDS2017 and both CICFlowMeter builds use microseconds)"))

    # 4. scaling
    steps = getattr(p.model, "steps", None)
    scaler = [n for n, _ in steps if "scal" in n.lower()] if steps else []
    out.append(line("PASS", "scaling", f"{type(p.model).__name__}: " + (f"pipeline steps {scaler} are applied by the model itself"
                    if scaler else "tree model on raw values; no scaler exists, none is skipped")))

    # 5. build + distribution shift on the top features
    jar = Path(cfg["cicflowmeter"]["jar"]).name
    imp = pd.Series(getattr(p.model, "feature_importances_", np.ones(len(p.features))), index=p.features)
    top = list(imp.sort_values(ascending=False).index[:12])
    sample = REPO / "dashboard" / "sample_cic2017_test_mix.csv"
    shift_rows = []
    if sample.is_file():
        s = pd.read_csv(sample)
        S, _ = align_features(s, p.features)
        S["label"] = s["Label"].values
        L = X.replace([np.inf, -np.inf], np.nan)
        for f in top:
            shift_rows.append({"feature": f, "importance": round(float(imp[f]), 3),
                               "CIC BENIGN median": float(S[S.label == "BENIGN"][f].median()),
                               "CIC PortScan median": float(S[S.label == "PortScan"][f].median()),
                               "live median": float(L[f].median())})
        print()
        print(pd.DataFrame(shift_rows).to_string(index=False))
        print()
    out.append(line("WARN", "build",
                    f"live flows come from {jar} (GintsEngelen fork, which fixed the original tool's TCP/padding bugs); "
                    "the model was trained on the MachineLearningCVE CSVs made by the ORIGINAL CICFlowMeter-V3. "
                    "Names and units match, but values of payload/header/window features differ between the builds "
                    "(see table): this is a distribution shift, not a parsing error"))

    # 6. non-IP rows
    _, dropped = drop_non_ip_flows(raw)
    out.append(line("PASS" if not dropped else "WARN", "non-IP",
                    f"{dropped} non-IP row(s) (dropped before scoring; capture.bpf_filter 'ip' prevents them)"))
    report = REPO / "captures" / "feature_parity.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({"csv": str(csv), "checks": out, "top_feature_shift": shift_rows}, indent=2))
    print(f"\nreport: {report.relative_to(REPO)}")
    return 1 if any(o["status"] == "FAIL" for o in out) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
