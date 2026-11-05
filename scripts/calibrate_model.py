"""Are the model's probabilities calibrated? (Expected calibration error + reliability table.)

    python scripts/calibrate_model.py

Uses the labelled CIC-IDS2017 sample (dashboard/sample_cic2017_test_mix.csv). The
deception thresholds compare confidences with fixed numbers, so they only mean what
they say if, e.g., flows scored 0.8 are right about 80 % of the time.

Decision rule: if the top-label ECE is above 0.05, a temperature is fitted with
5-fold cross-validation (on the sample) and saved to <model_dir>/calibration.json
for the predictor to apply. At or below 0.05 the probabilities are used unchanged
and nothing is written.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from live.config import load_config  # noqa: E402
from live.predictor import FlowPredictor  # noqa: E402
from live.schema import align_features  # noqa: E402

ECE_LIMIT = 0.05


def ece(conf: np.ndarray, correct: np.ndarray, bins: int = 10) -> tuple[float, list[dict]]:
    edges = np.linspace(0, 1, bins + 1)
    total, table = 0.0, []
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (conf > lo) & (conf <= hi)
        if not m.any():
            continue
        gap = abs(conf[m].mean() - correct[m].mean())
        total += m.mean() * gap
        table.append({"bin": f"{lo:.1f}-{hi:.1f}", "flows": int(m.sum()), "mean_confidence": round(float(conf[m].mean()), 3),
                      "accuracy": round(float(correct[m].mean()), 3)})
    return float(total), table


def temper(P: np.ndarray, T: float) -> np.ndarray:
    Q = np.power(np.clip(P, 1e-12, 1), 1.0 / T)
    return Q / Q.sum(axis=1, keepdims=True)


def main() -> int:
    cfg = load_config()
    p = FlowPredictor.from_config(cfg)
    s = pd.read_csv(REPO / "dashboard" / "sample_cic2017_test_mix.csv")
    y = s.pop("Label").astype(str).values
    X, _ = align_features(s, p.features)
    P = p.model.predict_proba(X.replace([np.inf, -np.inf], np.nan).fillna(0).to_numpy(np.float32))
    cls = np.asarray(p.classes).astype(str)
    conf, correct = P.max(1), cls[P.argmax(1)] == y
    e, table = ece(conf, correct)
    print(f"labelled flows: {len(y)}   accuracy {correct.mean():.4f}   top-label ECE {e:.4f}")
    print(pd.DataFrame(table).to_string(index=False))
    report = {"flows": int(len(y)), "accuracy": float(correct.mean()), "ece": e, "reliability": table,
              "limit": ECE_LIMIT, "calibrated": e <= ECE_LIMIT}
    if e <= ECE_LIMIT:
        print(f"\nECE {e:.4f} <= {ECE_LIMIT}: probabilities are calibrated on this data; no calibration applied.")
        print("Note: this says nothing about traffic unlike CIC-IDS2017. On the lab's own traffic the false "
              "positives scored 0.51-0.52, which is why the deception policy requires several flows >= 0.80.")
    else:
        idx = np.arange(len(y)) % 5
        best = min(np.linspace(0.5, 5, 46), key=lambda T: np.mean([
            -np.log(temper(P[idx == k], T)[np.arange((idx == k).sum()), np.searchsorted(cls, y[idx == k])] + 1e-12).mean()
            for k in range(5)]))
        Q = temper(P, best)
        e2, _ = ece(Q.max(1), cls[Q.argmax(1)] == y)
        print(f"\ntemperature {best:.2f}: ECE {e:.4f} -> {e2:.4f}; saved to {p.model_dir.name}/calibration.json")
        (p.model_dir / "calibration.json").write_text(json.dumps({"temperature": float(best), "ece_before": e,
                                                                   "ece_after": e2}, indent=2))
        report.update(temperature=float(best), ece_after=e2)
    (REPO / "captures").mkdir(exist_ok=True)
    (REPO / "captures" / "calibration_report.json").write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
