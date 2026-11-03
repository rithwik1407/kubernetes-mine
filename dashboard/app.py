"""IDS dashboard backend: scores CICFlowMeter CSVs with the trained model.

Run:
    pip install fastapi uvicorn python-multipart pandas numpy scikit-learn joblib lightgbm xgboost
    uvicorn app:app --port 8000          # from this folder, then open http://localhost:8000

Environment variables (optional):
    IDS_MODEL_DIR  folder with best_model.joblib + metrics.json + cm_*.png  (default ../models/cic-ids2017)
    IDS_PIPELINE   folder with prepare.py, for column-name mapping           (default ../ml)
"""
import io
import json
import os
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

HERE = Path(__file__).resolve().parent
MODEL_DIR = Path(os.environ.get("IDS_MODEL_DIR", HERE.parent / "models" / "cic-ids2017"))
sys.path.insert(0, str(Path(os.environ.get("IDS_PIPELINE", HERE.parent / "ml"))))
from prepare import canon, group_label  # noqa: E402  (same name mapping as training)

bundle = joblib.load(MODEL_DIR / "best_model.joblib")
MODEL, FEATURES, CLASSES = bundle["model"], bundle["features"], list(bundle["classes"])
METRICS = json.loads((MODEL_DIR / "metrics.json").read_text())
MAX_ROWS_RETURNED = 20_000          # per-flow rows sent to the browser; summaries use every row

# Identity columns shown in the flow table when the CSV has them.
ID_COLS = {"srcip": "src", "sourceip": "src", "dstip": "dst", "destinationip": "dst",
           "srcport": "sport", "sourceport": "sport", "dstport": "dport",
           "destinationport": "dport", "protocol": "proto", "timestamp": "ts"}

app = FastAPI(title="K3s IDS dashboard")
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

# Live pipeline, traffic lab, deception and cluster endpoints. Optional: if the
# live package or its deps are unavailable, the CSV scorer still runs.
try:
    from live_api import router as live_router
    app.include_router(live_router)
    LIVE_ENABLED = True
except Exception as _live_err:  # noqa: BLE001
    LIVE_ENABLED = False
    import traceback
    print("\n" + "=" * 70 + "\nLIVE FEATURES DISABLED - every /api/live, /api/trafficlab, /api/pipeline,\n"
          "/api/targets, /api/deception and /api/kubernetes route will return 404.\n"
          f"Reason: {type(_live_err).__name__}: {_live_err}\n"
          "Fix: pip install -r requirements.txt  (needs pyyaml and kubernetes)\n" + "=" * 70, file=sys.stderr)
    traceback.print_exc()
    _LIVE_IMPORT_ERROR = str(_live_err)


@app.get("/api/features")
def features():
    """Which parts of the dashboard are available in this deployment."""
    return {"live": LIVE_ENABLED, "live_error": None if LIVE_ENABLED else _LIVE_IMPORT_ERROR}


@app.get("/")
@app.get("/live")
def index():
    """The unified dashboard: sidebar with live monitoring, traffic generator, deception, cluster, CSV scorer."""
    return FileResponse(HERE / "static" / "app.html")


@app.get("/scorer")
def scorer_page():
    """The CSV scorer on its own (also embedded in the unified dashboard)."""
    return FileResponse(HERE / "static" / "index.html")


@app.get("/api/metrics")
def metrics():
    return {"best_model": METRICS.get("best_model"), "classes": METRICS["classes"],
            "split_counts": METRICS.get("split_counts"), "n_features": len(FEATURES),
            "models": {k: {kk: vv for kk, vv in v.items()} for k, v in METRICS["models"].items()}}


@app.get("/api/cm/{name}")
def cm_png(name: str):
    p = MODEL_DIR / f"cm_{Path(name).name}.png"
    if not p.exists():
        raise HTTPException(404)
    return FileResponse(p)


def score_frame(df: pd.DataFrame, source: str) -> dict:
    t0 = time.time()
    df.columns = [str(c).strip() for c in df.columns]
    label_col = next((c for c in df.columns if canon(c) == "label"), None)
    if label_col:   # CICFlowMeter sometimes repeats the header line inside the file
        df = df[df[label_col].astype(str).str.strip().str.upper() != "LABEL"]
    df = df.reset_index(drop=True)
    if df.empty:
        raise HTTPException(400, "The CSV has no data rows.")

    cols = {}
    for c in df.columns:
        cols.setdefault(canon(c), c)
    missing = [f for f in FEATURES if f not in cols]
    if len(missing) > len(FEATURES) // 2:
        raise HTTPException(400, f"This doesn't look like a CICFlowMeter CSV: {len(missing)} of "
                                 f"{len(FEATURES)} model features are missing.")
    X = pd.DataFrame({f: (pd.to_numeric(df[cols[f]], errors="coerce") if f in cols else 0.0)
                      for f in FEATURES})
    X = X.replace([np.inf, -np.inf], np.nan)
    bad_rows = int(X.isna().any(axis=1).sum())
    X = X.fillna(0.0)

    proba = MODEL.predict_proba(X.to_numpy(np.float32))
    pred_idx = proba.argmax(1)
    pred = np.array(CLASSES)[pred_idx]
    conf = proba.max(1)

    # Ground truth, if the CSV carries real CIC labels (not NeedManualLabel).
    truth = None
    if label_col:
        known = {c.upper(): c for c in CLASSES}   # accept already-grouped labels too
        g = df[label_col].map(lambda v: known.get(str(v).strip().upper()) or group_label(v))
        if g.notna().mean() > 0.5:
            truth = g.fillna("?").tolist()

    ident = {}
    for c in df.columns:
        k = ID_COLS.get(canon(c))
        if k and k not in ident:
            ident[k] = df[c].astype(str).tolist()

    timeline = None
    if "ts" in ident:   # CICFlowMeter writes e.g. "30/10/2026 12:19:24 PM" (day first)
        ts = pd.to_datetime(pd.Series(ident["ts"]), dayfirst=True, errors="coerce", format="mixed")
        if ts.notna().mean() > 0.5:
            span = (ts.max() - ts.min()).total_seconds()
            freq = "1s" if span <= 600 else "1min" if span <= 6 * 3600 else "1h"
            tl = (pd.DataFrame({"t": ts.dt.floor(freq), "c": pred}).dropna()
                  .groupby(["t", "c"]).size().unstack(fill_value=0))
            timeline = {"bucket": freq, "t": [str(x) for x in tl.index],
                        "series": {c: tl[c].astype(int).tolist() for c in tl.columns}}

    n = len(df)
    keep = np.arange(n)
    if n > MAX_ROWS_RETURNED:   # keep every attack, then fill with benign rows
        att = np.flatnonzero(pred != "BENIGN")
        ben = np.flatnonzero(pred == "BENIGN")
        room = max(MAX_ROWS_RETURNED - len(att), 0)
        keep = np.sort(np.concatenate([att[:MAX_ROWS_RETURNED], ben[:room]]))

    rows = []
    for i in keep:
        r = {"i": int(i), "pred": pred[i], "conf": round(float(conf[i]), 4),
             "p": [round(float(v), 4) for v in proba[i]]}
        for k, v in ident.items():
            r[k] = v[i]
        if truth:
            r["truth"] = truth[i]
        rows.append(r)

    counts = pd.Series(pred).value_counts().reindex(CLASSES, fill_value=0).astype(int).to_dict()
    out = {
        "source": source, "n_flows": n, "classes": CLASSES, "counts": counts,
        "n_attacks": int((pred != "BENIGN").sum()),
        "mean_conf": float(conf.mean()), "low_conf": int((conf < 0.6).sum()),
        "timeline": timeline, "rows": rows, "rows_truncated": n > len(rows), "has_ids": sorted(ident),
        "feature_check": {"used": len(FEATURES) - len(missing), "total": len(FEATURES),
                          "missing_filled_with_zero": missing, "rows_with_nan_or_inf": bad_rows},
        "seconds": round(time.time() - t0, 2),
    }
    if truth:
        t = np.array(truth)
        ok = t != "?"
        out["truth_accuracy"] = float((t[ok] == pred[ok]).mean()) if ok.any() else None
        out["truth_counts"] = pd.Series(t).value_counts().to_dict()
    return out


@app.post("/api/score")
async def score(file: UploadFile = File(...)):
    raw = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(raw), low_memory=False, encoding_errors="replace")
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"Could not read CSV: {e}")
    return JSONResponse(score_frame(df, file.filename or "upload.csv"))


@app.get("/api/demo")
def demo():
    p = HERE / "sample_cic2017_test_mix.csv"
    return JSONResponse(score_frame(pd.read_csv(p), p.name + " (held-out CIC-IDS2017 test rows)"))
