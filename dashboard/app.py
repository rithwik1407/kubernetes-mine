"""IDS dashboard backend: scores CICFlowMeter CSVs with the trained model.

Run:
    pip install fastapi uvicorn python-multipart pandas numpy scikit-learn joblib lightgbm xgboost
    uvicorn app:app --port 8000          # from this folder, then open http://localhost:8000

Environment variables (optional):
    IDS_MODEL_DIR  folder with best_model.joblib + metrics.json + cm_*.png  (default ../models/cic-ids2017)
    IDS_PIPELINE   folder with prepare.py, for column-name mapping           (default ../ml)
"""
import collections
import hashlib
import io
import json
import os
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

HERE = Path(__file__).resolve().parent
MODEL_DIR = Path(os.environ.get("IDS_MODEL_DIR", HERE.parent / "models" / "cic-ids2017"))
sys.path.insert(0, str(Path(os.environ.get("IDS_PIPELINE", HERE.parent / "ml"))))
sys.path.insert(0, str(HERE.parent))
from live.logging_setup import configure as _configure_logging, get_logger  # noqa: E402

_configure_logging("backend.log")
log = get_logger("api")
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
MAX_UPLOAD_BYTES = 200 * 2**20
REQUEST_LOG: collections.deque = collections.deque(maxlen=1000)   # shown on the System page


@app.middleware("http")
async def record_requests(request: Request, call_next):
    """Keep the last 1000 API calls (method, path, status, latency) and log failures."""
    t0 = time.perf_counter()
    try:
        response = await call_next(request)
        status = response.status_code
    except Exception:
        log.exception("unhandled error on %s %s", request.method, request.url.path)
        status = 500
        response = JSONResponse({"detail": "internal server error; see logs/backend.log"}, status_code=500)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    path = request.url.path
    if path.startswith("/api/") and path != "/api/system/requests":
        REQUEST_LOG.append({"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()), "method": request.method,
                            "path": path, "status": status, "ms": ms})
        if status >= 500:
            log.error("%s %s -> %s (%.0f ms)", request.method, path, status, ms)
        elif status >= 400:
            log.warning("%s %s -> %s (%.0f ms)", request.method, path, status, ms)
    return response

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
    log.error("live features disabled: %s", _live_err)


@app.get("/api/features")
def features():
    """Which parts of the dashboard are available in this deployment."""
    return {"live": LIVE_ENABLED, "live_error": None if LIVE_ENABLED else _LIVE_IMPORT_ERROR,
            "scorer_model": MODEL_DIR.name}


def _model_info(model_dir: Path) -> dict:
    """Everything the Model page shows, read from the saved artifacts (nothing is recomputed or invented)."""
    bundle_path = model_dir / "best_model.joblib"
    if not bundle_path.is_file():
        raise HTTPException(404, f"no model artifact in {model_dir.name}")
    m = json.loads((model_dir / "metrics.json").read_text())
    best = m.get("best_model")
    h = hashlib.sha256()
    with open(bundle_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    split = m.get("split_counts") or {}
    train = split.get("train") or {}
    rep_path = model_dir / "prepare_report.json"
    if not rep_path.is_file() and not m.get("source"):  # the cic-ids2017-lab model is built from the same prepared CIC data
        rep_path = model_dir.parent / "cic-ids2017" / "prepare_report.json"
    report = json.loads(rep_path.read_text()) if rep_path.is_file() else None
    per = (m["models"].get(best) or {}).get("per_class", {})
    min_reliable = 1000
    return {
        "name": model_dir.name, "source": m.get("source"), "best_model": best, "classes": m["classes"], "features": m.get("features"),
        "n_features": len(m.get("features") or []),
        "version": {"sha256": h.hexdigest()[:16], "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(bundle_path.stat().st_mtime)),
                    "size_mb": round(bundle_path.stat().st_size / 2**20, 1)},
        "training_status": "trained (artifact loaded from disk)",
        "split_counts": split, "train_samples": sum(train.values()), "test_samples": sum((split.get("test") or {}).values()),
        "models": m["models"],
        "dataset": None if not report else {k: report.get(k) for k in (
            "rows_loaded", "raw_label_counts", "dropped_rare_labels", "rows_with_nan_or_inf_dropped",
            "duplicate_rows_dropped", "conflicting_rows_dropped", "final_rows", "constant_columns_dropped")},
        "reliability": [{"class": c, "train_samples": train.get(c), "f1": (per.get(c) or {}).get("f1"),
                         "reliable": bool(train.get(c, 0) >= min_reliable and (per.get(c) or {}).get("f1", 0) >= 0.9)}
                        for c in m["classes"]],
        "reliability_rule": f"reliable = at least {min_reliable} training flows and test F1 >= 0.90",
    }


@app.get("/api/model")
def model_info(which: str = "live"):
    """The model used by the live pipeline (which=live) or by the CSV scorer (which=scorer)."""
    if which == "scorer":
        return _model_info(MODEL_DIR)
    if which != "live":
        raise HTTPException(400, "which must be 'live' or 'scorer'")
    if not LIVE_ENABLED:
        raise HTTPException(503, f"live features disabled: {_LIVE_IMPORT_ERROR}")
    from live.config import get_path, load_config
    return _model_info(get_path("model_dir", load_config()))


@app.get("/api/model/cm/{model}/{name}")
def model_cm_png(model: str, name: str):
    """Confusion-matrix image of either model folder."""
    if model not in ("cic-ids2017", "cic-ids2017-lab"):
        raise HTTPException(404)
    p = HERE.parent / "models" / model / f"cm_{Path(name).name}.png"
    if not p.is_file():
        raise HTTPException(404)
    return FileResponse(p)


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
    if file.filename and not file.filename.lower().endswith((".csv", ".txt")):
        raise HTTPException(400, "upload a .csv file produced by CICFlowMeter")
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"file larger than {MAX_UPLOAD_BYTES // 2**20} MB")
    if not raw.strip():
        raise HTTPException(400, "the file is empty")
    try:
        df = pd.read_csv(io.BytesIO(raw), low_memory=False, encoding_errors="replace")
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"Could not read CSV: {e}")
    return JSONResponse(score_frame(df, file.filename or "upload.csv"))


@app.get("/api/demo")
def demo():
    p = HERE / "sample_cic2017_test_mix.csv"
    return JSONResponse(score_frame(pd.read_csv(p), p.name + " (held-out CIC-IDS2017 test rows)"))
