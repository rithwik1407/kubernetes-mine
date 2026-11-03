# K3s IDS dashboard

A FastAPI backend plus an interactive web page (Plotly, bundled locally so it works offline).
Drop a CICFlowMeter CSV and see, for every flow, the predicted class, the model's confidence and every class probability.

## Run it

The app reads the model from `../models/cic-ids2017/` and the column-name mapping from `../ml/prepare.py`.

```bash
cd dashboard
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
# open http://localhost:8000
```

Use `--host 0.0.0.0` only if you want to open it from another machine on your network.
To use a different model folder: `IDS_MODEL_DIR=/path/to/out uvicorn app:app`.

## What you get

**Analyze traffic tab**
- A verdict banner (no attacks, or N suspicious flows by type) and KPI tiles: flows, flagged attacks, mean confidence, how many model features your CSV matched.
- Flows by predicted class (click a bar to filter the table), confidence distribution, flows over time stacked by class, and top destination IP:port.
- A sortable, searchable flow table. Click a row to see all seven class probabilities for that flow.
- A filter for low-confidence flows, and "Download predictions CSV".
- If the CSV has real CIC labels (not `NeedManualLabel`), it also shows agreement with those labels and marks mismatches in red.
- "Try a demo with attacks" scores `sample_cic2017_test_mix.csv`: 2,230 held-out CIC-IDS2017 test rows the model never trained on.

**Model performance tab**
- Comparison of RF, LightGBM, XGBoost and Naive Bayes (macro F1, accuracy, detection rate, false alarms).
- A per-class F1 heatmap, and a confusion matrix for any model.

## API
- `POST /api/score` with form field `file` (CSV) returns JSON predictions.
- `GET /api/demo` and `GET /api/metrics`.
