# IDS training pipeline (CIC-IDS2017 MachineLearningCVE)

Run from the repo root (dependencies are in the root `requirements.txt`):

```bash
python ml/prepare.py data/cic-ids2017/merged.csv out/     # or a folder with the 8 daily CSVs
python ml/train.py out/                                    # all features (68 after cleaning)
python ml/train.py out/ --own-csv data/k8s/k8s-lab-01.pcap_ISCX.csv   # only features your CSV also has
```

`out/` is git-ignored. To use a new model in the dashboard, copy `best_model.joblib`, `metrics.json`
and `cm_*.png` from `out/` into `models/cic-ids2017/`.

## What prepare.py does
1. Reads the 8 CSVs (or one merged CSV), strips column-name spaces, drops the duplicated `Fwd Header Length` column, the `Source_File` column of the merged CSV, and stray header rows.
2. Groups labels into BENIGN, DoS, DDoS, PortScan, BruteForce, WebAttack and Bot. It drops Heartbleed (11 rows) and Infiltration (36 rows).
3. Drops Destination Port and any IP, timestamp or flow-ID columns, because the port leaks the answer and won't carry over to the K3s NodePorts.
4. Turns inf into NaN and drops those rows, drops constant columns, and keeps valid zeros.
5. Drops exact duplicate rows *before* splitting. CIC-IDS2017 has hundreds of thousands of them, and leaving them in inflates test scores. It also drops rows whose identical features carry different labels.
6. Maps old and new CICFlowMeter column names to one name, so the model can score your own K3s CSVs.

## What train.py does
- 70/30 stratified split; **the test set is never resampled**.
- Training split only: BENIGN capped at 400k (`--benign-cap`), plus balanced class weights.
- Random Forest, Gaussian Naive Bayes (log + scale first), LightGBM, XGBoost.
- Reports per-class precision, recall and F1, macro F1, accuracy, attack detection rate and false alarm rate, and saves a confusion-matrix PNG for each model.
- Saves the best model by macro F1 to `out/best_model.joblib` (model + feature list + class names).

Judge models by **macro F1** and the per-class recall of the small classes (Bot, WebAttack). Accuracy is ~99% for almost any model because most traffic is BENIGN.

LightGBM uses learning_rate 0.05, min_child_weight 1.0 and reg_lambda 1.0. With balanced class weights and the
defaults it diverged on this data (macro F1 0.33 instead of 0.95).
