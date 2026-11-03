# IDS training pipeline (CIC-IDS2017 MachineLearningCVE)

```bash
pip install pandas numpy pyarrow scikit-learn lightgbm xgboost matplotlib joblib
python prepare.py <merged.csv OR folder_of_8_csvs> out/
python train.py out/                                     # all 78 CIC features
python train.py out/ --own-csv k8s-lab-01.pcap_ISCX.csv  # only features your own CICFlowMeter CSV also has
```

## What prepare.py does
1. Reads the 8 CSVs (or one merged CSV), strips column-name spaces, drops the duplicated `Fwd Header Length` column and stray header rows.
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
