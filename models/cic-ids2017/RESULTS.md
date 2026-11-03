# IDS results on the merged CIC-IDS2017 CSV (Drive file, 2026-11-03)

Input: 2,522,362 rows, all 15 raw labels, already de-duplicated (that is why it is below 2.83M).
After prepare.py: 2,198,339 rows, 68 features, 7 classes. Test split 30% (659,502 rows), never resampled.

| Model | Macro F1 | Accuracy | Attack detection | False alarms |
|---|---|---|---|---|
| Random Forest (saved as best_model.joblib) | 0.9521 | 0.9988 | 99.72% | 0.085% |
| LightGBM (after fix) | 0.9519 | 0.9991 | 99.97% | 0.094% |
| XGBoost | 0.9519 | 0.9991 | 99.96% | 0.099% |
| Naive Bayes | 0.3233 | 0.5549 | 99.36% | 50.7% |

Per-class F1 (RF / XGB / LGBM): BENIGN 0.999 all; DoS 0.996/0.998/0.998; DDoS 1.000 all;
BruteForce 0.994/0.998/0.998; PortScan 0.976/0.972/0.972; WebAttack 0.970/0.979/0.973; Bot 0.730/0.716/0.724.

Bot is the weak class everywhere: RF recall 0.78, precision 0.69; XGB/LGBM recall ~0.97 but precision ~0.57.

## Changes made to the pipeline
- prepare.py: drops the `Source_File` column (it is text, turned every row into NaN) and the duplicated `Fwd Header Length.1`.
- train.py: LightGBM learning_rate 0.05, min_child_weight 1.0, reg_lambda 1.0. With balanced class weights it diverged (macro F1 0.33).

## Note on PortScan
90,819 PortScan rows shrink to 1,850 once Destination Port is removed and duplicates dropped: the scan flows are identical apart from the port.

## Your K3s capture (k8s-lab-01.pcap_ISCX.csv)
181 flows, all 68 features matched after fixing three name aliases in prepare.py
(Total Bwd packets, Fwd/Bwd Segment Size Avg). Prediction: 181/181 BENIGN, confidence 75-98% (mean 88%).
Traffic: 90 DNS flows to 10.43.0.10:53 and 30 each to ports 1880, 3000 and 8086, all from 10.42.0.27.
The model never saw attack traffic from your cluster, so this checks false alarms only.
