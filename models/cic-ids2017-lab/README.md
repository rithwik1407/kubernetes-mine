# cic-ids2017-lab

The CIC-IDS2017 Random Forest **plus verified benign traffic captured in the K3s
lab** (data/k8s/lab-benign), all labelled BENIGN. Same attack classes and the same
CIC-IDS2017 test-set scores as models/cic-ids2017, but fewer false alarms on real
cluster traffic.

| | CIC-IDS2017 test macro F1 | False alarms on held-out lab benign |
|---|---|---|
| cic-ids2017 (CIC only) | 0.9521 | 0.97% |
| **cic-ids2017-lab (this)** | 0.9522 | **0.28%** |

Why: CIC-IDS2017 was recorded on a different network, so some ordinary K3s flows
(kubelet probes, CoreDNS, control plane) look unusual to a dataset-only model.
Showing it this cluster's normal traffic fixes that without touching the attack side.

The live pipeline (config/live.yaml) uses this model. The CSV scorer page keeps the
CIC-only model, which is reproducible from the public dataset alone.

Reproduce:
    python ml/prepare.py data/cic-ids2017/merged.csv out/
    python ml/augment_lab.py out/clean.parquet data/k8s/lab-benign --out out_lab/
    python ml/train.py out_lab/ --models RandomForest
    # then copy out_lab/best_model.joblib + metrics.json here
