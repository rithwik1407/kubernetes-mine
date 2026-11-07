# k8s-lab-live: the live pipeline's model

A RandomForest trained on flows that **this lab's live CICFlowMeter** produced, labelled by
the Traffic-lab runs that generated them. It replaces `cic-ids2017-lab` as the live model
(`paths.model_dir` in `config/live.yaml`). The CIC model stays on disk as
`paths.fallback_model_dir` and is used if this folder has no `best_model.joblib`. The CSV
scorer (`/api/score`) still uses the CIC-IDS2017 model.

## Why

The CIC-IDS2017 model scores CIC-IDS2017 rows well (99.9 % accuracy on its test split), but
the CICFlowMeter fork used here produces different feature values for the same kind of
traffic. Every lab attack was therefore predicted BENIGN (see
`scripts/check_feature_parity.py` and `scripts/sanity_replay.py`). This model learns from
the extractor's own output.

## Data and labels (`scripts/train_lab_model.py`)

* Each Traffic-lab run records its capture session and each Job's pod IP.
* A flow with that pod at either end gets the scenario's class: port_scan → PortScan,
  brute_force → BruteForce, web_attack → WebAttack, slow_dos → DoS, benign → BENIGN.
* The attack pod's DNS flows are left out, and so are the flows of web_recon and decoy_probe
  pods (those scenarios have no class).
* Every other flow in the session (kubelet probes, control plane, DNS) is BENIGN. The
  verified benign captures in `data/k8s/lab-benign` are added as BENIGN too (2,287 flows).
* Flows repeated across window CSVs are de-duplicated per session.

The model uses the same 68 features, the same inf/NaN → 0 handling and the same RandomForest
settings as the CIC model (200 trees, balanced_subsample, random_state 42).

## Test: whole held-out sessions

The model was tested on five capture sessions it never saw, using a target (influxdb) and
rates that none of the training runs used. The training runs used nodered and grafana.

| Split | BENIGN | PortScan | BruteForce | WebAttack | DoS |
|---|---|---|---|---|---|
| train (sessions 3–17) | 9,695 | 2,989 | 1,463 | 1,525 | 2,521 |
| test (sessions 18–22) | 2,870 | 1,006 | 494 | 394 | 478 |

Held-out results (from `metrics.json`):

| Class | Precision | Recall | F1 |
|---|---|---|---|
| BENIGN | 0.924 | 0.990 | 0.956 |
| BruteForce | 1.000 | 0.955 | 0.977 |
| DoS | 1.000 | 0.638 | 0.779 |
| PortScan | 1.000 | 1.000 | 1.000 |
| WebAttack | 0.927 | 0.901 | 0.914 |

Overall: accuracy 0.950, macro F1 0.925, attack detection 90.1 %, false alarms 1.0 %
(28 of 2,870 benign flows, all predicted WebAttack).

## Limits

* **The model only knows this lab.** Its training traffic comes from the lab's own
  generator and three targets. It has not seen real-world attacks, and it has no Bot or
  DDoS class.
* **Slow DoS is the weakest class.** 173 of 478 slow-DoS flows were predicted BENIGN. Those
  are mostly short, idle connections that look like normal ones.
* **The test is not independent of the generator.** The held-out sessions used a different
  target and rate, but the same generator code produced both training and test traffic.

`dashboard/sample_lab_test_mix.csv` holds up to 500 held-out flows per class (2,366 in all)
for the dashboard's Labelled check.

## Retrain on your own lab

```
python scripts/train_lab_model.py --list
python scripts/train_lab_model.py --test-sessions <ids>
```

`--list` shows the labelled sessions. In `--test-sessions <ids>`, the ids are sessions to
hold out, and they should use a different target or rate from the training sessions.
