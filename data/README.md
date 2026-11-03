# Data

## CIC-IDS2017 (training data, not in git)
The merged MachineLearningCVE CSV is ~980 MB, too big for GitHub. Put it here:

```
data/cic-ids2017/merged.csv
```

It is the 8 daily CSVs merged into one, already de-duplicated (2,522,362 rows, all 15 labels), with an extra `Source_File` column.
Source: the project's Google Drive copy, or the official dataset from the Canadian Institute for Cybersecurity (UNB).

## k8s/ (your own captures)
CICFlowMeter output from the K3s lab. `k8s-lab-01.pcap_ISCX.csv` has 181 flows, all normal service traffic
(labels are `NeedManualLabel`). Add new captures here, for example one per attack test.
