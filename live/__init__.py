"""Live detection pipeline for the K3s IDS.

Captures pod traffic in adaptive windows, converts each window to CICFlowMeter
flow features, scores every flow with the CIC-IDS2017 model in models/cic-ids2017,
runs a per-source flow-burst detector, and stores everything in SQLite.

Adapted from the k8s-adaptive-ids project (rithwik1407/k8s-security-system):
the capture, flow-burst and MAPE-K design are theirs; the model, the seven
CIC-IDS2017 classes and the attack-focused traffic lab are ours.
"""
