"""Sanity test: does known-labelled attack traffic come out of the LIVE pipeline as its class?

    python scripts/sanity_replay.py                              # labelled CIC-IDS2017 flow rows
    python scripts/sanity_replay.py --pcap scan.pcap PortScan    # a PCAP through capture's exact path
    python scripts/sanity_replay.py --pcap a.pcap PortScan --pcap b.pcap BENIGN

Part 1 replays the labelled CIC-IDS2017 rows (dashboard/sample_cic2017_test_mix.csv)
through the same FlowPredictor.predict_frame the capture service uses: this checks
schema alignment, feature order, inf/NaN handling and the model.

Part 2 (--pcap) runs a PCAP through the same conversion and scoring code as a live
capture window (CICFlowMeter -> non-IP filter -> model) and compares the predicted
classes with the label you give. To make a reference PCAP of the real attack tool on
the lab (run on the K3s host, needs nmap):

    IP=$(kubectl -n target-apps get pod -l app=nodered -o jsonpath='{.items[0].status.podIP}')
    sudo tcpdump -i cni0 -w /tmp/nmap.pcap host $IP & sleep 1
    sudo nmap -sS -p 1-1024 -T4 -n $IP; sleep 2; sudo kill %1
    python scripts/sanity_replay.py --pcap /tmp/nmap.pcap PortScan

The original CIC-IDS2017 PCAPs are ~50 GB and not part of this repo; any of them can
be passed with --pcap the same way.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from live.cicflowmeter import convert_pcap  # noqa: E402
from live.config import load_config  # noqa: E402
from live.predictor import FlowPredictor  # noqa: E402
from live.schema import read_flow_csv  # noqa: E402


def replay_rows(p: FlowPredictor) -> dict:
    s = pd.read_csv(REPO / "dashboard" / "sample_cic2017_test_mix.csv")
    y = s.pop("Label").astype(str).values
    pred = p.predict_frame(s, source="pcap")
    rows = []
    for cls in sorted(set(y)):
        m = y == cls
        got = pred.loc[m, "predicted_class"].value_counts().to_dict()
        rows.append({"class": cls, "flows": int(m.sum()), "recall": round(float((pred.loc[m, "predicted_class"] == cls).mean()), 4),
                     "predicted": got})
    acc = float((pred["predicted_class"].values == y).mean())
    print("Part 1 - labelled CIC-IDS2017 flow rows through the live scoring code")
    print(pd.DataFrame(rows).to_string(index=False))
    print(f"accuracy {acc:.4f} on {len(y)} flows -> {'PASS' if acc > 0.95 else 'FAIL'}\n")
    return {"accuracy": acc, "per_class": rows}


def replay_pcap(p: FlowPredictor, pcap: Path, label: str, cfg: dict) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        conv = convert_pcap(pcap, out_dir=Path(tmp), cfg=cfg)
        if conv.status != "converted":
            print(f"{pcap.name}: conversion {conv.status}: {conv.error}")
            return {"pcap": str(pcap), "status": conv.status, "error": conv.error}
        pred = p.predict_frame(read_flow_csv(conv.csv), source="pcap")
    counts = pred["predicted_class"].value_counts().to_dict()
    hit = float((pred["predicted_class"] == label).mean()) if len(pred) else 0.0
    print(f"{pcap.name}: {len(pred)} flows, expected {label}: {hit:.1%} -> {counts} "
          f"(mean confidence {pred['confidence'].mean():.3f}) -> {'PASS' if hit >= 0.5 else 'FAIL'}")
    return {"pcap": str(pcap), "expected": label, "flows": int(len(pred)), "match_rate": hit, "predicted": counts}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", nargs=2, action="append", metavar=("PCAP", "LABEL"), default=[])
    args = ap.parse_args(argv)
    cfg = load_config()
    p = FlowPredictor.from_config(cfg)
    out = {"rows": replay_rows(p), "pcaps": []}
    if args.pcap:
        print("Part 2 - PCAPs through CICFlowMeter + live scoring")
        out["pcaps"] = [replay_pcap(p, Path(f), lab, cfg) for f, lab in args.pcap]
    (REPO / "captures").mkdir(exist_ok=True)
    (REPO / "captures" / "sanity_replay.json").write_text(json.dumps(out, indent=2, default=str))
    fails = out["rows"]["accuracy"] <= 0.95 or any(x.get("match_rate", 0) < 0.5 for x in out["pcaps"])
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
