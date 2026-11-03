"""PCAP -> CICFlowMeter CSV -> CIC model -> stored detections + flow bursts.

    python -m live.process_pcap captures/pcap/<file>.pcap
    python -m live.process_pcap --pending
"""
from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from live.behavior import flow_bursts
from live.cicflowmeter import convert_pcap
from live.config import get_path, load_config
from live.logging_setup import get_logger
from live.predictor import FlowPredictor
from live.schema import SchemaError
from live import db

log = get_logger(__name__)
DONE_STATUSES = ("classified", "empty")


def resolve_pcap(path: str | Path, cfg: dict[str, Any] | None = None) -> Path:
    root = get_path("pcap_dir", cfg).resolve()
    p = Path(path)
    p = (p if p.is_absolute() else Path.cwd() / p).resolve()
    if p.suffix != ".pcap" or not p.is_relative_to(root):
        raise ValueError(f"{path} is not a .pcap file inside {root}")
    if not p.is_file():
        raise FileNotFoundError(p)
    return p


def process_pcap(pcap: Path, predictor: FlowPredictor, cfg: dict[str, Any] | None = None,
                 window_end_monotonic: float | None = None,
                 capture_fields: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    t_start = time.monotonic()
    with db.connect(db.db_path(cfg)) as conn:
        cap_id = db.upsert_capture(conn, pcap.name, **(capture_fields or {}))
    conv = convert_pcap(pcap, cfg=cfg)
    summary: dict[str, Any] = {"pcap": pcap.name, "conversion": conv.to_dict(), "capture_id": cap_id}

    with db.connect(db.db_path(cfg)) as conn:
        fields: dict[str, Any] = {"conversion_s": conv.seconds, "flows": conv.flows,
                                  "csv_file": Path(conv.csv).name if conv.csv else None}
        if conv.status != "converted":
            fields.update(status=conv.status, error=conv.error)
            db.upsert_capture(conn, pcap.name, **fields)
            summary["status"] = conv.status
            return summary
        try:
            pred = predictor.predict_csv(conv.csv, source="pcap")
        except (SchemaError, ValueError) as e:
            db.upsert_capture(conn, pcap.name, status="failed", error=f"prediction: {e}", **fields)
            summary.update(status="failed", error=str(e))
            return summary
        stored = db.insert_detections(conn, pred, capture_id=cap_id)
        row = conn.execute("SELECT duration_s FROM captures WHERE id = ?", (cap_id,)).fetchone()
        window_s = (capture_fields or {}).get("duration_s") or (row["duration_s"] if row else None)
        bursts = flow_bursts(pred, window_s, cfg)
        now = datetime.now(timezone.utc).isoformat()
        for b in bursts.to_dict(orient="records"):
            db.insert_row(conn, "behavior_alerts", capture_id=cap_id, capture_file=pcap.name, detected_at=now, **b)
        summary["flow_bursts"] = len(bursts)
        ref = window_end_monotonic if window_end_monotonic is not None else t_start
        fields.update(status="classified", prediction_ms=predictor.last_report["batch_ms"],
                      pipeline_s=time.monotonic() - ref, error=None)
        db.upsert_capture(conn, pcap.name, **fields)
    summary.update(
        status="classified", detections=stored, malicious=int(pred["is_malicious"].sum()),
        classes=pred["predicted_class"].value_counts().to_dict(),
        prediction_ms=predictor.last_report["batch_ms"], pipeline_s=fields["pipeline_s"])
    log.info("%s: %d flows, %d malicious, %d bursts, conv %.2fs, pipeline %.2fs", pcap.name, stored,
             summary["malicious"], summary["flow_bursts"], conv.seconds, fields["pipeline_s"])
    return summary


def pending_pcaps(cfg: dict[str, Any] | None = None) -> list[Path]:
    cfg = cfg or load_config()
    files = sorted(get_path("pcap_dir", cfg).glob("*.pcap"))
    with db.connect(db.db_path(cfg)) as conn:
        done = {r["pcap_file"] for r in conn.execute(
            f"SELECT pcap_file FROM captures WHERE status IN ({','.join('?' * len(DONE_STATUSES))})", DONE_STATUSES)}
    return [f for f in files if f.name not in done]


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcaps", nargs="*", type=Path)
    ap.add_argument("--pending", action="store_true")
    args = ap.parse_args(argv)
    cfg = load_config()
    targets = pending_pcaps(cfg) if args.pending else [resolve_pcap(p, cfg) for p in args.pcaps]
    if not targets:
        print("nothing to process")
        return
    predictor = FlowPredictor.from_config(cfg)
    for p in targets:
        print(process_pcap(p, predictor, cfg))


if __name__ == "__main__":
    main()
