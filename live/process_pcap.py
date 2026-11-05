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

import tempfile

from live import allowlist as allow
from live import flowcontext, labsources
from live.behavior import flow_bursts
from live.cicflowmeter import convert_pcap
from live.config import get_path, load_config
from live.logging_setup import get_logger
from live.predictor import FlowPredictor
from live.schema import SchemaError, read_flow_csv
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
    context_s = float(cfg["capture"].get("flow_context_seconds", 0) or 0)
    ctx: dict[str, Any] = {"seconds": context_s, "files": 0, "dropped_ended_before_window": 0}
    try:
        earlier = flowcontext.context_files(pcap, context_s)
        window_start = flowcontext.first_packet_time(pcap)
    except (OSError, ValueError):
        earlier, window_start = [], None
    if earlier:
        # Convert this window together with the preceding seconds of traffic, so connections
        # that cross a window boundary are scored whole (see live/flowcontext.py).
        tmpdir = tempfile.TemporaryDirectory(prefix="ctx-", dir=get_path("flows_dir", cfg))
        merged = Path(tmpdir.name) / pcap.name
        ctx["files"] = flowcontext.concat_pcaps(earlier + [pcap], merged) - 1
        conv = convert_pcap(merged, cfg=cfg)
        conv.pcap = str(pcap)
        tmpdir.cleanup()
    else:
        conv = convert_pcap(pcap, cfg=cfg)
    summary: dict[str, Any] = {"pcap": pcap.name, "conversion": conv.to_dict(), "capture_id": cap_id, "context": ctx}

    with db.connect(db.db_path(cfg)) as conn:
        fields: dict[str, Any] = {"conversion_s": conv.seconds, "flows": conv.flows,
                                  "csv_file": Path(conv.csv).name if conv.csv else None}
        if conv.status != "converted":
            fields.update(status=conv.status, error=conv.error)
            db.upsert_capture(conn, pcap.name, **fields)
            summary["status"] = conv.status
            return summary
        try:
            flows = read_flow_csv(conv.csv)
            if earlier:
                flows, ctx["dropped_ended_before_window"] = flowcontext.keep_active_flows(flows, window_start)
            fields["flows"] = len(flows)
            pred = predictor.predict_frame(flows, capture_file=Path(conv.csv).name, source="pcap")
            pred = allow.get(cfg).apply(pred)
            pred = labsources.tag(pred, labsources.get(cfg))
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
    ev_conf = float(cfg["capture"]["window"].get("evidence_confidence", 0.6))
    strong = pred[pred["is_malicious"].astype(bool) & (pred["confidence"] >= ev_conf)] if len(pred) else pred
    summary["evidence"] = {
        "malicious_flows": int(len(strong)), "bursts": int(len(bursts)),
        "top_class": strong["predicted_class"].value_counts().idxmax() if len(strong) else None,
        "max_confidence": float(strong["confidence"].max()) if len(strong) else None,
    }
    summary.update(
        status="classified", detections=stored, malicious=int(pred["is_malicious"].sum()) if len(pred) else 0,
        allowlisted=int(pred["allowlisted"].notna().sum()) if len(pred) else 0,
        lab_flows=pred["lab_scenario"].value_counts().to_dict() if len(pred) else {},
        dropped_non_ip=int(predictor.last_report.get("dropped_non_ip", 0)),
        classes=pred["predicted_class"].value_counts().to_dict() if len(pred) else {},
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
