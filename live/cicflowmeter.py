"""PCAP -> CICFlowMeter CSV conversion using the existing local CICFlowMeter build.

The CICFlowMeter command-line entry point only accepts a directory, so every PCAP
is symlinked into its own staging directory and converted in isolation. Success
is only reported after the output CSV exists and parses as a flow file.

Usage:
    python -m src.feature_extraction.cicflowmeter captures/pcap/<file>.pcap
"""
from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from live.schema import SRC_IP, SchemaError, read_flow_csv
from live.config import get_path, load_config, project_path
from live.logging_setup import get_logger

log = get_logger(__name__)

# libpcap link-layer header types (https://www.tcpdump.org/linktypes.html)
LINKTYPE_ETHERNET = 1
LINKTYPE_NAMES = {1: "Ethernet", 101: "Raw IP", 113: "Linux cooked (SLL)", 276: "Linux cooked v2 (SLL2)"}
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class ConversionError(RuntimeError):
    pass


@dataclass
class ConversionResult:
    pcap: str
    csv: str | None
    status: str  # converted | empty | failed
    flows: int
    seconds: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def pcap_linktype(path: Path) -> int:
    """Link type from the classic pcap global header."""
    with open(path, "rb") as fh:
        header = fh.read(24)
    if header[:4] == PCAPNG_MAGIC:
        raise ConversionError(f"{path.name} is pcapng; capture with tcpdump -w (classic pcap)")
    if len(header) < 24 or header[:4] not in PCAP_MAGICS:
        raise ConversionError(f"{path.name} is not a pcap file")
    return struct.unpack(PCAP_MAGICS[header[:4]] + "I", header[20:24])[0]


def java_command(cfg: dict[str, Any], in_dir: Path, out_dir: Path) -> list[str]:
    c = cfg["cicflowmeter"]
    home = project_path(c["home"])
    jnetpcap_dir = home / c["jnetpcap_dir"]
    classpath = [home / c["jar"], project_path(c["jnetpcap_maven_jar"]), jnetpcap_dir / "jnetpcap.jar"]
    for p in classpath + [jnetpcap_dir]:
        if not p.exists():
            raise ConversionError(f"CICFlowMeter component missing: {p}")
    return [
        c["java"], f"-Djava.library.path={jnetpcap_dir}",
        "-cp", ":".join(str(p) for p in classpath),
        "cic.cs.unb.ca.ifm.CICFlowMeter", f"{in_dir}/", f"{out_dir}/",
    ]


def output_name(pcap: Path) -> str:
    return f"{pcap.stem}.pcap_Flow.csv"


def convert_pcap(pcap: str | Path, out_dir: Path | None = None, cfg: dict[str, Any] | None = None) -> ConversionResult:
    cfg = cfg or load_config()
    pcap = Path(pcap).resolve()
    out_dir = (out_dir or get_path("flows_dir", cfg)).resolve()
    t0 = time.perf_counter()

    def fail(msg: str) -> ConversionResult:
        log.error("conversion of %s failed: %s", pcap.name, msg)
        return ConversionResult(str(pcap), None, "failed", 0, time.perf_counter() - t0, msg)

    if not pcap.is_file() or pcap.suffix != ".pcap":
        return fail("input must be an existing .pcap file")
    try:
        lt = pcap_linktype(pcap)
    except ConversionError as e:
        return fail(str(e))
    if lt != LINKTYPE_ETHERNET:
        return fail(f"link type {LINKTYPE_NAMES.get(lt, lt)} is not supported by CICFlowMeter's "
                    "parser; capture on an Ethernet interface such as cni0 (not 'any')")

    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cfm-", dir=out_dir) as tmp:
        stage_in, stage_out = Path(tmp, "in"), Path(tmp, "out")
        stage_in.mkdir()
        stage_out.mkdir()
        (stage_in / pcap.name).symlink_to(pcap)
        try:
            cmd = java_command(cfg, stage_in, stage_out)
            proc = subprocess.run(cmd, cwd=tmp, capture_output=True, text=True,
                                  timeout=cfg["cicflowmeter"]["timeout_seconds"])
        except ConversionError as e:
            return fail(str(e))
        except subprocess.TimeoutExpired:
            return fail("CICFlowMeter timed out")
        except FileNotFoundError as e:
            return fail(f"cannot run java: {e}")
        produced = list(stage_out.glob("*.csv"))
        if proc.returncode != 0:
            return fail(f"CICFlowMeter exited with {proc.returncode}: {proc.stderr[-500:]}")
        if not produced:
            # CICFlowMeter writes no CSV when a capture yields no flows.
            if "TOTAL FLOWS GENERATED: 0" in proc.stdout + proc.stderr:
                return ConversionResult(str(pcap), None, "empty", 0, time.perf_counter() - t0)
            return fail("CICFlowMeter produced no CSV")
        target = out_dir / output_name(pcap)
        shutil.move(str(produced[0]), target)

    try:
        df = read_flow_csv(target)
    except (SchemaError, ValueError) as e:
        return fail(f"output CSV invalid: {e}")
    if SRC_IP not in df.columns:
        return fail("output CSV has no flow columns")
    status = "converted" if len(df) else "empty"
    return ConversionResult(str(pcap), str(target), status, len(df), time.perf_counter() - t0)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--out-dir", type=Path)
    args = ap.parse_args(argv)
    res = convert_pcap(args.pcap, args.out_dir)
    print(res.to_dict())
    raise SystemExit(0 if res.status != "failed" else 1)


if __name__ == "__main__":
    main()
