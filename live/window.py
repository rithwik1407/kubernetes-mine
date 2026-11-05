"""Adaptive observation window: how long the next capture window should be.

The capture service records traffic in windows (one PCAP per window). After every
window it asks this module for the length of the next one. The decision is a pure
function of measured evidence, so it is deterministic, testable and logged:

  inputs   packet rate of the window just captured (packets / second), and the
           threat evidence from the most recently *scored* window(s): malicious
           ML flows at or above the evidence confidence, and flow bursts.

  rules (first match wins)
    R1 threat      threat evidence in the latest scored window
                   -> go to `threat_seconds` (default 3 s) if the current window is
                      longer, so the attack is re-observed and re-scored sooner.
                      Not the absolute minimum: CICFlowMeter converts each window
                      separately, so a 1 s window cuts most TCP flows in pieces
                      and distorts their features.
    R2 high_rate   rate >= high_rate_pps
                   -> one size smaller (bounded PCAPs, quicker scoring).
    R3 calm        no threat evidence for `calm_windows` consecutive scored
                   windows AND rate <= low_rate_pps
                   -> one size larger (more complete flows, less overhead).
    R4 hold        otherwise keep the current size.

Sizes come from `capture.window.sizes` (e.g. 1, 3, 5, 10 s) and are always clamped
to [min_seconds, max_seconds]. Nothing here is random.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Evidence:
    """What the policy looks at. Missing values mean 'not measured yet'."""
    packets: int | None = None
    duration_s: float | None = None
    malicious_flows: int = 0          # ML flows predicted malicious with confidence >= evidence_confidence
    flows: int = 0                    # flows scored in the latest scored window
    bursts: int = 0                   # flow bursts in the latest scored window
    top_class: str | None = None
    max_confidence: float | None = None
    calm_streak: int = 0              # consecutive scored windows without threat evidence
    scored_window: str | None = None  # which PCAP the threat evidence came from

    @property
    def pps(self) -> float | None:
        if self.packets is None or not self.duration_s or self.duration_s <= 0:
            return None
        return self.packets / self.duration_s

    @property
    def threat(self) -> bool:
        return self.malicious_flows > 0 or self.bursts > 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["pps"] = None if self.pps is None else round(self.pps, 2)
        d["threat"] = self.threat
        return d


@dataclass
class Decision:
    previous_s: float
    next_s: float
    rule: str
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def changed(self) -> bool:
        return self.next_s != self.previous_s

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "changed": self.changed}


def window_sizes(wcfg: dict[str, Any]) -> list[float]:
    """Allowed sizes, sorted and clamped to [min_seconds, max_seconds]."""
    lo, hi = float(wcfg["min_seconds"]), float(wcfg["max_seconds"])
    if lo <= 0 or hi < lo:
        raise ValueError(f"invalid window limits min={lo} max={hi}")
    sizes = sorted({float(s) for s in wcfg.get("sizes") or [lo, wcfg.get("default_seconds", lo), hi]
                    if lo <= float(s) <= hi})
    if not sizes:
        raise ValueError("capture.window.sizes has no size inside [min_seconds, max_seconds]")
    return sizes


def initial_window(wcfg: dict[str, Any]) -> float:
    return snap(float(wcfg["default_seconds"]), window_sizes(wcfg))


def snap(value: float, sizes: list[float]) -> float:
    """Closest allowed size (ties go to the smaller one)."""
    return min(sizes, key=lambda s: (abs(s - value), s))


def decide(current_s: float, ev: Evidence, wcfg: dict[str, Any]) -> Decision:
    sizes = window_sizes(wcfg)
    cur = snap(float(current_s), sizes)
    i = sizes.index(cur)
    pps = ev.pps
    high, low = float(wcfg["high_rate_pps"]), float(wcfg["low_rate_pps"])
    calm_needed = int(wcfg.get("calm_windows", 3))
    evd = ev.to_dict()
    rate_txt = "rate unknown" if pps is None else f"{pps:.1f} pkt/s"

    if ev.threat:
        what = []
        if ev.malicious_flows:
            what.append(f"{ev.malicious_flows} malicious flow(s)"
                        + (f", top {ev.top_class} @ {ev.max_confidence:.2f}" if ev.top_class and ev.max_confidence else ""))
        if ev.bursts:
            what.append(f"{ev.bursts} flow burst(s)")
        tgt = snap(float(wcfg.get("threat_seconds", sizes[0])), sizes)
        nxt = min(cur, tgt)
        return Decision(cur, nxt, "R1_threat",
                        f"threat evidence in {ev.scored_window or 'last scored window'} ({'; '.join(what)}) -> "
                        + (f"shrink to {nxt:g}s for faster re-detection" if nxt != cur else f"stay at {cur:g}s"), evd)
    if pps is not None and pps >= high:
        nxt = sizes[max(i - 1, 0)]
        return Decision(cur, nxt, "R2_high_rate",
                        f"{rate_txt} >= high_rate_pps {high:g} -> "
                        + (f"shrink to {nxt:g}s" if nxt != cur else f"already at minimum {cur:g}s"), evd)
    if ev.calm_streak >= calm_needed and pps is not None and pps <= low:
        nxt = sizes[min(i + 1, len(sizes) - 1)]
        return Decision(cur, nxt, "R3_calm",
                        f"no threat for {ev.calm_streak} scored window(s) (>= {calm_needed}) and {rate_txt} <= "
                        f"low_rate_pps {low:g} -> " + (f"grow to {nxt:g}s" if nxt != cur else f"already at maximum {cur:g}s"),
                        evd)
    why = []
    if pps is None:
        why.append("no packet count")
    elif low < pps < high:
        why.append(f"{rate_txt} between {low:g} and {high:g}")
    elif pps <= low:
        why.append(f"{rate_txt} is low but only {ev.calm_streak}/{calm_needed} calm scored windows")
    return Decision(cur, cur, "R4_hold", f"hold {cur:g}s: " + ("; ".join(why) or "no rule matched"), evd)


def policy_description(wcfg: dict[str, Any]) -> dict[str, Any]:
    """Human-readable policy for the dashboard and the docs."""
    sizes = window_sizes(wcfg)
    return {
        "sizes": sizes, "min_seconds": sizes[0], "max_seconds": sizes[-1], "initial_seconds": initial_window(wcfg),
        "threat_seconds": snap(float(wcfg.get("threat_seconds", sizes[0])), sizes),
        "high_rate_pps": wcfg["high_rate_pps"], "low_rate_pps": wcfg["low_rate_pps"],
        "calm_windows": int(wcfg.get("calm_windows", 3)),
        "evidence_confidence": float(wcfg.get("evidence_confidence", 0.6)),
        "rules": [
            {"id": "R1_threat", "when": "the latest scored window has malicious ML flows (confidence >= "
             f"{float(wcfg.get('evidence_confidence', 0.6)):g}) or a flow burst", "then": f"shrink to {snap(float(wcfg.get('threat_seconds', sizes[0])), sizes):g}s (or stay if already shorter)"},
            {"id": "R2_high_rate", "when": f"packet rate >= {wcfg['high_rate_pps']} pkt/s", "then": "one size smaller"},
            {"id": "R3_calm", "when": f"{int(wcfg.get('calm_windows', 3))} scored windows in a row without threat evidence "
             f"and packet rate <= {wcfg['low_rate_pps']} pkt/s", "then": "one size larger"},
            {"id": "R4_hold", "when": "none of the above", "then": "keep the current size"},
        ],
    }
