"""KubeDeceive-inspired adaptive deception controller (MAPE-K).

Monitor   new ML detections, flow bursts and simulated test events; decoy status
          from Kubernetes; decoy interactions from decoy logs
Analyze   group evidence by (source, attack class) and aggregate it per class policy:
          N flows >= min confidence from one source within T s, mean confidence >= X;
          engagements add hysteresis, a re-engage cooldown and the redirect of the source
Plan      map the class (or burst target port) to decoy profiles; choose deploy,
          scale, refresh or a suppression (limit, cooldown) per profile
Execute   create / scale / remove decoys through DecoyManager
Knowledge SQLite: every decision with its reason and evidence, decoy lifecycle,
          interactions; past engagement reorders profile choice and drives density

Housekeeping (status reconciliation, interaction collection, TTL expiry) runs every
cycle even while automatic deception is disabled. Simulated events are stored
and reported separately and never counted as ML detections. The ML model is
never retrained from decoy interactions.
"""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from live.k8s_decoys import _NAME_RE as DECOY_NAME_RE, DecoyError, decoy_name
from live import db
from live import redirect as redir
from live.config import load_config
from live.logging_setup import get_logger

log = get_logger(__name__)
ACTIVE = ("deploying", "active")
STAGES = ("idle", "monitor", "analyze", "plan", "execute", "knowledge")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(t: datetime) -> str:
    return t.isoformat()


def parse(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


class MapeKController:
    def __init__(self, cfg: dict[str, Any] | None = None, manager=None, manager_factory=None):
        self.cfg = cfg or load_config()
        self.d = self.cfg["deception"]
        self.benign_class = self.cfg["detection"]["benign_class"]
        self._manager = manager
        self._manager_factory = manager_factory
        self.manager_error: str | None = None
        self.last_error: str | None = None
        self.stage = "idle"
        self.last_cycle: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        with self._conn() as c:
            if db.kv_get(c, "deception_enabled") is None:
                db.kv_set(c, "deception_enabled", "1" if self.d["enabled_on_start"] else "0")

    # --- plumbing -------------------------------------------------------------------
    def _conn(self):
        return db.connect(db.db_path(self.cfg))

    @property
    def manager(self):
        if self._manager is None:
            try:
                if self._manager_factory:
                    self._manager = self._manager_factory()
                else:
                    from live.k8s_decoys import DecoyManager
                    self._manager = DecoyManager(self.cfg)
                self.manager_error = None
            except Exception as e:  # cluster down / kubeconfig missing: keep running on stored data
                self.manager_error = str(e)
                return None
        return self._manager

    @property
    def enabled(self) -> bool:
        with self._conn() as c:
            return db.kv_get(c, "deception_enabled") == "1"

    def set_enabled(self, value: bool) -> None:
        with self._conn() as c:
            if value:
                # Only evidence that arrives after enabling is acted on.
                for key, table in (("cursor_detections", "detections"), ("cursor_alerts", "behavior_alerts"),
                                   ("cursor_simulated", "simulated_events")):
                    db.kv_set(c, key, str(c.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()[0]))
            db.kv_set(c, "deception_enabled", "1" if value else "0")
        log.info("deception %s", "enabled" if value else "disabled")

    # --- detection policy (per class, editable) -----------------------------------------
    POLICY_KEYS = ("min_confidence", "min_flows", "window_seconds", "mean_confidence")

    def detection_policy(self) -> dict[str, Any]:
        """Config defaults overlaid with the overrides saved from the dashboard."""
        base = json.loads(json.dumps(self.d.get("detection_policy") or {"default": {
            "min_confidence": 0.8, "min_flows": 5, "window_seconds": 60, "mean_confidence": 0.85}}))
        hyst = dict(self.d.get("hysteresis") or {"release_ratio": 0.5, "quiet_seconds": 180, "reengage_cooldown_seconds": 120})
        with self._conn() as c:
            raw = db.kv_get(c, "detection_policy_override")
        ov = json.loads(raw) if raw else {}
        for cls, vals in (ov.get("classes") or {}).items():
            base.setdefault(cls, dict(base["default"])).update(vals)
        hyst.update(ov.get("hysteresis") or {})
        return {"classes": base, "hysteresis": hyst, "overridden": bool(ov), "updated_at": ov.get("updated_at")}

    def class_policy(self, cls: str) -> dict[str, Any]:
        pol = self.detection_policy()["classes"]
        return {**pol["default"], **pol.get(cls, {})}

    def set_detection_policy(self, classes: dict[str, dict[str, Any]] | None, hysteresis: dict[str, Any] | None,
                             reset: bool = False) -> dict[str, Any]:
        """Validate and store dashboard overrides. Raises ValueError with the offending field."""
        if reset:
            with self._conn() as c:
                c.execute("DELETE FROM kv WHERE key = 'detection_policy_override'")
            log.info("detection policy reset to config defaults")
            return self.detection_policy()
        known = set(self.d["attack_policy"]) | {"default"}
        limits = {"min_confidence": (0.5, 1.0, float), "mean_confidence": (0.5, 1.0, float),
                  "min_flows": (1, 1000, int), "window_seconds": (5, 3600, int),
                  "release_ratio": (0.1, 1.0, float), "quiet_seconds": (10, 7200, int),
                  "reengage_cooldown_seconds": (0, 7200, int)}

        def check(name, v):
            lo, hi, typ = limits[name]
            try:
                v = typ(v)
            except (TypeError, ValueError):
                raise ValueError(f"{name} must be a number")
            if not lo <= v <= hi:
                raise ValueError(f"{name} must be between {lo} and {hi}")
            return v

        out: dict[str, Any] = {"classes": {}, "hysteresis": {}}
        for cls, vals in (classes or {}).items():
            if cls not in known:
                raise ValueError(f"unknown class {cls!r}; one of {sorted(known)}")
            out["classes"][cls] = {k: check(k, v) for k, v in vals.items() if k in self.POLICY_KEYS}
            bad = set(vals) - set(self.POLICY_KEYS)
            if bad:
                raise ValueError(f"unknown field(s) for {cls}: {sorted(bad)}")
        for k, v in (hysteresis or {}).items():
            if k not in ("release_ratio", "quiet_seconds", "reengage_cooldown_seconds"):
                raise ValueError(f"unknown hysteresis field {k!r}")
            out["hysteresis"][k] = check(k, v)
        with self._conn() as c:
            prev = json.loads(db.kv_get(c, "detection_policy_override") or "{}")
            for cls, vals in out["classes"].items():
                prev.setdefault("classes", {}).setdefault(cls, {}).update(vals)
            prev.setdefault("hysteresis", {}).update(out["hysteresis"])
            prev["updated_at"] = iso(now_utc())
            db.kv_set(c, "detection_policy_override", json.dumps(prev))
        log.info("detection policy updated: %s", out)
        return self.detection_policy()

    def _record(self, c, cycle_id, **fields) -> int:
        fields.setdefault("created_at", iso(now_utc()))
        if isinstance(fields.get("evidence"), (dict, list)):
            fields["evidence"] = json.dumps(fields["evidence"])
        return db.insert_row(c, "decisions", cycle_id=cycle_id, **fields)

    # --- Monitor --------------------------------------------------------------------
    def _new_rows(self, c, table: str, cursor: str, where: str = "1=1", params: tuple = ()) -> list[dict]:
        last = int(db.kv_get(c, cursor, "0"))
        rows = [dict(r) for r in c.execute(f"SELECT * FROM {table} WHERE id > ? AND {where} ORDER BY id",
                                           (last, *params))]
        top = c.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()[0]
        db.kv_set(c, cursor, str(max(last, top)))
        return rows

    def monitor(self, c) -> dict[str, list[dict]]:
        sources = self.d["act_on_sources"]
        q = ",".join("?" * len(sources))
        return {
            "detections": self._new_rows(c, "detections", "cursor_detections",
                                         f"is_malicious = 1 AND simulated = 0 AND source IN ({q})", tuple(sources)),
            "alerts": self._new_rows(c, "behavior_alerts", "cursor_alerts"),
            "simulated": self._new_rows(c, "simulated_events", "cursor_simulated"),
        }

    # --- Analyze --------------------------------------------------------------------
    def analyze(self, c, ev: dict[str, list[dict]]) -> list[dict[str, Any]]:
        th = self.d["thresholds"]
        since = iso(now_utc() - timedelta(seconds=th["repeat_window_seconds"]))
        out = []

        groups: dict[tuple, list[dict]] = defaultdict(list)
        for r in ev["detections"]:
            groups[(r["src_ip"], r["predicted_class"])].append(r)
        for (src, cls), rows in groups.items():
            pol = self.class_policy(cls)
            t_since = iso(now_utc() - timedelta(seconds=pol["window_seconds"]))
            agg = [dict(x) for x in c.execute(
                "SELECT id, confidence, dst_ip, dst_port FROM detections WHERE is_malicious = 1 AND simulated = 0 "
                "AND predicted_class = ? AND src_ip IS ? AND detected_at >= ? AND confidence >= ? ORDER BY id DESC",
                (cls, src, t_since, pol["min_confidence"]))]
            n = len(agg)
            mean = sum(x["confidence"] for x in agg) / n if n else 0.0
            evidence = {"detection_ids": [x["id"] for x in agg[:30]], "new_in_cycle": len(rows), "flows": n,
                        "mean_confidence": round(mean, 4), "window_seconds": pol["window_seconds"],
                        "max_confidence_new": round(max(r["confidence"] for r in rows), 4),
                        "targets": sorted({f"{x['dst_ip']}:{x['dst_port']}" for x in agg[:30]})[:5], "policy": pol}
            out.append(self._assess_aggregate("ml", src, cls, n, mean, pol, evidence, simulated=False))

        for e in ev["simulated"]:
            pol = self.class_policy(e["attack_class"])
            out.append(self._assess_aggregate("simulated", e["src_ip"], e["attack_class"], e["count"], e["confidence"], pol,
                                              {"simulated_event_id": e["id"], "note": e["note"], "policy": pol},
                                              simulated=True))

        bursts: dict[tuple, list[dict]] = defaultdict(list)
        for a in ev["alerts"]:
            bursts[(a["src_ip"], a["dst_port"], a.get("alert_type") or "flow_burst")].append(a)
        for (src, port, kind), rows in bursts.items():
            a = max(rows, key=lambda r: r["flows"])
            windows = c.execute("SELECT COUNT(*) FROM behavior_alerts WHERE src_ip = ? AND dst_port IS ? AND alert_type = ? "
                                "AND detected_at >= ?", (src, port, kind, since)).fetchone()[0]
            if kind == "port_sweep":
                out.append({
                    "trigger": "behavior", "src_ip": src, "attack_class": "Reconnaissance (port sweep)",
                    "assessment": "high", "max_confidence": None, "evidence_count": max(windows, len(rows)),
                    "actionable": True, "target_port": "sweep", "simulated": False,
                    "reason": (f"port sweep: {a.get('distinct_ports')} distinct ports of {a['dst_ip']} in "
                               f"{a['window_s']:.0f}s from {src} (threshold {self.cfg['behavior'].get('sweep_min_ports', 10)})"),
                    "evidence": {"behavior_alert_ids": [r["id"] for r in rows],
                                 "ml_classes": json.loads(a["ml_classes"] or "{}")},
                })
                continue
            out.append({
                "trigger": "behavior", "src_ip": src, "attack_class": "Reconnaissance (flow burst)",
                "assessment": "high", "max_confidence": None, "evidence_count": max(windows, len(rows)),
                "actionable": True, "target_port": port, "simulated": False,
                "reason": (f"flow burst: {a['flows']} flows in {a['window_s']:.0f}s ({a['rate_per_s']}/s) from "
                           f"{src} to {a['dst_ip']}:{port} (threshold {self.cfg['behavior']['min_flows']}); "
                           f"{max(windows, len(rows))} burst window(s) in {th['repeat_window_seconds']}s"),
                "evidence": {"behavior_alert_ids": [r["id"] for r in rows],
                             "ml_classes": json.loads(a["ml_classes"] or "{}")},
            })
        return out

    def _assess_aggregate(self, trigger, src, cls, n, mean, pol, evidence, simulated) -> dict[str, Any]:
        """Per-class aggregation: N confident flows from one source within T seconds, mean confidence >= X."""
        tag = "SIMULATED test event: " if simulated else ""
        base = {"trigger": trigger, "src_ip": src, "attack_class": cls, "max_confidence": round(mean, 4) if n else None,
                "evidence_count": n, "evidence": evidence, "simulated": simulated, "target_port": None,
                "mean_confidence": mean}
        if cls == self.benign_class:
            return {**base, "assessment": "benign", "actionable": False, "reason": tag + "benign traffic never triggers decoys"}
        if cls not in self.d["attack_policy"]:
            return {**base, "assessment": "n/a", "actionable": False, "reason": tag + f"no decoy policy for {cls}"}
        need = (f"{pol['min_flows']} flows >= {pol['min_confidence']:.2f} in {pol['window_seconds']}s "
                f"with mean >= {pol['mean_confidence']:.2f}")
        got = f"{n} flow(s) from {src}, mean confidence {mean:.2f}"
        if n >= pol["min_flows"] and mean >= pol["mean_confidence"]:
            return {**base, "assessment": "high", "actionable": True, "reason": tag + f"{cls}: {got} (policy: {need})"}
        hyst = self.detection_policy()["hysteresis"]
        r = float(hyst.get("release_ratio", 0.5))
        holding = n >= max(1, int(pol["min_flows"] * r + 0.999)) and mean >= pol["mean_confidence"] * r
        return {**base, "assessment": "medium" if n else "low", "actionable": False, "sustains": holding,
                "reason": tag + f"{cls}: {got}; below policy ({need}), recorded and monitored"}

    # --- Engagements: hysteresis, cooldown, redirect --------------------------------
    redirector = redir

    def engage(self, c, cycle_id: int, assessments: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Per-source state machine: trigger -> engaged (redirected) -> released after a quiet period."""
        from live import allowlist as allow
        hyst = self.detection_policy()["hysteresis"]
        al = allow.get(self.cfg)
        now = now_utc()
        out = []
        for a in assessments:
            src = a.get("src_ip")
            if src and al.reason(src, None, None, None):
                out.append({**a, "actionable": False, "assessment": "allowlisted",
                            "reason": a["reason"] + f"; {src} is control-plane traffic ({al.reason(src, None, None, None)}), never acted on"})
                continue
            if a["simulated"] or not src:
                out.append(a)
                continue
            if src in self.decoy_ips():
                out.append({**a, "actionable": False, "assessment": "decoy",
                            "reason": a["reason"] + f"; {src} is one of our decoy pods (its replies), never acted on"})
                continue
            eng = c.execute("SELECT * FROM engagements WHERE src_ip = ? AND state = 'active'", (src,)).fetchone()
            if a["actionable"]:
                if eng:
                    db.update_row(c, "engagements", eng["id"], last_evidence_at=iso(now))
                    a = {**a, "engagement_id": eng["id"], "reason": a["reason"] + f"; source already engaged (#{eng['id']})"}
                else:
                    last = parse(c.execute("SELECT MAX(released_at) FROM engagements WHERE src_ip = ?", (src,)).fetchone()[0])
                    wait = float(hyst.get("reengage_cooldown_seconds", 120))
                    if last and (now - last).total_seconds() < wait:
                        a = {**a, "actionable": False, "assessment": "cooldown",
                             "reason": a["reason"] + f"; {src} was released {(now - last).total_seconds():.0f}s ago "
                                                     f"(re-engage cooldown {wait:.0f}s)"}
                    else:
                        # The source is redirected only once one of its decoys is Ready
                        # (_apply_redirects); until then its traffic still reaches the real service.
                        rd = {"applied": False, "pending": True, "reason": "waiting for a Ready decoy"}
                        scen = self.scenario_of(src)
                        eid = db.insert_row(c, "engagements", src_ip=src, attack_class=a["attack_class"],
                                            trigger=a["trigger"], state="active", started_at=iso(now),
                                            last_evidence_at=iso(now), decoys="[]", redirect=json.dumps(rd),
                                            reason=a["reason"])
                        self._record(c, cycle_id, trigger=a["trigger"], src_ip=src, attack_class=a["attack_class"],
                                     assessment=a["assessment"], max_confidence=a.get("max_confidence"),
                                     evidence_count=a.get("evidence_count"), action="engage", result="ok",
                                     reason=f"engagement #{eid} opened for {src} (scenario {scen}): {a['reason']}. "
                                            f"The source is redirected to its decoy as soon as the decoy is Ready",
                                     evidence={**(a.get("evidence") or {}), "engagement_id": eid})
                        a = {**a, "engagement_id": eid}
            elif eng and a.get("sustains"):
                db.update_row(c, "engagements", eng["id"], last_evidence_at=iso(now))
                a = {**a, "reason": a["reason"] + f"; still >= {hyst['release_ratio']:.0%} of the trigger level, "
                                                  f"engagement #{eng['id']} kept (hysteresis)"}
            out.append(a)
        return out

    def scenario_of(self, ip: str | None) -> str:
        """Traffic-lab scenario of a source pod (for the event log), or UNKNOWN."""
        from live import labsources
        hit = labsources.get(self.cfg).get(str(ip)) if ip else None
        return f"{hit['scenario']} ({hit['job']})" if hit else "UNKNOWN"

    def decoy_ips(self) -> set[str]:
        from live import labsources
        return labsources.decoy_ips(self.cfg)

    def _link_decoy(self, c, engagement_id: int | None, name: str | None) -> None:
        if not engagement_id or not name:
            return
        row = c.execute("SELECT decoys FROM engagements WHERE id = ?", (engagement_id,)).fetchone()
        names = json.loads(row["decoys"] or "[]") if row else []
        if name not in names:
            db.update_row(c, "engagements", engagement_id, decoys=json.dumps(names + [name]))

    def _apply_redirects(self, c, cycle_id: int, out: dict[str, Any]) -> None:
        """Redirect each engaged source to a Ready decoy of its engagement (once)."""
        ns = self.d["namespace"]
        for e in [dict(r) for r in c.execute("SELECT * FROM engagements WHERE state = 'active'")]:
            rd = json.loads(e["redirect"] or "{}")
            if not rd.get("pending"):
                continue
            names = json.loads(e["decoys"] or "[]")
            ready = [dict(r) for r in c.execute(
                f"SELECT * FROM decoys WHERE status = 'active' AND name IN ({','.join('?' * len(names))}) ORDER BY id",
                names)] if names else []
            if not ready:
                continue
            d = min(ready, key=lambda r: names.index(r["name"]))   # the policy's preferred decoy
            to = f"{d['name']}.{ns}.svc.cluster.local:{d['port']}"
            new = self.redirector.quarantine(e["src_ip"], self.cfg, redirect_to=to) if self.redirector else \
                {"applied": False, "reason": "redirect not configured"}
            new["decoy"] = d["name"]
            db.update_row(c, "engagements", e["id"], redirect=json.dumps(new))
            self._record(c, cycle_id, trigger="engagement", src_ip=e["src_ip"], attack_class=e["attack_class"],
                         action="redirect", decoy_profile=d["profile"], decoy_name=d["name"],
                         result="ok" if new.get("applied") else "skipped", assessment="n/a",
                         reason=f"engagement #{e['id']} ({e['src_ip']}, scenario {self.scenario_of(e['src_ip'])}): "
                                f"decoy {d['name']} is Ready ({to}). Redirect: {new['reason']}",
                         evidence={"engagement_id": e["id"]})
            out.setdefault("redirected", []).append(e["src_ip"])

    def _release_quiet(self, c, cycle_id: int, out: dict[str, Any]) -> None:
        """Release engagements without evidence or decoy interaction for quiet_seconds."""
        quiet = float(self.detection_policy()["hysteresis"].get("quiet_seconds", 180))
        now = now_utc()
        for e in [dict(r) for r in c.execute("SELECT * FROM engagements WHERE state = 'active'")]:
            marks = [parse(e["last_evidence_at"])]
            for sql in ("SELECT MAX(ts) FROM interactions WHERE src_ip = ?",
                        "SELECT MAX(detected_at) FROM behavior_alerts WHERE src_ip = ?"):
                v = c.execute(sql, (e["src_ip"],)).fetchone()[0]
                if v:
                    try:
                        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
                        marks.append(t if t.tzinfo else t.replace(tzinfo=timezone.utc))
                    except ValueError:
                        pass
            idle = (now - max(marks)).total_seconds()
            if idle < quiet:
                continue
            rel = self.redirector.release(json.loads(e["redirect"] or "{}"), self.cfg) if self.redirector else \
                {"released": False, "reason": "redirect not configured"}
            others = set()
            for r in c.execute("SELECT decoys FROM engagements WHERE state = 'active' AND id != ?", (e["id"],)):
                others |= set(json.loads(r["decoys"] or "[]"))
            removed = []
            for name in json.loads(e["decoys"] or "[]"):
                if name not in others and self.remove_decoy(
                        c, name, "removed", cycle_id, "hysteresis",
                        f"engagement #{e['id']} ({e['src_ip']}) quiet for {idle:.0f}s >= {quiet:.0f}s") == "ok":
                    removed.append(name)
            db.update_row(c, "engagements", e["id"], state="released", released_at=iso(now))
            self._record(c, cycle_id, trigger="hysteresis", src_ip=e["src_ip"], attack_class=e["attack_class"],
                         action="release", result="ok", assessment="n/a",
                         reason=f"engagement #{e['id']} released: no evidence or decoy interaction for {idle:.0f}s "
                                f"(quiet period {quiet:.0f}s). Redirect: {rel['reason']}. "
                                f"Decoys torn down: {', '.join(removed) or 'none (still used or already gone)'}",
                         evidence={"engagement_id": e["id"]})
            out.setdefault("released", []).append(e["src_ip"])

    def engagements(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM engagements ORDER BY id DESC LIMIT ?", (int(limit),))]
        for r in rows:
            r["decoys"] = json.loads(r["decoys"] or "[]")
            r["redirect"] = json.loads(r["redirect"] or "{}")
        return rows

    # --- Plan -----------------------------------------------------------------------
    def _profiles_for(self, c, a: dict[str, Any]) -> list[str]:
        if a["trigger"] == "behavior":
            pol = self.d["behavior_policy"]
            profiles = list(pol.get(str(a["target_port"]), pol["default"]))
        else:
            profiles = list(self.d["attack_policy"][a["attack_class"]])
        # Knowledge: profiles that attracted more interactions before come first.
        engagement = {r["decoy_profile"]: r["n"] for r in c.execute(
            "SELECT decoy_profile, COUNT(*) n FROM interactions GROUP BY decoy_profile")}
        return sorted(profiles, key=lambda p: (-engagement.get(p, 0), profiles.index(p)))

    def plan(self, c, assessments: list[dict[str, Any]]) -> list[dict[str, Any]]:
        now = now_utc()
        decoys = {r["name"]: dict(r) for r in c.execute(f"SELECT * FROM decoys WHERE status IN {ACTIVE}")}
        active_count = len(decoys)
        last_deploy = parse(c.execute("SELECT MAX(created_at) FROM decoys").fetchone()[0])
        actions: list[dict[str, Any]] = []
        planned: set[str] = set()
        for a in assessments:
            if not a["actionable"]:
                actions.append({**a, "action": "await_evidence" if a["assessment"] == "medium" else "monitor",
                                "profile": None})
                continue
            for profile in self._profiles_for(c, a):
                name = decoy_name(profile)
                act = {**a, "profile": profile, "name": name}
                if name in planned:
                    # another source in this cycle already asked for this decoy: share it
                    self._link_decoy(c, a.get("engagement_id"), name)
                    continue
                if name in decoys:
                    d = decoys[name]
                    if (profile in self.d["scale_on_repeat"] and d["replicas"] < self.d["max_replicas"]
                            and a["evidence_count"] >= self.d["thresholds"]["repeat_count"]):
                        actions.append({**act, "action": "scale", "replicas": d["replicas"] + 1,
                                        "reason": a["reason"] + f"; repeated evidence -> scale {name} to {d['replicas'] + 1} replicas"})
                    else:
                        actions.append({**act, "action": "refresh",
                                        "reason": a["reason"] + f"; {name} already active (duplicate prevented), TTL extended"})
                elif active_count >= self.d["max_active_decoys"]:
                    actions.append({**act, "action": "suppress_limit",
                                    "reason": a["reason"] + f"; max {self.d['max_active_decoys']} active decoys reached"})
                elif last_deploy and (now - last_deploy).total_seconds() < self.d["cooldown_seconds"]:
                    actions.append({**act, "action": "suppress_cooldown",
                                    "reason": a["reason"] + f"; deployment cooldown {self.d['cooldown_seconds']}s"})
                elif self._recently_removed(c, profile, now):
                    actions.append({**act, "action": "suppress_cooldown",
                                    "reason": a["reason"] + f"; {profile} removed < {self.d['redeploy_cooldown_seconds']}s ago"})
                else:
                    # The cooldown is measured from deployments of earlier cycles, so every
                    # profile mapped to this assessment can be deployed together.
                    actions.append({**act, "action": "deploy",
                                    "reason": a["reason"] + f"; policy {a['attack_class']} -> {profile}"})
                    active_count += 1
                planned.add(name)
        return actions

    def _recently_removed(self, c, profile: str, now: datetime) -> bool:
        t = parse(c.execute("SELECT MAX(removed_at) FROM decoys WHERE profile = ?", (profile,)).fetchone()[0])
        return bool(t and (now - t).total_seconds() < self.d["redeploy_cooldown_seconds"])

    # --- Execute --------------------------------------------------------------------
    def _deploy(self, c, profile: str, decision_id: int, detection_id=None, simulated=False) -> tuple[str, str | None]:
        mgr = self.manager
        if mgr is None:
            return "failed", f"Kubernetes unavailable: {self.manager_error}"
        name = decoy_name(profile)
        t = now_utc()
        try:
            info = mgr.deploy(profile, 1)
        except DecoyError as e:
            db.insert_row(c, "decoys", name=name, profile=profile, namespace=self.d["namespace"], status="failed",
                          created_at=iso(t), removed_at=iso(t), decision_id=decision_id, simulated=int(simulated),
                          error=str(e))
            return "failed", str(e)
        log.info("decoy %s deployed (profile %s, service %s:%s), waiting for readiness", name, profile,
                 info["service_ip"], info["port"])
        db.insert_row(c, "decoys", name=name, profile=profile, namespace=self.d["namespace"], status="deploying",
                      replicas=1, port=info["port"], service_ip=info["service_ip"], created_at=iso(t),
                      expires_at=iso(t + timedelta(seconds=self.d["decoy_ttl_seconds"])), decision_id=decision_id,
                      detection_id=detection_id, simulated=int(simulated))
        return "ok", None

    def execute(self, c, cycle_id: int, actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results = []
        for a in actions:
            dec = {k: a.get(k) for k in ("trigger", "src_ip", "attack_class", "assessment", "max_confidence",
                                         "evidence_count", "reason", "evidence")}
            dec_id = self._record(c, cycle_id, action=a["action"], decoy_profile=a.get("profile"),
                                  decoy_name=a.get("name"), result="planned", simulated=int(a["simulated"]), **dec)
            result, error = "skipped", None
            if a["action"] == "deploy":
                det_ids = (a.get("evidence") or {}).get("detection_ids") or [None]
                result, error = self._deploy(c, a["profile"], dec_id, det_ids[0], a["simulated"])
            elif a["action"] == "scale":
                result, error = self._scale(c, a["name"], a["replicas"])
            elif a["action"] == "refresh":
                self._extend(c, a["name"])
                result = "ok"
            db.update_row(c, "decisions", dec_id, result=result,
                          reason=a["reason"] + (f" [failed: {error}]" if error else ""))
            if result == "ok" and a["action"] in ("deploy", "scale", "refresh"):
                self._link_decoy(c, a.get("engagement_id"), a.get("name"))
            results.append({"decision_id": dec_id, "action": a["action"], "profile": a.get("profile"), "result": result})
        return results

    def _scale(self, c, name: str, replicas: int) -> tuple[str, str | None]:
        mgr = self.manager
        if mgr is None:
            return "failed", f"Kubernetes unavailable: {self.manager_error}"
        try:
            mgr.scale(name, replicas)
        except DecoyError as e:
            return "failed", str(e)
        c.execute("UPDATE decoys SET replicas = ? WHERE name = ? AND status IN ('deploying', 'active')", (replicas, name))
        self._extend(c, name)
        return "ok", None

    def _extend(self, c, name: str) -> None:
        row = c.execute("SELECT id, created_at FROM decoys WHERE name = ? AND status IN ('deploying', 'active')",
                        (name,)).fetchone()
        if row:
            cap = parse(row["created_at"]) + timedelta(seconds=self.d["max_lifetime_seconds"])
            new = min(now_utc() + timedelta(seconds=self.d["decoy_ttl_seconds"]), cap)
            db.update_row(c, "decoys", row["id"], expires_at=iso(new))

    def remove_decoy(self, c, name: str, status: str, cycle_id: int | None, trigger: str, reason: str) -> str:
        mgr = self.manager
        if mgr is None:
            return "failed"
        self._collect_for(c, name)  # keep the last interactions before the pods disappear
        try:
            existed = mgr.remove(name)
        except DecoyError as e:
            log.error("remove %s failed: %s", name, e)
            self.last_error = str(e)
            return "failed"
        row = c.execute("SELECT * FROM decoys WHERE name = ? AND status IN ('deploying', 'active')", (name,)).fetchone()
        if not existed and row is None:
            return "not_found"
        log.info("decoy %s removed (%s): %s", name, status, reason)
        if row:
            db.update_row(c, "decoys", row["id"], status=status, removed_at=iso(now_utc()))
        self._record(c, cycle_id, trigger=trigger, action="remove", decoy_profile=row["profile"] if row else None,
                     decoy_name=name, result="ok", reason=reason, assessment="n/a",
                     simulated=int(row["simulated"]) if row else 0)
        return "ok"

    # --- Housekeeping ---------------------------------------------------------------
    def _collect_for(self, c, name: str) -> int:
        mgr = self.manager
        row = c.execute("SELECT * FROM decoys WHERE name = ? ORDER BY id DESC LIMIT 1", (name,)).fetchone()
        if mgr is None or row is None:
            return 0
        since = max(60, int((now_utc() - parse(row["created_at"])).total_seconds()) + 60)
        n = 0
        collected = iso(now_utc())
        for pod, rec in mgr.interaction_lines(name, since):
            cur = c.execute(
                "INSERT OR IGNORE INTO interactions (ts, decoy_name, decoy_profile, pod, src_ip, src_port, method, path, "
                "query, user_agent, status, interaction_type, body_bytes, decoy_id, decision_id, detection_id, collected_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (rec.get("ts"), name, rec.get("profile"), pod, rec.get("src_ip"), rec.get("src_port"), rec.get("method"),
                 rec.get("path"), rec.get("query"), rec.get("user_agent"), rec.get("status"), rec.get("type"),
                 rec.get("body_bytes"), row["id"], row["decision_id"], row["detection_id"], collected))
            n += cur.rowcount
        if n:
            self._extend(c, name)
        return n

    def housekeeping(self, c, cycle_id: int) -> dict[str, Any]:
        out = {"interactions": 0, "expired": [], "ready": [], "vanished": [], "scaled": []}
        mgr = self.manager
        if mgr is None:
            return {**out, "error": self.manager_error}
        try:
            live = mgr.list_decoys()
        except Exception as e:
            self._manager = None
            return {**out, "error": f"list failed: {e}"}
        now = now_utc()
        rows = [dict(r) for r in c.execute(f"SELECT * FROM decoys WHERE status IN {ACTIVE}")]
        for r in rows:
            k = live.get(r["name"])
            if k is None:
                db.update_row(c, "decoys", r["id"], status="removed", removed_at=iso(now), error="deleted outside controller")
                out["vanished"].append(r["name"])
                continue
            if r["status"] == "deploying":
                reachable = k.get("service", True) and (k.get("endpoints") is None or k["endpoints"] >= 1)
                if k["ready_replicas"] >= 1 and reachable:
                    secs = (now - parse(r["created_at"])).total_seconds()
                    db.update_row(c, "decoys", r["id"], status="active", ready_at=iso(now), deploy_seconds=secs)
                    log.info("decoy %s ready after %.1fs (%s endpoint(s))", r["name"], secs, k.get("endpoints"))
                    self._record(c, cycle_id, trigger="readiness", action="decoy_ready", decoy_profile=r["profile"],
                                 decoy_name=r["name"], result="ok", assessment="n/a", simulated=int(r["simulated"]),
                                 reason=f"{r['name']} Ready after {secs:.1f}s: {k['ready_replicas']} ready replica(s), "
                                        f"{k.get('endpoints')} Service endpoint(s)")
                    out["ready"].append(r["name"])
                elif (now - parse(r["created_at"])).total_seconds() > self.d["deploy_timeout_seconds"]:
                    mgr.remove(r["name"])
                    db.update_row(c, "decoys", r["id"], status="failed", removed_at=iso(now), error="readiness timeout")
                    self._record(c, cycle_id, trigger="readiness", action="deploy_failed", decoy_profile=r["profile"],
                                 decoy_name=r["name"], result="failed", assessment="n/a", simulated=int(r["simulated"]),
                                 reason=f"{r['name']} not Ready within {self.d['deploy_timeout_seconds']}s "
                                        f"({k['ready_replicas']} ready replica(s), {k.get('endpoints')} endpoint(s)); removed")
                    continue
            out["interactions"] += self._collect_for(c, r["name"])

        self._apply_redirects(c, cycle_id, out)
        self._release_quiet(c, cycle_id, out)
        e = self.d["engagement"]
        since = iso(now - timedelta(seconds=e["window_seconds"]))
        for r in [dict(x) for x in c.execute("SELECT * FROM decoys WHERE status = 'active'")]:
            if parse(r["expires_at"]) <= now:
                self.remove_decoy(c, r["name"], "expired", cycle_id, "ttl",
                                  f"TTL expired at {r['expires_at']} with no recent interaction")
                out["expired"].append(r["name"])
                continue
            recent = c.execute("SELECT COUNT(*) FROM interactions WHERE decoy_id = ? AND ts >= ?",
                               (r["id"], since)).fetchone()[0]
            last_scale = c.execute("SELECT MAX(created_at) FROM decisions WHERE decoy_name = ? AND action = 'scale'",
                                   (r["name"],)).fetchone()[0]
            if (recent >= e["scale_up_interactions"] and r["replicas"] < self.d["max_replicas"]
                    and (last_scale is None or last_scale < since)):
                res, err = self._scale(c, r["name"], r["replicas"] + 1)
                self._record(c, cycle_id, trigger="engagement", action="scale", decoy_profile=r["profile"],
                             decoy_name=r["name"], result=res, assessment="n/a", simulated=int(r["simulated"]),
                             reason=f"{recent} interactions in {e['window_seconds']}s >= {e['scale_up_interactions']}: "
                                    f"density increased to {r['replicas'] + 1}" + (f" [failed: {err}]" if err else ""))
                out["scaled"].append(r["name"])
        return out

    # --- cycle ----------------------------------------------------------------------
    def run_cycle(self) -> dict[str, Any]:
        with self._lock:
            t0 = time.perf_counter()
            with self._conn() as c:
                cycle_id = int(db.kv_get(c, "cycle_id", "0")) + 1
                db.kv_set(c, "cycle_id", str(cycle_id))
                summary: dict[str, Any] = {"cycle_id": cycle_id, "started_at": iso(now_utc()), "enabled": self.enabled}
                self.stage = "monitor"
                summary["housekeeping"] = self.housekeeping(c, cycle_id)
                if summary["enabled"]:
                    ev = self.monitor(c)
                    summary["evidence"] = {k: len(v) for k, v in ev.items()}
                    self.stage = "analyze"
                    assessments = self.engage(c, cycle_id, self.analyze(c, ev))
                    self.stage = "plan"
                    actions = self.plan(c, assessments)
                    self.stage = "execute"
                    summary["actions"] = self.execute(c, cycle_id, actions)
                else:
                    summary["evidence"], summary["actions"] = {}, []
                self.stage = "knowledge"
                summary["duration_ms"] = (time.perf_counter() - t0) * 1000
                db.kv_set(c, "last_cycle", json.dumps(summary, default=str))
            self.stage = "idle"
            self.last_cycle = summary
            return summary

    # --- manual controls ------------------------------------------------------------
    def manual_deploy(self, profile: str) -> dict[str, Any]:
        if profile not in self.d["profiles"]:
            raise DecoyError(f"unknown profile {profile!r}")
        with self._lock, self._conn() as c:
            name = decoy_name(profile)
            if c.execute(f"SELECT 1 FROM decoys WHERE name = ? AND status IN {ACTIVE}", (name,)).fetchone():
                raise DecoyError(f"{name} is already active")
            dec_id = self._record(c, None, trigger="manual", action="deploy", decoy_profile=profile, decoy_name=name,
                                  result="planned", assessment="n/a", reason="manual deployment from dashboard/API")
            result, error = self._deploy(c, profile, dec_id)
            db.update_row(c, "decisions", dec_id, result=result,
                          reason="manual deployment from dashboard/API" + (f" [failed: {error}]" if error else ""))
            return {"decision_id": dec_id, "name": name, "result": result, "error": error}

    def manual_remove(self, name: str) -> dict[str, Any]:
        if not DECOY_NAME_RE.match(name):
            raise DecoyError(f"invalid decoy name {name!r}")
        with self._lock, self._conn() as c:
            self.last_error = None
            res = self.remove_decoy(c, name, "removed", None, "manual", "manual removal from dashboard/API")
            return {"name": name, "result": res, "error": self.last_error or (self.manager_error if res == "failed" else None)}

    def submit_simulated_event(self, attack_class: str, confidence: float, src_ip: str | None = None,
                               count: int = 1, note: str = "") -> int:
        if attack_class not in self.d["attack_policy"] and attack_class != self.benign_class:
            raise ValueError(f"unknown attack class {attack_class!r}")
        if not 0 <= confidence <= 1 or not 1 <= count <= 100:
            raise ValueError("confidence must be 0..1 and count 1..100")
        with self._conn() as c:
            return db.insert_row(c, "simulated_events", created_at=iso(now_utc()), src_ip=src_ip,
                                 attack_class=attack_class, confidence=confidence, count=count,
                                 note=f"SIMULATED: {note}".strip())

    # --- background loop ------------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()

        def loop():
            while not self._stop.is_set():
                try:
                    self.run_cycle()
                except Exception:
                    log.exception("MAPE-K cycle failed")
                    self.stage = "idle"
                self._stop.wait(self.d["loop_interval_seconds"])

        self._thread = threading.Thread(target=loop, name="mape-k", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=30)

    def status(self) -> dict[str, Any]:
        with self._conn() as c:
            last = db.kv_get(c, "last_cycle")
            decoys = db.query_df(c, f"SELECT * FROM decoys WHERE status IN {ACTIVE} ORDER BY created_at")
        cluster, cluster_error = None, None
        mgr = self.manager
        if mgr is not None:
            try:
                cluster = list(mgr.list_decoys().values())   # what Kubernetes actually has right now
            except Exception as e:  # noqa: BLE001
                cluster_error = str(e)[:300]
        return {
            "cluster_decoys": cluster, "cluster_error": cluster_error,
            "enabled": self.enabled, "stage": self.stage, "loop_running": bool(self._thread and self._thread.is_alive()),
            "kubernetes_available": self.manager is not None, "kubernetes_error": self.manager_error,
            "last_cycle": json.loads(last) if last else None,
            "active_decoys": decoys.astype(object).where(decoys.notna(), None).to_dict(orient="records"),
            "limits": {k: self.d[k] for k in ("max_active_decoys", "max_replicas", "decoy_ttl_seconds",
                                               "cooldown_seconds", "redeploy_cooldown_seconds")},
            "thresholds": self.d["thresholds"],
            "detection_policy": self.detection_policy(),
            "engagements": [e for e in self.engagements(50) if e["state"] == "active"],
        }
