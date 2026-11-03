"""KubeDeceive-inspired adaptive deception controller (MAPE-K).

Monitor   new ML detections, flow bursts and simulated test events; decoy status
          from Kubernetes; decoy interactions from decoy logs
Analyze   group evidence by (source, attack class); apply confidence thresholds,
          repeated-evidence and corroboration rules
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
            history = c.execute(
                "SELECT COUNT(*) FROM detections WHERE is_malicious = 1 AND simulated = 0 AND predicted_class = ? "
                "AND src_ip IS ? AND detected_at >= ?", (cls, src, since)).fetchone()[0]
            corroborated = src is not None and c.execute(
                "SELECT COUNT(*) FROM behavior_alerts WHERE src_ip = ? AND detected_at >= ?", (src, since)).fetchone()[0] > 0
            out.append(self._assess("ml", src, cls, max(r["confidence"] for r in rows), max(history, len(rows)),
                                    corroborated, {"detection_ids": [r["id"] for r in rows[:50]], "batch": len(rows)},
                                    simulated=False))

        for e in ev["simulated"]:
            out.append(self._assess("simulated", e["src_ip"], e["attack_class"], e["confidence"], e["count"], False,
                                    {"simulated_event_id": e["id"], "note": e["note"]}, simulated=True))

        bursts: dict[tuple, list[dict]] = defaultdict(list)
        for a in ev["alerts"]:
            bursts[(a["src_ip"], a["dst_port"])].append(a)
        for (src, port), rows in bursts.items():
            a = max(rows, key=lambda r: r["flows"])
            windows = c.execute("SELECT COUNT(*) FROM behavior_alerts WHERE src_ip = ? AND dst_port = ? AND detected_at >= ?",
                                (src, port, since)).fetchone()[0]
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

    def _assess(self, trigger, src, cls, conf, count, corroborated, evidence, simulated) -> dict[str, Any]:
        th = self.d["thresholds"]
        tag = "SIMULATED test event: " if simulated else ""
        base = {"trigger": trigger, "src_ip": src, "attack_class": cls, "max_confidence": conf,
                "evidence_count": count, "evidence": evidence, "simulated": simulated, "target_port": None}
        if cls == self.benign_class:
            return {**base, "assessment": "benign", "actionable": False, "reason": tag + "benign traffic never triggers decoys"}
        if cls not in self.d["attack_policy"]:
            return {**base, "assessment": "n/a", "actionable": False, "reason": tag + f"no decoy policy for {cls}"}
        if conf >= th["high_confidence"]:
            return {**base, "assessment": "high", "actionable": True,
                    "reason": tag + f"confidence {conf:.2f} >= high threshold {th['high_confidence']}"}
        if conf >= th["medium_confidence"]:
            if count >= th["repeat_count"] or corroborated:
                why = (f"{count} detections in {th['repeat_window_seconds']}s >= {th['repeat_count']}"
                       if count >= th["repeat_count"] else "corroborated by a flow burst from the same source")
                return {**base, "assessment": "medium", "actionable": True,
                        "reason": tag + f"medium confidence {conf:.2f} confirmed: {why}"}
            return {**base, "assessment": "medium", "actionable": False,
                    "reason": tag + f"medium confidence {conf:.2f}; {count}/{th['repeat_count']} repeated detections, awaiting evidence"}
        return {**base, "assessment": "low", "actionable": False,
                "reason": tag + f"confidence {conf:.2f} below {th['medium_confidence']}; recorded and monitored"}

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
            mgr.remove(name)
        except DecoyError as e:
            log.error("remove %s failed: %s", name, e)
            return "failed"
        row = c.execute("SELECT * FROM decoys WHERE name = ? AND status IN ('deploying', 'active')", (name,)).fetchone()
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
                if k["ready_replicas"] >= 1:
                    secs = (now - parse(r["created_at"])).total_seconds()
                    db.update_row(c, "decoys", r["id"], status="active", ready_at=iso(now), deploy_seconds=secs)
                    out["ready"].append(r["name"])
                elif (now - parse(r["created_at"])).total_seconds() > self.d["deploy_timeout_seconds"]:
                    mgr.remove(r["name"])
                    db.update_row(c, "decoys", r["id"], status="failed", removed_at=iso(now), error="readiness timeout")
                    continue
            out["interactions"] += self._collect_for(c, r["name"])

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
                    assessments = self.analyze(c, ev)
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
            res = self.remove_decoy(c, name, "removed", None, "manual", "manual removal from dashboard/API")
            return {"name": name, "result": res}

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
        return {
            "enabled": self.enabled, "stage": self.stage, "loop_running": bool(self._thread and self._thread.is_alive()),
            "kubernetes_available": self.manager is not None, "kubernetes_error": self.manager_error,
            "last_cycle": json.loads(last) if last else None,
            "active_decoys": decoys.astype(object).where(decoys.notna(), None).to_dict(orient="records"),
            "limits": {k: self.d[k] for k in ("max_active_decoys", "max_replicas", "decoy_ttl_seconds",
                                               "cooldown_seconds", "redeploy_cooldown_seconds")},
            "thresholds": self.d["thresholds"],
        }
