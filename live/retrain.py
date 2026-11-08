"""Retrain the live model on THIS lab's own labelled runs (dashboard button).

Runs scripts/train_lab_model.py in a background process with a fixed argument list
(only integers chosen here, nothing from the request), so the model learns the flows
that this machine's CICFlowMeter produces. Before it overwrites the live model, the
current best_model.joblib / metrics.json are copied to <model_dir>/history/<time>/,
so no trained model is ever lost.

Held-out test: per class (scripts/train_lab_model.py split_per_class), so every class
with data is in the test set. The new model replaces the live one only if no class's
recall drops and at least one improves on the same held-out flows; otherwise it is
saved to <model_dir>/candidate/ and the live model stays.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
from datetime import datetime, timezone
from typing import Any

from live import db
from live.config import get_path, load_config, repo_path
from live.logging_setup import get_logger

log = get_logger(__name__)
_STATE: dict[str, Any] = {"state": "idle", "started_at": None, "finished_at": None, "log": "", "error": None,
                          "test_sessions": [], "backup": None}
_LOCK = threading.Lock()
SCRIPT = repo_path("scripts/train_lab_model.py")


def labelled_sessions(cfg: dict[str, Any]) -> dict[int, list[str]]:
    with db.connect(db.db_path(cfg)) as c:
        row = c.execute("SELECT value FROM kv WHERE key = 'pipeline_runs'").fetchone()
    out: dict[int, list[str]] = {}
    for r in json.loads(row[0]) if row else []:
        if r.get("session_id"):
            out.setdefault(int(r["session_id"]), []).extend(j["scenario"] for j in r.get("jobs", []) if j.get("pod_ip"))
    return {k: v for k, v in out.items() if v}


def choose_test_sessions(sessions: dict[int, list[str]]) -> list[int]:
    attack = {"port_scan", "brute_force", "web_attack", "slow_dos"}
    by: dict[str, list[int]] = {}
    for sid, scs in sessions.items():
        if len(set(scs)) == 1 and scs[0] in attack | {"benign"}:      # single-scenario sessions only
            by.setdefault(scs[0], []).append(sid)
    return sorted(max(ids) for sc, ids in by.items() if len(ids) >= 2)


def status() -> dict[str, Any]:
    with _LOCK:
        return dict(_STATE)


def start(cfg: dict[str, Any] | None = None, on_done=None) -> dict[str, Any]:
    cfg = cfg or load_config()
    with _LOCK:
        if _STATE["state"] == "running":
            raise RuntimeError("a retraining is already running")
        sessions = labelled_sessions(cfg)
        attack = {s for v in sessions.values() for s in v} & {"port_scan", "brute_force", "web_attack", "slow_dos"}
        if not attack:
            raise RuntimeError("no labelled attack runs yet: run the attack scenarios from the Traffic lab first")
        test: list[int] = []           # the script holds out per class (every class is tested)
        model_dir = get_path("local_model_dir", cfg) if cfg["paths"].get("local_model_dir") else get_path("model_dir", cfg)
        # the model that is live now: the new one replaces it only if per-class recall improves
        current = model_dir if (model_dir / "best_model.joblib").is_file() else get_path("model_dir", cfg)
        _STATE.update(state="running", started_at=datetime.now(timezone.utc).isoformat(), finished_at=None,
                      log="", error=None, test_sessions=test, backup=None, sessions=len(sessions),
                      scenarios=sorted({s for v in sessions.values() for s in v}))

    def work():
        backup = None
        try:
            if (model_dir / "best_model.joblib").is_file():
                backup = model_dir / "history" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                backup.mkdir(parents=True, exist_ok=True)
                for f in ("best_model.joblib", "metrics.json"):
                    if (model_dir / f).is_file():
                        shutil.copy2(model_dir / f, backup / f)
            argv = [sys.executable, str(SCRIPT), "--out", str(model_dir),
                    "--sample-out", str(model_dir / "sample_test_mix.csv")]
            argv += ["--compare", str(current)]
            cic = repo_path("data/cic-ids2017/merged.csv")
            if cic.is_file():               # add CIC-IDS2017 rows of the same classes to training
                argv += ["--cic-csv", str(cic)]
            p = subprocess.run(argv, capture_output=True, text=True, timeout=1800, cwd=str(repo_path(".")))
            text = (p.stdout + p.stderr)[-6000:]
            with _LOCK:
                _STATE.update(log=text, backup=str(backup) if backup else None)
            if p.returncode != 0:
                raise RuntimeError(f"training exited with {p.returncode}")
            cand = model_dir / "candidate" / "metrics.json"
            live_m = model_dir / "metrics.json"
            mp = cand if cand.is_file() and (not live_m.is_file() or cand.stat().st_mtime > live_m.stat().st_mtime) else live_m
            metrics = json.loads(mp.read_text())
            res = (metrics.get("models") or {}).get("RandomForest") or {}
            prev = ((metrics.get("previous_model") or {}).get("on_same_test") or {})
            with _LOCK:
                _STATE.update(state="done", result={k: res.get(k) for k in ("accuracy", "macro_f1", "attack_detection_rate",
                                                                             "false_alarm_rate", "per_class")},
                              previous={k: prev.get(k) for k in ("macro_f1", "per_class")} if prev else None,
                              replaced=bool(metrics.get("replaced", True)), decision=metrics.get("decision"),
                              warnings=metrics.get("warnings") or [],
                              train_counts=(metrics.get("split_counts") or {}).get("train"),
                              test_counts=(metrics.get("split_counts") or {}).get("test"))
            if on_done and metrics.get("replaced", True):
                on_done()
            log.info("lab model retrained (test sessions %s)", test)
        except Exception as e:  # noqa: BLE001
            log.exception("retraining failed")
            with _LOCK:
                _STATE.update(state="failed", error=str(e)[:500], backup=str(backup) if backup else None)
        finally:
            with _LOCK:
                _STATE["finished_at"] = datetime.now(timezone.utc).isoformat()

    threading.Thread(target=work, name="retrain-lab", daemon=True).start()
    return status()
