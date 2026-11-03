"""Check every dashboard API endpoint before you open the UI.

    python scripts/check_api.py            # in-process, no server needed
    python scripts/check_api.py --live     # also launches a real port_scan run (needs the cluster)

Prints one line per endpoint: OK / WARN (works, but something is not ready) / FAIL.
Exit code 1 if anything FAILs.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
os.chdir(REPO / "dashboard")
sys.path.insert(0, str(REPO / "dashboard"))
sys.path.insert(0, str(REPO))

G, Y, R, D = "\033[32m", "\033[33m", "\033[31m", "\033[0m"
if not sys.stdout.isatty():
    G = Y = R = D = ""
results: list[tuple[str, str, str]] = []


def line(status: str, name: str, detail: str = "") -> None:
    c = {"OK": G, "WARN": Y, "FAIL": R}[status]
    print(f"  {c}{status:<4}{D}  {name:<42} {detail[:110]}")
    results.append((status, name, detail))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="also launch a real port_scan run")
    args = ap.parse_args()

    print("\n== Python packages")
    missing = []
    for mod in ("fastapi", "uvicorn", "pandas", "sklearn", "joblib", "yaml", "kubernetes", "multipart"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    line("FAIL" if missing else "OK", "required packages", f"missing: {missing} -> pip install -r requirements.txt" if missing else "all installed")
    if missing:
        return 1

    import logging, warnings
    warnings.filterwarnings("ignore")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    from fastapi.testclient import TestClient
    import app as dash

    print("\n== Dashboard app")
    if not dash.LIVE_ENABLED:
        line("FAIL", "live features loaded", dash._LIVE_IMPORT_ERROR)
        return 1
    line("OK", "live features loaded")
    c = TestClient(dash.app)

    def get(path, name=None, warn_if=None):
        name = name or "GET " + path
        try:
            r = c.get(path)
        except Exception as e:
            line("FAIL", name, f"{type(e).__name__}: {e}")
            return None
        if r.status_code != 200:
            line("FAIL", name, f"HTTP {r.status_code}: {r.text[:100]}")
            return None
        body = r.json() if "json" in r.headers.get("content-type", "") else r.text
        msg = warn_if(body) if warn_if else None
        line("WARN" if msg else "OK", name, msg or "200")
        return body

    print("\n== Pages & model")
    get("/", "GET / (dashboard page)")
    get("/scorer", "GET /scorer (CSV scorer page)")
    get("/api/features")
    get("/api/metrics")
    get("/api/demo", "GET /api/demo (score bundled sample)")

    print("\n== Cluster & target pods")
    tg = get("/api/targets", warn_if=lambda b: None if b["all_running"] else
             (b.get("error") or ", ".join(f"{a['key']}={a['state']}" for a in b["apps"])))
    if tg and tg.get("connected"):
        for a in tg["apps"]:
            pod = a["pods"][0]["name"] if a["pods"] else "-"
            line("OK" if a["state"] == "running" else "FAIL", f"  pod {a['key']}", f"{a['state']} ({pod})")
    get("/api/kubernetes/status", warn_if=lambda b: None if b.get("connected") else b.get("error"))

    print("\n== Live pipeline")
    pre = get("/api/pipeline/preflight", warn_if=lambda b: None if b["can_generate"] else "cannot generate traffic yet")
    if pre:
        for s in pre["steps"]:
            line("OK" if s["ok"] else "WARN", "  " + s["label"], (s.get("detail") or "") + (f"  FIX: {s['fix']}" if s.get("fix") else ""))
    get("/api/live/capture/status", warn_if=lambda b: None if b["support"]["supported"] else b["support"]["reason"])
    for p in ("/api/live/metrics", "/api/live/stats", "/api/live/detections?limit=5", "/api/live/bursts?limit=5",
              "/api/live/captures?limit=5", "/api/pipeline/status"):
        get(p)

    print("\n== Traffic generator")
    get("/api/trafficlab/scenarios")
    get("/api/trafficlab/jobs", warn_if=lambda b: b[0]["error"] if b and "error" in b[0] else None)

    print("\n== Deception")
    for p in ("/api/deception/status", "/api/deception/policy", "/api/deception/decisions?limit=5",
              "/api/deception/decoys?limit=5", "/api/deception/interactions?limit=5", "/api/deception/test-events?limit=5"):
        get(p)

    if args.live:
        print("\n== Real run: port_scan with auto-capture")
        r = c.post("/api/pipeline/run", json={"scenario": "port_scan", "count": 200})
        line("OK" if r.status_code == 200 else "FAIL", "POST /api/pipeline/run", r.text[:160])

    fails = sum(s == "FAIL" for s, _, _ in results)
    warns = sum(s == "WARN" for s, _, _ in results)
    print(f"\n{len(results)} checks: {len(results) - fails - warns} OK, {warns} WARN, {fails} FAIL\n")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
