"""Regression tests for the follow-up fixes (no cluster needed):
ARP parsing, control-plane allowlist, window-boundary context, generator time budget and
exit codes, Job failure reasons, multi-Job runs, auto-stop, Overview activity buckets."""
import json
import os
import struct
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as NS

import pandas as pd

from live import allowlist, db, flowcontext, pipeline, queries
from live.behavior import flow_bursts
from live.schema import drop_non_ip_flows
from live.trafficlab import failure_reason

REPO = Path(__file__).resolve().parents[1]


# --- 1. ARP rows ---------------------------------------------------------------------------
def test_arp_rows_are_dropped():
    df = pd.DataFrame({"Src IP": ["8.6.0.1", "10.42.0.5"], "Dst IP": ["8.0.6.4", "10.42.0.6"],
                       "Protocol": [0, 6], "Flow Duration": [0, 5]})
    out, dropped = drop_non_ip_flows(df)
    assert dropped == 1 and list(out["Src IP"]) == ["10.42.0.5"]
    # CIC MachineLearningCVE CSVs have no address columns: untouched
    assert drop_non_ip_flows(pd.DataFrame({"Flow Duration": [1]}))[1] == 0


def test_capture_filter_is_ipv4_only(cfg):
    assert cfg["capture"]["bpf_filter"] == "ip"


# --- 2. control-plane allowlist ---------------------------------------------------------------
def _pred(rows):
    base = {"src_port": 40000, "protocol": 6, "predicted_class": "DoS", "confidence": 0.52, "is_malicious": True}
    return pd.DataFrame([{**base, **r} for r in rows])


def test_api_server_flows_are_allowlisted_not_malicious():
    al = allowlist.Allowlist(ips={"10.43.0.1": "API server Service", "10.42.0.2": "kube-system pod (kube-dns)"})
    out = al.apply(_pred([
        {"src_ip": "10.42.0.26", "dst_ip": "172.27.149.160", "dst_port": 6443},   # pod -> API server
        {"src_ip": "10.43.0.1", "dst_ip": "10.42.0.26", "src_port": 443, "dst_port": 36628},
        {"src_ip": "10.42.0.9", "dst_ip": "10.42.0.2", "dst_port": 53},
        {"src_ip": "10.42.0.9", "dst_ip": "10.42.0.30", "dst_port": 1880},          # a real lab flow
    ]))
    assert list(out["is_malicious"]) == [False, False, False, True]
    assert out["allowlisted"].iloc[0] == "control-plane port 6443"
    assert out["predicted_class"].iloc[0] == "DoS"          # prediction kept for transparency


def test_allowlisted_flows_never_form_bursts(cfg):
    rows = [{"src_ip": "10.42.0.26", "dst_ip": "172.27.0.1", "dst_port": 6443, "is_malicious": False,
             "allowlisted": "control-plane port 6443"} for _ in range(50)]
    assert flow_bursts(_pred(rows), 5.0, cfg).empty


# --- 3. window-boundary context ------------------------------------------------------------
def _pcap(path: Path, times: list[float]):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t in times:
            frame = b"\x00" * 60
            fh.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(frame), len(frame)) + frame)


def test_context_files_and_concat(tmp_path):
    t = 1_800_000_000.0
    for i, name in enumerate(["win_cni0_20260101T000000_1.pcap", "win_cni0_20260101T000005_1.pcap",
                              "win_cni0_20260101T000030_1.pcap", "win_cni0_20260101T000035_1.pcap"]):
        _pcap(tmp_path / name, [t + [0, 5, 30, 35][i], t + [0, 5, 30, 35][i] + 1])
    cur = tmp_path / "win_cni0_20260101T000035_1.pcap"
    ctx = flowcontext.context_files(cur, 20)
    assert [p.name for p in ctx] == ["win_cni0_20260101T000030_1.pcap"]      # 30 s ago is outside 20 s
    out = tmp_path / "merged.pcap"
    assert flowcontext.concat_pcaps(ctx + [cur], out) == 2
    assert out.stat().st_size == 24 + 4 * (16 + 60)
    assert flowcontext.first_packet_time(out) == t + 30


def test_keep_only_flows_active_in_current_window():
    start = datetime(2026, 1, 1, 12, 0, 10).timestamp()
    df = pd.DataFrame({"Timestamp": ["2026-01-01 12:00:01", "2026-01-01 12:00:02", "2026-01-01 12:00:11"],
                       "Flow Duration": [2_000_000, 9_500_000, 100]})   # ends 12:00:03, 12:00:11.5, 12:00:11
    kept, dropped = flowcontext.keep_active_flows(df, start)
    assert dropped == 1 and len(kept) == 2


# --- 1. generator: time budget + exit code -------------------------------------------------
def _gen(env):
    e = {**os.environ, "PYTHONUNBUFFERED": "1", **env}
    p = subprocess.run([sys.executable, str(REPO / "deploy" / "traffic-lab" / "traffic_generator.py")],
                       env=e, capture_output=True, text=True, timeout=60)
    return p.returncode, [json.loads(x) for x in p.stdout.splitlines() if x.startswith("{")]


def test_generator_fails_with_reason_when_nothing_answers():
    rc, recs = _gen({"MODE": "web_attack", "TARGET": "127.0.0.1:1", "COUNT": "3", "DELAY": "0"})
    assert rc == 2 and recs[-1]["action"] == "fatal" and "no request was answered" in recs[-1]["error"]


def test_generator_stops_at_time_budget_instead_of_being_killed():
    rc, recs = _gen({"MODE": "port_scan", "TARGET": "127.0.0.1:1", "PORT_START": "1", "PORT_END": "60000",
                     "DELAY": "0.05", "TIME_BUDGET_S": "1"})
    acts = [r["action"] for r in recs]
    assert "budget_exhausted" in acts and acts[-1] in ("done", "fatal")
    assert rc == 0                                      # refused ports are answers: partial run, not a failure


# --- 1. Job failure reason ------------------------------------------------------------------
def _job(reason, failed=1):
    cond = NS(type="Failed", status="True", reason=reason, message="Job was active longer than specified deadline",
              last_transition_time=None)
    return NS(status=NS(failed=failed, conditions=[cond]), spec=NS(active_deadline_seconds=300))


def test_failure_reason_deadline_without_pod():
    f = failure_reason(_job("DeadlineExceeded"), pods=[], log_lines=[])
    assert f["job_reason"] == "DeadlineExceeded" and "time limit" in f["summary"] and "deleted" in f["summary"]


def test_failure_reason_exit_code_and_log():
    term = NS(exit_code=2, reason="Error", message=None)
    pod = NS(status=NS(container_statuses=[NS(state=NS(terminated=term), last_state=None)]))
    log = [json.dumps({"action": "http", "error": "URLError"}),
           json.dumps({"action": "fatal", "error": "no request was answered by the target"})]
    f = failure_reason(_job("BackoffLimitExceeded"), [pod], log)
    assert f["exit_code"] == 2 and "exit code 2" in f["summary"] and "no request was answered" in f["summary"]
    assert failure_reason(NS(status=NS(failed=0, conditions=[])), [], []) is None


# --- 3. multi-select run + auto-stop --------------------------------------------------------
def test_multi_select_launches_one_job_per_attack_and_target(cfg, monkeypatch):
    launched = []
    monkeypatch.setattr(pipeline.cap, "read_state", lambda c=None: {"running": True})
    monkeypatch.setattr(pipeline, "launch", lambda sc, tgt, count, delay, cfg, run_id=None:
                        launched.append((sc, tgt, run_id)) or {"job": f"j-{len(launched)}", "target": f"{tgt}:1",
                                                               "target_label": tgt, "expect_class": "X"})
    run = pipeline.run_scenarios(["port_scan", "web_attack", "decoy_probe"], ["nodered", "grafana"],
                                 auto_stop=False, cfg=cfg)
    assert len(run["jobs"]) == 5                      # 2 attacks x 2 targets + decoy_probe once
    assert {(s, t) for s, t, _ in launched} >= {("port_scan", "nodered"), ("web_attack", "grafana"), ("decoy_probe", None)}
    assert len({r for _, _, r in launched}) == 1      # all share the run id


def test_auto_stop_stops_capture_after_jobs_finish(cfg, monkeypatch):
    cfg = {**cfg, "traffic_lab": {**cfg["traffic_lab"], "auto_stop_drain_seconds": 0},
           "capture": {**cfg["capture"], "window": {**cfg["capture"]["window"], "sizes": [0]}}}
    stopped = []
    monkeypatch.setattr(pipeline.cap, "read_state", lambda c=None: {"running": True})
    monkeypatch.setattr(pipeline.cap, "stop", lambda c=None: stopped.append(1) or {})
    monkeypatch.setattr(pipeline, "launch", lambda *a, **k: {"job": "j1", "target": "t:1", "target_label": "nodered"})
    monkeypatch.setattr(pipeline, "list_jobs", lambda c=None: [{"name": "j1", "state": "failed"}])
    monkeypatch.setattr(pipeline, "job_detail", lambda *a, **k: {"pods": []})
    run = pipeline.run_scenarios(["web_attack"], ["nodered"], auto_stop=False, cfg=cfg)
    pipeline._update_run(run["id"], cfg, auto_stop={"enabled": True, "state": "waiting for Jobs"})
    pipeline._watch(run["id"], cfg, poll_s=0.01)
    assert stopped == [1]
    with db.connect(db.db_path(cfg)) as c:
        r = pipeline._runs(c)[0]
    assert r["auto_stop"]["state"] == "stopped" and r.get("finished_at")


def test_manual_stop_cancels_pending_auto_stop(cfg, monkeypatch):
    monkeypatch.setattr(pipeline.cap, "read_state", lambda c=None: {"running": True})
    monkeypatch.setattr(pipeline, "launch", lambda *a, **k: {"job": "j1", "target": "t:1"})
    run = pipeline.run_scenarios(["benign"], None, auto_stop=False, cfg=cfg)
    pipeline._update_run(run["id"], cfg, auto_stop={"enabled": True, "state": "draining"})
    pipeline.cancel_auto_stop(cfg)
    with db.connect(db.db_path(cfg)) as c:
        assert pipeline._runs(c)[0]["auto_stop"]["enabled"] is False


# --- 2. expected vs predicted ------------------------------------------------------------------
def test_breakdown_counts_flows_of_the_generator_pod(cfg):
    now = datetime.now(timezone.utc).isoformat()
    with db.connect(db.db_path(cfg)) as c:
        for cls, n in (("BENIGN", 8), ("PortScan", 2)):
            for _ in range(n):
                db.insert_row(c, "detections", predicted_class=cls, confidence=0.9, is_malicious=int(cls != "BENIGN"),
                              source="pcap", detected_at=now, src_ip="10.42.0.77", dst_ip="10.42.0.5", model="m")
        b = pipeline._breakdown(c, {"pod_ip": "10.42.0.77", "expect_class": "PortScan"},
                                (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(), None)
    assert b["flows"] == 10 and b["matched"] == 2 and b["accuracy"] == 0.2


# --- 5. Overview activity buckets ---------------------------------------------------------------
def test_activity_buckets_mark_capture_off(cfg):
    now = datetime.now(timezone.utc)
    with db.connect(db.db_path(cfg)) as c:
        cid = db.upsert_capture(c, "w1.pcap", started_at=(now - timedelta(seconds=400)).isoformat(),
                                ended_at=(now - timedelta(seconds=395)).isoformat(), packets=10, status="classified")
        db.insert_row(c, "detections", capture_id=cid, predicted_class="DoS", confidence=0.9, is_malicious=1,
                      source="pcap", detected_at=now.isoformat(), src_ip="10.42.0.9", dst_ip="10.42.0.5", model="m")
    a = queries.activity(minutes=10, bucket_s=30, cfg=cfg)
    assert a["bucket_seconds"] == 30 and len(a["buckets"]) >= 20
    on = [b for b in a["buckets"] if b["capture_on"]]
    assert len(on) == 1 and on[0]["malicious"] == 1
    assert sum(b["capture_on"] is False for b in a["buckets"]) >= 15
    assert a["events"][0]["predicted_class"] == "DoS"


# --- scenario tags, generator redirect ---------------------------------------------
def test_lab_scenario_tags_prefer_running_pod_on_ip_reuse():
    from datetime import datetime, timezone
    from types import SimpleNamespace as NS
    import pandas as pd
    from live import labsources

    def pod(name, ip, phase, scen, job, t):
        return NS(metadata=NS(name=name, labels={"app": "traffic-lab", "scenario": scen, "job-name": job}),
                  status=NS(pod_ip=ip, phase=phase, start_time=datetime(2026, 1, 1, 0, t, tzinfo=timezone.utc)))
    m = labsources.build_map([pod("a", "10.42.0.5", "Succeeded", "port-scan", "traffic-port-scan-x", 1),
                              pod("b", "10.42.0.5", "Running", "web-attack", "traffic-web-attack-y", 0),
                              pod("c", "10.42.0.6", "Succeeded", "brute-force", "traffic-brute-force-z", 2)])
    assert m["10.42.0.5"]["scenario"] == "web_attack"
    pred = pd.DataFrame({"src_ip": ["10.42.0.5", "10.43.0.9", "1.2.3.4"],
                         "dst_ip": ["10.43.0.9", "10.42.0.6", "5.6.7.8"]})
    out = labsources.tag(pred, m)
    assert list(out["lab_scenario"]) == ["web_attack", "brute_force", None]
    assert out["lab_job"][1] == "traffic-brute-force-z"


def test_build_job_mounts_annotations_for_redirect(cfg):
    from live.trafficlab import build_job
    j = build_job("port_scan", cfg, target="10.42.0.7:1880")
    spec = j["spec"]["template"]["spec"]
    vol = next(v for v in spec["volumes"] if v["name"] == "podinfo")
    assert vol["downwardAPI"]["items"][0]["fieldRef"]["fieldPath"] == "metadata.annotations"
    env = {e["name"]: e["value"] for e in spec["containers"][0]["env"]}
    assert env["REDIRECT_FILE"] == "/etc/podinfo/annotations"


def test_generator_follows_redirect_annotation(tmp_path, monkeypatch, capsys):
    import importlib.util
    from pathlib import Path
    f = tmp_path / "annotations"
    f.write_text('ids/other="x"\n')
    monkeypatch.setenv("REDIRECT_FILE", str(f))
    src = Path(__file__).resolve().parents[1] / "deploy" / "traffic-lab" / "traffic_generator.py"
    spec = importlib.util.spec_from_file_location("tg_redirect", src)
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    assert g.aim("nodered.target-apps.svc.cluster.local", 1880) == ("nodered.target-apps.svc.cluster.local", 1880)
    f.write_text('ids/other="x"\nids-deception/redirect-to="decoy-nodered.ids-deception.svc.cluster.local:1880"\n')
    g._REDIRECT["checked"] = 0.0
    assert g.aim("10.42.0.9", 22) == ("decoy-nodered.ids-deception.svc.cluster.local", 1880)
    assert g.aim_url("http://grafana.target-apps.svc.cluster.local:3000") == \
        "http://decoy-nodered.ids-deception.svc.cluster.local:1880"
    assert '"action": "redirected"' in capsys.readouterr().out


def test_window_grows_when_scoring_falls_behind_and_never_shrinks_below_it(cfg):
    from live.window import Evidence, decide
    w = cfg["capture"]["window"]
    d = decide(1, Evidence(packets=900, duration_s=1, processing_s=2.1, backlog=5), w)
    assert d.rule == "R0_backlog" and d.next_s == 3
    d = decide(3, Evidence(packets=900, duration_s=3, processing_s=2.1, bursts=1), w)   # threat, but can't go below 3
    assert d.next_s == 3
    d = decide(3, Evidence(packets=3000, duration_s=3, processing_s=2.1), w)            # high rate: hold at 3
    assert d.next_s == 3
    d = decide(3, Evidence(packets=3000, duration_s=3, processing_s=0.4), w)            # fast scoring: may shrink
    assert d.next_s == 1


def test_parse_timestamps_iso_is_not_day_swapped():
    import pandas as pd
    from live.schema import parse_timestamps
    got = parse_timestamps(pd.Series(["2026-11-05 11:00:12.836503", "30/10/2026 12:19:24 PM", "05/11/2026 11:00:12 AM"]))
    assert [str(t.date()) for t in got] == ["2026-11-05", "2026-10-30", "2026-11-05"]


def test_predictor_falls_back_when_live_model_missing(cfg, tmp_path):
    import copy
    from live.predictor import FlowPredictor
    c = copy.deepcopy(cfg)
    c["paths"]["model_dir"] = str(tmp_path / "missing")
    p = FlowPredictor.from_config(c)
    assert p.name == Path(c["paths"]["fallback_model_dir"]).name


def test_allowlist_discovers_node_bridge_for_kubelet_probes(monkeypatch):
    from live import allowlist as al
    node = NS(metadata=NS(name="vm"), spec=NS(pod_cidrs=["10.42.0.0/24"], pod_cidr="10.42.0.0/24"))
    core = NS(read_namespaced_service=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")),
              list_namespaced_pod=lambda *a, **k: NS(items=[]), list_namespaced_service=lambda *a, **k: NS(items=[]),
              list_node=lambda **k: NS(items=[node]))
    import kubernetes.client
    monkeypatch.setattr(kubernetes.client, "CoreV1Api", lambda api: core)
    import live.kube
    monkeypatch.setattr(live.kube, "api_client", lambda cfg: (None, "test"))
    ips, _ = al._discover({})
    assert "bridge" in ips["10.42.0.1"]
    a = al.Allowlist(ips=ips)
    assert a.reason("10.42.0.1", "10.42.0.157", 50320, 8081)      # probe to a decoy: never an attack
    assert a.reason("10.42.0.156", "10.42.0.138", 40000, 8086) is None
