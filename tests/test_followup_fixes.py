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
import pytest

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
    monkeypatch.setattr(pipeline, "launch", lambda sc, tgt, count, delay, cfg, run_id=None, params=None:
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


# --- node-specific deception, threat counter ---------------------------------------
def test_generator_redirects_only_connections_to_the_attacked_pod(tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path
    f = tmp_path / "annotations"
    f.write_text('ids-deception/redirect-to="decoy-web-portal-vm.ids-deception.svc.cluster.local:80"\n'
                 'ids-deception/redirect-only="10.42.0.138,influxdb,influxdb.target-apps.svc.cluster.local,10.43.0.20"\n')
    monkeypatch.setenv("REDIRECT_FILE", str(f))
    src = Path(__file__).resolve().parents[1] / "deploy" / "traffic-lab" / "traffic_generator.py"
    spec = importlib.util.spec_from_file_location("tg_only", src)
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    monkeypatch.setattr(g.socket, "gethostbyname", lambda h: {"grafana.target-apps.svc.cluster.local": "10.43.0.30"}.get(h, "0.0.0.0"))
    decoy = ("decoy-web-portal-vm.ids-deception.svc.cluster.local", 80)
    assert g.aim("influxdb.target-apps.svc.cluster.local", 8086) == decoy          # the attacked pod
    assert g.aim("10.42.0.138", 8086) == decoy
    assert g.aim("grafana.target-apps.svc.cluster.local", 3000) == ("grafana.target-apps.svc.cluster.local", 3000)
    assert g.aim_url("http://grafana.target-apps.svc.cluster.local:3000") == "http://grafana.target-apps.svc.cluster.local:3000"


def test_decoy_is_rendered_on_the_attacked_node(cfg, monkeypatch):
    from live import k8s_decoys
    assert k8s_decoys.decoy_name("web-portal", "worker-2.lab") == "decoy-web-portal-worker-2-lab"
    assert k8s_decoys.decoy_name("web-portal") == "decoy-web-portal"
    m = k8s_decoys.DecoyManager.__new__(k8s_decoys.DecoyManager)
    d = cfg["deception"]
    m.profiles, m.max_replicas = d["profiles"], int(d["max_replicas"])
    m.template = (Path(__file__).resolve().parents[1] / d["template"]).read_text()
    dep, svc = m.render("web-portal", 1, "worker-2.lab")
    assert dep["metadata"]["name"] == svc["metadata"]["name"] == "decoy-web-portal-worker-2-lab"
    assert dep["spec"]["template"]["spec"]["nodeSelector"] == {"kubernetes.io/hostname": "worker-2.lab"}
    dep, _ = m.render("web-portal", 1)
    assert "nodeSelector" not in dep["spec"]["template"]["spec"]


def test_engagement_targets_the_attacked_pod_and_its_node(cfg, monkeypatch):
    from live import podinfo
    from live.controller import MapeKController
    pods = podinfo.build(
        [NS(metadata=NS(name="influxdb-1", namespace="target-apps", labels={"app": "influxdb"}, creation_timestamp=None),
            spec=NS(node_name="worker-2"), status=NS(pod_ip="10.43.0.5", phase="Running")),
         NS(metadata=NS(name="traffic-port-scan-x", namespace="ids-traffic", labels={"app": "traffic-lab"}, creation_timestamp=None),
            spec=NS(node_name="worker-1"), status=NS(pod_ip="10.42.0.9", phase="Running"))],
        [NS(metadata=NS(name="influxdb", namespace="target-apps"),
            spec=NS(selector={"app": "influxdb"}, cluster_ip="10.43.9.9", ports=[NS(port=8086)]))])
    podinfo._CACHE.update(at=float("inf"), value=pods, error=None)

    class Mgr:
        def __init__(self): self.calls = []
        def deploy(self, profile, replicas, node=None):
            self.calls.append((profile, node)); return {"port": 80, "service_ip": "10.0.0.1"}
        def list_decoys(self): return {}
        def interaction_lines(self, name, since): return []
        def remove(self, name): return True

    class Red:
        def __init__(self): self.only = None
        def quarantine(self, ip, cfg, redirect_to=None, only=None):
            self.only = only; return {"applied": True, "namespace": "ids-traffic", "pod": "p", "to": redirect_to, "reason": "ok"}

    mgr, red = Mgr(), Red()
    ctl = MapeKController(cfg, manager=mgr)
    ctl.redirector = red
    ctl.set_enabled(True)
    with db.connect(cfg["paths"]["database"]) as c:
        for _ in range(ctl.class_policy("PortScan")["min_flows"]):
            db.insert_row(c, "detections", predicted_class="PortScan", confidence=0.99, is_malicious=1, source="live",
                          detected_at=datetime.now(timezone.utc).isoformat(), src_ip="10.42.0.9", dst_ip="10.43.0.5",
                          dst_port=8086, protocol=6, model="m")
    ctl.run_cycle()
    e = ctl.engagements()[0]
    assert e["node"] == "worker-2" and e["target"]["pod"] == "influxdb-1" and e["attacker"]["node"] == "worker-1"
    assert mgr.calls and all(n == "worker-2" for _, n in mgr.calls)          # decoys on the attacked node
    assert all(n.endswith("-worker-2") for n in e["decoys"])
    # decoy becomes Ready -> redirect limited to the attacked pod and its Service
    mgr.list_decoys = lambda: {n: {"ready_replicas": 1, "endpoints": 1} for n in e["decoys"]}
    ctl.run_cycle()
    assert set(red.only) >= {"10.43.0.5", "influxdb", "influxdb.target-apps.svc.cluster.local", "10.43.9.9"}
    det = ctl.engagement_details()["engagements"][0]
    assert det["traffic"]["decoy_flows"] == 0 and det["target"]["node"] == "worker-2"


def test_threat_counter_shows_current_run_then_clears(cfg):
    now = datetime.now(timezone.utc)
    with db.connect(cfg["paths"]["database"]) as c:
        for cls, sess, mal in (("PortScan", 1, 1), ("PortScan", 2, 1), ("WebAttack", 2, 1), ("BENIGN", 2, 0)):
            db.insert_row(c, "detections", predicted_class=cls, confidence=0.9, is_malicious=mal, source="live",
                          detected_at=now.isoformat(), session_id=sess, src_ip="10.42.0.9", model="m")
        run = {"id": "r2", "started_at": (now - timedelta(seconds=30)).isoformat(), "scenario": "port_scan",
               "session_id": 2, "auto_stop": {"enabled": True, "state": "waiting for Jobs"}, "jobs": []}
        db.kv_set(c, "pipeline_runs", json.dumps([run]))
    t = queries.threat_counter(cfg)
    assert t["run"]["malicious"] == 2 and t["run"]["by_class"] == {"PortScan": 1, "WebAttack": 1}
    assert t["total"]["malicious"] == 3 and t["total"]["by_class"]["PortScan"] == 2
    run["auto_stop"] = {"enabled": True, "state": "stopped"}
    with db.connect(cfg["paths"]["database"]) as c:
        db.kv_set(c, "pipeline_runs", json.dumps([run]))
    t = queries.threat_counter(cfg)
    assert t["run"] is None and t["total"]["malicious"] == 3


# --- severity engagement, generator params, detection matrix, flow graph ------------
def test_generator_params_are_validated_and_become_env(cfg):
    from live import trafficlab
    job = trafficlab.build_job("brute_force", cfg, "grafana.target-apps.svc.cluster.local:3000",
                               params={"concurrency": 4, "minutes": 3, "target_port": 8080, "login_path": "/api/login"})
    env = {e["name"]: e["value"] for e in job["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["CONCURRENCY"] == "4" and env["RUN_SECONDS"] == "180" and env["TIME_BUDGET_S"] == "180"
    assert env["LOGIN_PATH"] == "/api/login"
    # the Job's time limit follows the chosen minutes (+ start margin), so it never fails on it
    assert job["spec"]["activeDeadlineSeconds"] == 180 + cfg["traffic_lab"]["job_start_margin_seconds"]
    assert env["TARGET"] == "grafana.target-apps.svc.cluster.local:8080"
    assert [e["name"] for e in job["spec"]["template"]["spec"]["containers"][0]["env"]].count("LOGIN_PATH") == 1
    for bad in ({"concurrency": 99}, {"login_path": "/x; rm -rf /"}, {"payload_set": "evil"}, {"nope": 1},
                {"port_start": 900, "port_end": 10}):
        with pytest.raises(trafficlab.TrafficLabError):
            trafficlab.check_params(bad)


def test_detection_matrix_uses_job_pods_as_ground_truth(cfg):
    now = datetime.now(timezone.utc).isoformat()
    with db.connect(cfg["paths"]["database"]) as c:
        for cls, n in (("BruteForce", 8), ("BENIGN", 2)):
            for _ in range(n):
                db.insert_row(c, "detections", predicted_class=cls, confidence=0.9, is_malicious=int(cls != "BENIGN"),
                              source="live", detected_at=now, session_id=5, src_ip="10.42.0.50", dst_ip="10.42.0.7",
                              src_port=40000, dst_port=3000, lab_scenario="brute_force", model="k8s-lab-live")
        db.insert_row(c, "detections", predicted_class="BENIGN", confidence=0.9, is_malicious=0, source="live",
                      detected_at=now, session_id=5, src_ip="10.42.0.50", dst_ip="10.43.0.10", src_port=5353,
                      dst_port=53, lab_scenario="brute_force", model="k8s-lab-live")          # DNS: left out
        db.kv_set(c, "pipeline_runs", json.dumps([{"id": "r", "started_at": now, "session_id": 5, "jobs": [
            {"scenario": "brute_force", "pod_ip": "10.42.0.50", "expect_class": "BruteForce",
             "target_label": "grafana", "target": "grafana.target-apps.svc.cluster.local:3000"}]}]))
    m = queries.detection_matrix(cfg)["cells"]
    assert len(m) == 1 and m[0]["target"] == "grafana" and m[0]["flows"] == 10 and m[0]["detection_rate"] == 0.8


def test_flow_graph_points_attacker_to_target_to_decoy(cfg):
    now = datetime.now(timezone.utc).isoformat()
    pods = {"10.42.0.50": {"pod": "atk", "namespace": "ids-traffic", "node": "n1", "labels": {}},
            "10.42.0.7": {"pod": "grafana-1", "namespace": "target-apps", "node": "n1", "labels": {}},
            "10.42.0.90": {"pod": "decoy-web-portal-n1-x", "namespace": "ids-deception", "node": "n1", "labels": {}}}
    with db.connect(cfg["paths"]["database"]) as c:
        for src, dst, cls in [("10.42.0.50", "10.42.0.7", "BruteForce")] * 6 + [("10.42.0.90", "10.42.0.50", "BENIGN")] * 3:
            db.insert_row(c, "detections", predicted_class=cls, confidence=0.95, is_malicious=int(cls != "BENIGN"),
                          source="live", detected_at=now, src_ip=src, dst_ip=dst, src_port=1, dst_port=2, model="m")
    g = queries.flow_graph(60, 10, cfg, pods=pods)
    roles = {n["id"]: n["role"] for n in g["nodes"]}
    assert roles == {"10.42.0.50": "attacker", "10.42.0.7": "target", "10.42.0.90": "decoy"}
    e = {(x["src"], x["dst"]): x for x in g["edges"]}
    assert e[("10.42.0.50", "10.42.0.7")]["severity"] == "high"
    assert ("10.42.0.50", "10.42.0.90") in e and e[("10.42.0.50", "10.42.0.90")]["redirect"]   # reply flipped forward


def test_target_replying_to_a_lab_pod_is_never_engaged(cfg):
    from live import podinfo
    from live.controller import MapeKController
    pods = podinfo.build(
        [NS(metadata=NS(name="grafana-1", namespace="target-apps", labels={"app": "grafana"}, creation_timestamp=None),
            spec=NS(node_name="vm"), status=NS(pod_ip="10.42.0.195", phase="Running")),
         NS(metadata=NS(name="traffic-slow-dos-x", namespace="ids-traffic", labels={}, creation_timestamp=None),
            spec=NS(node_name="vm"), status=NS(pod_ip="10.42.0.220", phase="Running"))], [])
    podinfo._CACHE.update(at=float("inf"), value=pods, error=None)
    ctl = MapeKController(cfg, manager=None)
    a = {"trigger": "behavior", "src_ip": "10.42.0.195", "target_ip": "10.42.0.220", "attack_class": "Reconnaissance (port sweep)",
         "assessment": "high", "actionable": True, "simulated": False, "reason": "port sweep", "evidence_count": 1}
    with db.connect(cfg["paths"]["database"]) as c:
        out = ctl.engage(c, 1, [a])
    assert out[0]["actionable"] is False and out[0]["assessment"] == "reply"


def test_engagement_replay_shows_target_first_then_decoy(cfg):
    from datetime import timedelta
    t0 = datetime.now(timezone.utc) - timedelta(minutes=2)
    naive = lambda s: (t0 + timedelta(seconds=s)).replace(tzinfo=None).isoformat()
    with db.connect(cfg["paths"]["database"]) as c:
        for i in range(20):                      # 0-19 s: scan of the real target
            db.insert_row(c, "detections", predicted_class="PortScan", confidence=0.97, is_malicious=1, source="live",
                          detected_at=(t0 + timedelta(seconds=i + 2)).isoformat(), timestamp=naive(i),
                          src_ip="10.42.0.50", dst_ip="10.42.0.7", src_port=40000 + i, dst_port=i + 1, model="m")
        for i in range(20, 30):                  # 20-29 s: redirected to the decoy
            db.insert_row(c, "detections", predicted_class="PortScan", confidence=0.95, is_malicious=1, source="live",
                          detected_at=(t0 + timedelta(seconds=i + 2)).isoformat(), timestamp=naive(i),
                          src_ip="10.42.0.50", dst_ip="10.42.0.90", src_port=40000 + i, dst_port=80, model="m")
    eng = {"id": 1, "src_ip": "10.42.0.50", "attack_class": "PortScan", "state": "released",
           "started_at": (t0 + timedelta(seconds=10)).isoformat(), "released_at": (t0 + timedelta(seconds=60)).isoformat(),
           "decoy_pod_ips": ["10.42.0.90"], "decoy_rows": [], "target": {"ip": "10.42.0.7", "pod": "grafana-1"},
           "attacker": {"pod": "atk", "namespace": "ids-traffic"},
           "redirect": {"applied": True, "at": (t0 + timedelta(seconds=19)).isoformat(), "decoy": "decoy-web-portal-n1"}}
    r = queries.engagement_replay(eng, cfg, frames=10, pods={})
    assert r["to_target"] == 20 and r["to_decoy"] == 10
    mid, last = r["frames"][4], r["frames"][-1]
    assert {e["dst"] for e in mid["edges"]} == {"10.42.0.7"}            # before the redirect: target only
    assert {e["dst"]: e["redirect"] for e in last["edges"]} == {"10.42.0.7": False, "10.42.0.90": True}
    roles = {n["id"]: (n["role"], n["label"]) for n in r["nodes"]}
    assert roles["10.42.0.50"] == ("attacker", "atk") and roles["10.42.0.90"] == ("decoy", "decoy-web-portal-n1 pod")
    kinds = [e["kind"] for e in r["events"]]
    assert kinds[:1] == ["engaged"] and "redirect" in kinds


def test_window_policy_describes_every_rule_and_setting(cfg):
    from live.window import policy_description
    d = policy_description(cfg["capture"]["window"])
    assert [r["id"] for r in d["rules"]] == ["R0_backlog", "R1_threat", "R2_high_rate", "R3_calm", "R4_hold"]
    assert all(r.get("why") for r in d["rules"])
    assert {s["key"] for s in d["settings"]} >= {"sizes", "threat_seconds", "high_rate_pps", "low_rate_pps",
                                                 "calm_windows", "evidence_confidence", "default_seconds"}


def test_job_stops_by_the_deadline_and_stale_generator_is_reported(cfg):
    import time as _t
    from live import trafficlab
    job = trafficlab.build_job("port_scan", cfg, "10.42.0.7:1880")
    env = {e["name"]: e["value"] for e in job["spec"]["template"]["spec"]["containers"][0]["env"]}
    deadline = job["spec"]["activeDeadlineSeconds"]
    assert abs(int(env["JOB_DEADLINE_EPOCH"]) - (_t.time() + deadline - 25)) < 5
    cur = trafficlab.GENERATOR_FILE.read_text()
    assert trafficlab.generator_freshness(NS(data={"traffic_generator.py": cur})) == {"generator_current": True}
    old = trafficlab.generator_freshness(NS(data={"traffic_generator.py": "print('old')"}))
    assert old["generator_current"] is False and old["fix"] == "kubectl apply -k deploy/traffic-lab"


def test_deadline_failure_keeps_the_last_log_summary():
    from live.pipeline import snapshot_diagnosis
    snap = {"at": "2026-11-07T20:30:00+00:00", "verification": {"ok": 120, "errors": 0,
            "actions": {"port_open": 20, "port_closed": 100, "port_filtered": 400, "redirected": 1}, "error_types": {}}}
    text = snapshot_diagnosis(snap)
    assert "120 answered" in text and "400 ports timed out" in text and "update the generator script" in text
