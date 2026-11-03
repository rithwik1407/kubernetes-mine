"""Traffic-lab Job construction (no cluster needed)."""
import pytest

from live.trafficlab import TrafficLabError, build_job, scenarios


def test_scenarios_cover_the_cic_attack_classes(cfg):
    sc = scenarios(cfg)
    detectable = {s["expect_class"] for s in sc.values() if s["detectable"]}
    assert {"PortScan", "DoS", "BruteForce", "WebAttack"} <= detectable


def test_build_job_is_bounded_and_locked_down(cfg):
    job = build_job("port_scan", cfg, target="svc:1880", count=100, delay=0.1)
    assert job["kind"] == "Job"
    spec = job["spec"]
    assert spec["backoffLimit"] == 0 and spec["activeDeadlineSeconds"] <= 600
    pod = spec["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    sc = pod["containers"][0]["securityContext"]
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["capabilities"]["drop"] == ["ALL"]
    env = {e["name"]: e["value"] for e in pod["containers"][0]["env"]}
    assert env["MODE"] == "port_scan" and env["TARGET"] == "svc:1880" and env["COUNT"] == "100"


def test_build_job_rejects_unknown_scenario(cfg):
    with pytest.raises(TrafficLabError):
        build_job("nuke_everything", cfg)
