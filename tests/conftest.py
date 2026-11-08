import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

LAB = Path("/home/user/rithwik1407/k8s-security-system/k8s-adaptive-ids/data/lab")


@pytest.fixture
def cfg(tmp_path):
    from live.config import load_config
    c = load_config(str(REPO / "config" / "live.yaml"))
    c = {**c, "paths": {**c["paths"], "database": str(tmp_path / "t.sqlite"),
                       "local_model_dir": str(tmp_path / "no-local-model")},
         # unit tests never talk to a cluster: static allowlist only, no redirect
         "detection": {**c["detection"], "allowlist": {**c["detection"]["allowlist"], "discover": False}},
         "deception": {**c["deception"], "redirect": {**c["deception"]["redirect"], "enabled": False}}}
    from live import allowlist, labsources, podinfo
    allowlist.reset_cache()
    labsources._CACHE.update(at=float("inf"), value={}, error=None)   # no pod lookups in unit tests
    podinfo._CACHE.update(at=float("inf"), value={}, error=None)
    labsources._DECOYS.update(at=float("inf"), value=set())
    return c


@pytest.fixture
def model_available():
    return (REPO / "models" / "cic-ids2017" / "best_model.joblib").is_file()
