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
    c = {**c, "paths": {**c["paths"], "database": str(tmp_path / "t.sqlite")}}
    return c


@pytest.fixture
def model_available():
    return (REPO / "models" / "cic-ids2017" / "best_model.joblib").is_file()
