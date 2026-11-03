"""Configuration for the live pipeline, the traffic lab and the deception controller.

All tunables live in `config/live.yaml` at the repo root. Relative paths are
resolved against the repo root. `IDS_CONFIG` overrides the config file location.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "config" / "live.yaml"


@lru_cache(maxsize=4)
def load_config(path: str | None = None) -> dict[str, Any]:
    cfg_path = Path(path or os.environ.get("IDS_CONFIG", DEFAULT_CONFIG))
    with open(cfg_path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def repo_path(rel: str | Path) -> Path:
    p = Path(rel).expanduser()
    return p if p.is_absolute() else REPO_ROOT / p


def get_path(key: str, cfg: dict[str, Any] | None = None) -> Path:
    cfg = cfg or load_config()
    return repo_path(cfg["paths"][key])


# Alias kept so modules adapted from the friend's repo read naturally.
project_path = repo_path
