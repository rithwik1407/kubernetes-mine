"""Logging for the live pipeline.

Every process logs one format to stderr and to a file under logs/:
    logs/backend.log           the dashboard API (uvicorn) process
    logs/capture_service.log   the background capture service (its stdout/stderr)
The System page reads these files back (live.syslog) so the logs are visible in
the UI with level / component filters.
"""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG_DIR = Path(__file__).resolve().parents[1] / "logs"
_CONFIGURED = False


def configure(file_name: str | None = None) -> None:
    """Configure the root logger once. file_name=None -> stderr only."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    root = logging.getLogger()
    root.setLevel(os.environ.get("IDS_LOG_LEVEL", "INFO"))
    fmt = logging.Formatter(FORMAT)
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.addHandler(sh)
    if file_name:
        LOG_DIR.mkdir(exist_ok=True)
        fh = RotatingFileHandler(LOG_DIR / file_name, maxBytes=5_000_000, backupCount=2, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    if not _CONFIGURED and not logging.getLogger().handlers:
        configure(None)
    return logging.getLogger(name)
