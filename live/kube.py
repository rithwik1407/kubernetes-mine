"""One place that builds the Kubernetes API client.

Preference order:
  1. config/ids-controller.kubeconfig  (least-privilege identity, deploy/rbac)
  2. the default kubeconfig (KUBECONFIG or ~/.kube/config), e.g. K3s admin

(2) makes the dashboard work out of the box on a lab machine; the status panel
shows which identity is in use so it is never a surprise.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from live.config import load_config, project_path


class KubeUnavailable(RuntimeError):
    pass


def default_kubeconfigs() -> list[Path]:
    env = os.environ.get("KUBECONFIG")
    paths = [Path(p) for p in env.split(os.pathsep) if p] if env else []
    paths.append(Path.home() / ".kube" / "config")
    return paths


def api_client(cfg: dict[str, Any] | None = None):
    """Return (ApiClient, identity). Raises KubeUnavailable with an actionable message."""
    cfg = cfg or load_config()
    try:
        from kubernetes import config as kconfig
    except ImportError as e:  # pragma: no cover
        raise KubeUnavailable(f"kubernetes client not installed ({e}); pip install kubernetes")
    ctl = project_path(cfg["deception"]["kubeconfig"])
    try:
        if ctl.is_file():
            return kconfig.new_client_from_config(config_file=str(ctl)), "ids-controller"
        for p in default_kubeconfigs():
            if p.is_file():
                return kconfig.new_client_from_config(config_file=str(p)), f"default kubeconfig ({p})"
    except Exception as e:
        raise KubeUnavailable(f"could not load kubeconfig: {str(e)[:200]}")
    raise KubeUnavailable(
        "no kubeconfig found. Run the dashboard where K3s runs (WSL/Linux) or copy "
        "/etc/rancher/k3s/k3s.yaml to ~/.kube/config (see docs/live-system.md)")
