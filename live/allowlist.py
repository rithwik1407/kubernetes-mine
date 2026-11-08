"""Control-plane allowlist: Kubernetes system traffic is scored but never treated as an attack.

Measured in the lab: the only non-BENIGN predictions on benign traffic were flows
between pods and the API server (pod -> <node>:6443 and 10.43.0.1:443 -> pod, 2-4
packets, 0 payload bytes, confidence 0.51-0.52). They are fragments of long-lived
API watch connections cut at capture-window boundaries, not attacks.

A flow is allowlisted when either end is control-plane infrastructure:

  * a control-plane port (API server 6443, kubelet 10250, etcd, scheduler, ...)
  * the `kubernetes` Service IP or one of its endpoint addresses (the API server)
  * a pod or Service in kube-system (CoreDNS, metrics-server, ...)
  * the node's pod-bridge address (kubelet health probes)
  * an extra CIDR from config (detection.allowlist.cidrs)

Allowlisted flows keep their model prediction (for transparency) but get
is_malicious = 0 and an `allowlisted` reason, so they never count as detections,
never form flow bursts and never trigger deception.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from typing import Any

import pandas as pd

from live.config import load_config
from live.logging_setup import get_logger

log = get_logger(__name__)
DEFAULT_PORTS = [6443, 10250, 10257, 10259, 2379, 2380]
_CACHE: dict[str, Any] = {"at": 0.0, "value": None}
_LOCK = threading.Lock()


class Allowlist:
    def __init__(self, ports=None, ips: dict[str, str] | None = None, cidrs=None, error: str | None = None):
        self.ports = {int(p) for p in (ports or DEFAULT_PORTS)}
        self.ips = dict(ips or {})
        self.nets = [ipaddress.ip_network(c, strict=False) for c in (cidrs or [])]
        self.error = error

    def _ip_reason(self, ip) -> str | None:
        if ip is None or ip is pd.NA:
            return None
        ip = str(ip)
        if ip in self.ips:
            return self.ips[ip]
        if self.nets:
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                return None
            for n in self.nets:
                if a in n:
                    return f"allowlisted network {n}"
        return None

    def reason(self, src_ip, dst_ip, src_port, dst_port) -> str | None:
        for port in (dst_port, src_port):
            try:
                if port is not None and port is not pd.NA and int(port) in self.ports:
                    return f"control-plane port {int(port)}"
            except (TypeError, ValueError):
                pass
        return self._ip_reason(dst_ip) or self._ip_reason(src_ip)

    def apply(self, pred: pd.DataFrame) -> pd.DataFrame:
        """Add `allowlisted` and clear is_malicious for allowlisted rows."""
        if pred.empty:
            pred["allowlisted"] = pd.Series(dtype="object")
            return pred
        reasons = [self.reason(r.src_ip, r.dst_ip, r.src_port, r.dst_port)
                   for r in pred[["src_ip", "dst_ip", "src_port", "dst_port"]].itertuples(index=False)]
        pred = pred.copy()
        pred["allowlisted"] = reasons
        pred["is_malicious"] = pred["is_malicious"].astype(bool) & pred["allowlisted"].isna()
        return pred

    def describe(self) -> dict[str, Any]:
        return {"ports": sorted(self.ports), "addresses": dict(sorted(self.ips.items())),
                "cidrs": [str(n) for n in self.nets], "discovery_error": self.error}


def _discover(cfg: dict[str, Any]) -> tuple[dict[str, str], str | None]:
    """API server, kube-system pods/Services. Read-only; best effort."""
    ips: dict[str, str] = {}
    try:
        from kubernetes import client
        from live.kube import api_client
        api, _ = api_client(cfg)
        core = client.CoreV1Api(api)
    except Exception as e:  # noqa: BLE001
        return ips, f"cluster unavailable: {str(e)[:160]}"
    errors = []
    try:
        svc = core.read_namespaced_service("kubernetes", "default", _request_timeout=5)
        if svc.spec.cluster_ip:
            ips[svc.spec.cluster_ip] = "API server Service"
        ep = core.read_namespaced_endpoints("kubernetes", "default", _request_timeout=5)
        for s in ep.subsets or []:
            for a in s.addresses or []:
                ips[a.ip] = "API server"
    except Exception as e:  # noqa: BLE001
        errors.append(f"API server lookup: {getattr(e, 'status', '')} {getattr(e, 'reason', e)}")
    try:
        for p in core.list_namespaced_pod("kube-system", _request_timeout=5).items:
            if p.status.pod_ip and not p.spec.host_network:
                app = (p.metadata.labels or {}).get("k8s-app") or p.metadata.name.rsplit("-", 2)[0]
                ips[p.status.pod_ip] = f"kube-system pod ({app})"
        for s in core.list_namespaced_service("kube-system", _request_timeout=5).items:
            if s.spec.cluster_ip and s.spec.cluster_ip != "None":
                ips[s.spec.cluster_ip] = f"kube-system Service ({s.metadata.name})"
    except Exception as e:  # noqa: BLE001
        errors.append(f"kube-system lookup: {getattr(e, 'status', '')} {getattr(e, 'reason', e)}")
    try:
        # kubelet health probes reach pods from the node's bridge address (the first IP of its
        # pod CIDR, e.g. 10.42.0.1). A new pod refuses them until it listens, and those short
        # refused flows look like a scan (measured: decoy pods' :8081 probes predicted PortScan).
        for n in core.list_node(_request_timeout=5).items:
            for cidr in (n.spec.pod_cidrs or [n.spec.pod_cidr] if n.spec else []):
                if cidr:
                    gw = next(ipaddress.ip_network(cidr, strict=False).hosts(), None)
                    if gw:
                        ips[str(gw)] = f"node {n.metadata.name} bridge (kubelet probes)"
    except Exception as e:  # noqa: BLE001
        errors.append(f"node lookup: {getattr(e, 'status', '')} {getattr(e, 'reason', e)}")
    return ips, "; ".join(errors) or None


def get(cfg: dict[str, Any] | None = None, refresh_s: float = 60) -> Allowlist:
    """Cached allowlist (refreshed every minute; static rules apply even without a cluster)."""
    cfg = cfg or load_config()
    a = cfg["detection"].get("allowlist") or {}
    if a.get("enabled", True) is False:
        return Allowlist(ports=[], ips={}, cidrs=[])
    with _LOCK:
        if _CACHE["value"] is None or time.monotonic() - _CACHE["at"] > refresh_s:
            ips, err = _discover(cfg) if a.get("discover", True) else ({}, None)
            for ip, why in (a.get("addresses") or {}).items():
                ips[str(ip)] = str(why)
            _CACHE["value"] = Allowlist(a.get("ports", DEFAULT_PORTS), ips, a.get("cidrs", []), err)
            _CACHE["at"] = time.monotonic()
            if err:
                log.warning("control-plane allowlist: static rules only (%s)", err)
        return _CACHE["value"]


def reset_cache() -> None:
    with _LOCK:
        _CACHE.update(at=0.0, value=None)
