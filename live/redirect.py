"""Divert an attacking lab pod to the decoys (NetworkPolicy quarantine).

Mechanism: the traffic-lab egress NetworkPolicy only selects pods WITHOUT the
quarantine label, and a second policy (deploy/traffic-lab/networkpolicy.yaml,
`traffic-lab-quarantine`) selects pods WITH it and allows egress only to the decoys
in ids-deception and to DNS. Labelling the source pod therefore cuts it off from
the real services (Node-RED, Grafana, InfluxDB) while the decoys stay reachable; removing
the label restores normal access. NetworkPolicies only add allowances, which is why
the base policy must exclude the label rather than a second policy "subtracting".

The decoy then receives the source's traffic: the controller only redirects once a
decoy for the engagement is Ready, and it sets the pod annotation
`ids-deception/redirect-to=<decoy service>:<port>` together with the label. The
generator reads its own annotations through a downward-API volume and sends every
new connection to that decoy. This stands in for a transparent DNAT on the node,
which needs root on the node (iptables), which the lab does not have.

Scope and limits (deliberate):
  * only pods in `deception.redirect.namespaces` (the lab's own ids-traffic) are ever
    touched; a source anywhere else is logged, never modified
  * it is not a transparent DNAT: a connection to the real service's IP is dropped,
    not answered by the decoy. Only connections to the decoy Services get an answer.
"""
from __future__ import annotations

from typing import Any

from live.config import load_config
from live.logging_setup import get_logger

log = get_logger(__name__)
DEFAULT_LABEL = "ids-deception/quarantine"
REDIRECT_ANNOTATION = "ids-deception/redirect-to"


class RedirectError(RuntimeError):
    pass


def _core(cfg: dict[str, Any]):
    from kubernetes import client
    from live.kube import api_client
    api, _ = api_client(cfg)
    return client.CoreV1Api(api)


def settings(cfg: dict[str, Any]) -> dict[str, Any]:
    r = cfg["deception"].get("redirect") or {}
    return {"enabled": bool(r.get("enabled", True)), "namespaces": list(r.get("namespaces", ["ids-traffic"])),
            "label": r.get("label", DEFAULT_LABEL)}


def find_pod(ip: str, cfg: dict[str, Any], core=None) -> dict[str, Any] | None:
    """The pod with this IP in an allowed (lab) namespace, or None."""
    st = settings(cfg)
    core = core or _core(cfg)
    for ns in st["namespaces"]:
        for p in core.list_namespaced_pod(ns, field_selector=f"status.podIP={ip}", _request_timeout=5).items:
            if p.status.phase in ("Running", "Pending"):
                return {"namespace": ns, "pod": p.metadata.name}
    return None


def quarantine(ip: str, cfg: dict[str, Any] | None = None, core=None, redirect_to: str | None = None) -> dict[str, Any]:
    """Label the source pod so only the decoys are reachable from it, and point it at
    `redirect_to` (decoy host:port). Never raises for 'not applicable'."""
    cfg = cfg or load_config()
    st = settings(cfg)
    if not st["enabled"]:
        return {"applied": False, "reason": "redirect disabled in config"}
    try:
        core = core or _core(cfg)
        pod = find_pod(ip, cfg, core)
        if pod is None:
            return {"applied": False, "reason": f"{ip} is not a running pod in {', '.join(st['namespaces'])}; "
                                                "only lab pods are ever redirected"}
        meta: dict[str, Any] = {"labels": {st["label"]: "true"}}
        if redirect_to:
            meta["annotations"] = {REDIRECT_ANNOTATION: redirect_to}
        core.patch_namespaced_pod(pod["pod"], pod["namespace"], {"metadata": meta})
    except Exception as e:  # noqa: BLE001
        return {"applied": False, "reason": f"Kubernetes refused the label change: {getattr(e, 'reason', e)}"}
    log.info("redirect: %s (%s/%s) quarantined, sent to %s", ip, pod["namespace"], pod["pod"], redirect_to)
    return {"applied": True, **pod, "label": st["label"], "to": redirect_to,
            "reason": f"pod {pod['namespace']}/{pod['pod']} labelled {st['label']}=true (egress limited to decoys + DNS)"
                      + (f" and redirected to {redirect_to}" if redirect_to else "")}


def release(redirect: dict[str, Any] | None, cfg: dict[str, Any] | None = None, core=None) -> dict[str, Any]:
    cfg = cfg or load_config()
    if not redirect or not redirect.get("applied"):
        return {"released": False, "reason": "nothing was redirected"}
    try:
        core = core or _core(cfg)
        core.patch_namespaced_pod(redirect["pod"], redirect["namespace"],
                                  {"metadata": {"labels": {redirect.get("label", DEFAULT_LABEL): None},
                                                "annotations": {REDIRECT_ANNOTATION: None}}})
    except Exception as e:  # noqa: BLE001
        if getattr(e, "status", None) == 404:
            return {"released": True, "reason": "pod no longer exists"}
        return {"released": False, "reason": f"could not remove label: {getattr(e, 'reason', e)}"}
    return {"released": True, "reason": f"label and redirect removed from {redirect['namespace']}/{redirect['pod']}"}
