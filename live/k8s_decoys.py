"""Kubernetes operations for decoys (the MAPE-K Execute stage).

Decoys are rendered from the predefined deploy/deception/decoy-template.yaml
and managed only in the deception namespace, using the least-privilege
ids-controller service account. Only resources labelled
app.kubernetes.io/managed-by=ids-deception-controller are ever modified.
"""
from __future__ import annotations

import json
import re
from string import Template
from typing import Any

import yaml

from live.config import load_config, project_path
from live.logging_setup import get_logger

log = get_logger(__name__)
MANAGED_BY = "ids-deception-controller"
SELECTOR = f"app.kubernetes.io/managed-by={MANAGED_BY}"
_NAME_RE = re.compile(r"^decoy-[a-z0-9-]{1,40}$")


class DecoyError(RuntimeError):
    pass


def decoy_name(profile: str) -> str:
    return f"decoy-{profile}"


class DecoyManager:
    def __init__(self, cfg: dict[str, Any] | None = None, api_client=None):
        from kubernetes import client, config as kconfig

        self.cfg = cfg or load_config()
        d = self.cfg["deception"]
        self.ns = d["namespace"]
        self.profiles = d["profiles"]
        self.max_replicas = int(d["max_replicas"])
        self.template = project_path(d["template"]).read_text()
        if api_client is None:
            kubeconfig = project_path(d["kubeconfig"])
            if not kubeconfig.is_file():
                raise DecoyError(f"{kubeconfig} missing; run deploy/rbac/create-kubeconfig.sh")
            api_client = kconfig.new_client_from_config(config_file=str(kubeconfig))
        self.apps = client.AppsV1Api(api_client)
        self.core = client.CoreV1Api(api_client)
        self._api_exc = client.exceptions.ApiException

    # --- rendering ------------------------------------------------------------------
    def render(self, profile: str, replicas: int = 1) -> tuple[dict, dict]:
        if profile not in self.profiles:
            raise DecoyError(f"unknown decoy profile {profile!r}")
        if not 1 <= int(replicas) <= self.max_replicas:
            raise DecoyError(f"replicas must be 1..{self.max_replicas}")
        name = decoy_name(profile)
        if not _NAME_RE.match(name):
            raise DecoyError(f"invalid decoy name {name!r}")
        text = Template(self.template).substitute(
            name=name, profile=profile, port=int(self.profiles[profile]["port"]), replicas=int(replicas))
        docs = [d for d in yaml.safe_load_all(text) if d]
        dep = next(d for d in docs if d["kind"] == "Deployment")
        svc = next(d for d in docs if d["kind"] == "Service")
        return dep, svc

    # --- operations -----------------------------------------------------------------
    def deploy(self, profile: str, replicas: int = 1) -> dict[str, Any]:
        dep, svc = self.render(profile, replicas)
        name = dep["metadata"]["name"]
        try:
            self.apps.create_namespaced_deployment(self.ns, dep)
        except self._api_exc as e:
            if e.status == 409:
                raise DecoyError(f"{name} already exists") from e
            raise DecoyError(f"deployment create failed: {e.reason}") from e
        try:
            created = self.core.create_namespaced_service(self.ns, svc)
        except self._api_exc as e:
            if e.status != 409:
                self._delete(name)
                raise DecoyError(f"service create failed: {e.reason}") from e
            created = self.core.read_namespaced_service(name, self.ns)
        return {"name": name, "service_ip": created.spec.cluster_ip, "port": int(self.profiles[profile]["port"])}

    def _owned(self, name: str) -> bool:
        try:
            dep = self.apps.read_namespaced_deployment(name, self.ns)
        except self._api_exc as e:
            if e.status == 404:
                return False
            raise
        return (dep.metadata.labels or {}).get("app.kubernetes.io/managed-by") == MANAGED_BY

    def scale(self, name: str, replicas: int) -> None:
        if not 1 <= replicas <= self.max_replicas:
            raise DecoyError(f"replicas must be 1..{self.max_replicas}")
        if not self._owned(name):
            raise DecoyError(f"{name} is not a managed decoy")
        self.apps.patch_namespaced_deployment_scale(name, self.ns, {"spec": {"replicas": replicas}})

    def _delete(self, name: str) -> None:
        for fn in (self.apps.delete_namespaced_deployment, self.core.delete_namespaced_service):
            try:
                fn(name, self.ns)
            except self._api_exc as e:
                if e.status != 404:
                    raise

    def remove(self, name: str) -> bool:
        """Delete a managed decoy. Returns False if it no longer exists."""
        if not _NAME_RE.match(name):
            raise DecoyError(f"invalid decoy name {name!r}")
        if not self._owned(name):
            try:  # a leftover service without its deployment
                svc = self.core.read_namespaced_service(name, self.ns)
                if (svc.metadata.labels or {}).get("app.kubernetes.io/managed-by") == MANAGED_BY:
                    self.core.delete_namespaced_service(name, self.ns)
            except self._api_exc:
                pass
            return False
        self._delete(name)
        return True

    def list_decoys(self) -> dict[str, dict[str, Any]]:
        deps = self.apps.list_namespaced_deployment(self.ns, label_selector=SELECTOR).items
        svcs = {s.metadata.name: s for s in self.core.list_namespaced_service(self.ns, label_selector=SELECTOR).items}
        out = {}
        for d in deps:
            name = d.metadata.name
            svc = svcs.get(name)
            out[name] = {
                "name": name, "profile": (d.metadata.labels or {}).get("ids/profile"),
                "replicas": d.spec.replicas or 0, "ready_replicas": d.status.ready_replicas or 0,
                "created": d.metadata.creation_timestamp.isoformat() if d.metadata.creation_timestamp else None,
                "service_ip": svc.spec.cluster_ip if svc else None,
                "port": svc.spec.ports[0].port if svc and svc.spec.ports else None,
            }
        return out

    def interaction_lines(self, name: str, since_seconds: int) -> list[tuple[str, dict[str, Any]]]:
        """(pod, parsed JSON line) for request log lines of a decoy's pods."""
        pods = self.core.list_namespaced_pod(self.ns, label_selector=f"ids/decoy={name}").items
        out = []
        for p in pods:
            if p.status.phase not in ("Running", "Succeeded", "Failed"):
                continue
            try:
                text = self.core.read_namespaced_pod_log(p.metadata.name, self.ns, since_seconds=since_seconds)
            except self._api_exc as e:
                log.warning("log read failed for %s: %s", p.metadata.name, e.reason)
                continue
            for line in text.splitlines():
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict) and "method" in rec:
                    out.append((p.metadata.name, rec))
        return out

    def recent_events(self, namespace: str, limit: int = 20) -> list[dict[str, Any]]:
        evs = self.core.list_namespaced_event(namespace).items
        evs.sort(key=lambda e: (e.last_timestamp or e.event_time or e.metadata.creation_timestamp), reverse=True)
        return [{"namespace": namespace, "type": e.type, "reason": e.reason, "object": f"{e.involved_object.kind}/{e.involved_object.name}",
                 "message": (e.message or "")[:300],
                 "time": str(e.last_timestamp or e.event_time or e.metadata.creation_timestamp)} for e in evs[:limit]]
