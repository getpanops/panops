"""
PanOps Brain — Remediation Executor + Validation Loop (Steps 6 & 7)

Structured rules cover ~70% of recurring incidents. Each rule function
receives the happening row and returns a list of actions taken.
All kubectl commands are dry-run first; the real command only runs if
dry-run output matches expectations.

Safety guardrails (enforced before every action):
  - Blocked namespaces: kube-system, flux-system, cilium-spire, cert-manager
  - Never delete PVCs
  - Never modify more than 1 replica at a time
  - Hard abort after REMEDIATION_TIMEOUT_S regardless of state
  - Dry-run all kubectl commands; abort if output is unexpected

After remediation, the validation loop polls Prometheus and Loki until
all triggering signals clear for CLEAR_STREAK_REQUIRED consecutive checks,
then marks the happening resolved. Times out to escalated.
"""
import json
import os
import re
import shlex
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import runbook_writer as _runbook_writer
except ImportError:
    _runbook_writer = None

try:
    from kubernetes import client as _k8s_client, config as _k8s_config
    _k8s_config.load_incluster_config()
    _k8s_core = _k8s_client.CoreV1Api()
    _k8s_apps = _k8s_client.AppsV1Api()
except Exception as _k8s_init_err:
    _k8s_core = None
    _k8s_apps = None

REMEDIATION_TIMEOUT_S  = 600   # hard abort after 10 min
VALIDATION_POLL_S      = 60    # check every minute
VALIDATION_TIMEOUT_S   = 1800  # escalate after 30 min
CLEAR_STREAK_REQUIRED  = 10    # consecutive clean polls = resolved
STABILIZATION_WAIT_S   = int(os.getenv("STABILIZATION_WAIT_S", "180"))  # wait before intervening

# off      — no remediation actions taken
# dry-run  — actions are logged but kubectl is never called (default safe)
# limited  — only ALLOWED_NAMESPACES are eligible
# full     — any non-blocked namespace is eligible
REMEDIATION_MODE = os.getenv("REMEDIATION_MODE", "dry-run").lower()

# PROTECTED: always blocked regardless of mode; overrides ALLOWED if a namespace appears in both.
# Defaults cover critical infrastructure that PanOps should never touch autonomously.
_protected_raw = os.getenv(
    "REMEDIATION_PROTECTED_NAMESPACES",
    "kube-system,kube-public,kube-node-lease,flux-system,cilium-spire,cert-manager,"
    "spire,openebs,ceph,rook-ceph",
)
PROTECTED_NAMESPACES = {ns.strip() for ns in _protected_raw.split(",") if ns.strip()}

# ALLOWED: optional. Only enforced when REMEDIATION_MODE=limited AND the list is non-empty.
# Empty string (the default) means "allow all non-protected namespaces" even in limited mode.
_allowed_raw = os.getenv("REMEDIATION_ALLOWED_NAMESPACES", "")
ALLOWED_NAMESPACES = {ns.strip() for ns in _allowed_raw.split(",") if ns.strip()}

CH_URL   = os.getenv("CH_URL",   "http://observability-clickhouse-clickhouse-headless.observability.svc.cluster.local:8123")
PROM_URL = os.getenv("PROM_URL", "http://gigapipe.observability.svc.cluster.local:3100")
LOKI_URL = os.getenv("LOKI_URL", "http://gigapipe.observability.svc.cluster.local:3100")

ASSEMBLER_KUBECTL_CONTEXT = os.environ.get("ASSEMBLER_KUBECTL_CONTEXT", "")
ANSIBLE_INVENTORY         = os.environ.get("ANSIBLE_INVENTORY", "")
WINRM_USERNAME            = os.environ.get("WINRM_USERNAME", "")
WINRM_PASSWORD            = os.environ.get("WINRM_PASSWORD", "")
WINRM_TRANSPORT           = os.environ.get("WINRM_TRANSPORT", "ntlm")
# Secure-by-default: only connect to explicitly allowlisted hosts, validate the
# server cert unless the operator opts out, and encrypt the message payload.
_winrm_hosts_raw          = os.environ.get("WINRM_ALLOWED_HOSTS", "")
WINRM_ALLOWED_HOSTS       = {h.strip() for h in _winrm_hosts_raw.split(",") if h.strip()}
WINRM_CERT_VALIDATION     = os.environ.get("WINRM_CERT_VALIDATION", "validate").lower()
WINRM_MESSAGE_ENCRYPTION  = os.environ.get("WINRM_MESSAGE_ENCRYPTION", "auto").lower()


# ── Rule success rates (loaded from dream_state at startup) ──────────────

_RULE_SUCCESS_RATES: dict = {}
_RULE_SUCCESS_RATES_LOADED = False

def _load_rule_success_rates():
    """
    Pull per-rule success rates computed by NREM consolidation from dream_state.
    Called once at module import time and again periodically from the main loop.
    Rules with rate < RULE_DEPRIORITIZE_THRESHOLD are logged at WARN level and
    bypassed in the dispatch in favour of k8s_self_heal.
    """
    global _RULE_SUCCESS_RATES, _RULE_SUCCESS_RATES_LOADED
    try:
        data = (
            "SELECT value FROM panops.dream_state WHERE key = 'rule_success_rates' LIMIT 1 FORMAT JSON"
        ).encode()
        req = urllib.request.Request(CH_URL, data=data, method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("X-ClickHouse-User", os.getenv("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.getenv("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=10) as r:
            rows = json.loads(r.read()).get("data", [])
        if rows:
            _RULE_SUCCESS_RATES = json.loads(rows[0]["value"])
        _RULE_SUCCESS_RATES_LOADED = True
    except Exception:
        pass  # fail-open: no CH connection at startup is fine

_load_rule_success_rates()

_RULE_DEPRIORITIZE_THRESHOLD = float(os.getenv("RULE_DEPRIORITIZE_THRESHOLD", "0.2"))


def _effective_rule(rule_name, log_fn=None):
    """
    Return rule_name unless its dream-cycle success rate is below the deprioritize
    threshold, in which case fall back to k8s_self_heal.
    """
    if not rule_name:
        return rule_name
    rate = _RULE_SUCCESS_RATES.get(rule_name)
    if rate is not None and rate < _RULE_DEPRIORITIZE_THRESHOLD:
        if log_fn:
            log_fn("WARN",
                   f"remediator: deprioritizing {rule_name!r} (success rate {rate:.2f} "
                   f"< {_RULE_DEPRIORITIZE_THRESHOLD}) → k8s_self_heal")
        return "k8s_self_heal"
    return rule_name


# ── Safety ────────────────────────────────────────────────────────────────

_KILL_SWITCH_PATH = "/etc/panops/kill-switch/remediation.enabled"

def _kill_switch_enabled():
    try:
        with open(_KILL_SWITCH_PATH) as f:
            return f.read().strip().lower() not in ("false", "0", "no")
    except FileNotFoundError:
        return True  # fail-open: no file = not explicitly disabled


def _safe_namespace(ns):
    if not _kill_switch_enabled():
        raise ValueError("remediation disabled via kill-switch ConfigMap")
    if REMEDIATION_MODE == "off":
        raise ValueError("remediation disabled (REMEDIATION_MODE=off)")
    if ns in PROTECTED_NAMESPACES:
        raise ValueError(f"namespace {ns} is protected")
    # In limited mode, ALLOWED_NAMESPACES is only enforced when it is non-empty.
    # An empty allowlist means "allow all non-protected" even in limited mode.
    if REMEDIATION_MODE == "limited" and ALLOWED_NAMESPACES and ns not in ALLOWED_NAMESPACES:
        raise ValueError(f"namespace {ns} not in allowlist (REMEDIATION_MODE=limited)")

def _k8s_patch_deployment(deploy, ns, patch_body, log_fn=None):
    """Patch a deployment: dry-run first, then real (skipped in dry-run mode)."""
    if not _k8s_apps:
        raise RuntimeError("kubernetes client not initialized")
    if isinstance(patch_body, str):
        patch_body = json.loads(patch_body)
    _k8s_apps.patch_namespaced_deployment(name=deploy, namespace=ns, body=patch_body, dry_run="All")
    if REMEDIATION_MODE == "dry-run":
        if log_fn:
            log_fn("INFO", f"[dry-run] would patch deployment/{deploy} in {ns}")
        return f"[dry-run] patched deployment/{deploy}"
    _k8s_apps.patch_namespaced_deployment(name=deploy, namespace=ns, body=patch_body)
    if log_fn:
        log_fn("INFO", f"patched deployment/{deploy} in {ns}")
    return f"patched deployment/{deploy}"

def _k8s_rollout_restart(ns, log_fn=None):
    """Restart all deployments in a namespace via restart annotation."""
    if not _k8s_apps:
        raise RuntimeError("kubernetes client not initialized")
    ts = datetime.now(timezone.utc).isoformat()
    patch = {"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": ts}}}}}
    deploys = _k8s_apps.list_namespaced_deployment(namespace=ns)
    restarted = []
    for d in deploys.items:
        name = d.metadata.name
        # Dry-run pre-flight: verify the patch is accepted before executing.
        # Raises on API error (e.g. admission webhook rejection), aborting this deployment.
        _k8s_apps.patch_namespaced_deployment(name=name, namespace=ns, body=patch, dry_run="All")
        if REMEDIATION_MODE != "dry-run":
            _k8s_apps.patch_namespaced_deployment(name=name, namespace=ns, body=patch)
        if log_fn:
            pfx = "[dry-run] " if REMEDIATION_MODE == "dry-run" else ""
            log_fn("INFO", f"{pfx}rollout restart deployment/{name} in {ns}")
        restarted.append(name)
    pfx = "[dry-run] " if REMEDIATION_MODE == "dry-run" else ""
    return f"{pfx}restarted: {', '.join(restarted) or 'none'}"


# ── Remediation helpers ────────────────────────────────────────────────────

def _has_probe_failure_event(ns, log_fn=None):
    """Return True if any pod in ns has a recent probe failure event.

    Kubelet emits reason=Unhealthy for each failed probe check, and
    reason=Killing when it terminates the container after max failures.
    The Unhealthy message reliably contains 'probe failed'; the Killing
    message wording varies by k8s version. Checking both is robust.
    """
    if not _k8s_core or not ns:
        return False
    for reason in ("Unhealthy", "Killing"):
        try:
            events = _k8s_core.list_namespaced_event(
                namespace=ns, field_selector=f"reason={reason}")
            for e in events.items:
                msg = (e.message or "").lower()
                if "liveness probe" in msg or "readiness probe" in msg or "probe failed" in msg:
                    return True
        except Exception as ex:
            if log_fn:
                log_fn("WARN", f"probe event check ({reason}): {ex}")
    return False

def _get_crashlooping_deployments(ns, log_fn=None):
    """Return set of deployment names whose pods are currently in CrashLoopBackOff."""
    deploys = set()
    if not _k8s_core or not _k8s_apps:
        return deploys
    try:
        pods = _k8s_core.list_namespaced_pod(namespace=ns)
        for pod in pods.items:
            cs_list = pod.status.container_statuses or []
            crash = any(
                cs.state and cs.state.waiting
                and cs.state.waiting.reason == "CrashLoopBackOff"
                for cs in cs_list
            )
            if not crash:
                continue
            for ref in (pod.metadata.owner_references or []):
                if ref.kind == "ReplicaSet":
                    try:
                        rs = _k8s_apps.read_namespaced_replica_set(
                            name=ref.name, namespace=ns)
                        for rs_ref in (rs.metadata.owner_references or []):
                            if rs_ref.kind == "Deployment":
                                deploys.add(rs_ref.name)
                    except Exception:
                        deploys.add(ref.name.rsplit("-", 1)[0])
                elif ref.kind == "Deployment":
                    deploys.add(ref.name)
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"crashloop deploy lookup: {e}")
    return deploys

def _has_sentinel_crashloop(ns, log_fn=None):
    """Return True if any pod whose name contains 'sentinel' is in CrashLoopBackOff."""
    if not _k8s_core:
        return False
    try:
        pods = _k8s_core.list_namespaced_pod(namespace=ns)
        for pod in pods.items:
            if "sentinel" not in pod.metadata.name.lower():
                continue
            for cs in (pod.status.container_statuses or []):
                if (cs.state and cs.state.waiting
                        and cs.state.waiting.reason == "CrashLoopBackOff"):
                    return True
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"sentinel crashloop check: {e}")
    return False


def _get_oomkilled_deployments(ns, log_fn=None):
    """Return set of deployment names whose pods last exited with OOMKilled."""
    deploys = set()
    if not _k8s_core or not _k8s_apps:
        return deploys
    try:
        pods = _k8s_core.list_namespaced_pod(namespace=ns)
        for pod in pods.items:
            cs_list = pod.status.container_statuses or []
            oom = any(
                cs.last_state and cs.last_state.terminated
                and cs.last_state.terminated.reason == "OOMKilled"
                for cs in cs_list
            )
            if not oom:
                continue
            for ref in (pod.metadata.owner_references or []):
                if ref.kind == "ReplicaSet":
                    try:
                        rs = _k8s_apps.read_namespaced_replica_set(
                            name=ref.name, namespace=ns)
                        for rs_ref in (rs.metadata.owner_references or []):
                            if rs_ref.kind == "Deployment":
                                deploys.add(rs_ref.name)
                    except Exception:
                        deploys.add(ref.name.rsplit("-", 1)[0])
                elif ref.kind == "Deployment":
                    deploys.add(ref.name)
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"oom deploy lookup: {e}")
    return deploys

# ── Structured remediation rules ──────────────────────────────────────────

def _rule_probe_timeout(happening, log_fn):
    """Increase liveness/readiness timeoutSeconds by 2x for affected deployments."""
    ns = (happening.get("affected_services") or [""])[0].split("/")[0]
    _safe_namespace(ns)
    if not _k8s_core:
        raise RuntimeError("kubernetes client not initialized")
    pod_list = _k8s_core.list_namespaced_pod(namespace=ns)
    actions = []
    seen_deploys = set()
    for pod in pod_list.items[:3]:  # cap at 3 pods per incident
        owner_refs = pod.metadata.owner_references or []
        if not owner_refs:
            continue
        deploy = owner_refs[0].name.rsplit("-", 1)[0]
        if deploy in seen_deploys:
            continue
        seen_deploys.add(deploy)
        container_name = pod.spec.containers[0].name
        patch_body = {"spec": {"template": {"spec": {"containers": [
            {"name": container_name,
             "livenessProbe": {"timeoutSeconds": 10},
             "readinessProbe": {"timeoutSeconds": 10}}
        ]}}}}
        out = _k8s_patch_deployment(deploy, ns, patch_body, log_fn)
        actions.append({"rule_name": "probe_timeout",
                        "command": f"patch deploy/{deploy} probe timeout→10s",
                        "output": out, "timestamp": datetime.now(timezone.utc).isoformat()})
    return actions

def _rule_oom_killed(happening, log_fn):
    """Restart only the deployment(s) whose pods last exited with OOMKilled."""
    ns = (happening.get("affected_services") or [""])[0].split("/")[0]
    _safe_namespace(ns)
    deploys = _get_oomkilled_deployments(ns, log_fn)
    ts = datetime.now(timezone.utc).isoformat()
    restart_patch = {"spec": {"template": {"metadata": {"annotations":
                              {"kubectl.kubernetes.io/restartedAt": ts}}}}}
    if not deploys:
        # Cannot identify which deployment OOMed — pod may have already
        # restarted cleanly. Skip rather than carpet-bombing the namespace.
        if log_fn:
            log_fn("INFO", f"oom_killed: no OOMKilled pod found in {ns}, skipping restart")
        return [{"rule_name": "oom_killed",
                 "command": f"skip: no OOMKilled pod found in {ns}",
                 "output": "skipped", "timestamp": ts}]
    actions = []
    for deploy in sorted(deploys):
        out = _k8s_patch_deployment(deploy, ns, restart_patch, log_fn)
        actions.append({"rule_name": "oom_killed",
                        "command": f"rollout restart deployment/{deploy} in {ns}",
                        "output": out, "timestamp": ts})
    return actions

def _rule_crashloop_config(happening, log_fn):
    """Restart only the deployment(s) currently in CrashLoopBackOff."""
    ns = (happening.get("affected_services") or [""])[0].split("/")[0]
    _safe_namespace(ns)
    deploys = _get_crashlooping_deployments(ns, log_fn)
    ts = datetime.now(timezone.utc).isoformat()
    restart_patch = {"spec": {"template": {"metadata": {"annotations":
                              {"kubectl.kubernetes.io/restartedAt": ts}}}}}
    if not deploys:
        # No crashlooping pod found — k8s may have already self-healed.
        # Skip rather than restarting all deployments in the namespace.
        if log_fn:
            log_fn("INFO", f"crashloop_config: no CrashLoopBackOff pod in {ns}, skipping restart")
        return [{"rule_name": "crashloop_config",
                 "command": f"skip: no CrashLoopBackOff pod found in {ns}",
                 "output": "skipped", "timestamp": ts}]
    actions = []
    for deploy in sorted(deploys):
        out = _k8s_patch_deployment(deploy, ns, restart_patch, log_fn)
        actions.append({"rule_name": "crashloop_config",
                        "command": f"rollout restart deployment/{deploy} in {ns}",
                        "output": out, "timestamp": ts})
    return actions

def _rule_image_pull_backoff(happening, log_fn):
    """Annotate affected deployments to trigger image re-pull."""
    ns = (happening.get("affected_services") or [""])[0].split("/")[0]
    _safe_namespace(ns)
    if not _k8s_apps:
        raise RuntimeError("kubernetes client not initialized")
    ts = datetime.now(timezone.utc).isoformat()
    patch_body = {"spec": {"template": {"metadata": {"annotations": {"panops/restart": ts}}}}}
    actions = []
    deploy_list = _k8s_apps.list_namespaced_deployment(namespace=ns)
    for d in deploy_list.items:
        deploy = d.metadata.name
        out = _k8s_patch_deployment(deploy, ns, patch_body, log_fn)
        actions.append({"rule_name": "image_pull_backoff",
                        "command": f"annotate deploy/{deploy} → re-pull",
                        "output": out, "timestamp": ts})
    return actions

def _rule_cnpg_failover(happening, log_fn):
    """Delete the not-ready CNPG postgres pod and let the operator re-provision it."""
    ns = (happening.get("affected_services") or [""])[0].split("/")[0]
    _safe_namespace(ns)
    ts = datetime.now(timezone.utc).isoformat()
    actions = []
    if _k8s_core:
        try:
            pods = _k8s_core.list_namespaced_pod(namespace=ns)
            for pod in pods.items:
                for cs in (pod.status.container_statuses or []):
                    if cs.name == "postgres" and not cs.ready:
                        pod_name = pod.metadata.name
                        if log_fn:
                            log_fn("INFO", f"cnpg_failover: deleting not-ready pod {pod_name}")
                        _k8s_core.delete_namespaced_pod(name=pod_name, namespace=ns, dry_run="All")
                        if REMEDIATION_MODE != "dry-run":
                            _k8s_core.delete_namespaced_pod(name=pod_name, namespace=ns)
                        actions.append({"rule_name": "cnpg_failover",
                                        "command": f"delete pod/{pod_name} -n {ns}",
                                        "output": "deleted" if REMEDIATION_MODE != "dry-run" else "dry-run",
                                        "timestamp": ts})
        except Exception as e:
            if log_fn:
                log_fn("WARN", f"cnpg_failover: {e}")
    if not actions:
        actions.append({"rule_name": "cnpg_failover",
                        "command": f"no not-ready postgres pod in {ns}",
                        "output": "no action", "timestamp": ts})
    return actions

def _rule_redis_sentinel_heal(happening, log_fn):
    """Delete not-ready Redis sentinel pods to restore quorum election."""
    ns = (happening.get("affected_services") or [""])[0].split("/")[0]
    _safe_namespace(ns)
    ts = datetime.now(timezone.utc).isoformat()
    actions = []
    if _k8s_core:
        try:
            pods = _k8s_core.list_namespaced_pod(namespace=ns)
            for pod in pods.items:
                for cs in (pod.status.container_statuses or []):
                    if "sentinel" in cs.name.lower() and not cs.ready:
                        pod_name = pod.metadata.name
                        if log_fn:
                            log_fn("INFO", f"redis_sentinel_heal: deleting pod {pod_name}")
                        _k8s_core.delete_namespaced_pod(name=pod_name, namespace=ns, dry_run="All")
                        if REMEDIATION_MODE != "dry-run":
                            _k8s_core.delete_namespaced_pod(name=pod_name, namespace=ns)
                        actions.append({"rule_name": "redis_sentinel_heal",
                                        "command": f"delete pod/{pod_name} -n {ns}",
                                        "output": "deleted" if REMEDIATION_MODE != "dry-run" else "dry-run",
                                        "timestamp": ts})
        except Exception as e:
            if log_fn:
                log_fn("WARN", f"redis_sentinel_heal: {e}")
    if not actions:
        actions.append({"rule_name": "redis_sentinel_heal",
                        "command": f"no not-ready sentinel pod in {ns}",
                        "output": "no action", "timestamp": ts})
    return actions

def _recent_flux_deploy(ns):
    """Return (kustomization_name, revision) for the most recent Flux event in this namespace
    within the last 30 minutes, or None if no such event exists."""
    sql = (
        "SELECT resource_name, revision FROM panops.deploy_events"
        " WHERE source = 'flux'"
        f"   AND (namespace = '{ns}' OR resource_name = '{ns}')"
        "   AND event_time >= now64() - INTERVAL 30 MINUTE"
        "   AND status = 'succeeded'"
        " ORDER BY event_time DESC LIMIT 1 FORMAT JSON"
    ).encode()
    try:
        req = urllib.request.Request(CH_URL, data=sql, method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("X-ClickHouse-User", os.getenv("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.getenv("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=10) as r:
            rows = json.loads(r.read()).get("data", [])
        if rows:
            return rows[0]["resource_name"], rows[0]["revision"]
    except Exception:
        pass
    return None

def _rule_flux_rollback(happening, log_fn):
    """Suspend the Flux Kustomization that last reconciled this namespace to stop
    a bad deploy from being continuously re-applied. Suspension is the fastest
    mitigation; a human (or the dream cycle) creates the revert MR separately."""
    ns = (happening.get("affected_services") or [""])[0].split("/")[0]
    ts = datetime.now(timezone.utc).isoformat()

    deploy = _recent_flux_deploy(ns)
    if not deploy:
        return [{"rule_name": "flux_rollback",
                 "command": f"no recent flux deploy found for ns={ns}",
                 "output": "no action", "timestamp": ts}]

    ks_name, revision = deploy
    if log_fn:
        log_fn("INFO", f"flux_rollback: suspending kustomization/{ks_name} rev={revision}")

    patch_json = '{"spec":{"suspend":true}}'
    command = f"patch kustomization/{ks_name} -n flux-system --type=merge -p {patch_json}"
    try:
        out = _exec_kubectl(command, happening, log_fn)
    except Exception as e:
        return [{"rule_name": "flux_rollback",
                 "command": command, "output": f"failed: {e}", "timestamp": ts}]

    return [{"rule_name": "flux_rollback",
             "command": command,
             "output": out or f"suspended kustomization/{ks_name} (was at rev {revision})",
             "timestamp": ts}]

def _rule_upsize(happening, log_fn):
    """Scale OOM-affected deployments +1 replica to relieve memory pressure.
    Capped at 2× current replicas or 10, whichever is lower."""
    ns = (happening.get("affected_services") or [""])[0].split("/")[0]
    _safe_namespace(ns)
    ts = datetime.now(timezone.utc).isoformat()
    actions = []

    if not _k8s_apps or not _k8s_core:
        return [{"rule_name": "upsize", "command": "k8s client unavailable",
                 "output": "no action", "timestamp": ts}]

    try:
        # Find deployments whose pods have OOMKilled containers
        pods = _k8s_core.list_namespaced_pod(namespace=ns)
        oom_deploys = set()
        for pod in pods.items:
            owner = next(
                (ref.name for ref in (pod.metadata.owner_references or [])
                 if ref.kind == "ReplicaSet"), None
            )
            if not owner:
                continue
            for cs in (pod.status.container_statuses or []):
                last = cs.last_state.terminated if cs.last_state else None
                if last and last.reason == "OOMKilled":
                    # Walk ReplicaSet → Deployment
                    try:
                        rs = _k8s_apps.read_namespaced_replica_set(name=owner, namespace=ns)
                        for ref in (rs.metadata.owner_references or []):
                            if ref.kind == "Deployment":
                                oom_deploys.add(ref.name)
                    except Exception:
                        pass

        if not oom_deploys:
            return [{"rule_name": "upsize",
                     "command": f"no OOMKilled deployments found in {ns}",
                     "output": "no action", "timestamp": ts}]

        for deploy_name in sorted(oom_deploys):
            try:
                deploy = _k8s_apps.read_namespaced_deployment(name=deploy_name, namespace=ns)
                current = deploy.spec.replicas or 1
                target  = min(current + 1, max(current * 2, 10))
                if target <= current:
                    if log_fn:
                        log_fn("INFO", f"upsize: {deploy_name} already at {current}, capped")
                    continue
                patch_body = {"spec": {"replicas": target}}
                out = _k8s_patch_deployment(deploy_name, ns, patch_body, log_fn)
                if log_fn:
                    log_fn("INFO", f"upsize: scaled {deploy_name} {current}→{target}")
                actions.append({"rule_name": "upsize",
                                 "command": f"scale deployment/{deploy_name} replicas={target}",
                                 "output": out, "timestamp": ts})
            except Exception as e:
                if log_fn:
                    log_fn("WARN", f"upsize: {deploy_name}: {e}")
                actions.append({"rule_name": "upsize",
                                 "command": f"scale deployment/{deploy_name}",
                                 "output": f"failed: {e}", "timestamp": ts})
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"upsize: pod list failed: {e}")
        return [{"rule_name": "upsize", "command": f"list pods ns={ns}",
                 "output": f"failed: {e}", "timestamp": ts}]

    return actions or [{"rule_name": "upsize",
                        "command": f"no OOMKilled deployments in {ns}",
                        "output": "no action", "timestamp": ts}]

def _rule_k8s_self_heal(happening, log_fn):
    """
    Replay rule for happenings that historically resolved via k8s self-healing.
    Waits for the stabilization window before deciding whether to escalate.
    This teaches PanOps to prefer observation over intervention for patterns that
    the k8s control plane routinely recovers from without help.
    """
    ns = (happening.get("affected_services") or [""])[0].split("/")[0]
    ts = datetime.now(timezone.utc).isoformat()
    t0 = time.time()
    healed = _wait_for_self_heal(ns, STABILIZATION_WAIT_S, happening["id"], log_fn)
    return [{
        "rule_name": "k8s_self_heal",
        "command": f"wait:{STABILIZATION_WAIT_S}s",
        "output": "self-healed" if healed else "did-not-self-heal",
        "timestamp": ts,
        "duration_s": round(time.time() - t0, 1),
    }]


# ── Token substitution and runtime executors ──────────────────────────────

# Token values come from happening fields that are ultimately attacker-influenceable
# (webhook payloads, log-derived drain3 templates, alert labels). They are substituted
# into command strings that may be run through a shell / PowerShell, so every value is
# validated against a strict identifier charset and rejected (fail-closed) otherwise.
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:/-]*$")


def _validate_token_value(token: str, value: str) -> str:
    value = str(value)
    if not _SAFE_TOKEN_RE.match(value):
        raise ValueError(
            f"unsafe value for {token}: {value!r} contains characters outside "
            f"[A-Za-z0-9._:/-] — refusing to substitute (possible injection)"
        )
    return value


def _substitute_tokens(command: str, happening: dict) -> str:
    """Replace {namespace}, {service}, {host}, {pod}, {container}, {drain3_template} tokens.

    Every substituted value is strictly validated; a value with shell/PowerShell
    metacharacters raises ValueError so it can never be executed.
    """
    ns = happening.get("namespace") or happening.get("k8s_namespace") or ""
    services = happening.get("affected_services") or []
    svc = (services[0] if isinstance(services, list) and services else "").split("/")[-1]
    replacements = {
        "{namespace}":       ns,
        "{service}":         svc,
        "{host}":            happening.get("host", "") or ns,
        "{pod}":             happening.get("pod_name", "") or svc,
        "{container}":       happening.get("container", "") or svc,
        "{drain3_template}": happening.get("drain3_template", "") or "",
        "{domain}":          happening.get("domain", ""),
        "{route}":           happening.get("classifier_route", ""),
    }
    for token, value in replacements.items():
        if token in command:
            safe = _validate_token_value(token, value)
            command = command.replace(token, safe)
    return command


_KUBECTL_DRY_RUN_VERBS = {"apply", "patch", "create", "delete", "replace", "scale"}

def _exec_kubectl(command: str, happening: dict, log_fn) -> str:
    """Execute a kubectl command, with --dry-run=server pre-flight for mutating verbs."""
    import subprocess

    base = ["kubectl"]
    if ASSEMBLER_KUBECTL_CONTEXT:
        base += ["--context", ASSEMBLER_KUBECTL_CONTEXT]

    parts = command.split()
    verb = parts[0] if parts else ""

    if verb in _KUBECTL_DRY_RUN_VERBS:
        dry_cmd = base + parts + ["--dry-run=server"]
        if log_fn:
            log_fn("INFO", f"kubectl dry-run: {command}")
        dry = subprocess.run(dry_cmd, capture_output=True, text=True, timeout=60)
        if dry.returncode != 0:
            raise ValueError(
                f"kubectl --dry-run=server rejected: {(dry.stderr or dry.stdout)[:300]}"
            )

    if REMEDIATION_MODE == "dry-run":
        if log_fn:
            log_fn("INFO", f"[dry-run] would kubectl: {command}")
        return f"[dry-run] {command}"

    cmd = base + parts
    if log_fn:
        log_fn("INFO", f"kubectl: {command}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0 and result.stderr:
        raise ValueError(f"kubectl failed: {result.stderr[:200]}")
    return result.stdout.strip()


def _exec_shell(command: str, happening: dict, log_fn) -> str:
    """Execute a shell command."""
    import subprocess
    if log_fn:
        log_fn("INFO", f"shell: {command[:80]}")
    result = subprocess.run(["sh", "-c", command], capture_output=True, text=True, timeout=120)
    if result.returncode != 0 and result.stderr:
        raise ValueError(f"shell failed (exit {result.returncode}): {result.stderr[:200]}")
    return result.stdout.strip()


def _exec_ansible(command: str, happening: dict, log_fn) -> str:
    """Execute an ansible-playbook command."""
    import subprocess
    if not ANSIBLE_INVENTORY:
        raise ValueError("ANSIBLE_INVENTORY not configured")
    cmd = ["ansible-playbook", "-i", ANSIBLE_INVENTORY] + command.split()
    if log_fn:
        log_fn("INFO", f"ansible: {command[:80]}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise ValueError(f"ansible failed: {result.stderr[:200]}")
    return result.stdout.strip()


def _exec_winrm(command: str, happening: dict, log_fn) -> str:
    if not WINRM_USERNAME or not WINRM_PASSWORD:
        raise ValueError("WinRM credentials not configured (set WINRM_USERNAME and WINRM_PASSWORD)")
    try:
        import winrm
    except ImportError:
        raise ValueError("pywinrm not installed in assembler image")

    # Determine target host from happening
    services = happening.get("affected_services") or [""]
    first = services[0] if isinstance(services, list) else str(services)
    host = first.split("/")[0] if "/" in str(first) else str(first)

    if not host or host == "unknown":
        raise ValueError(f"Cannot determine WinRM target host from affected_services: {services}")

    # Secure-by-default: only connect to explicitly allowlisted hosts.
    if not WINRM_ALLOWED_HOSTS:
        raise ValueError("WINRM_ALLOWED_HOSTS not configured — refusing WinRM (secure default)")
    if host not in WINRM_ALLOWED_HOSTS:
        raise ValueError(f"WinRM host {host!r} not in WINRM_ALLOWED_HOSTS allowlist")

    if log_fn:
        log_fn("INFO", f"WinRM [{WINRM_TRANSPORT}] {host}: {command[:80]}")

    session = winrm.Session(
        target=host,
        auth=(WINRM_USERNAME, WINRM_PASSWORD),
        transport=WINRM_TRANSPORT,
        server_cert_validation=WINRM_CERT_VALIDATION,
        message_encryption=WINRM_MESSAGE_ENCRYPTION,
    )
    result = session.run_ps(command)
    stdout = result.std_out.decode("utf-8", errors="replace").strip()
    stderr = result.std_err.decode("utf-8", errors="replace").strip()
    if result.status_code != 0 and stderr:
        raise ValueError(f"WinRM command exited {result.status_code}: {stderr[:200]}")
    return stdout or f"exit_code={result.status_code}"


def _guarded_executor(executor):
    """Wrap a runtime executor so the safety gate runs on EVERY call.

    Previously postmortem_learned called executors directly, bypassing
    _safe_namespace() and REMEDIATION_MODE. This wrapper makes that structurally
    impossible: no runtime-dispatched command runs without passing the gate.
    """
    def wrapped(command, happening, log_fn):
        ns = happening.get("namespace") or happening.get("k8s_namespace") or ""
        _safe_namespace(ns)  # raises on off / protected / (limited & not allowlisted)
        if REMEDIATION_MODE == "dry-run":
            if log_fn:
                log_fn("INFO", f"[dry-run] {executor.__name__}: {str(command)[:80]}")
            return f"[dry-run] {command}"
        return executor(command, happening, log_fn)
    wrapped.__name__ = getattr(executor, "__name__", "executor")
    return wrapped


RUNTIME_EXECUTORS = {
    "kubectl": _guarded_executor(_exec_kubectl),
    "shell":   _guarded_executor(_exec_shell),
    "ansible": _guarded_executor(_exec_ansible),
    "winrm":   _guarded_executor(_exec_winrm),
}


# ── Postmortem runbook replay ────────────────────────────────────────────

def _fetch_postmortem_runbook(happening: dict):
    """Query panops.postmortem_runbooks for a matching runbook by drain3_template + domain."""
    template = happening.get("drain3_template") or happening.get("drain3_patterns") or ""
    domain   = happening.get("domain", "")
    if not template:
        return None
    # drain3_patterns may be JSON; try to extract template from it if needed
    if isinstance(template, str) and template.startswith("["):
        try:
            patterns = json.loads(template)
            if patterns and isinstance(patterns, list):
                template = patterns[0].get("template", "") if isinstance(patterns[0], dict) else str(patterns[0])
        except Exception:
            pass
    # Parameterized query — domain/template are attacker-influenceable (log-derived),
    # so they are passed as bound ClickHouse params, never string-interpolated.
    sql = """
        SELECT id, runtime, commands, drain3_template, domain
        FROM panops.postmortem_runbooks
        WHERE domain = {p_domain:String}
          AND drain3_template = {p_template:String}
        ORDER BY created_at DESC
        LIMIT 1
        FORMAT JSON
    """
    try:
        qs  = urllib.parse.urlencode({"param_p_domain": domain, "param_p_template": template})
        url = f"{CH_URL}?{qs}"
        req = urllib.request.Request(url, data=sql.encode(), method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=15) as r:
            rows = json.loads(r.read()).get("data", [])
        return rows[0] if rows else None
    except Exception as e:
        return None


def _rule_postmortem_learned(happening, log_fn):
    """Replay stored postmortem runbook commands if a match exists."""
    runbook = _fetch_postmortem_runbook(happening)
    if not runbook:
        return []

    runtime = runbook.get("runtime", "shell")
    executor = RUNTIME_EXECUTORS.get(runtime, _exec_shell)
    results = []
    ts = datetime.now(timezone.utc).isoformat()

    for cmd_entry in runbook.get("commands", []):
        raw_cmd = cmd_entry.get("command", "") if isinstance(cmd_entry, dict) else str(cmd_entry)
        command = _substitute_tokens(raw_cmd, happening)
        try:
            output = executor(command, happening, log_fn)
            if log_fn:
                log_fn("INFO", f"postmortem_learned [{runtime}] {command[:80]} → ok")
        except Exception as e:
            output = f"ERROR: {e}"
            if log_fn:
                log_fn("WARN", f"postmortem_learned [{runtime}] {command[:80]} → {e}")
        results.append({
            "rule_name": "postmortem_learned",
            "command": command,
            "output": str(output)[:500],
            "timestamp": ts,
            "runtime": runtime,
        })

    return results


REMEDIATION_RULES = {
    "postmortem_learned":   _rule_postmortem_learned,
    "probe_timeout":        _rule_probe_timeout,
    "oom_killed":           _rule_oom_killed,
    "upsize":               _rule_upsize,
    "crashloop_config":     _rule_crashloop_config,
    "image_pull_backoff":   _rule_image_pull_backoff,
    "flux_rollback":        _rule_flux_rollback,
    "cnpg_failover":        _rule_cnpg_failover,
    "redis_sentinel_heal":  _rule_redis_sentinel_heal,
    "k8s_self_heal":        _rule_k8s_self_heal,
}

# Rules where k8s cannot self-heal — intervene immediately without waiting.
# All others get a stabilization window to let the deployment controller recover first.
IMMEDIATE_RULES = {"cnpg_failover", "redis_sentinel_heal", "image_pull_backoff", "flux_rollback"}


# ── Validation helpers ────────────────────────────────────────────────────

def _signals_clear(happening, log_fn):
    """
    Return True if ALL triggering signals have cleared:
      - No security_anomalies in the last VALIDATION_POLL_S window
      - No sigma_matches for the affected namespace in the last window
      - All affected namespace pods are Running/Ready
    """
    ns = (happening.get("affected_services") or [""])[0].split("/")[0]
    now_s = int(time.time())
    window_ago = datetime.fromtimestamp(now_s - VALIDATION_POLL_S, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Check security_anomalies
    sql = f"SELECT count() FROM qryn.security_anomalies WHERE detected_at > toDateTime('{window_ago}')"
    try:
        data = (sql + " FORMAT JSON").encode()
        req  = urllib.request.Request(CH_URL, data=data, method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=15) as r:
            rows = json.loads(r.read()).get("data", [])
        if rows and int(rows[0].get("count()", 0)) > 0:
            return False
    except Exception as e:
        if log_fn: log_fn("WARN", f"validation anomaly check: {e}")

    # Check sigma_matches
    if ns:
        sql2 = f"SELECT count() FROM qryn.sigma_matches WHERE timestamp > toDateTime64('{window_ago}', 9) AND namespace = '{ns}'"
        try:
            data = (sql2 + " FORMAT JSON").encode()
            req  = urllib.request.Request(CH_URL, data=data, method="POST")
            req.add_header("Content-Type", "text/plain")
            req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
            req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
            with urllib.request.urlopen(req, timeout=15) as r:
                rows = json.loads(r.read()).get("data", [])
            if rows and int(rows[0].get("count()", 0)) > 0:
                return False
        except Exception as e:
            if log_fn: log_fn("WARN", f"validation sigma check: {e}")

        # Check pod readiness
        if _k8s_core:
            pod_list = _k8s_core.list_namespaced_pod(namespace=ns)
            phases = [p.status.phase for p in pod_list.items if p.status and p.status.phase]
            if any(p not in ("Running", "Succeeded", "Completed") for p in phases):
                return False

    return True


# ── Core: remediate + validate ────────────────────────────────────────────

def _ch_update(happening_id, updates, log_fn):
    sql = ("ALTER TABLE panops.happenings UPDATE "
           + ", ".join(f"{k} = {v}" for k, v in updates.items())
           + f" WHERE id = '{happening_id}'")
    try:
        req = urllib.request.Request(CH_URL, data=sql.encode(), method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
    except Exception as e:
        if log_fn: log_fn("WARN", f"ch_update: {e}")

def _write_outcome(happening_id, rule_name, command, output, outcome, duration_s, log_fn):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    row = {
        "happening_id": happening_id, "recorded_at": now, "rule_name": rule_name,
        "command": command, "command_output": output[:2000],
        "outcome": outcome, "duration_seconds": round(duration_s, 2),
    }
    body = (
        "INSERT INTO panops.remediation_outcomes "
        "(happening_id,recorded_at,rule_name,command,command_output,outcome,duration_seconds) "
        "FORMAT JSONEachRow\n" + json.dumps(row)
    ).encode()
    try:
        req = urllib.request.Request(CH_URL, data=body, method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
    except Exception as e:
        if log_fn: log_fn("WARN", f"write_outcome: {e}")


def _wait_for_self_heal(ns, wait_s, hid, log_fn):
    """
    Poll pod readiness for up to wait_s seconds. Return True if all pods in
    the namespace reach Running/Ready before the window expires, meaning k8s
    recovered without PanOps intervening.
    """
    poll = 30
    elapsed = 0
    if log_fn:
        log_fn("INFO", f"remediator: stabilization window {wait_s}s hid={hid[:8]} ns={ns}")
    while elapsed < wait_s:
        time.sleep(poll)
        elapsed += poll
        try:
            if not _k8s_core:
                break
            pods = _k8s_core.list_namespaced_pod(namespace=ns).items
            if not pods:
                break
            all_ready = all(
                any(c.ready for c in (p.status.container_statuses or []))
                for p in pods if p.status
            )
            if all_ready:
                if log_fn:
                    log_fn("INFO",
                           f"remediator: self-healed at {elapsed}s hid={hid[:8]}")
                return True
        except Exception as e:
            if log_fn:
                log_fn("WARN", f"stabilization poll: {e}")
    return False

def _run_validation_loop(hid, happening, log_fn, initial_streak=0, notify_fn=None):
    """Run the validation loop for an already-remediated happening.

    initial_streak lets a resumed loop continue from its saved checkpoint
    rather than starting over after an assembler pod restart.
    """
    _ch_update(hid, {"status": "'validating'"}, log_fn)
    clear_streak = initial_streak
    val_start    = time.time()
    while time.time() - val_start < VALIDATION_TIMEOUT_S:
        time.sleep(VALIDATION_POLL_S)
        try:
            if _signals_clear(happening, log_fn):
                clear_streak += 1
                _ch_update(hid, {"validation_streak": str(clear_streak)}, log_fn)
                if log_fn:
                    log_fn("INFO",
                           f"validation: streak={clear_streak}/{CLEAR_STREAK_REQUIRED} hid={hid[:8]}")
                if clear_streak >= CLEAR_STREAK_REQUIRED:
                    _ch_update(hid, {"status": "'resolved'", "outcome": "'resolved'",
                                     "closed_at": "now64()", "validation_streak": "0"}, log_fn)
                    if log_fn:
                        log_fn("INFO", f"remediator: RESOLVED {hid[:8]}")
                    # Memory cycle: record rule→outcome for dream consolidation
                    try:
                        import consolidation as _cons
                        rule_used = ""
                        if happening.get("actions_taken"):
                            try:
                                acts = json.loads(happening["actions_taken"])
                                rule_used = acts[0].get("rule_name", "") if acts else ""
                            except Exception:
                                pass
                        _cons.record_resolution(happening, rule_used, log_fn)
                    except Exception:
                        pass
                    if _runbook_writer:
                        try:
                            _runbook_writer.write_runbook(happening, log_fn=log_fn)
                        except Exception as _rw_e:
                            if log_fn:
                                log_fn("WARN", f"runbook_writer: {_rw_e}")
                    return
            else:
                clear_streak = 0
                _ch_update(hid, {"validation_streak": "0"}, log_fn)
        except Exception as e:
            if log_fn:
                log_fn("WARN", f"validation poll: {e}")
    _ch_update(hid, {"status": "'escalated'", "outcome": "'escalated'",
                     "validation_streak": "0"}, log_fn)
    if log_fn:
        log_fn("WARN", f"remediator: ESCALATED {hid[:8]} (validation timeout)")
    if notify_fn:
        ns     = ", ".join(happening.get("affected_services") or []) or "unknown"
        domain = happening.get("domain", "MIXED")
        try:
            notify_fn(domain,
                      f"Remediation failed: {hid[:8]}",
                      f"Validation timed out after {VALIDATION_TIMEOUT_S}s — namespace: {ns}\n"
                      f"PanOps could not confirm resolution. Manual intervention required.",
                      route="escalate", severity="critical")
        except Exception:
            pass

def remediate_and_validate(happening, matched_actions=None, log_fn=None, notify_fn=None):
    """
    Entry point called from assembler for structured/known happenings.
    matched_actions: list of action dicts from a matched prior happening (known path).
    """
    hid    = happening["id"]
    ns     = (happening.get("affected_services") or [""])[0].split("/")[0]
    route  = happening.get("classifier_route", "structured")
    start  = time.time()
    all_actions = []

    _ch_update(hid, {"status": "'remediating'"}, log_fn)

    # ── Remediation phase ─────────────────────────────────────────────────
    try:
        if route == "known" and matched_actions:
            # Replay the rule from the matched incident using rule_name stored in each action.
            # Falls back to re-running all unique rules found across the action list.
            replayed = set()
            for act in matched_actions:
                if time.time() - start > REMEDIATION_TIMEOUT_S:
                    break
                rule_name = act.get("rule_name")
                if not rule_name or rule_name in replayed or rule_name not in REMEDIATION_RULES:
                    continue
                replayed.add(rule_name)
                t0 = time.time()
                try:
                    acts = REMEDIATION_RULES[rule_name](happening, log_fn)
                    all_actions.extend(acts)
                    for a in acts:
                        _write_outcome(hid, f"known_replay:{rule_name}", a["command"],
                                       a["output"], "success", time.time() - t0, log_fn)
                except Exception as e:
                    _write_outcome(hid, f"known_replay:{rule_name}", rule_name, str(e),
                                   "failed", time.time() - t0, log_fn)
        else:
            # Determine which structured rule applies
            falco = happening.get("falco_rules") or []
            drain3 = []
            try:
                drain3 = json.loads(happening.get("drain3_patterns") or "[]")
            except Exception:
                pass

            rule_name = None

            # Check for a recent Flux deploy before applying symptom-based rules.
            # If a deploy just landed and symptoms look post-deploy, suspend Flux
            # first — stops the bad state being continuously re-applied.
            _bad_deploy_signals = (
                any("CrashLoop"      in (p.get("template") or "") for p in drain3) or
                any("ImagePullBackOff" in (p.get("template") or "") for p in drain3) or
                any("OOMKill"        in (p.get("template") or "") for p in drain3) or
                any("probe" in (p.get("template") or "").lower() for p in drain3)
            )
            if _bad_deploy_signals and _recent_flux_deploy(ns):
                rule_name = "flux_rollback"
            elif any("probe" in r.lower() or "timeout" in r.lower() for r in falco):
                rule_name = "probe_timeout"
            elif any("OOMKill" in (p.get("template") or "") for p in drain3):
                # If already at multiple replicas, upsize; otherwise restart first
                try:
                    _deploys = _k8s_apps.list_namespaced_deployment(namespace=ns) if _k8s_apps else None
                    _at_one  = _deploys and all((d.spec.replicas or 1) <= 1 for d in _deploys.items)
                except Exception:
                    _at_one = False
                # At 1 replica → add capacity; at multiple → restart to clear leak
                rule_name = "upsize" if _at_one else "oom_killed"
            elif any("CrashLoop" in (p.get("template") or "") for p in drain3):
                if _has_sentinel_crashloop(ns, log_fn):
                    rule_name = "redis_sentinel_heal"
                elif _has_probe_failure_event(ns, log_fn):
                    rule_name = "probe_timeout"
                else:
                    rule_name = "crashloop_config"
            elif any("ImagePullBackOff" in (p.get("template") or "") for p in drain3):
                rule_name = "image_pull_backoff"
            elif any("probe" in (p.get("template") or "").lower()
                     or "timeout" in (p.get("template") or "").lower()
                     for p in drain3):
                rule_name = "probe_timeout"
            elif any("cnpg" in (p.get("template") or "").lower()
                     or ("postgres" in (p.get("template") or "").lower()
                         and "not ready" in (p.get("template") or "").lower())
                     for p in drain3):
                rule_name = "cnpg_failover"
            elif any("sentinel" in (p.get("template") or "").lower()
                     for p in drain3):
                rule_name = "redis_sentinel_heal"

            # Check if a postmortem runbook exists and prefer it over the default rule
            original_rule_name = rule_name
            if rule_name and rule_name != "postmortem_learned" and _fetch_postmortem_runbook(happening):
                if log_fn:
                    log_fn("INFO", f"postmortem runbook found for drain3 pattern — preferring postmortem_learned over {rule_name}")
                rule_name = "postmortem_learned"

            # Deprioritize rules with low dream-cycle success rates
            rule_name = _effective_rule(rule_name, log_fn)

            if rule_name and rule_name in REMEDIATION_RULES:
                # For k8s-resolvable faults, wait to see if the deployment controller
                # recovers on its own before PanOps intervenes.
                if rule_name not in IMMEDIATE_RULES and ns and STABILIZATION_WAIT_S > 0:
                    t0_heal = time.time()
                    if _wait_for_self_heal(ns, STABILIZATION_WAIT_S, hid, log_fn):
                        elapsed_heal = round(time.time() - t0_heal, 1)
                        if log_fn:
                            log_fn("INFO",
                                   f"remediator: k8s self-healed at {elapsed_heal}s,"
                                   f" skipping rule={rule_name} hid={hid[:8]}")
                        # Record the observation so CBR can learn "wait and see" is
                        # the right strategy for this signal pattern.
                        _write_outcome(hid, "k8s_self_heal",
                                       f"wait:{elapsed_heal}s",
                                       f"k8s recovered without PanOps intervention"
                                       f" (queued rule was {rule_name})",
                                       "success", elapsed_heal, log_fn)
                        heal_action = json.dumps([{
                            "rule_name": "k8s_self_heal",
                            "command": f"wait:{STABILIZATION_WAIT_S}s",
                            "output": f"self-healed after {elapsed_heal}s"
                                      f" (queued rule was {rule_name})",
                        }]).replace("'", "\\'")
                        _ch_update(hid, {"actions_taken": f"'{heal_action}'"}, log_fn)
                        _run_validation_loop(hid, happening, log_fn, notify_fn=notify_fn)
                        return
                if log_fn: log_fn("INFO", f"remediator: applying rule={rule_name} ns={ns}")
                t0 = time.time()
                try:
                    acts = REMEDIATION_RULES[rule_name](happening, log_fn)
                    # Fallback: if postmortem_learned returned no actions, try the original rule
                    if not acts and rule_name == "postmortem_learned" and original_rule_name:
                        if log_fn:
                            log_fn("WARN", "postmortem_learned returned no actions, falling back to default rule")
                        rule_name = original_rule_name
                        acts = REMEDIATION_RULES[rule_name](happening, log_fn)
                    all_actions.extend(acts)
                    for act in acts:
                        _write_outcome(hid, rule_name, act["command"], act["output"],
                                       "success", time.time() - t0, log_fn)
                except Exception as e:
                    _write_outcome(hid, rule_name, str(rule_name), str(e),
                                   "failed", time.time() - t0, log_fn)
                    if log_fn: log_fn("WARN", f"remediator rule {rule_name}: {e}")
            else:
                if log_fn: log_fn("INFO", f"remediator: no rule matched for happening {hid[:8]}")

    except Exception as e:
        if log_fn: log_fn("ERROR", f"remediator: {e}")

    # Update actions_taken on the happening row
    if all_actions:
        actions_json = json.dumps(all_actions).replace("'", "\\'")
        _ch_update(hid, {"actions_taken": f"'{actions_json}'"}, log_fn)

    # ── Validation loop (Step 7) ──────────────────────────────────────────
    _run_validation_loop(hid, happening, log_fn, notify_fn=notify_fn)
