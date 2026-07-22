"""
PanOps Brain — Happening Assembler (Step 2)
Receives Grafana webhook alerts and polls ClickHouse for new sigma/anomaly signals.
For each trigger, assembles a composite happening and writes to panops.happenings.
Metric correlator (Step 3) and classifier similarity path (Step 5) slot in here later.
"""
import base64
import html
import json
import os
import sys
import threading
import time
import uuid
import urllib.request
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone, timedelta

try:
    import bcrypt as _bcrypt
except ImportError:
    _bcrypt = None

# correlator.py lives alongside this script in /scripts/
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import correlator as _correlator
except ImportError:
    _correlator = None
try:
    import drain3_detector as _drain3
except ImportError:
    _drain3 = None
XOPS_ML_ENABLED  = os.getenv("XOPS_ML_ENABLED",  "true").lower() not in ("false", "0", "no")
XOPS_LLM_ENABLED = os.getenv("XOPS_LLM_ENABLED", "true").lower() not in ("false", "0", "no")

if XOPS_ML_ENABLED:
    try:
        import classifier as _classifier
    except ImportError:
        _classifier = None
else:
    _classifier = None
try:
    import remediator as _remediator
except ImportError:
    _remediator = None
try:
    import runbook_writer as _runbook_writer  # noqa: F401 — imported by remediator
except ImportError:
    _runbook_writer = None
if XOPS_ML_ENABLED:
    try:
        import consolidation as _consolidation
    except ImportError:
        _consolidation = None
else:
    _consolidation = None

CH_URL             = os.getenv("CH_URL",   "http://observability-clickhouse-clickhouse-headless.observability.svc.cluster.local:8123")
LOKI_URL           = os.getenv("LOKI_URL", "http://gigapipe.observability.svc.cluster.local:3100")
PROM_URL           = os.getenv("PROM_URL", "http://gigapipe.observability.svc.cluster.local:3100")
LLAMA_SERVER_URL   = os.getenv("LLAMA_SERVER_URL", "http://panops-llama-server.panops.svc:8080")
LLM_EXTERNAL_URL   = os.getenv("LLM_EXTERNAL_URL", "")
LLM_EXTERNAL_TOKEN = os.getenv("LLM_EXTERNAL_TOKEN", "")
LLM_CONFIDENCE_THR = float(os.getenv("LLM_CONFIDENCE_THRESHOLD", "0.6"))
WEB_SEARCH_ENABLED  = os.getenv("WEB_SEARCH_ENABLED", "false").lower() == "true"
POLL_INTERVAL       = int(os.getenv("POLL_INTERVAL_S", "60"))
K8S_GRACE_S        = int(os.getenv("K8S_GRACE_S", "300"))  # wait before LLM; lets k8s self-heal
LISTEN_PORT        = int(os.getenv("LISTEN_PORT", "8080"))
_MAX_WEBHOOK_BODY = 1 * 1024 * 1024  # 1 MB

# ── Postmortem Learning UI auth ───────────────────────────────────────────────
POSTMORTEM_PASSWORD = os.environ.get("POSTMORTEM_PASSWORD", "")
POSTMORTEM_USERNAME = os.environ.get("POSTMORTEM_USERNAME", "")
_PM_HASH = None
_PM_USER = ""

FALCO_CRITICAL_RULES = {
    "Terminal Shell in Container",
    "Contact K8S API Server",
    "Detect crypto miners",
    "Write below root",
}

_state = {
    "sigma_cursor":   None,
    "anomaly_cursor": None,
    "lock":           threading.Lock(),
}

_HEARTBEAT_INTERVAL = 300  # write heartbeat row every 5 minutes

# Limit concurrent metric-correlator threads so gigapipe isn't flooded
_CORRELATOR_SEM = threading.Semaphore(4)
# Cap concurrent poll-triggered assemble() calls so a sigma burst across
# many namespaces can't block the poll thread past the watchdog threshold
_POLL_SEM = threading.Semaphore(4)
# Cap concurrent remediation/LLM threads so a burst of happenings can't
# exhaust the thread pool or flood the LLM service
_REMEDIATION_SEM = threading.Semaphore(4)
_LLM_SEM = threading.Semaphore(2)
# Cap concurrent ClickHouse operations. CH default max_concurrent_queries=100
# (raised from 20); this semaphore keeps the assembler's share bounded so
# sigma-scanner and qryn always have headroom. On HTTP 500 (code 202
# TOO_MANY_SIMULTANEOUS_QUERIES) we release the slot, back off, and retry.
_CH_SEM = threading.Semaphore(12)

# Per-namespace locks to serialize the dedup-check+insert to prevent race conditions
# when concurrent webhooks arrive for the same namespace.
_NS_LOCKS: dict = {}
_NS_LOCKS_MU = threading.Lock()


def _get_ns_lock(ns: str) -> threading.Lock:
    with _NS_LOCKS_MU:
        if ns not in _NS_LOCKS:
            _NS_LOCKS[ns] = threading.Lock()
        return _NS_LOCKS[ns]

# Watchdog: poll_loop updates this; daemon thread exits if stale > 3× poll interval
_last_poll_time = [time.time()]  # mutable container so inner function can write it

# Dream cycle mutex to prevent concurrent runs
_DREAM_LOCK = threading.Lock()

# LLM circuit breaker: open if >3 job failures within 1 hour
_llm_circuit = {
    "open":     False,
    "failures": [],        # epoch timestamps of recent failures
    "lock":     threading.Lock(),
}

def log(level, msg):
    ts = datetime.now(timezone.utc).isoformat()
    print(f"{ts} [{level}] {msg}", flush=True)

# ── Postmortem auth init ──────────────────────────────────────────────────

def _init_postmortem_auth():
    """Initialize postmortem auth: hash password if configured."""
    global _PM_HASH, _PM_USER
    if POSTMORTEM_PASSWORD and _bcrypt:
        _PM_HASH = _bcrypt.hashpw(POSTMORTEM_PASSWORD.encode(), _bcrypt.gensalt())
        _PM_USER = POSTMORTEM_USERNAME
        log("INFO", f"postmortem auth enabled (user={_PM_USER})")
    else:
        _PM_HASH = None
        _PM_USER = ""
        if POSTMORTEM_PASSWORD and not _bcrypt:
            log("WARN", "postmortem password set but bcrypt not installed")

def _check_postmortem_auth(handler) -> bool:
    """Check Basic auth for postmortem endpoints. Returns True if authorized.

    Fails closed: postmortem runbooks are replayed as remediation commands, so
    the endpoints require auth to be configured (POSTMORTEM_PASSWORD + bcrypt).
    """
    if _PM_HASH is None:
        handler.send_response(403)
        handler.end_headers()
        return False
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        handler.send_response(401)
        handler.send_header("WWW-Authenticate", 'Basic realm="PanOps Postmortem"')
        handler.end_headers()
        return False
    try:
        decoded = base64.b64decode(auth[6:]).decode()
        user, pw = decoded.split(":", 1)
        if user != _PM_USER:
            raise ValueError("username mismatch")
        if not _bcrypt.checkpw(pw.encode(), _PM_HASH):
            raise ValueError("password mismatch")
        return True
    except Exception:
        handler.send_response(401)
        handler.send_header("WWW-Authenticate", 'Basic realm="PanOps Postmortem"')
        handler.end_headers()
        return False

# ── Grafana Alertmanager notifications ───────────────────────────────────────

def _send_notification(domain, title, body, route="", severity="warning"):
    """Log a notification. Alerting is handled by Grafana alert rules querying
    panops.happenings directly — no external push needed."""
    log("INFO", f"notify [{domain}/{severity}] {title}: {body[:120]}")

# ── ClickHouse helpers ────────────────────────────────────────────────────

def ch_query(sql):
    data = (sql.strip() + " FORMAT JSON").encode()
    for attempt in range(3):
        with _CH_SEM:
            try:
                req = urllib.request.Request(CH_URL, data=data, method="POST")
                req.add_header("Content-Type", "text/plain")
                req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
                req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
                with urllib.request.urlopen(req, timeout=30) as r:
                    return json.loads(r.read())
            except (urllib.error.HTTPError, urllib.error.URLError) as e:
                if attempt < 2 and (not isinstance(e, urllib.error.HTTPError) or e.code == 500):
                    pass
                else:
                    raise
        time.sleep(0.5 * (2 ** attempt))

def ch_exec(sql, params=None):
    """Execute a statement. Pass `params` to use ClickHouse bound parameters
    ({name:Type} placeholders in sql) so untrusted values are never interpolated."""
    data = sql.strip().encode()
    url = CH_URL
    if params:
        qs  = urllib.parse.urlencode({f"param_{k}": ("" if v is None else str(v)) for k, v in params.items()})
        url = f"{CH_URL}?{qs}"
    for attempt in range(3):
        with _CH_SEM:
            try:
                req = urllib.request.Request(url, data=data, method="POST")
                req.add_header("Content-Type", "text/plain")
                req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
                req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
                with urllib.request.urlopen(req, timeout=60) as r:
                    r.read()
                    return
            except (urllib.error.HTTPError, urllib.error.URLError) as e:
                if attempt < 2 and (not isinstance(e, urllib.error.HTTPError) or e.code == 500):
                    pass
                else:
                    raise
        time.sleep(0.5 * (2 ** attempt))

def ch_insert_happening(row):
    cols = (
        "id,opened_at,closed_at,window_start,window_end,affected_services,"
        "domain,classifier_route,similarity_score,matched_incident_id,"
        "status,outcome,runbook_ref,falco_rules,sigma_rule_ids,yara_matches,"
        "drain3_patterns,metric_anomalies,metric_correlations,actions_taken"
    )
    body = (
        f"INSERT INTO panops.happenings ({cols}) FORMAT JSONEachRow\n"
        + json.dumps(row)
    ).encode()
    for attempt in range(3):
        with _CH_SEM:
            try:
                req = urllib.request.Request(CH_URL, data=body, method="POST")
                req.add_header("Content-Type", "text/plain")
                req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
                req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
                with urllib.request.urlopen(req, timeout=30) as r:
                    r.read()
                    return
            except urllib.error.HTTPError as e:
                if e.code == 500 and attempt < 2:
                    pass
                else:
                    raise
        time.sleep(0.5 * (2 ** attempt))

# ── Loki helper ──────────────────────────────────────────────────────────

def loki_query_range(logql, start_ns, end_ns, limit=500):
    params = {
        "query": logql, "start": str(start_ns), "end": str(end_ns),
        "limit": str(limit), "direction": "backward",
    }
    url = f"{LOKI_URL}/loki/api/v1/query_range?{urllib.parse.urlencode(params)}"
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.loads(r.read())

# ── Signal gatherers ──────────────────────────────────────────────────────

def gather_sigma(namespace, ws_iso, we_iso):
    ns_clause = f"AND namespace = '{namespace}'" if namespace else ""
    sql = f"""
        SELECT rule_id, rule_title, rule_level
        FROM qryn.sigma_matches
        WHERE timestamp >= toDateTime64('{ws_iso}', 9)
          AND timestamp <  toDateTime64('{we_iso}', 9)
          {ns_clause}
        ORDER BY timestamp DESC
        LIMIT 50
    """
    try:
        rows = ch_query(sql).get("data", [])
        return [r["rule_id"] for r in rows]
    except Exception as e:
        log("WARN", f"sigma gather: {e}")
        return []

def gather_deploy_events(namespace, ws_iso, we_iso):
    ns_clause = (
        f"AND (namespace = '{namespace}' OR resource_name = '{namespace}')"
        if namespace else ""
    )
    sql = f"""
        SELECT event_time, source, event_type, namespace, resource_name, revision, status, actor, message
        FROM panops.deploy_events
        WHERE event_time >= toDateTime64('{ws_iso[:19]}', 3)
          AND event_time <  toDateTime64('{we_iso[:19]}', 3)
          {ns_clause}
        ORDER BY event_time DESC
        LIMIT 20
    """
    try:
        rows = ch_query(sql).get("data", [])
        return [
            {
                "event_time":    r["event_time"],
                "source":        r["source"],
                "event_type":    r["event_type"],
                "resource_name": r["resource_name"],
                "revision":      r["revision"],
                "status":        r["status"],
                "actor":         r["actor"],
                "message":       r["message"],
            }
            for r in rows
        ]
    except Exception as e:
        log("WARN", f"deploy events gather: {e}")
        return []

def gather_anomalies(ws_iso, we_iso):
    sql = f"""
        SELECT metric_name, deviation_ratio
        FROM qryn.security_anomalies
        WHERE detected_at >= toDateTime('{ws_iso[:19]}')
          AND detected_at <  toDateTime('{we_iso[:19]}')
        ORDER BY deviation_ratio DESC
        LIMIT 20
    """
    try:
        rows = ch_query(sql).get("data", [])
        return [{"metric": r["metric_name"], "deviation_ratio": float(r["deviation_ratio"])} for r in rows]
    except Exception as e:
        log("WARN", f"anomaly gather: {e}")
        return []

def gather_drain3(namespace, ws_ns, we_ns):
    # Query Loki for log lines in the window; count unique Drain3 pattern labels.
    # qryn exposes pattern labels on streams when the Drain3 parser is enabled.
    ns_filter = (f'{{exporter="loki", k8s_namespace_name="{namespace}"}}'
                 if namespace else '{exporter="loki"}')
    try:
        result = loki_query_range(ns_filter, ws_ns, we_ns, limit=200)
        streams = result.get("data", {}).get("result", [])
        counts = {}
        for stream in streams:
            tmpl = stream.get("stream", {}).get("pattern") or stream.get("stream", {}).get("detected_level", "unknown")
            counts[tmpl] = counts.get(tmpl, 0) + len(stream.get("values", []))
        return [
            {"template": t, "count": c, "is_novel": False}
            for t, c in sorted(counts.items(), key=lambda x: -x[1])[:20]
        ]
    except Exception as e:
        log("WARN", f"drain3 gather: {e}")
        return []

def gather_yara(ws_ns, we_ns):
    """Query Loki for YARA match log lines and return unique rule names."""
    logql = '{k8s_namespace_name="security"} |= "yara_match"'
    try:
        result = loki_query_range(logql, ws_ns, we_ns, limit=100)
        streams = result.get("data", {}).get("result", [])
        rules = set()
        for stream in streams:
            for _, line in stream.get("values", []):
                try:
                    obj = json.loads(line)
                    match_str = obj.get("yara_match", "")
                    if match_str:
                        # "RuleName /path/to/file" — take only the rule name part
                        rules.add(match_str.split()[0])
                except Exception:
                    pass
        return sorted(rules)
    except Exception as e:
        log("WARN", f"yara gather: {e}")
        return []

# ── Fast classifier ───────────────────────────────────────────────────────

def fast_classify(falco_rules, sigma_ids, drain3_patterns, metric_anomalies):
    if any(r in FALCO_CRITICAL_RULES for r in falco_rules):
        return "SOC", "known"
    if sigma_ids:
        return "SOC", "structured"
    if any(p.get("is_novel") and p.get("falco_correlated") for p in drain3_patterns):
        return "MIXED", "escalate"
    if any(p.get("is_novel") for p in drain3_patterns):
        # Falco + novel drain3 → SOC (Falco signal takes precedence over MIXED)
        if falco_rules:
            return "SOC", "novel"
        return "MIXED", "novel"
    if metric_anomalies and not falco_rules:
        return "SRE", "structured"
    if falco_rules:
        return "SOC", "structured"
    return "MIXED", "structured"

# ── LLM Job spawner (Step 9) ──────────────────────────────────────────────

# ── Deduplication helpers ─────────────────────────────────────────────────

def _find_open_happening(namespace, falco_rule):
    """Return most recent open happening id covering this namespace/rule, or None."""
    ns_clause = (
        f"AND has(affected_services, '{namespace}')" if namespace
        else "AND length(affected_services) = 0"
    )
    rule_clause = (
        f"AND has(falco_rules, '{falco_rule.replace(chr(39), chr(39)*2)}')"
        if falco_rule else ""
    )
    sql = (
        "SELECT toString(id) AS id FROM panops.happenings"
        " WHERE status IN ('open', 'remediating', 'validating')"
        "   AND classifier_route != 'heartbeat'"
        "   AND window_end > now64() - INTERVAL 30 MINUTE"
        f"  {ns_clause} {rule_clause}"
        " ORDER BY opened_at DESC LIMIT 1"
    )
    try:
        data = ch_query(sql).get("data", [])
        return data[0]["id"] if data else None
    except Exception as e:
        log("WARN", f"dedup query failed: {e}")
        return None

def _merge_happening(existing_id, new_sigma_ids, new_falco_rules, new_domain="MIXED"):
    """Merge new signal IDs into an existing happening and extend its window_end.
    Upgrades domain toward higher specificity (SOC > SRE > MIXED) but never downgrades."""
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    def _arr_lit(items):
        return "[" + ",".join(f"'{s.replace(chr(39), chr(39)*2)}'" for s in items) + "]" if items else "[]"
    domain_sql = (
        f"CASE WHEN '{new_domain}' = 'SOC' THEN 'SOC'"
        f" WHEN '{new_domain}' = 'SRE' AND domain = 'MIXED' THEN 'SRE'"
        " ELSE domain END"
    )
    sql = (
        "ALTER TABLE panops.happenings UPDATE"
        f"  sigma_rule_ids = arrayDistinct(arrayConcat(sigma_rule_ids, {_arr_lit(new_sigma_ids)})),"
        f"  falco_rules    = arrayDistinct(arrayConcat(falco_rules,    {_arr_lit(new_falco_rules)})),"
        f"  domain         = {domain_sql},"
        f"  window_end     = '{now_ts}'"
        f" WHERE id = '{existing_id}'"
    )
    try:
        ch_exec(sql)
    except Exception as e:
        log("WARN", f"dedup merge failed for {existing_id}: {e}")

def _llm_fetch_similar(happening_id):
    emb_rows = ch_query(
        f"SELECT embedding FROM panops.incident_embeddings"
        f" WHERE happening_id = '{happening_id}' LIMIT 1"
    ).get("data", [])
    if not emb_rows:
        return []
    emb = emb_rows[0]["embedding"]
    return ch_query(
        f"SELECT ie.happening_id, h.domain, h.outcome, h.actions_taken, h.runbook_ref,"
        f"       cosineDistance(ie.embedding, {emb}) AS dist"
        f" FROM panops.incident_embeddings ie"
        f" JOIN panops.happenings h ON h.id = ie.happening_id"
        f" WHERE ie.happening_id != '{happening_id}' AND h.status = 'resolved'"
        f" ORDER BY dist ASC LIMIT 3"
    ).get("data", [])

def _infer_platform(happening: dict) -> str:
    """Infer the platform (kubernetes, windows, or linux) from the happening context."""
    services = happening.get("affected_services") or []
    drain3 = happening.get("drain3_patterns") or []
    falco = happening.get("falco_rules") or []
    sigma = happening.get("sigma_rule_ids") or []

    # Windows signals
    if any("windows" in str(s).lower() for s in sigma + drain3):
        return "windows"
    if any("EventID" in str(s) for s in drain3):
        return "windows"
    # K8s signals
    if any("CrashLoop" in str(s) or "OOMKill" in str(s) or "Pod" in str(s)
           for s in drain3 + falco):
        return "kubernetes"
    # Namespace/deployment style affected_services suggests K8s
    if any("/" in str(s) for s in services):
        return "kubernetes"
    return "linux"

def _available_actions(happening: dict) -> str:
    """Build a string describing available remediation actions for the LLM prompt."""
    platform = _infer_platform(happening)
    services = happening.get("affected_services") or ["<namespace>/<service>"]
    first = services[0] if services else "<namespace>/<service>"
    ns  = first.split("/")[0] if "/" in str(first) else str(first)
    svc = first.split("/")[1] if "/" in str(first) else str(first)

    if platform == "kubernetes":
        return (
            f"- kubectl rollout restart deployment/{svc} -n {ns}\n"
            f"- kubectl delete pod -l app={svc} -n {ns}\n"
            f"- kubectl scale deployment/{svc} --replicas=0 -n {ns}\n"
            f"- kubectl scale deployment/{svc} --replicas=1 -n {ns}\n"
            f"- kubectl describe pod -l app={svc} -n {ns}\n"
            f"- kubectl logs -l app={svc} -n {ns} --tail=100"
        )
    elif platform == "windows":
        return (
            f"- Restart-Service -Name {{{{service}}}} -Force\n"
            f"- Stop-Process -Name {{{{service}}}} -Force -ErrorAction SilentlyContinue\n"
            f"- Restart-VM -Name {{{{pod}}}} -Force\n"
            f"- Get-EventLog -LogName System -EntryType Error -Newest 20 | Format-List\n"
            f"- Get-Service {{{{service}}}} | Select-Object Status,Name,DisplayName"
        )
    else:
        return (
            f"- systemctl restart {{{{service}}}}\n"
            f"- systemctl status {{{{service}}}}\n"
            f"- journalctl -u {{{{service}}}} -n 100\n"
            f"- kill -HUP $(pgrep -f {{{{service}}}})\n"
            f"- ansible-playbook restart-service.yml -e service={{{{service}}}} -e host={{{{host}}}}"
        )

def _web_search(query, log_fn=None):
    """Call DuckDuckGo Instant Answer API; return top snippets as a plain string."""
    _log = log_fn or log
    try:
        encoded = urllib.parse.quote_plus(query)
        url = f"https://api.duckduckgo.com/?q={encoded}&format=json&no_html=1&skip_disambig=1"
        req = urllib.request.Request(url, headers={"User-Agent": "panops-brain/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        snippets = []
        if data.get("AbstractText"):
            snippets.append(data["AbstractText"])
        for item in (data.get("RelatedTopics") or [])[:4]:
            text = item.get("Text") or (item.get("Topics") or [{}])[0].get("Text", "")
            if text:
                snippets.append(text)
        result = "\n".join(f"- {s}" for s in snippets[:5]) if snippets else "(no results)"
        _log("INFO", f"web_search({query[:60]}): {len(snippets)} snippet(s)")
        return result
    except Exception as e:
        _log("WARN", f"web_search failed: {e}")
        return f"(search unavailable: {e})"


def _llm_build_prompt(happening, similar):
    import attck

    similar_text = "".join(
        f"\n- Domain: {s.get('domain')}, Outcome: {s.get('outcome')},"
        f" Actions: {s.get('actions_taken')}, Distance: {s.get('dist', 0):.3f}"
        for s in similar
    )
    attck_block = attck.enrich_sigma_ids(happening.get("sigma_rule_ids") or [])

    opened_at = happening.get("opened_at", "")
    deploy_lookback = ""
    try:
        from datetime import datetime, timezone, timedelta
        _ot = datetime.fromisoformat(str(opened_at).replace(" ", "T").rstrip("0").rstrip("."))
        _ws = (_ot - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
        _we = _ot.strftime("%Y-%m-%d %H:%M:%S")
        _evts = gather_deploy_events(
            (happening.get("affected_services") or [None])[0],
            _ws, _we,
        )
        if _evts:
            deploy_lookback = "Recent deploy events (last 30m before incident):\n" + "".join(
                f"  [{e['event_time']}] {e['source']}/{e['event_type']} "
                f"{e['resource_name']} rev={e['revision']} status={e['status']} actor={e['actor']}\n"
                for e in _evts
            )
    except Exception as _de:
        log("WARN", f"deploy events in prompt: {_de}")

    system_msg = (
        "You are PanOps-Brain, an autonomous SRE/SOC operations assistant managing mixed infrastructure "
        "(Kubernetes clusters, Linux hosts, Windows servers, and Hyper-V hypervisors). "
        "Analyse the incident happening and output ONLY valid JSON matching the schema. "
        "Do not add any text outside the JSON object."
    )
    user_msg = (
        f"Incident happening:\n"
        f"  id: {happening['id']}\n"
        f"  domain: {happening.get('domain','')}\n"
        f"  platform: {_infer_platform(happening)}\n"
        f"  affected_services: {happening.get('affected_services','')}\n"
        f"  opened_at: {happening.get('opened_at','')}\n\n"
        f"Signals:\n"
        + ("\n".join(f"  - {s}" for s in (
            list(happening.get('falco_rules') or []) +
            list(happening.get('sigma_rule_ids') or []) +
            list(happening.get('yara_matches') or []) +
            list(happening.get('drain3_patterns') or [])
        )) or "  (none)") + "\n\n"
        + (f"{attck_block}\n\n" if attck_block else "")
        + (f"{deploy_lookback}\n" if deploy_lookback else "")
        + f"Similar past incidents:\n{similar_text if similar_text else '  (none)'}\n\n"
        f"Available remediation actions (platform: {_infer_platform(happening)}):\n"
        f"{_available_actions(happening)}\n\n"
        f'Output JSON schema:\n'
        f'{{"diagnosis":"<1-2 sentence root cause>",'
        f'"steps":[{{"command":"<command>","expected_output":"<success indicator>"}}],'
        f'"validation_query":"<PromQL, LogQL, or PowerShell check>",'
        f'"confidence":<float 0-1>,'
        f'"runbook_entry":"<markdown paragraph>"}}'
    )
    return system_msg, user_msg

_WEB_SEARCH_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web for information about an error, technology, or remediation steps.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query string"},
                },
                "required": ["query"],
            },
        },
    }
]

def _llm_call(system_msg, user_msg, log_fn=None, use_tools=False):
    """
    Call the local llama-server. When use_tools=True and WEB_SEARCH_ENABLED,
    passes the web_search tool definition and executes any tool_calls the model
    emits (max 2 rounds) before returning the final JSON response.
    """
    _log = log_fn or log
    messages = [
        {"role": "system", "content": system_msg},
        {"role": "user",   "content": user_msg},
    ]
    tools = _WEB_SEARCH_TOOLS if (use_tools and WEB_SEARCH_ENABLED) else None

    for _round in range(3):  # max 2 tool-call rounds + 1 final
        body = {
            "model": "qwen",
            "messages": messages,
            "max_tokens": 1024,
            "temperature": 0.1,
        }
        if tools and _round < 2:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        else:
            body["response_format"] = {"type": "json_object"}

        payload = json.dumps(body).encode()
        llm_base = LLM_EXTERNAL_URL if LLM_EXTERNAL_URL else LLAMA_SERVER_URL
        headers = {"Content-Type": "application/json"}
        if LLM_EXTERNAL_URL and LLM_EXTERNAL_TOKEN:
            headers["Authorization"] = f"Bearer {LLM_EXTERNAL_TOKEN}"
        req = urllib.request.Request(
            f"{llm_base}/v1/chat/completions",
            data=payload,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            resp = json.loads(r.read())

        choice = resp["choices"][0]
        msg = choice["message"]
        finish = choice.get("finish_reason", "")

        if finish == "tool_calls" and msg.get("tool_calls"):
            messages.append(msg)
            for tc in msg["tool_calls"]:
                fn = tc["function"]
                args = json.loads(fn.get("arguments", "{}"))
                if fn["name"] == "web_search":
                    result = _web_search(args.get("query", ""), _log)
                else:
                    result = f"(unknown tool: {fn['name']})"
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": result,
                })
            continue  # re-call with tool results

        raw = msg.get("content", "").strip()
        _log("INFO", f"llm response: {raw[:120]}…")
        return json.loads(raw)

def _deferred_llm_call(happening_id, log_fn=None):
    """Sleep K8S_GRACE_S, then skip if k8s already resolved the happening."""
    _log = log_fn or log
    _log("INFO", f"llm: grace period {K8S_GRACE_S}s for {happening_id[:8]}")
    time.sleep(K8S_GRACE_S)
    try:
        rows = ch_query(
            f"SELECT status, closed_at FROM panops.happenings WHERE id='{happening_id}' LIMIT 1"
        ).get("data", [])
        if rows and rows[0].get("status") in ("resolved", "dismissed", "validating"):
            _log("INFO", f"llm: skipping {happening_id[:8]} — already {rows[0]['status']} after grace period")
            return
    except Exception as e:
        _log("WARN", f"llm: grace check failed for {happening_id[:8]}: {e}")
    _call_llm_server(happening_id, log_fn=log_fn)


def _call_llm_server(happening_id, log_fn=None):
    _log = log_fn or log
    try:
        rows = ch_query(
            f"SELECT * FROM panops.happenings WHERE id='{happening_id}' LIMIT 1"
        ).get("data", [])
        if not rows:
            _log("WARN", f"LLM: happening {happening_id} not found")
            return
        happening = rows[0]
        similar   = _llm_fetch_similar(happening_id)
        _log("INFO", f"llm: {len(similar)} similar resolved incidents for {happening_id[:8]}")
        system_msg, user_msg = _llm_build_prompt(happening, similar)
        result     = _llm_call(system_msg, user_msg, _log, use_tools=True)
        confidence = float(result.get("confidence", 0.0))
        actions    = json.dumps(result.get("steps", []))
        runbook    = result.get("runbook_entry", "").replace("'", "''")
        diagnosis  = result.get("diagnosis",    "").replace("'", "''")
        status     = "validating" if confidence >= LLM_CONFIDENCE_THR else "escalated"
        ch_exec(
            f"ALTER TABLE panops.happenings UPDATE"
            f"  actions_taken = '{actions}',"
            f"  runbook_ref   = 'auto-llm: {diagnosis[:200]}',"
            f"  status        = '{status}'"
            f" WHERE id = '{happening_id}'"
        )
        _log("INFO", f"llm: updated {happening_id[:8]} status={status} confidence={confidence:.2f}")
        if status == "escalated":
            runbook_entry = result.get("runbook_entry", "").strip()
            mr_url = _create_runbook_mr(happening_id, happening, runbook_entry, _log) if runbook_entry else None
            _send_postmortem_draft(happening_id, happening, result.get("diagnosis", ""), _log, mr_url=mr_url)
    except Exception as e:
        _log("WARN", f"LLM call failed for {happening_id}: {e}")
        now_ts = time.time()
        with _llm_circuit["lock"]:
            _llm_circuit["failures"] = [
                t for t in _llm_circuit["failures"] if now_ts - t < 3600
            ]
            _llm_circuit["failures"].append(now_ts)
            if len(_llm_circuit["failures"]) > 3 and not _llm_circuit["open"]:
                _llm_circuit["open"] = True
                _send_notification("NOC", "LLM circuit breaker OPEN",
                                 "LLM circuit breaker is open — novel happenings will not be diagnosed.",
                                 route="escalate", severity="critical")
                _log("WARN", "LLM circuit breaker opened")

def _create_runbook_mr(happening_id, happening, runbook_entry, log_fn=None):
    """Create a GitLab branch + MR with the LLM's proposed runbook entry. Returns mr_url or None."""
    _log = log_fn or log
    gitlab_url = os.getenv("GITLAB_URL", "")
    token      = os.getenv("GITLAB_TOKEN", "")
    project_id = os.getenv("GITLAB_PROJECT_ID", "")
    if not all([gitlab_url, token, project_id]):
        return None
    try:
        ns        = (happening.get("affected_services") or ["unknown"])[0]
        branch    = f"panops/runbook-{happening_id[:8]}"
        filename  = f"docs/runbooks/auto/{ns}-{happening_id[:8]}.md"
        proj_enc  = urllib.parse.quote(str(project_id), safe="")
        base_url  = f"{gitlab_url}/api/v4/projects/{proj_enc}"
        headers   = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        def _gl(method, url, data=None):
            body = json.dumps(data).encode() if data else None
            req  = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    return json.loads(r.read() or b"{}"), r.status
            except urllib.error.HTTPError as e:
                return json.loads(e.read() or b"{}"), e.code

        _gl("POST", f"{base_url}/repository/branches", {"branch": branch, "ref": "main"})
        _, cs = _gl("POST", f"{base_url}/repository/commits", {
            "branch": branch,
            "commit_message": f"panops: proposed runbook for {happening_id[:8]}",
            "actions": [{"action": "create", "file_path": filename, "content": runbook_entry}],
        })
        if cs not in (200, 201):
            _log("WARN", f"runbook MR: commit failed (status {cs})")
            return None
        domain = happening.get("domain", "MIXED")
        mr_resp, mr_status = _gl("POST", f"{base_url}/merge_requests", {
            "source_branch": branch,
            "target_branch": "main",
            "title":         f"[PanOps] Proposed runbook: {ns} — {happening_id[:8]}",
            "description":   f"Auto-generated by PanOps LLM escalation path\n\n"
                             f"**Domain**: {domain}  **Happening**: {happening_id[:8]}\n\n"
                             f"{runbook_entry[:1000]}",
            "remove_source_branch": True,
        })
        if mr_status in (200, 201):
            mr_url = mr_resp.get("web_url", "")
            _log("INFO", f"runbook MR opened: {mr_url}")
            return mr_url
        _log("WARN", f"runbook MR: open failed (status {mr_status})")
    except Exception as e:
        _log("WARN", f"_create_runbook_mr: {e}")
    return None


def _send_postmortem_draft(happening_id, happening, diagnosis, log_fn=None, mr_url=None):
    """
    Auto-draft a postmortem skeleton when a happening escalates (LLM confidence
    too low for autonomous remediation). Sends to the domain Matrix room so
    the on-call engineer has structured context immediately.
    """
    _log = log_fn or log
    try:
        ns      = ", ".join(happening.get("affected_services") or []) or "unknown"
        domain  = happening.get("domain", "unknown")
        route   = happening.get("classifier_route", "unknown")
        falco   = ", ".join(happening.get("falco_rules") or []) or "none"
        sigma   = ", ".join(happening.get("sigma_rule_ids") or []) or "none"

        drain3_text = ""
        try:
            patterns = json.loads(happening.get("drain3_patterns") or "[]")
            drain3_text = " | ".join(
                p.get("template", "") for p in patterns[:3] if p.get("template")
            ) or "none"
        except Exception:
            drain3_text = "none"

        anom_text = ""
        try:
            anoms = json.loads(happening.get("metric_anomalies") or "[]")
            anom_text = ", ".join(
                a.get("metric") or a.get("name", "") for a in anoms[:3] if a.get("metric") or a.get("name")
            ) or "none"
        except Exception:
            anom_text = "none"

        mr_line = f"\nGitLab MR (proposed fix): {mr_url}" if mr_url else ""
        draft = (
            f"## Postmortem Draft — {domain} escalation\n"
            f"Happening: {happening_id[:8]}  |  Namespace: {ns}  |  Route: {route}\n"
            f"Falco: {falco}\n"
            f"Sigma: {sigma}\n"
            f"Log patterns: {drain3_text}\n"
            f"Anomalous metrics: {anom_text}\n"
            f"LLM diagnosis: {diagnosis[:300] or 'n/a'}"
            f"{mr_line}\n"
            f"\n"
            f"Next steps:\n"
            f"  [ ] Identify root cause\n"
            f"  [ ] Apply fix\n"
            f"  [ ] Update runbook (POST /postmortem)\n"
            f"  [ ] Add YARA/Sigma rule if novel threat"
        )
        title = (f"Escalated + MR raised: {happening_id[:8]}" if mr_url
                 else f"Escalated: {happening_id[:8]} — postmortem draft")
        _send_notification(domain, title, draft, route="escalate", severity="critical")
        _log("INFO", f"postmortem draft sent for {happening_id[:8]}")
    except Exception as e:
        _log("WARN", f"_send_postmortem_draft: {e}")


# ── Core assembly ─────────────────────────────────────────────────────────

def assemble(trigger_source, namespace, alert_labels):
    now          = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=10)
    ws_iso       = window_start.strftime("%Y-%m-%d %H:%M:%S.%f")
    we_iso       = now.strftime("%Y-%m-%d %H:%M:%S.%f")
    ws_ns        = int(window_start.timestamp() * 1e9)
    we_ns        = int(now.timestamp() * 1e9)

    falco_rules = []
    if alert_labels.get("falco_rule"):
        falco_rules = [alert_labels["falco_rule"]]

    # Dedup: if an open happening already covers this namespace/rule within
    # the last 30 min, merge new sigma IDs into it and skip full assembly.
    # This avoids duplicate rows when poll_sigma fires every 60s against
    # the same namespace, or when Falco fires the same rule repeatedly.
    _existing = _find_open_happening(namespace, falco_rules[0] if falco_rules else "")
    if _existing:
        _new_sigma = gather_sigma(namespace, ws_iso, we_iso)
        if falco_rules or _new_sigma:
            _merge_domain = "SOC"
        elif alert_labels.get("source") in ("sre", "observability"):
            _merge_domain = "SRE"
        else:
            _merge_domain = "MIXED"
        _merge_happening(_existing, _new_sigma, falco_rules, _merge_domain)
        log("INFO",
            f"dedup src={trigger_source} ns={namespace or '*'}"
            f" → merged into {_existing} sigma={len(_new_sigma)}")
        return

    sigma_ids        = gather_sigma(namespace, ws_iso, we_iso)
    metric_anomalies = gather_anomalies(ws_iso, we_iso)

    # Step 4: enriched Drain3 detection (novelty + freq anomaly + Falco correlation)
    if _drain3:
        try:
            drain3_patterns = _drain3.enrich_drain3(
                ch_url=CH_URL, loki_url=LOKI_URL, namespace=namespace,
                window_start_s=window_start.timestamp(),
                window_end_s=now.timestamp(), log_fn=log,
            )
        except Exception as e:
            log("WARN", f"drain3 detector error: {e}")
            drain3_patterns = gather_drain3(namespace, ws_ns, we_ns)
    else:
        drain3_patterns = gather_drain3(namespace, ws_ns, we_ns)

    # When log analysis finds no patterns, synthesize a drain3 entry from the
    # Grafana alertname so the remediator's template-based dispatch can match it.
    if not drain3_patterns and alert_labels.get("alertname"):
        drain3_patterns = [{"template": alert_labels["alertname"],
                            "count": 1, "source": "grafana_alert"}]

    # Step 3: metric correlator — deferred to a background thread to avoid
    # blocking the insert. Correlations are written to CH after the happening row
    # is created, so they appear in metric_correlations on the next read.
    metric_correlations = []

    domain, route = fast_classify(falco_rules, sigma_ids, drain3_patterns, metric_anomalies)
    # Promote MIXED→SRE for webhook alerts explicitly labelled source=sre/observability
    # with no security signals — prevents infra probes routing to NOC as MIXED noise.
    if domain == "MIXED" and route == "structured" and not falco_rules and not sigma_ids:
        if alert_labels.get("source") in ("sre", "observability"):
            domain = "SRE"

    # Gather YARA match names from Loki when alert source is yara.
    yara_matches = []
    if alert_labels.get("source") == "yara":
        yara_matches = gather_yara(ws_ns, we_ns)

    affected = [namespace] if namespace else []

    row = {
        "id":                  str(uuid.uuid4()),
        "opened_at":           now.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "closed_at":           None,
        "window_start":        ws_iso,
        "window_end":          we_iso,
        "affected_services":   affected,
        "domain":              domain,
        "classifier_route":    route,
        "similarity_score":    None,
        "matched_incident_id": None,
        "status":              "open",
        "outcome":             "",
        "runbook_ref":         None,
        "falco_rules":         falco_rules,
        "sigma_rule_ids":      sigma_ids,
        "yara_matches":        yara_matches,
        "drain3_patterns":     json.dumps(drain3_patterns),
        "metric_anomalies":    json.dumps(metric_anomalies),
        "metric_correlations": json.dumps(metric_correlations),
        "actions_taken":       json.dumps([]),
    }

    # Second dedup check under lock to close the race between concurrent webhooks
    # that both passed the first check before either one inserted.
    with _get_ns_lock(namespace):
        _existing2 = _find_open_happening(namespace, falco_rules[0] if falco_rules else "")
        if _existing2:
            _merge_happening(_existing2, sigma_ids, falco_rules, domain)
            log("INFO",
                f"dedup(2) src={trigger_source} ns={namespace or '*'} → merged into {_existing2}")
            return
        try:
            ch_insert_happening(row)
        except Exception as e:
            log("ERROR", f"write happening failed: {e}")
            return

    log("INFO",
        f"happening {row['id']} src={trigger_source} ns={namespace or '*'} "
        f"domain={domain} route={route} falco={len(falco_rules)} "
        f"sigma={len(sigma_ids)} anomalies={len(metric_anomalies)}")

    # Deferred metric correlation — runs in background to avoid blocking insert.
    if _correlator and namespace:
        _row_id = row["id"]
        _ws     = window_start.timestamp()
        _we     = now.timestamp()
        def _run_correlator():
            with _CORRELATOR_SEM:
                try:
                    _correlator.correlate_metrics(
                        prom_url=PROM_URL, ch_url=CH_URL, namespace=namespace,
                        service_a=namespace, window_start_ts=_ws, window_end_ts=_we,
                        log_fn=log,
                    )
                except Exception as _e:
                    log("WARN", f"correlator error: {_e}")
        threading.Thread(target=_run_correlator, daemon=True).start()

    # Step 5: embed + kNN similarity match (slow path, ~50ms)
    if _classifier:
        try:
            sim, matched_id, route_override = _classifier.embed_and_match(
                CH_URL, row, log_fn=log
            )
            if sim is not None or matched_id is not None:
                updates = []
                if sim is not None:
                    updates.append(f"similarity_score = {sim}")
                if matched_id:
                    updates.append(f"matched_incident_id = '{matched_id}'")
                if route_override:
                    updates.append(f"classifier_route = '{route_override}'")
                if updates:
                    ch_exec(
                        f"ALTER TABLE panops.happenings UPDATE "
                        + ", ".join(updates)
                        + f" WHERE id = '{row['id']}'"
                    )
                    if route_override:
                        row["classifier_route"] = route_override
        except Exception as e:
            log("WARN", f"classifier error: {e}")

    # Steps 6 & 7: remediation + validation for structured/known happenings.
    # novel/escalate routes go to LLM Job (step 9); SOC routes handled by Talon.
    final_route = row.get("classifier_route", route)
    if _remediator and final_route in ("structured", "known") and domain in ("SRE", "MIXED"):
        matched_acts = []
        if final_route == "known" and row.get("matched_incident_id"):
            try:
                mid = row["matched_incident_id"]
                sql_acts = f"SELECT actions_taken FROM panops.happenings WHERE id = '{mid}' LIMIT 1"
                data = (sql_acts + " FORMAT JSON").encode()
                req = urllib.request.Request(CH_URL, data=data, method="POST")
                req.add_header("Content-Type", "text/plain")
                req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
                req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
                with urllib.request.urlopen(req, timeout=15) as r:
                    result = json.loads(r.read()).get("data", [])
                if result:
                    matched_acts = json.loads(result[0].get("actions_taken", "[]"))
            except Exception as e:
                log("WARN", f"fetch matched actions: {e}")
        _row_snap = row
        _acts_snap = matched_acts
        def _run_remediation(row=_row_snap, matched_acts=_acts_snap):
            with _REMEDIATION_SEM:
                _remediator.remediate_and_validate(row, matched_acts, log, notify_fn=_send_notification)
        threading.Thread(target=_run_remediation, daemon=True).start()

    # Step 9: LLM Job for novel/escalate happenings (gated on circuit breaker)
    # Deferred by K8S_GRACE_S to allow k8s self-healing before LLM steps in.
    if final_route in ("novel", "escalate") and domain in ("SRE", "MIXED"):
        if not XOPS_LLM_ENABLED:
            log("INFO", f"LLM disabled — skipping deferred call for {row['id'][:8]}")
        else:
            with _llm_circuit["lock"]:
                circuit_open = _llm_circuit["open"]
            if circuit_open:
                log("WARN", f"LLM circuit open — skipping job for {row['id']}")
            else:
                _rid = row["id"]
                def _run_llm(rid=_rid):
                    with _LLM_SEM:
                        _deferred_llm_call(rid, log)
                threading.Thread(target=_run_llm, daemon=True).start()

# ── Postmortem HTML rendering ────────────────────────────────────────────────

def _render_postmortem_list(rows):
    """Render list of resolved happenings as HTML table."""
    html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PanOps Postmortem Learning</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f5f5;
            padding: 20px;
        }
        @media (prefers-color-scheme: dark) {
            body { background: #1e1e1e; color: #e0e0e0; }
            table { border-color: #444; }
            tr:hover { background-color: #2a2a2a; }
            a { color: #64b5f6; }
        }
        h1 { margin-bottom: 20px; font-size: 24px; }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border: 1px solid #ddd;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        @media (prefers-color-scheme: dark) {
            table { background: #2a2a2a; }
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        @media (prefers-color-scheme: dark) {
            th, td { border-bottom: 1px solid #444; }
        }
        th {
            background: #f9f9f9;
            font-weight: 600;
        }
        @media (prefers-color-scheme: dark) {
            th { background: #1a1a1a; }
        }
        tr:hover { background-color: #f9f9f9; }
        a { color: #0066cc; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>PanOps Postmortem Learning</h1>
    <p style="margin-bottom: 20px; color: #666;">
        @media (prefers-color-scheme: dark) { color: #999; }
        Resolved incidents from the last 30 days. Click to view details and save parameterized runbooks.
    </p>
    <table>
        <thead>
            <tr>
                <th>Date</th>
                <th>Domain</th>
                <th>Route</th>
                <th>Affected Services</th>
                <th>Status</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
"""
    for row in rows:
        opened_at = row.get("opened_at", "")[:16]
        domain = row.get("domain", "UNKNOWN")
        route = row.get("classifier_route", "")
        services = ", ".join(row.get("affected_services", [])[:3]) or "cluster"
        status = row.get("status", "unknown")
        hid = row.get("id", "")
        html += f"""            <tr>
                <td>{opened_at}</td>
                <td>{domain}</td>
                <td><code style="background:#f0f0f0;padding:2px 4px;border-radius:3px;">{route}</code></td>
                <td>{services}</td>
                <td>{status}</td>
                <td><a href="/postmortem/{hid}">View</a></td>
            </tr>
"""
    html += """        </tbody>
    </table>
</body>
</html>"""
    return html

def _render_postmortem_detail(happening):
    """Render detail view for a single happening with runbook form."""
    hid = happening.get("id", "")
    domain = happening.get("domain", "UNKNOWN")
    route = happening.get("classifier_route", "")
    services = ", ".join(happening.get("affected_services", []))
    signals = happening.get("drain3_patterns", "[]")
    try:
        signals_parsed = json.loads(signals)
        signals_text = "\n".join(
            [f"  - {s.get('template', 'unknown')} (count={s.get('count', 0)})"
             for s in signals_parsed[:5]]
        ) or "  (no signals)"
    except Exception:
        signals_text = "  (error parsing signals)"

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PanOps Postmortem - {hid[:8]}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            max-width: 1000px;
            margin: 0 auto;
        }}
        @media (prefers-color-scheme: dark) {{
            body {{ background: #1e1e1e; color: #e0e0e0; }}
            .section {{ background: #2a2a2a; border-color: #444; }}
            input, textarea, select {{ background: #333; color: #e0e0e0; border-color: #444; }}
        }}
        h1 {{ margin-bottom: 20px; font-size: 24px; }}
        .section {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .section h2 {{ font-size: 18px; margin-bottom: 12px; color: #333; }}
        @media (prefers-color-scheme: dark) {{
            .section h2 {{ color: #e0e0e0; }}
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 12px;
        }}
        .summary-item {{
            padding: 8px;
            background: #f9f9f9;
            border-radius: 4px;
            font-size: 13px;
        }}
        @media (prefers-color-scheme: dark) {{
            .summary-item {{ background: #1a1a1a; }}
        }}
        .summary-item strong {{ display: block; color: #666; font-weight: 600; }}
        @media (prefers-color-scheme: dark) {{
            .summary-item strong {{ color: #999; }}
        }}
        label {{
            display: block;
            margin-top: 12px;
            font-weight: 600;
            font-size: 13px;
            margin-bottom: 4px;
        }}
        select, textarea, input[type="text"] {{
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: monospace;
            font-size: 13px;
        }}
        button {{
            background: #0066cc;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
            margin-top: 12px;
        }}
        button:hover {{ background: #0052a3; }}
        @media (prefers-color-scheme: dark) {{
            button {{ background: #1976d2; }}
            button:hover {{ background: #1565c0; }}
        }}
        .back {{ display: inline-block; margin-bottom: 20px; color: #0066cc; text-decoration: none; }}
        .back:hover {{ text-decoration: underline; }}
        .signals {{
            background: #f0f0f0;
            padding: 12px;
            border-radius: 4px;
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 12px;
            color: #333;
        }}
        @media (prefers-color-scheme: dark) {{
            .signals {{ background: #1a1a1a; color: #e0e0e0; }}
        }}
    </style>
</head>
<body>
    <a class="back" href="/postmortem">&larr; Back to list</a>
    <h1>Postmortem: {domain} ({route})</h1>

    <div class="section">
        <h2>Incident Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <strong>ID</strong>
                <code>{hid[:16]}</code>
            </div>
            <div class="summary-item">
                <strong>Domain</strong>
                {domain}
            </div>
            <div class="summary-item">
                <strong>Route</strong>
                {route}
            </div>
            <div class="summary-item">
                <strong>Services</strong>
                {services or "cluster-wide"}
            </div>
        </div>
        <div style="margin-top: 12px;">
            <strong style="display:block; color: #666; font-size: 13px; margin-bottom: 4px;">@media (prefers-color-scheme: dark) {{ strong {{ color: #999; }} }} Signals/Patterns:</strong>
            <div class="signals">{signals_text}</div>
        </div>
    </div>

    <div class="section">
        <h2>Parameterize Runbook</h2>
        <form id="parseForm">
            <label>Runtime</label>
            <select name="runtime" required>
                <option value="shell">bash/shell</option>
                <option value="kubectl">kubectl</option>
                <option value="ansible">ansible</option>
                <option value="powershell">powershell</option>
            </select>

            <label>Terminal Output / Commands</label>
            <textarea name="paste" rows="15" placeholder="Paste the terminal session or commands that resolved this incident..." required></textarea>

            <label>Notes (optional)</label>
            <textarea name="notes" rows="4" placeholder="Context about what was done and why..."></textarea>

            <label>Created By (optional)</label>
            <input type="text" name="created_by" placeholder="Your name or handle">

            <button type="button" onclick="parseRunbook()">Parse & Preview</button>
        </form>
    </div>

    <div id="previewSection" style="display:none;" class="section">
        <h2>Preview</h2>
        <div id="previewContent" style="white-space:pre-wrap;font-family:monospace;font-size:12px;"></div>
        <button type="button" onclick="saveRunbook()">Confirm & Save</button>
    </div>

    <script>
    function parseRunbook() {{
        const runtime = document.querySelector('[name="runtime"]').value;
        const paste = document.querySelector('[name="paste"]').value;
        const notes = document.querySelector('[name="notes"]').value;
        const created_by = document.querySelector('[name="created_by"]').value;

        const payload = {{ runtime, paste, notes, created_by }};

        fetch('/postmortem/{hid}/parse', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify(payload)
        }})
        .then(r => r.json())
        .then(data => {{
            document.getElementById('previewContent').textContent = JSON.stringify(data, null, 2);
            document.getElementById('previewSection').style.display = 'block';
            window.lastPreview = data;
        }})
        .catch(e => alert('Parse error: ' + e));
    }}

    function saveRunbook() {{
        const payload = window.lastPreview;
        payload.created_by = document.querySelector('[name="created_by"]').value;

        fetch('/postmortem/{hid}/save', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify(payload)
        }})
        .then(r => r.json())
        .then(data => {{
            alert('Saved! ' + JSON.stringify(data));
            window.location.href = '/postmortem';
        }})
        .catch(e => alert('Save error: ' + e));
    }}
    </script>
</body>
</html>"""
    return html

# ── Webhook server ────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    # HTTP/1.1 keeps connections alive so each request doesn't pay the full
    # TCP close round-trip (which is ~1s through kubectl port-forward).
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # assembler writes its own structured logs

    def _json(self, status_code, data):
        """Send JSON response with given status code."""
        body = json.dumps(data).encode()
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, status_code, body: str):
        """Send HTML response with given status code."""
        encoded = body.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path == "/healthz":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/test":
            # Synthetic test happening for pre-chaos validation
            self._fire_test()
        elif self.path == "/decisions":
            # Recent happenings summary (last 20)
            self._decisions_summary()
        elif self.path == "/test/llm/ping":
            # Fast availability check — no LLM call, used by test fixture
            self._json(200, {"available": True})
        elif self.path == "/test/llm":
            # End-to-end LLM path test: insert synthetic novel happening → call LLM → return result
            self._test_llm_path()
        elif self.path == "/test/nrem":
            # Trigger NREM dream phase synchronously and return summary
            self._test_nrem_phase()
        elif self.path == "/postmortem" or self.path == "/postmortem/":
            if not _check_postmortem_auth(self):
                return
            self._postmortem_list()
        elif self.path.startswith("/postmortem/") and not self.path.endswith("/parse") and not self.path.endswith("/save"):
            if not _check_postmortem_auth(self):
                return
            happening_id = self.path.split("/")[2]
            self._postmortem_detail(happening_id)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _fire_test(self):
        scenarios = [
            ("test_sigma",   "default",     {"alertname": "test-sigma-match",   "source": "soc"}),
            ("test_oom",     "default",     {"alertname": "test-oom",            "source": "sre"}),
            ("test_falco",   "default",     {"alertname": "test-falco-critical", "falco_rule": "Terminal shell in container", "source": "soc"}),
            ("test_novel",   "",            {"alertname": "test-novel-pattern",  "source": "sre"}),
        ]
        results = []
        for src, ns, labels in scenarios:
            try:
                threading.Thread(target=assemble, args=(src, ns, labels), daemon=True).start()
                results.append(f"fired: {src} ns={ns or '*'}")
            except Exception as e:
                results.append(f"error: {src} {e}")
        body = "\n".join(results).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _decisions_summary(self):
        try:
            rows = ch_query(
                "SELECT toString(id) as id, opened_at, domain, classifier_route, status, "
                "outcome, length(affected_services) as svc_count, "
                "length(falco_rules) as falco_count, length(sigma_rule_ids) as sigma_count "
                "FROM panops.happenings "
                "ORDER BY opened_at DESC LIMIT 20"
            ).get("data", [])
            body = json.dumps(rows, indent=2).encode()
        except Exception as e:
            body = f"error: {e}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _test_llm_path(self):
        """
        Insert a synthetic novel happening into CH, call _call_llm_server on it,
        then read back the updated row. Blocks until LLM responds (up to 120s).
        Returns JSON: {happening_id, status, confidence, actions_taken, elapsed_s, error?}
        """
        import time as _time
        start = _time.time()
        fake_id = str(uuid.uuid4())
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
        now_dt = datetime.now(timezone.utc)
        ws_iso = (now_dt - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S.%f")
        row = {
            "id":                  fake_id,
            "opened_at":           now_str,
            "closed_at":           None,
            "window_start":        ws_iso,
            "window_end":          now_str,
            "domain":              "SRE",
            "classifier_route":    "novel",
            "status":              "open",
            "similarity_score":    None,
            "matched_incident_id": None,
            "affected_services":   ["panops-test"],
            "falco_rules":         [],
            "sigma_rule_ids":      [],
            "yara_matches":        [],
            "drain3_patterns":     json.dumps([{"template": "test-novel-oomkill-pattern", "count": 3, "is_novel": True}]),
            "metric_anomalies":    "[]",
            "metric_correlations": "[]",
            "actions_taken":       json.dumps([]),
            "runbook_ref":         None,
            "outcome":             "",
        }
        result = {"happening_id": fake_id, "status": "error"}
        try:
            ch_insert_happening(row)
            _call_llm_server(fake_id, log_fn=log)
            updated = ch_query(
                f"SELECT status, actions_taken, runbook_ref "
                f"FROM panops.happenings WHERE id = '{fake_id}' LIMIT 1"
            ).get("data", [{}])[0]
            actions = updated.get("actions_taken", "")
            try:
                steps = json.loads(actions) if actions else []
                confidence_guess = 0.8 if updated.get("status") == "validating" else 0.3
            except Exception:
                steps = []
                confidence_guess = 0.0
            result = {
                "happening_id": fake_id,
                "status":       updated.get("status", "unknown"),
                "confidence":   confidence_guess,
                "actions_taken": actions,
                "elapsed_s":    round(_time.time() - start, 2),
            }
        except Exception as e:
            result["error"]     = str(e)
            result["elapsed_s"] = round(_time.time() - start, 2)
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _test_nrem_phase(self):
        """
        Trigger the NREM dream phase synchronously and return a summary.
        Returns JSON: {brittleness_scores, cbr_refreshed, negative_rewards_recorded, elapsed_s}
        Requires _consolidation to be available (consolidation.py imported).
        """
        import time as _time
        start = _time.time()
        if not _consolidation:
            body = json.dumps({"error": "consolidation module not loaded"}).encode()
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        try:
            scores = _consolidation.run_nrem_phase(log_fn=log)
            result = {
                "brittleness_scores": scores,
                "elapsed_s": round(_time.time() - start, 2),
            }
        except Exception as e:
            result = {"error": str(e), "elapsed_s": round(_time.time() - start, 2)}
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/dream":
            if not _consolidation:
                self._json(503, {"status": "error", "error": "consolidation module not loaded"})
                return
            if not _DREAM_LOCK.acquire(blocking=False):
                self._json(409, {"status": "busy", "error": "dream cycle already running"})
                return
            try:
                result = _consolidation.run_dream_cycle(log_fn=log)
                self._json(200, {"status": "ok", "result": str(result)})
            except Exception as e:
                self._json(500, {"status": "error", "error": str(e)})
            finally:
                _DREAM_LOCK.release()
        elif self.path == "/investigate":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            agent_url = os.getenv("AGENT_URL", "http://panops-llama-server:8081")
            try:
                data = json.dumps(body).encode()
                req = urllib.request.Request(f"{agent_url}/invoke", data=data,
                                             headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    result = json.loads(resp.read())
                self._json(202, result)
            except Exception as e:
                self._json(502, {"error": str(e)})
        elif self.path == "/webhook":
            length = int(self.headers.get("Content-Length", 0))
            if length > _MAX_WEBHOOK_BODY:
                self._json(413, {"error": "payload too large"})
                return
            body = self.rfile.read(length)
            resp_body = b"accepted"
            self.send_response(200)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            threading.Thread(target=self._process, args=(body,), daemon=True).start()
        elif self.path == "/deploy-event":
            length = int(self.headers.get("Content-Length", 0))
            if length > _MAX_WEBHOOK_BODY:
                self._json(413, {"error": "payload too large"})
                return
            body = self.rfile.read(length)
            resp_body = b"accepted"
            self.send_response(200)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)
            threading.Thread(target=_handle_deploy_event, args=(body,), daemon=True).start()
        elif self.path.endswith("/parse") and self.path.startswith("/postmortem/"):
            if not _check_postmortem_auth(self):
                return
            happening_id = self.path.split("/")[2]
            self._postmortem_parse(happening_id)
        elif self.path.endswith("/save") and self.path.startswith("/postmortem/"):
            if not _check_postmortem_auth(self):
                return
            happening_id = self.path.split("/")[2]
            self._postmortem_save(happening_id)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _postmortem_list(self):
        """List resolved/escalated happenings from last 30 days."""
        try:
            rows = ch_query("""
                SELECT toString(id) as id, opened_at, closed_at,
                       domain, classifier_route, affected_services, drain3_patterns, status
                FROM panops.happenings
                WHERE status IN ('resolved', 'escalated')
                  AND opened_at > now64() - INTERVAL 30 DAY
                ORDER BY opened_at DESC
                LIMIT 50
                FORMAT JSON
            """).get("data", [])
            self._html(200, _render_postmortem_list(rows))
        except Exception as e:
            log("WARN", f"postmortem list error: {e}")
            self._html(500, f"<h1>Error</h1><p>{html.escape(str(e))}</p>")

    def _postmortem_detail(self, happening_id):
        """Show detail view and runbook form for a specific happening."""
        try:
            try:
                uuid.UUID(happening_id)
            except ValueError:
                self._json(400, {"error": "invalid id"})
                return
            rows = ch_query(f"""
                SELECT toString(id) as id, opened_at, closed_at, domain,
                       classifier_route, affected_services, drain3_patterns,
                       falco_rules, sigma_rule_ids, actions_taken, status
                FROM panops.happenings
                WHERE id = '{happening_id}'
                LIMIT 1
                FORMAT JSON
            """).get("data", [])
            if not rows:
                self._json(404, {"error": "not found"})
                return
            self._html(200, _render_postmortem_detail(rows[0]))
        except Exception as e:
            log("WARN", f"postmortem detail error: {e}")
            self._html(500, f"<h1>Error</h1><p>{html.escape(str(e))}</p>")

    def _postmortem_parse(self, happening_id):
        """Parse postmortem paste and parameterize commands via LLM."""
        try:
            length = int(self.headers.get("Content-Length", 0))
            if not length:
                self._json(400, {"error": "missing body"})
                return
            body = json.loads(self.rfile.read(length))
            raw_paste = body.get("raw_paste", "")
            runtime = body.get("runtime", "shell")
            notes = body.get("notes", "")

            if not raw_paste:
                self._json(400, {"error": "raw_paste required"})
                return

            # Fetch happening for context
            try:
                uuid.UUID(happening_id)
            except ValueError:
                self._json(400, {"error": "invalid id"})
                return
            rows = ch_query(f"""
                SELECT toString(id) as id, domain, affected_services, drain3_patterns,
                       classifier_route, falco_rules, sigma_rule_ids
                FROM panops.happenings
                WHERE id = '{happening_id}'
                LIMIT 1
                FORMAT JSON
            """).get("data", [])
            if not rows:
                self._json(404, {"error": "happening not found"})
                return
            happening = rows[0]

            # Call LLM to parameterize the commands
            system_msg = (
                "You are an SRE assistant analyzing postmortem terminal output. "
                "Extract the commands that fixed the incident and replace specific values with {token} placeholders. "
                "Available tokens: {namespace}, {service}, {deployment}, {pod}, {host}, {ip}. "
                "Return ONLY valid JSON with no additional text."
            )
            user_msg = (
                f"Incident context:\n"
                f"  domain: {happening.get('domain', 'MIXED')}\n"
                f"  affected_services: {happening.get('affected_services', [])}\n"
                f"  patterns: {happening.get('drain3_patterns', [])}\n"
                f"  runtime: {runtime}\n\n"
                f"Terminal paste / commands:\n{raw_paste}\n\n"
                f"Notes: {notes}\n\n"
                f"Output JSON schema: {{"
                f'"commands": [{{"command": "<parameterised cmd>", "description": "<one line>"}}], '
                f'"drain3_template": "<if applicable>", '
                f'"runtime": "{runtime}", '
                f'"domain": "{happening.get("domain", "MIXED")}"'
                f"}}"
            )
            try:
                result = _llm_call(system_msg, user_msg)
                # Ensure runtime and domain are in response
                result["runtime"] = runtime
                result["domain"] = happening.get("domain", "MIXED")
                self._json(200, result)
            except Exception as e:
                log("WARN", f"LLM call failed for postmortem parse: {e}")
                self._json(503, {"error": "LLM unavailable"})
        except Exception as e:
            log("WARN", f"postmortem parse error: {e}")
            self._json(500, {"error": html.escape(str(e))})

    def _postmortem_save(self, happening_id):
        """Save confirmed postmortem runbook to ClickHouse."""
        try:
            length = int(self.headers.get("Content-Length", 0))
            if not length:
                self._json(400, {"error": "missing body"})
                return
            body = json.loads(self.rfile.read(length))

            # Validate required fields (created_by is NOT client-supplied — see below)
            required = ["drain3_template", "domain", "runtime", "commands", "raw_paste"]
            for field in required:
                if field not in body:
                    self._json(400, {"error": f"missing field: {field}"})
                    return

            # runtime must be one of the known executors — these commands are replayed.
            if body["runtime"] not in ("kubectl", "shell", "ansible", "winrm"):
                self._json(400, {"error": f"invalid runtime: {body['runtime']}"})
                return

            runbook_id = str(uuid.uuid4())

            # Parameterized INSERT — no value is string-interpolated. created_by is
            # pinned to the authenticated identity (_PM_USER), not client input, so
            # the highest-privilege write path is accountable.
            sql = (
                "INSERT INTO panops.postmortem_runbooks "
                "(id, happening_id, drain3_template, domain, runtime, commands, raw_paste, notes, created_by, created_at) "
                "VALUES ({id:String}, {hid:String}, {tmpl:String}, {domain:String}, {runtime:String}, "
                "{commands:String}, {raw_paste:String}, {notes:String}, {created_by:String}, now64())"
            )
            params = {
                "id":         runbook_id,
                "hid":        happening_id,
                "tmpl":       body["drain3_template"],
                "domain":     body["domain"],
                "runtime":    body["runtime"],
                "commands":   json.dumps(body["commands"]),
                "raw_paste":  body["raw_paste"],
                "notes":      body.get("notes", ""),
                "created_by": _PM_USER or "unknown",
            }
            ch_exec(sql, params)
            self._json(201, {"id": runbook_id, "status": "saved"})
        except Exception as e:
            log("WARN", f"postmortem save error: {e}")
            self._json(500, {"error": html.escape(str(e))})

    def _process(self, body):
        try:
            payload = json.loads(body)
        except Exception:
            log("WARN", "webhook: invalid JSON body")
            return
        for alert in payload.get("alerts", []):
            status = alert.get("status", "")
            labels = alert.get("labels", {})
            ann    = alert.get("annotations", {})
            ns     = labels.get("namespace", "")
            name   = labels.get("alertname", "unknown")

            if status == "resolved":
                log("INFO", f"webhook resolved: {name} ns={ns}")
                # Close any open happenings for this namespace so dedup doesn't
                # keep them alive across assembler restarts or re-fires.
                try:
                    if ns:
                        ch_exec(
                            "ALTER TABLE panops.happenings UPDATE"
                            " status = 'resolved',"
                            " outcome = 'alert resolved by Grafana',"
                            " closed_at = now64()"
                            " WHERE status NOT IN ('resolved', 'dismissed')"
                            " AND has(affected_services, {ns:String})",
                            params={"ns": ns},
                        )
                    else:
                        ch_exec(
                            "ALTER TABLE panops.happenings UPDATE"
                            " status = 'resolved',"
                            " outcome = 'alert resolved by Grafana',"
                            " closed_at = now64()"
                            " WHERE status NOT IN ('resolved', 'dismissed')"
                            " AND length(affected_services) = 0"
                        )
                except Exception as _e:
                    log("WARN", f"webhook resolved: ch close failed: {_e}")
                continue

            if status != "firing":
                continue
            log("INFO", f"webhook: {name} ns={ns}")
            assemble("webhook", ns, labels)

# ── Poll loop ─────────────────────────────────────────────────────────────

def _init_cursors():
    lookback = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    with _state["lock"]:
        _state["sigma_cursor"]   = lookback
        _state["anomaly_cursor"] = lookback
    log("INFO", f"poll cursors initialised with 10m lookback at {lookback}")

def _poll_sigma():
    with _state["lock"]:
        cursor = _state["sigma_cursor"]
    sql = f"""
        SELECT DISTINCT namespace
        FROM qryn.sigma_matches
        WHERE timestamp > toDateTime64('{cursor}', 9)
    """
    try:
        rows = ch_query(sql).get("data", [])
        if rows:
            for r in rows:
                ns = r["namespace"]
                log("INFO", f"poll sigma: new matches in ns={ns}")
                def _run_sigma(ns=ns):
                    with _POLL_SEM:
                        assemble("poll_sigma", ns, {"namespace": ns})
                threading.Thread(target=_run_sigma, daemon=True).start()
            with _state["lock"]:
                _state["sigma_cursor"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        log("WARN", f"poll sigma: {e}")

def _poll_anomalies():
    with _state["lock"]:
        cursor = _state["anomaly_cursor"]
    sql = f"""
        SELECT metric_name
        FROM qryn.security_anomalies
        WHERE detected_at > toDateTime('{cursor}')
        LIMIT 10
    """
    try:
        rows = ch_query(sql).get("data", [])
        if rows:
            metrics = [r["metric_name"] for r in rows]
            log("INFO", f"poll anomaly: {metrics}")
            def _run_anomaly():
                with _POLL_SEM:
                    assemble("poll_anomaly", "", {})
            threading.Thread(target=_run_anomaly, daemon=True).start()
            with _state["lock"]:
                _state["anomaly_cursor"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        log("WARN", f"poll anomaly: {e}")

_BACKFILL_INTERVAL = 300  # embed novel patterns every 5 minutes

# ── Self-healing ──────────────────────────────────────────────────────────

def _write_heartbeat():
    now = datetime.now(timezone.utc)
    ts  = now.strftime("%Y-%m-%d %H:%M:%S.%f")
    row = {"recorded_at": ts, "component": "assembler", "status": "ok", "detail": ""}
    body = (
        "INSERT INTO panops.component_heartbeats "
        "(recorded_at,component,status,detail) FORMAT JSONEachRow\n"
        + json.dumps(row)
    ).encode()
    try:
        req = urllib.request.Request(CH_URL, data=body, method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
    except Exception as e:
        log("WARN", f"heartbeat write failed: {e}")

def _watchdog():
    threshold = POLL_INTERVAL * 3
    while True:
        time.sleep(POLL_INTERVAL)
        age = time.time() - _last_poll_time[0]
        if age > threshold:
            log("ERROR", f"poll loop stalled {age:.0f}s — watchdog exit")
            os._exit(1)

def _ensure_deploy_events_table():
    sql = """
        CREATE TABLE IF NOT EXISTS panops.deploy_events (
            event_time   DateTime64(3),
            source       LowCardinality(String),
            event_type   LowCardinality(String),
            namespace    String,
            resource_name String,
            revision     String,
            status       LowCardinality(String),
            actor        String,
            message      String
        ) ENGINE = MergeTree()
        ORDER BY (event_time, source, namespace)
        TTL event_time + INTERVAL 30 DAY
    """
    try:
        req = urllib.request.Request(
            CH_URL, data=sql.encode(), method="POST",
            headers={"Content-Type": "text/plain",
                     "X-ClickHouse-User": os.environ.get("CH_USER", "default"),
                     "X-ClickHouse-Key":  os.environ.get("CH_PASSWORD", "")})
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()
        log("INFO", "schema: panops.deploy_events table ensured")
    except Exception as e:
        log("WARN", f"schema deploy_events: {e}")

def _ensure_outcome_feedback_score_column():
    sql = "ALTER TABLE panops.happenings ADD COLUMN IF NOT EXISTS outcome_feedback_score Float32 DEFAULT -1"
    try:
        req = urllib.request.Request(
            CH_URL, data=sql.encode(), method="POST",
            headers={"Content-Type": "text/plain",
                     "X-ClickHouse-User": os.environ.get("CH_USER", "default"),
                     "X-ClickHouse-Key":  os.environ.get("CH_PASSWORD", "")})
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()
        log("INFO", "schema: happenings.outcome_feedback_score column ensured")
    except Exception as e:
        log("WARN", f"schema: outcome_feedback_score column: {e}")

def _ensure_ml_judge_score_column():
    sql = "ALTER TABLE panops.happenings ADD COLUMN IF NOT EXISTS ml_judge_score Float32 DEFAULT -1"
    try:
        req = urllib.request.Request(
            CH_URL, data=sql.encode(), method="POST",
            headers={"Content-Type": "text/plain",
                     "X-ClickHouse-User": os.environ.get("CH_USER", "default"),
                     "X-ClickHouse-Key":  os.environ.get("CH_PASSWORD", "")})
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()
        log("INFO", "schema: happenings.ml_judge_score column ensured")
    except Exception as e:
        log("WARN", f"schema: ml_judge_score column: {e}")


def _ensure_time_series_token_index():
    sql = "ALTER TABLE qryn.time_series ADD INDEX IF NOT EXISTS labels_token labels TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4"
    try:
        req = urllib.request.Request(
            CH_URL, data=sql.encode(), method="POST",
            headers={"Content-Type": "text/plain",
                     "X-ClickHouse-User": os.environ.get("CH_USER", "default"),
                     "X-ClickHouse-Key":  os.environ.get("CH_PASSWORD", "")})
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
        log("INFO", "schema: qryn.time_series labels_token index ensured")
    except Exception as e:
        log("WARN", f"schema: time_series token index: {e}")

def _handle_deploy_event(body):
    try:
        payload = json.loads(body)
    except Exception:
        log("WARN", "deploy-event: invalid JSON")
        return

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    # Flux notification-controller format
    if "involvedObject" in payload:
        obj       = payload.get("involvedObject", {})
        kind      = obj.get("kind", "")
        name      = obj.get("name", "")
        ns        = obj.get("namespace", "")
        severity  = payload.get("severity", "info")
        reason    = payload.get("reason", "")
        message   = payload.get("message", "")
        meta      = payload.get("metadata", {})
        revision  = meta.get("revision", "")
        status    = "failed" if severity == "error" else "succeeded"
        event_type = kind.lower() if kind else "flux"
        row = {
            "event_time":    now_str,
            "source":        "flux",
            "event_type":    event_type,
            "namespace":     ns,
            "resource_name": name,
            "revision":      revision,
            "status":        status,
            "actor":         payload.get("reportingController", "flux"),
            "message":       message[:500],
        }

    # GitLab push event
    elif payload.get("object_kind") == "push":
        ref      = payload.get("ref", "")
        branch   = ref.replace("refs/heads/", "")
        actor    = payload.get("user_name", "")
        commits  = payload.get("commits", [])
        revision = commits[0]["id"][:12] if commits else ""
        message  = commits[0].get("message", "")[:200] if commits else ""
        row = {
            "event_time":    now_str,
            "source":        "gitlab",
            "event_type":    "push",
            "namespace":     "",
            "resource_name": payload.get("repository", {}).get("name", ""),
            "revision":      revision,
            "status":        "pushed",
            "actor":         actor,
            "message":       f"branch={branch} {message}",
        }

    # GitLab merge request event
    elif payload.get("object_kind") == "merge_request":
        attrs    = payload.get("object_attributes", {})
        state    = attrs.get("state", "")
        actor    = payload.get("user", {}).get("name", "")
        revision = attrs.get("last_commit", {}).get("id", "")[:12]
        row = {
            "event_time":    now_str,
            "source":        "gitlab",
            "event_type":    "merge_request",
            "namespace":     "",
            "resource_name": payload.get("repository", {}).get("name", ""),
            "revision":      revision,
            "status":        state,
            "actor":         actor,
            "message":       attrs.get("title", "")[:200],
        }

    else:
        log("WARN", f"deploy-event: unrecognised format keys={list(payload.keys())[:8]}")
        return

    sql = (
        "INSERT INTO panops.deploy_events"
        " (event_time, source, event_type, namespace, resource_name,"
        "  revision, status, actor, message)"
        " VALUES"
        " ({event_time:String}, {source:String}, {event_type:String},"
        "  {namespace:String}, {resource_name:String},"
        "  {revision:String}, {status:String},"
        "  {actor:String}, {message:String})"
    )
    try:
        ch_exec(sql, params={
            "event_time":    row["event_time"],
            "source":        row["source"],
            "event_type":    row["event_type"],
            "namespace":     row["namespace"],
            "resource_name": row["resource_name"],
            "revision":      row["revision"],
            "status":        row["status"],
            "actor":         row["actor"],
            "message":       row["message"],
        })
        log("INFO", f"deploy-event: recorded {row['source']}/{row['event_type']} {row['resource_name']} rev={row['revision']}")
    except Exception as e:
        log("WARN", f"deploy-event: ch insert failed: {e}")

def _startup_health_check():
    import sys as _sys
    checks = {
        "clickhouse": (CH_URL, "SELECT 1", True),
        "loki":       (f"{LOKI_URL}/ready", None, False),
    }
    for name, (url, body, fatal) in checks.items():
        if not url:
            continue
        try:
            if body:
                req = urllib.request.Request(
                    url, data=body.encode(), method="POST",
                    headers={"Content-Type": "text/plain",
                             "X-ClickHouse-User": os.environ.get("CH_USER", "default"),
                             "X-ClickHouse-Key":  os.environ.get("CH_PASSWORD", "")})
            else:
                req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10):
                pass
            log("INFO", f"startup check {name}: ok")
        except Exception as e:
            level = "ERROR" if fatal else "WARN"
            log(level, f"startup check {name}: {e}")
            if fatal:
                _sys.exit(1)

    # Kubernetes API: only checked when running inside a cluster
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        try:
            from kubernetes import client as _kc, config as _cfg
            _cfg.load_incluster_config()
            _kc.CoreV1Api().list_namespaced_pod(namespace="panops", limit=1)
            log("INFO", "startup check kubernetes: ok")
        except Exception as e:
            log("ERROR", f"startup check kubernetes: {e}")
            import sys as _sys2; _sys2.exit(1)
    else:
        log("INFO", "startup check kubernetes: skipped (not in-cluster)")

def _ensure_validation_streak_column():
    """Add validation_streak column to panops.happenings if it doesn't exist yet."""
    sql = (
        "ALTER TABLE panops.happenings"
        " ADD COLUMN IF NOT EXISTS validation_streak Int32 DEFAULT 0"
    )
    try:
        req = urllib.request.Request(
            CH_URL, data=sql.encode(), method="POST",
            headers={"Content-Type": "text/plain",
                     "X-ClickHouse-User": os.environ.get("CH_USER", "default"),
                     "X-ClickHouse-Key":  os.environ.get("CH_PASSWORD", "")})
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()
        log("INFO", "schema: validation_streak column ensured")
    except Exception as e:
        log("WARN", f"schema migration validation_streak: {e}")

def _resume_open_validations():
    """Re-spawn validation threads for happenings stuck in validating/remediating at startup."""
    sql = (
        "SELECT id, opened_at, closed_at, affected_services, domain, classifier_route,"
        " status, drain3_patterns, falco_rules, actions_taken, metric_anomalies,"
        " validation_streak"
        " FROM panops.happenings"
        " WHERE closed_at IS NULL"
        " AND status IN ('validating','remediating')"
        " AND opened_at > now() - INTERVAL 2 HOUR"
        " FORMAT JSON"
    )
    try:
        req = urllib.request.Request(
            CH_URL, data=sql.encode(), method="POST",
            headers={"Content-Type": "text/plain",
                     "X-ClickHouse-User": os.environ.get("CH_USER", "default"),
                     "X-ClickHouse-Key":  os.environ.get("CH_PASSWORD", "")})
        with urllib.request.urlopen(req, timeout=15) as r:
            rows = json.loads(r.read()).get("data", [])
    except Exception as e:
        log("WARN", f"resume validations: {e}")
        return
    if not _remediator:
        log("WARN", "resume validations: remediator not loaded, skipping")
        return
    for row in rows:
        hid = row.get("id", "?")[:8]
        streak = int(row.get("validation_streak") or 0)
        log("INFO", f"resume: re-spawning validation for stuck happening {hid} streak={streak}")
        threading.Thread(
            target=_remediator._run_validation_loop,
            args=(row["id"], row),
            kwargs={"log_fn": log, "initial_streak": streak, "notify_fn": _send_notification},
            daemon=True,
        ).start()



def _reconcile_stale_happenings():
    """Mark in_progress/validating happenings as auto-resolved when they are clearly stuck."""
    # Max legitimate lifetime = remediation + validation + 5-min grace
    stale_s = (
        (_remediator.REMEDIATION_TIMEOUT_S if _remediator else 600)
        + (_remediator.VALIDATION_TIMEOUT_S if _remediator else 1800)
        + 300
    )
    try:
        rows = ch_query(
            f"SELECT id FROM panops.happenings "
            f"WHERE status IN ('in_progress', 'validating') "
            f"  AND opened_at < now() - INTERVAL {stale_s} SECOND"
        ).get("data", [])
    except Exception as e:
        log("WARN", f"reconcile stale: query failed: {e}")
        return

    if not rows:
        return

    for row in rows:
        hid = row.get("id", "")
        try:
            ch_exec(
                f"ALTER TABLE panops.happenings UPDATE "
                f"  status = 'resolved', outcome = 'auto-resolved', closed_at = now64() "
                f"WHERE id = '{hid}'"
            )
            log("INFO", f"reconcile: auto-resolved stale happening {hid[:8]}")
        except Exception as e:
            log("WARN", f"reconcile: update failed for {hid[:8]}: {e}")


def poll_loop():
    _init_cursors()
    last_backfill   = 0.0
    last_heartbeat  = 0.0
    last_reconcile  = 0.0
    RECONCILE_INTERVAL_S = 300
    while True:
        time.sleep(POLL_INTERVAL)
        try:
            _poll_sigma()
            _poll_anomalies()
            _last_poll_time[0] = time.time()
        except Exception as e:
            log("ERROR", f"poll cycle: {e}")
        # Heartbeat dead-man's switch
        if time.time() - last_heartbeat > _HEARTBEAT_INTERVAL:
            _write_heartbeat()
            last_heartbeat = time.time()
        # Backfill pattern embeddings periodically (not on every poll tick)
        if _classifier and time.time() - last_backfill > _BACKFILL_INTERVAL:
            try:
                _classifier.backfill_pattern_embeddings(CH_URL, log_fn=log)
                last_backfill = time.time()
            except Exception as e:
                log("WARN", f"backfill: {e}")
        # Reconcile stale happenings every 5 minutes
        if time.time() - last_reconcile > RECONCILE_INTERVAL_S:
            try:
                _reconcile_stale_happenings()
                last_reconcile = time.time()
            except Exception as e:
                log("WARN", f"reconcile: {e}")

# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    log("INFO", f"panops-assembler starting port={LISTEN_PORT} poll={POLL_INTERVAL}s")
    _init_postmortem_auth()
    _startup_health_check()
    _ensure_validation_streak_column()
    _ensure_deploy_events_table()
    _ensure_outcome_feedback_score_column()
    _ensure_ml_judge_score_column()
    _ensure_time_series_token_index()
    _resume_open_validations()
    _last_poll_time[0] = time.time()
    threading.Thread(target=poll_loop,  daemon=True).start()
    threading.Thread(target=_watchdog,  daemon=True).start()
    if _consolidation:
        threading.Thread(
            target=_consolidation.dream_scheduler,
            kwargs={"log_fn": log, "notify_fn": _send_notification},
            daemon=True,
        ).start()
        log("INFO", f"consolidation: dream cycle scheduled"
            f" {_consolidation.DREAM_START_HOUR:02d}:00–"
            f"{_consolidation.DREAM_END_HOUR:02d}:00 UTC daily")
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    log("INFO", "ready")
    server.serve_forever()
