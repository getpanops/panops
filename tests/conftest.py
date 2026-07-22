import json
import os
import time
import uuid
import urllib.request
import urllib.error
import pytest

ASSEMBLER_URL = os.getenv("ASSEMBLER_URL", "http://panops-assembler.panops.svc:8080")
CH_URL        = os.getenv("CH_URL",        "http://clickhouse.clickhouse.svc:8123")
CH_USER       = os.getenv("CH_USER",       "default")
CH_PASSWORD   = os.getenv("CH_PASSWORD",   "")
LLAMA_URL     = os.getenv("LLAMA_URL",     "http://panops-llama-server.panops.svc:8080")
POLL_TIMEOUT  = int(os.getenv("TEST_TIMEOUT", "45"))
POLL_INTERVAL = 2


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def http_get(path, base=None, timeout=10):
    url = (base or ASSEMBLER_URL) + path
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode()


def http_post(path, body, base=None, timeout=10):
    url = (base or ASSEMBLER_URL) + path
    data = json.dumps(body).encode() if isinstance(body, dict) else body.encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode()


def ch_query(sql, retries=3):
    body = sql.encode()
    for attempt in range(retries):
        try:
            req = urllib.request.Request(CH_URL + "?default_format=JSON", data=body, method="POST")
            req.add_header("X-ClickHouse-User", CH_USER)
            req.add_header("X-ClickHouse-Key",  CH_PASSWORD)
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
            if attempt == retries - 1:
                raise
            time.sleep(1 + attempt)


def ch_exec(sql):
    body = sql.encode()
    req = urllib.request.Request(CH_URL, data=body, method="POST")
    req.add_header("X-ClickHouse-User", CH_USER)
    req.add_header("X-ClickHouse-Key",  CH_PASSWORD)
    with urllib.request.urlopen(req, timeout=15) as r:
        r.read()


# ── Webhook helpers ───────────────────────────────────────────────────────────

def fire_webhook(alertname, namespace="", source="sre", extra_labels=None, status="firing"):
    """POST an Alertmanager-format webhook payload to the assembler."""
    labels = {"alertname": alertname, "source": source}
    if namespace:
        labels["namespace"] = namespace
    if extra_labels:
        labels.update(extra_labels)
    payload = {"alerts": [{"status": status, "labels": labels, "annotations": {}}]}
    return http_post("/webhook", payload)


def poll_happening(alertname=None, domain=None, route=None, namespace=None,
                   min_age_s=0, timeout=None):
    """
    Poll panops.happenings until a matching row appears.
    Returns the row dict or raises TimeoutError.
    """
    deadline = time.time() + (timeout or POLL_TIMEOUT)
    clauses = ["opened_at > now64() - INTERVAL 5 MINUTE"]
    if alertname:
        clauses.append(f"has(drain3_patterns, '{alertname}') OR "
                       f"JSONExtractString(drain3_patterns,'0','template') LIKE '%{alertname}%'")
    if domain:
        clauses.append(f"domain = '{domain}'")
    if route:
        clauses.append(f"classifier_route = '{route}'")
    if namespace:
        clauses.append(f"has(affected_services, '{namespace}')")

    where = " AND ".join(clauses)
    sql = (
        "SELECT toString(id) as id, domain, classifier_route, status, "
        "outcome, actions_taken, runbook_ref, "
        "length(affected_services) as svc_count "
        f"FROM panops.happenings WHERE {where} "
        "ORDER BY opened_at DESC LIMIT 1"
    )
    while time.time() < deadline:
        try:
            rows = ch_query(sql).get("data", [])
            if rows:
                return rows[0]
        except Exception:
            pass
        time.sleep(POLL_INTERVAL)
    raise TimeoutError(f"No matching happening found within {timeout or POLL_TIMEOUT}s")


def poll_happening_by_id(happening_id, field_check=None, timeout=None):
    """Poll until a specific happening's field matches the check fn."""
    deadline = time.time() + (timeout or POLL_TIMEOUT)
    sql = (
        f"SELECT toString(id) as id, domain, classifier_route, status, "
        f"outcome, actions_taken, runbook_ref "
        f"FROM panops.happenings WHERE id = '{happening_id}' LIMIT 1"
    )
    while time.time() < deadline:
        try:
            rows = ch_query(sql).get("data", [])
            if rows:
                row = rows[0]
                if field_check is None or field_check(row):
                    return row
        except Exception:
            pass
        time.sleep(POLL_INTERVAL)
    raise TimeoutError(f"Happening {happening_id[:8]} did not satisfy condition within {timeout or POLL_TIMEOUT}s")


# ── Pytest fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def run_id():
    """Unique prefix for test artifacts to avoid collision with real happenings."""
    return f"th-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="session")
def urls():
    return {
        "assembler": ASSEMBLER_URL,
        "ch":        CH_URL,
        "llama":     LLAMA_URL,
    }
