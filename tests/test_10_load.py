"""
Load and concurrency tests for the PanOps assembler.

NOTE: All tests run via kubectl port-forward which is a single-tunnel proxy
not designed for high concurrency. Concurrency is capped at 4 connections;
throughput tests use sequential requests.
"""
import json
import os
import subprocess
import time
import threading
import urllib.request
import urllib.error
import pytest
from conftest import http_post, ch_query, http_get, ASSEMBLER_URL, POLL_TIMEOUT

MAX_CONCURRENCY = 4  # port-forward safe limit


def _ensure_assembler_portforward():
    """Restart assembler port-forward if it's down (e.g. left dead by chaos tests)."""
    try:
        status, body = http_get("/healthz", timeout=3)
        if status == 200 and body.strip() == "ok":
            return
    except Exception:
        pass
    # Port-forward is down — restart it
    subprocess.run(["pkill", "-f", "port-forward.*panops-assembler"], capture_output=True)
    time.sleep(1)
    subprocess.Popen(
        ["kubectl", "port-forward", "-n", "panops", "svc/panops-assembler", "8080:8080"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            status, body = http_get("/healthz", timeout=3)
            if status == 200 and body.strip() == "ok":
                return
        except Exception:
            pass
        time.sleep(3)
    pytest.skip("Assembler unreachable after 90s — port-forward could not reconnect")


@pytest.fixture(scope="module", autouse=True)
def ensure_portforward():
    """Re-establish port-forward before load tests in case chaos tests left it dead."""
    _ensure_assembler_portforward()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _post_webhook(ns, alertname, results, idx):
    try:
        payload = json.dumps({"alerts": [{"status": "firing", "labels": {
            "alertname": alertname, "source": "sre", "namespace": ns,
        }, "annotations": {}}]}).encode()
        req = urllib.request.Request(
            ASSEMBLER_URL + "/webhook", data=payload, method="POST"
        )
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10) as r:
            results[idx] = r.status
    except Exception as e:
        results[idx] = str(e)


def sequential_post(n, ns_prefix, alertname, delay=0.05):
    """Fire n webhooks sequentially; return (successes, elapsed, errors)."""
    results = []
    start = time.time()
    for i in range(n):
        try:
            status, _ = http_post("/webhook", {"alerts": [{"status": "firing", "labels": {
                "alertname": alertname, "source": "sre",
                "namespace": f"{ns_prefix}-{i}",
            }, "annotations": {}}]})
            results.append(status)
        except Exception as e:
            results.append(str(e))
        if delay:
            time.sleep(delay)
    elapsed = time.time() - start
    successes = sum(1 for r in results if r == 200)
    errors = [r for r in results if r != 200]
    return successes, elapsed, errors


# ── Throughput ────────────────────────────────────────────────────────────────

def test_webhook_sequential_throughput():
    """Fire 30 webhooks sequentially; all should succeed.

    Note: each request creates a new TCP connection through kubectl port-forward
    which adds ~1s of overhead (SPDY channel teardown). Throughput here reflects
    port-forward limits, not assembler capacity. Threshold is intentionally low.
    """
    n = 30
    successes, elapsed, errors = sequential_post(n, "th-load-seq", "LoadTest", delay=0)
    rps = n / elapsed
    print(f"  {successes}/{n} OK in {elapsed:.2f}s ({rps:.1f} req/s)")
    assert successes == n, f"Failures: {errors[:3]}"
    assert rps > 0.3, f"Throughput unexpectedly low (assembler may be hung): {rps:.1f} req/s"


# ── Low-concurrency parallel ──────────────────────────────────────────────────

def test_low_concurrency_parallel():
    """4 concurrent webhooks (port-forward safe); all should succeed."""
    n = MAX_CONCURRENCY
    results = [None] * n
    threads = [
        threading.Thread(target=_post_webhook, args=(f"th-par-{i}", "ParTest", results, i))
        for i in range(n)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    errors = [r for r in results if r != 200]
    assert not errors, f"Concurrent failures: {errors}"


# ── Dedup under low concurrency ───────────────────────────────────────────────

def test_concurrent_dedup_same_namespace(run_id):
    """4 concurrent webhooks for the same namespace should produce ≤2 happenings."""
    ns = f"th-load-dedup-{run_id}"
    results = [None] * MAX_CONCURRENCY
    threads = [
        threading.Thread(target=_post_webhook, args=(ns, "ConcurrentFlood", results, i))
        for i in range(MAX_CONCURRENCY)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert all(r == 200 for r in results), f"Request failures: {results}"
    time.sleep(8)

    rows = ch_query(
        f"SELECT count() as n FROM panops.happenings "
        f"WHERE has(affected_services, '{ns}') "
        f"AND opened_at > now64() - INTERVAL 3 MINUTE"
    ).get("data", [])
    count = int(rows[0]["n"]) if rows else 0
    assert count <= 2, f"Dedup failed: {count} happenings for {MAX_CONCURRENCY} identical alerts"


# ── Namespace isolation ───────────────────────────────────────────────────────

def test_distinct_namespaces_no_bleed(run_id):
    """Sequential webhooks for 5 different namespaces each create their own happening."""
    namespaces = [f"th-iso-ns{i}-{run_id}" for i in range(5)]
    for ns in namespaces:
        status, _ = http_post("/webhook", {"alerts": [{"status": "firing", "labels": {
            "alertname": "IsolationTest", "source": "sre", "namespace": ns,
        }, "annotations": {}}]})
        assert status == 200

    time.sleep(10)

    for ns in namespaces:
        rows = ch_query(
            f"SELECT count() as n FROM panops.happenings "
            f"WHERE has(affected_services, '{ns}') "
            f"AND opened_at > now64() - INTERVAL 3 MINUTE"
        ).get("data", [])
        count = int(rows[0]["n"]) if rows else 0
        assert count >= 1, f"No happening created for namespace {ns}"


# ── Burst: many sequential, check no 5xx ─────────────────────────────────────

def test_burst_no_5xx():
    """100 sequential webhooks across 10 namespaces; no 5xx responses."""
    successes, elapsed, errors = sequential_post(100, "th-burst", "BurstTest", delay=0)
    server_errors = [e for e in errors if isinstance(e, str) and "500" in e]
    assert not server_errors, f"{len(server_errors)} server errors in burst"
    assert successes == 100, f"Non-200 responses: {errors[:3]}"
    print(f"  Burst: {successes}/100 OK in {elapsed:.1f}s")


# ── Post-load health check ────────────────────────────────────────────────────

def test_assembler_still_healthy_after_load():
    """After all load tests, assembler healthz must still respond OK."""
    status, body = http_get("/healthz")
    assert status == 200
    assert body.strip() == "ok"
