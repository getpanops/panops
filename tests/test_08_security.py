"""
Black-box security tests for the PanOps assembler HTTP API.

Tests input validation, injection resilience, and that the assembler
doesn't leak internal state through error responses. No external tools
required — pure stdlib HTTP calls from this machine via port-forward.
"""
import json
import subprocess
import time
import urllib.request
import urllib.error
import pytest
from conftest import http_get, http_post, ch_query, ASSEMBLER_URL, POLL_TIMEOUT


@pytest.fixture(scope="module", autouse=True)
def ensure_portforward():
    """Re-establish port-forward before security tests in case test_07 NREM probe left it blocked."""
    try:
        status, body = http_get("/healthz", timeout=5)
        if status == 200 and body.strip() == "ok":
            return
    except Exception:
        pass
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
    pytest.skip("Assembler unreachable after 90s — cannot run security tests")


# ── Helpers ───────────────────────────────────────────────────────────────────

def raw_post(path, body_bytes, content_type="application/json", timeout=10):
    url = ASSEMBLER_URL + path
    req = urllib.request.Request(url, data=body_bytes, method="POST")
    req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


# ── Input validation ──────────────────────────────────────────────────────────

def test_empty_body_accepted():
    """Assembler must not crash on an empty POST body."""
    status, _ = raw_post("/webhook", b"")
    assert status == 200


def test_null_bytes_in_body():
    """Null bytes in payload should not crash the assembler."""
    status, _ = raw_post("/webhook", b"\x00" * 64)
    assert status == 200


def test_oversized_payload_handled():
    """A 2 MB payload should be accepted or rejected cleanly — not crash."""
    big = json.dumps({
        "alerts": [{"status": "firing", "labels": {
            "alertname": "A" * (2 * 1024 * 1024),
            "source": "sre",
        }, "annotations": {}}]
    }).encode()
    status, _ = raw_post("/webhook", big)
    assert status in (200, 400, 413)


def test_deeply_nested_json():
    """Pathological nesting should not cause a stack overflow or hang."""
    nested = {"a": None}
    for _ in range(500):
        nested = {"a": nested}
    status, _ = raw_post("/webhook", json.dumps(nested).encode())
    assert status in (200, 400)


def test_wrong_content_type_still_handled():
    """Content-Type: text/plain with JSON body should be handled gracefully."""
    payload = json.dumps({"alerts": []}).encode()
    status, _ = raw_post("/webhook", payload, content_type="text/plain")
    assert status == 200


# ── Injection resilience ──────────────────────────────────────────────────────

def test_sql_injection_in_alertname():
    """SQL metacharacters in alertname must not reach ClickHouse unescaped."""
    malicious = "'; DROP TABLE panops.happenings; --"
    status, _ = http_post("/webhook", {
        "alerts": [{"status": "firing", "labels": {
            "alertname": malicious, "source": "sre", "namespace": "default",
        }, "annotations": {}}]
    })
    assert status == 200
    # Verify table still exists after the injection attempt
    rows = ch_query("SELECT count() as n FROM panops.happenings").get("data", [])
    assert rows, "happenings table was dropped — SQL injection succeeded"


def test_sql_injection_in_namespace():
    """SQL injection via namespace label."""
    malicious_ns = "default' OR '1'='1"
    status, _ = http_post("/webhook", {
        "alerts": [{"status": "firing", "labels": {
            "alertname": "InjectionProbe", "source": "sre",
            "namespace": malicious_ns,
        }, "annotations": {}}]
    })
    assert status == 200
    rows = ch_query("SELECT count() as n FROM panops.happenings").get("data", [])
    assert rows, "happenings table missing after namespace injection"


def test_newline_injection_in_labels():
    """Newline/CRLF injection in label values."""
    status, _ = http_post("/webhook", {
        "alerts": [{"status": "firing", "labels": {
            "alertname": "Test\r\nX-Injected: evil",
            "source": "sre",
        }, "annotations": {}}]
    })
    assert status == 200


def test_unicode_and_emoji_in_labels():
    """Unicode, emoji, RTL text should not crash string handling."""
    status, _ = http_post("/webhook", {
        "alerts": [{"status": "firing", "labels": {
            "alertname": "Test 🔥 ‮ reversed  null",
            "source": "sre",
            "namespace": "défault",
        }, "annotations": {}}]
    })
    assert status == 200


# ── Information disclosure ────────────────────────────────────────────────────

def test_404_does_not_leak_stack_trace():
    """Unknown paths should return a short error, not a Python traceback."""
    status, body = raw_post("/nonexistent-endpoint-xyz", b"{}")
    assert status in (404, 405)
    assert "Traceback" not in body
    assert "File \"" not in body


def test_healthz_does_not_expose_internals():
    """Healthz response should be minimal — no version, path, or config leak."""
    status, body = http_get("/healthz")
    assert status == 200
    assert len(body) < 256, f"healthz response suspiciously large: {len(body)} bytes"


# ── Webhook replay / ordering ─────────────────────────────────────────────────

def test_duplicate_alert_ids_are_idempotent():
    """Firing the same alert 10× rapidly should not create 10 happenings."""
    ns = f"th-sec-idem-{int(time.time())}"
    for _ in range(10):
        http_post("/webhook", {"alerts": [{"status": "firing", "labels": {
            "alertname": "DuplicateFlood", "source": "sre", "namespace": ns,
        }, "annotations": {}}]})
    time.sleep(5)
    rows = ch_query(
        f"SELECT count() as n FROM panops.happenings "
        f"WHERE has(affected_services, '{ns}') "
        f"AND opened_at > now64() - INTERVAL 2 MINUTE"
    ).get("data", [])
    count = int(rows[0]["n"]) if rows else 0
    assert count <= 2, f"Dedup failed: {count} happenings created for 10 identical alerts"


def test_resolved_without_prior_firing():
    """A resolved alert with no open happening should be handled without error."""
    status, _ = http_post("/webhook", {"alerts": [{"status": "resolved", "labels": {
        "alertname": "NeverFired", "source": "sre", "namespace": "orphan-resolve",
    }, "annotations": {}}]})
    assert status == 200
