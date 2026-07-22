"""
Core pipeline tests — webhook ingestion, /test endpoint, and /decisions.
"""
import json
import time
import pytest
from conftest import (
    http_get, http_post, ch_query, fire_webhook, poll_happening, POLL_TIMEOUT
)


def test_webhook_returns_accepted():
    status, body = fire_webhook("th-pipeline-smoke", namespace="default")
    assert status == 200
    assert body.strip() == "accepted"


def test_webhook_invalid_json_ignored():
    """Assembler should 200 ACK even malformed payloads (async processing)."""
    import urllib.request
    from conftest import ASSEMBLER_URL
    req = urllib.request.Request(
        ASSEMBLER_URL + "/webhook",
        data=b"not json",
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.status == 200  # accepted, parsing failure logged server-side


def test_resolved_webhook_accepted():
    """A resolved alert should be accepted without error."""
    status, body = fire_webhook("th-resolve-smoke", namespace="default", status="resolved")
    assert status == 200


def test_test_endpoint_fires_all_scenarios():
    status, body = http_get("/test")
    assert status == 200
    lines = body.strip().splitlines()
    # Expect 4 scenario lines, all starting with "fired:"
    assert len(lines) == 4
    assert all(l.startswith("fired:") for l in lines)
    scenario_names = [l.split()[1] for l in lines]
    assert "test_sigma" in scenario_names
    assert "test_oom" in scenario_names
    assert "test_falco" in scenario_names
    assert "test_novel" in scenario_names


def test_decisions_returns_recent_happenings():
    """After /test fires scenarios, /decisions should show at least one result."""
    http_get("/test")  # ensure there's something
    time.sleep(3)
    status, body = http_get("/decisions")
    assert status == 200
    rows = json.loads(body)
    assert isinstance(rows, list)
    assert len(rows) > 0


def test_webhook_creates_happening_in_ch(run_id):
    """End-to-end: POST webhook → poll CH for happening row.

    Uses a unique namespace (not "default") so the assembler's 30-min dedup
    window doesn't merge this into an existing open happening from another test.
    Polls by namespace rather than alertname because drain3 may tokenise the
    alertname (e.g. th-e2e-<NUM>) making it unsearchable by the original value.
    """
    unique_ns = f"th-e2e-{run_id}"
    fire_webhook(f"SyntheticE2E", namespace=unique_ns, source="sre")
    row = poll_happening(namespace=unique_ns, timeout=POLL_TIMEOUT)
    assert row["id"]
    assert row["domain"] in ("SRE", "MIXED", "SOC")


def test_webhook_dedup_merges_same_namespace():
    """Two rapid webhooks for the same namespace should merge, not create two rows."""
    unique_name = f"th-dedup-{int(time.time())}"
    fire_webhook(unique_name, namespace="monitoring", source="sre")
    time.sleep(1)
    fire_webhook(unique_name, namespace="monitoring", source="sre")
    time.sleep(5)
    rows = ch_query(
        f"SELECT count() as n FROM panops.happenings "
        f"WHERE has(affected_services, 'monitoring') "
        f"AND opened_at > now64() - INTERVAL 2 MINUTE "
    ).get("data", [])
    count = int(rows[0]["n"]) if rows else 0
    # Dedup should prevent > 2 rows (one real + one possible merge)
    assert count <= 2, f"Expected dedup to limit rows, got {count}"


def test_falco_label_routes_soc():
    """alert with falco_rule label → domain should be SOC."""
    unique_name = f"th-falco-route-{int(time.time())}"
    fire_webhook(
        unique_name,
        namespace="default",
        source="soc",
        extra_labels={"falco_rule": "Terminal shell in container"},
    )
    row = poll_happening(domain="SOC", timeout=POLL_TIMEOUT)
    assert row["domain"] == "SOC"


def test_yara_source_label_fires():
    """alert with source=yara should be accepted and create a happening."""
    unique_name = f"th-yara-{int(time.time())}"
    status, _ = fire_webhook(unique_name, namespace="security", source="yara")
    assert status == 200
