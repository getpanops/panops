"""
Dream cycle (NREM/REM) tests.
Verifies schema, SQL correctness, and manual trigger via /test/nrem endpoint.

The /test/nrem endpoint is optional — tests degrade gracefully to SQL-only
checks if the assembler hasn't been patched with the endpoint.
"""
import json
import time
import urllib.error
import pytest
from conftest import http_get, ch_query


# ── Schema and SQL correctness ────────────────────────────────────────────────

def test_dream_state_table_writable():
    """panops.dream_state must accept UPSERT-style writes (ReplacingMergeTree)."""
    from conftest import ch_exec
    ch_exec(
        "INSERT INTO panops.dream_state (key, value, updated_at) "
        f"VALUES ('test_key', 'test_value', now64())"
    )
    rows = ch_query(
        "SELECT value FROM panops.dream_state "
        "WHERE key = 'test_key' LIMIT 1"
    ).get("data", [])
    assert rows, "dream_state write-read failed"


def test_dream_state_last_rem_run_exists():
    """last_rem_run key should exist after first dream cycle completes."""
    rows = ch_query(
        "SELECT value FROM panops.dream_state WHERE key = 'last_rem_run' LIMIT 1"
    ).get("data", [])
    if not rows:
        pytest.skip("last_rem_run not yet set — dream cycle may not have run")
    print(f"  last_rem_run = {rows[0]['value']}")


def test_brittleness_sql_valid():
    """The NREM brittleness query should execute without error."""
    rows = ch_query(
        "SELECT rule_name, "
        "countIf(outcome='escalated') AS esc, "
        "count() AS total, "
        "toFloat64(countIf(outcome='escalated')) / count() AS score "
        "FROM panops.consolidation_rewards "
        "WHERE recorded_at > now64() - INTERVAL 30 DAY "
        "GROUP BY rule_name "
        "HAVING total >= 3 "
        "ORDER BY score DESC "
        "LIMIT 10"
    ).get("data", [])
    print(f"  Brittleness rows: {len(rows)}")
    for row in rows:
        score = float(row["score"])
        assert 0.0 <= score <= 1.0


def test_negative_rewards_sql_valid():
    """
    The negative reward recording SQL should be syntactically valid.
    This is the query that finds escalated happenings not yet in rewards and inserts them.
    """
    rows = ch_query(
        "SELECT toString(h.id) as id, h.classifier_route "
        "FROM panops.happenings h "
        "WHERE h.outcome = 'escalated' "
        "AND h.closed_at > now64() - INTERVAL 7 DAY "
        "AND NOT EXISTS ("
        "  SELECT 1 FROM panops.consolidation_rewards r "
        "  WHERE r.happening_id = toString(h.id) AND r.outcome = 'escalated'"
        ") "
        "LIMIT 5"
    ).get("data", [])
    print(f"  Happenings needing negative rewards: {len(rows)}")


def test_cbr_budget_sql_valid():
    """CBR refresh budget allocation SQL should execute cleanly."""
    rows = ch_query(
        "SELECT toString(id) as id, domain, classifier_route, "
        "length(affected_services) as svc_count "
        "FROM panops.happenings "
        "WHERE status = 'resolved' "
        "AND opened_at > now64() - INTERVAL 30 DAY "
        "ORDER BY opened_at DESC LIMIT 50"
    ).get("data", [])
    print(f"  CBR candidate happenings: {len(rows)}")
    assert len(rows) >= 0  # just verify SQL runs


def test_leading_indicator_sql_valid():
    """Leading indicator mining SQL should execute without error."""
    rows = ch_query(
        "SELECT metric_a, metric_b, count() as hits, avg(pearson_r) as avg_r "
        "FROM panops.metric_correlations "
        "WHERE discovered_at > now64() - INTERVAL 30 DAY "
        "GROUP BY metric_a, metric_b "
        "ORDER BY hits DESC LIMIT 10"
    ).get("data", [])
    print(f"  Leading indicator candidates: {len(rows)}")


# ── /test/nrem endpoint (optional) ───────────────────────────────────────────

def _check_testnrem_available():
    try:
        status, _ = http_get("/test/nrem", timeout=10)
        return status != 404
    except urllib.error.HTTPError as e:
        return e.code != 404
    except Exception:
        return False


@pytest.fixture(scope="module")
def testnrem_available():
    if not _check_testnrem_available():
        pytest.skip(
            "/test/nrem endpoint not found — apply the assembler patch and redeploy."
        )


def test_nrem_phase_runs_via_endpoint(testnrem_available):
    """
    GET /test/nrem triggers the NREM phase synchronously and returns a summary.
    Expected response: {brittleness_scores: {...}, cbr_refreshed: N,
                        negative_rewards_recorded: N, elapsed_s: F}
    """
    status, body = http_get("/test/nrem", timeout=120)
    assert status == 200
    result = json.loads(body)
    assert "brittleness_scores" in result, f"Response missing brittleness_scores: {result}"
    assert "elapsed_s" in result
    print(f"  NREM result: {result}")


def test_nrem_brittleness_scores_valid(testnrem_available):
    """All brittleness scores returned by NREM should be floats in [0, 1]."""
    status, body = http_get("/test/nrem", timeout=120)
    assert status == 200
    result = json.loads(body)
    scores = result.get("brittleness_scores", {})
    if not scores:
        pytest.skip("No brittleness scores returned (insufficient data for 30d window)")
    for route, score in scores.items():
        assert 0.0 <= float(score) <= 1.0, f"Route {route!r} has invalid score: {score}"
    print(f"  Brittleness scores: {scores}")
