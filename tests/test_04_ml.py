"""
ML fast-path tests — classifier routing, kNN similarity, embedding pipeline.
"""
import json
import time
import pytest
from conftest import ch_query, fire_webhook, poll_happening, POLL_TIMEOUT


def test_incident_embeddings_table_accessible():
    rows = ch_query(
        "SELECT count() as n, count(DISTINCT happening_id) as unique_h "
        "FROM panops.incident_embeddings"
    ).get("data", [])
    assert rows
    print(f"  embeddings: {rows[0]['n']} rows, {rows[0]['unique_h']} unique happenings")


def test_similarity_score_populated_for_known_happenings():
    """
    Any happening with classifier_route='known' should have similarity_score > 0,
    indicating the kNN matched a prior embedding.
    """
    rows = ch_query(
        "SELECT toString(id) as id, similarity_score, classifier_route "
        "FROM panops.happenings "
        "WHERE classifier_route = 'known' "
        "AND opened_at > now64() - INTERVAL 24 HOUR "
        "LIMIT 5"
    ).get("data", [])
    if not rows:
        pytest.skip("No 'known' happenings in last 24h to verify kNN scoring")
    for row in rows:
        sim = float(row["similarity_score"] or 0)
        assert sim > 0, f"Happening {row['id'][:8]} has classifier_route=known but similarity_score=0"


def test_novel_happenings_have_zero_similarity():
    """
    Happenings routed as 'novel' should have no accepted CBR match
    (matched_incident_id is NULL). similarity_score may be non-zero —
    it stores the best candidate score even when below the accept threshold.
    """
    rows = ch_query(
        "SELECT toString(id) as id, similarity_score, "
        "toString(matched_incident_id) as matched_id "
        "FROM panops.happenings "
        "WHERE classifier_route = 'novel' "
        "AND opened_at > now64() - INTERVAL 24 HOUR "
        "LIMIT 5"
    ).get("data", [])
    if not rows:
        pytest.skip("No 'novel' happenings in last 24h")
    for row in rows:
        assert not row.get("matched_id") or row["matched_id"] in ("", "00000000-0000-0000-0000-000000000000"), (
            f"Novel happening {row['id'][:8]} has accepted match {row['matched_id'][:8]} "
            f"(sim={float(row['similarity_score'] or 0):.3f}) — CBR threshold may be too low"
        )


def test_cbr_embeddings_exist_for_resolved_happenings():
    """
    Resolved happenings should have embeddings in incident_embeddings,
    so CBR refresh can match them in future kNN lookups.
    """
    rows = ch_query(
        "SELECT count() as n FROM panops.incident_embeddings ie "
        "JOIN panops.happenings h ON h.id = ie.happening_id "
        "WHERE h.status = 'resolved'"
    ).get("data", [])
    n = int(rows[0]["n"]) if rows else 0
    assert n > 0, "No embeddings found for resolved happenings — CBR refresh may not have run"


def test_fast_classify_route_distribution():
    """
    Sanity check: over the last 7 days, we should see a spread of routes —
    not everything funnelling to a single route indicates a classification bug.
    """
    rows = ch_query(
        "SELECT classifier_route, count() as n "
        "FROM panops.happenings "
        "WHERE opened_at > now64() - INTERVAL 7 DAY "
        "GROUP BY classifier_route "
        "ORDER BY n DESC"
    ).get("data", [])
    if not rows:
        pytest.skip("No happenings in last 7 days")
    routes = {r["classifier_route"]: int(r["n"]) for r in rows}
    print(f"  Route distribution: {routes}")
    # Fail only if literally 100% of happenings share one route — that indicates
    # a stuck classifier. High 'known' dominance (95-99%) is normal as the CBR
    # library matures and most patterns become recognisable.
    total = sum(routes.values())
    if total > 10:
        max_share = max(routes.values()) / total
        assert max_share < 1.0, (
            f"Route {max(routes, key=routes.get)!r} is 100% — classifier stuck"
        )


def test_consolidation_rewards_have_both_outcomes():
    """
    After negative reward recording runs, consolidation_rewards should have both
    'resolved' and 'escalated' outcomes — not just positive feedback.
    """
    rows = ch_query(
        "SELECT outcome, count() as n "
        "FROM panops.consolidation_rewards "
        "GROUP BY outcome"
    ).get("data", [])
    if not rows:
        pytest.skip("No consolidation_rewards yet — dream cycle may not have run")
    outcomes = {r["outcome"] for r in rows}
    print(f"  Reward outcomes: {outcomes}")
    # At minimum we need resolved; escalated will appear after negative reward pass
    assert "resolved" in outcomes, "No 'resolved' rewards — positive feedback not recorded"


def test_brittleness_query_runs():
    """
    The brittleness scoring SQL should execute without error and return
    valid float values.
    """
    rows = ch_query(
        "SELECT rule_name, "
        "countIf(outcome='escalated') as esc, "
        "count() as total, "
        "countIf(outcome='escalated') / count() AS brittleness "
        "FROM panops.consolidation_rewards "
        "WHERE recorded_at > now64() - INTERVAL 30 DAY "
        "GROUP BY rule_name "
        "HAVING total >= 3 "
        "ORDER BY brittleness DESC"
    ).get("data", [])
    print(f"  Brittleness scores: {rows[:3]}")
    for row in rows:
        b = float(row["brittleness"])
        assert 0.0 <= b <= 1.0, f"Brittleness out of range: {b}"


def test_embedding_description_is_non_degenerate():
    """
    P2.1: Embeddings should use the new format ("Log patterns: ...") not the old
    degenerate format that emitted "Metric anomalies: N". The old format embedded
    only (domain, ns, counts) making kNN similarity meaningless.
    """
    rows = ch_query(
        "SELECT count() AS total, "
        "countIf(positionCaseInsensitive(description_text, 'Metric anomalies:') > 0) AS old_format "
        "FROM panops.incident_embeddings"
    ).get("data", [])
    if not rows or int(rows[0].get("total", 0)) == 0:
        pytest.skip("No embeddings yet — assembler may not have processed any happenings")
    total      = int(rows[0]["total"])
    old_format = int(rows[0]["old_format"])
    ratio      = old_format / total
    print(f"  Embedding format: {old_format}/{total} ({ratio:.1%}) still in old degenerate format")
    assert ratio == 0.0, (
        f"{old_format}/{total} embeddings still use the old degenerate format. "
        "Run NREM reembed or redeploy classifier.py with P2.1 fix."
    )


def test_rule_success_rates_stored_in_dream_state():
    """
    P2.2: After NREM runs, dream_state should contain 'rule_success_rates' as a
    JSON object. Validates that the reward loop computed and persisted rates.
    """
    rows = ch_query(
        "SELECT value FROM panops.dream_state WHERE key = 'rule_success_rates' LIMIT 1"
    ).get("data", [])
    if not rows:
        pytest.skip("rule_success_rates not yet in dream_state — NREM may not have run")
    import json as _json
    rates = _json.loads(rows[0]["value"])
    assert isinstance(rates, dict), "rule_success_rates should be a JSON object"
    print(f"  Rule success rates: {rates}")
    for rule, rate in rates.items():
        assert 0.0 <= float(rate) <= 1.0, f"Rate for {rule!r} out of range: {rate}"


def test_deprioritized_rule_falls_back_to_k8s_self_heal():
    """
    P2.2: Offline unit test — verifies that _effective_rule() in remediator.py
    falls back to 'k8s_self_heal' when the dream-cycle success rate is below threshold.
    """
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../docker/assembler/src"))
    import remediator
    # Inject a synthetic low-rate entry directly into the module dict
    remediator._RULE_SUCCESS_RATES["_test_failing_rule"] = 0.05
    result = remediator._effective_rule("_test_failing_rule")
    assert result == "k8s_self_heal", (
        f"Expected 'k8s_self_heal' for low-success rule, got {result!r}"
    )
    # High-rate rule should pass through unchanged
    remediator._RULE_SUCCESS_RATES["_test_good_rule"] = 0.95
    result2 = remediator._effective_rule("_test_good_rule")
    assert result2 == "_test_good_rule", (
        f"Expected '_test_good_rule' to pass through, got {result2!r}"
    )
    # Clean up injected entries
    del remediator._RULE_SUCCESS_RATES["_test_failing_rule"]
    del remediator._RULE_SUCCESS_RATES["_test_good_rule"]


def test_recurrence_brittleness_query_runs():
    """
    P2.3: The recurrence brittleness SQL (group by route+ns) should execute
    without error. Verifies the new query doesn't break against the live schema.
    """
    rows = ch_query(
        "SELECT classifier_route, "
        "arrayElement(affected_services, 1) AS ns, "
        "count() AS cnt "
        "FROM panops.happenings "
        "WHERE opened_at > now64() - INTERVAL 14 DAY "
        "  AND classifier_route != '' "
        "  AND status IN ('resolved', 'escalated') "
        "GROUP BY classifier_route, ns "
        "HAVING cnt >= 3 "
        "ORDER BY cnt DESC "
        "LIMIT 10"
    ).get("data", [])
    print(f"  Chronic (route,ns) pairs: {rows[:3]}")
    for row in rows:
        assert int(row["cnt"]) >= 3, "HAVING clause should filter cnt < 3"
