"""
PanOps Brain — Offline Consolidation ("Dream Cycle")

Two loops run independently:

  Memory cycle  — record_resolution() called immediately after each happening
                  closes. Records the rule→outcome reward so the dream cycle
                  can learn from it. _record_negative_rewards() adds the missing
                  negative signal for escalated-but-never-resolved happenings.

  Dream cycle   — runs once per day in DREAM_START_HOUR–DREAM_END_HOUR UTC.
                  Two sequential phases:

                  NREM: statistical consolidation — brittleness scoring,
                  negative reward recording, brittleness-weighted CBR refresh,
                  and Prometheus leading indicator mining.

                  REM: LLM-driven synthesis — proposes new classifier/
                  remediator/Sigma rules targeting the most brittle incident
                  types and opens GitLab MRs. Conditional: runs when max
                  brittleness >= 0.3 or weekly, whichever comes first.
"""
import json
import os
import statistics
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta

CH_URL           = os.getenv("CH_URL",   "http://observability-clickhouse-clickhouse-headless.observability.svc.cluster.local:8123")
PROM_URL         = os.getenv("PROM_URL", "http://gigapipe.observability.svc.cluster.local:3100")
LLAMA_SERVER_URL = os.getenv("LLAMA_SERVER_URL", "http://panops-llama-server.panops.svc:8080")

DREAM_START_HOUR   = int(os.getenv("DREAM_START_HOUR",   "16"))
DREAM_START_MINUTE = int(os.getenv("DREAM_START_MINUTE", "30"))
DREAM_END_HOUR     = int(os.getenv("DREAM_END_HOUR",     "18"))
DREAM_END_MINUTE   = int(os.getenv("DREAM_END_MINUTE",   "30"))
LOOKAHEAD_MINUTES = int(os.getenv("LOOKAHEAD_MINUTES", "60"))

ML_JUDGE_THRESHOLD_POOR = 0.50  # cosine sim below this → emit negative_ml_judge reward

# Metrics evaluated against a namespace in the window before each incident.
INDICATOR_METRICS = [
    'container_memory_working_set_bytes',
    'container_cpu_usage_seconds_total',
    'kube_pod_container_restarts_total',
    'kube_pod_status_ready',
]


def _ch_query(sql):
    try:
        body = (sql + " FORMAT JSON").encode()
        req  = urllib.request.Request(CH_URL, data=body, method="POST")
        req.add_header("Content-Type",      "text/plain")
        req.add_header("X-ClickHouse-User", os.getenv("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.getenv("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read()).get("data", [])
    except Exception as e:
        print(f"[WARN] consolidation ch_query: {e}", file=sys.stderr, flush=True)
        return []


def _ch_exec(sql):
    try:
        req = urllib.request.Request(CH_URL, data=sql.encode(), method="POST")
        req.add_header("Content-Type",      "text/plain")
        req.add_header("X-ClickHouse-User", os.getenv("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.getenv("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
    except Exception as e:
        print(f"[WARN] consolidation ch_exec: {e}", file=sys.stderr, flush=True)


def _prom_query_range(promql, start_ts, end_ts, step="60s"):
    try:
        params = urllib.parse.urlencode({
            "query": promql, "start": int(start_ts),
            "end": int(end_ts), "step": step,
        })
        req = urllib.request.Request(
            f"{PROM_URL}/api/v1/query_range?{params}", method="GET")
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
        results = data.get("data", {}).get("result", [])
        if not results:
            return []
        return [(float(t), float(v)) for t, v in results[0].get("values", [])]
    except Exception:
        return []


def _slope(xs, ys):
    n = len(xs)
    if n < 2:
        return 0.0
    mx, my = sum(xs) / n, sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    return num / den if den else 0.0


def _compute_brittleness(log_fn=None):
    """
    Compute a brittleness score per incident type.
    score = escalation_rate = escalated_count / total_count
    Types with fewer than 3 happenings are excluded.
    Returns dict[str, float] sorted descending.
    """
    try:
        rows = _ch_query(
            "SELECT classifier_route,"
            "       countIf(status = 'escalated') AS esc,"
            "       count() AS total"
            " FROM panops.happenings"
            " WHERE opened_at > now() - INTERVAL 30 DAY"
            "   AND classifier_route != ''"
            " GROUP BY classifier_route"
        )
        if not rows:
            return {}
        scores = {}
        for row in rows:
            total = int(row.get("total", 0))
            if total < 3:
                continue
            esc = int(row.get("esc", 0))
            scores[row["classifier_route"]] = round(esc / total, 4)
        scores = dict(sorted(scores.items(), key=lambda kv: kv[1], reverse=True))
        if log_fn and scores:
            top = list(scores.items())[:3]
            log_fn("INFO", f"consolidation: brittleness top-3: {top}")
        return scores
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: _compute_brittleness: {e}")
        return {}


RECURRENCE_THRESHOLD = int(os.getenv("RECURRENCE_THRESHOLD", "3"))  # incidents per (route,ns) in 14d
RULE_DEPRIORITIZE_THRESHOLD = float(os.getenv("RULE_DEPRIORITIZE_THRESHOLD", "0.2"))


def _compute_rule_success_rates(log_fn=None):
    """
    Compute per-rule success rate from unindexed consolidation_rewards rows.
    Returns dict[str, float] of rule_name → resolved/(resolved+escalated).
    Marks processed rows dream_indexed=1 so they aren't reprocessed.
    Stores the result in dream_state under 'rule_success_rates' as JSON.
    """
    try:
        rows = _ch_query(
            "SELECT rule_name,"
            "       countIf(outcome = 'resolved') AS resolved,"
            "       countIf(outcome = 'escalated') AS escalated"
            " FROM panops.consolidation_rewards"
            " WHERE dream_indexed = 0"
            " GROUP BY rule_name"
            " HAVING (resolved + escalated) >= 3"
        )
        if not rows:
            if log_fn:
                log_fn("INFO", "consolidation: rule success rates — no unindexed data yet")
            return {}

        rates = {}
        for row in rows:
            res = int(row.get("resolved", 0))
            esc = int(row.get("escalated", 0))
            total = res + esc
            if total < 3:
                continue
            rates[row["rule_name"]] = round(res / total, 4)

        # Persist to dream_state for remediator to read at startup
        now_iso = datetime.now(timezone.utc).isoformat()
        _ch_exec(
            "INSERT INTO panops.dream_state (key, value, updated_at) VALUES"
            f" ('rule_success_rates', '{json.dumps(rates).replace(chr(39), chr(39)*2)}', now64(3))"
        )

        # Mark these rows as indexed so next NREM only processes new data
        _ch_exec(
            "ALTER TABLE panops.consolidation_rewards UPDATE dream_indexed = 1"
            " WHERE dream_indexed = 0"
        )

        if log_fn:
            low = [(k, v) for k, v in rates.items() if v < RULE_DEPRIORITIZE_THRESHOLD]
            log_fn("INFO",
                   f"consolidation: rule success rates — {len(rates)} rules, "
                   f"{len(low)} below deprioritize threshold {RULE_DEPRIORITIZE_THRESHOLD}")
        return rates
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: _compute_rule_success_rates: {e}")
        return {}


def _compute_recurrence_brittleness(log_fn=None):
    """
    Group happenings by (classifier_route, namespace) over 14 days.
    Pairs with >= RECURRENCE_THRESHOLD incidents that each resolved individually
    are "chronically recurring" — they mask-not-fix the underlying problem.
    Returns list of (route, ns, count) tuples sorted descending by count.
    """
    try:
        rows = _ch_query(
            "SELECT classifier_route,"
            "       arrayElement(affected_services, 1) AS ns,"
            "       count() AS cnt"
            " FROM panops.happenings"
            " WHERE opened_at > now() - INTERVAL 14 DAY"
            "   AND classifier_route != ''"
            "   AND status IN ('resolved', 'escalated')"
            " GROUP BY classifier_route, ns"
            f" HAVING cnt >= {RECURRENCE_THRESHOLD}"
            " ORDER BY cnt DESC"
        )
        if not rows:
            return []
        pairs = [(r["classifier_route"], r["ns"], int(r["cnt"])) for r in rows]
        if log_fn and pairs:
            log_fn("INFO",
                   f"consolidation: recurrence brittleness — {len(pairs)} chronic (route,ns) pairs: "
                   + ", ".join(f"{r}:{ns}×{n}" for r, ns, n in pairs[:3]))
        return pairs
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: _compute_recurrence_brittleness: {e}")
        return []


def _ensure_schema():
    _ch_exec("""
        CREATE TABLE IF NOT EXISTS panops.leading_indicators (
            indicator_name   String,
            namespace        String,
            metric_query     String,
            incident_type    String,
            slope_threshold  Float64,
            zscore_threshold Float64,
            sample_count     UInt32,
            trained_at       DateTime64(3, 'UTC')
        ) ENGINE = ReplacingMergeTree(trained_at)
        ORDER BY (indicator_name, namespace, incident_type)
    """)
    _ch_exec("""
        CREATE TABLE IF NOT EXISTS panops.consolidation_rewards (
            happening_id  String,
            rule_name     String,
            outcome       String,
            recorded_at   DateTime64(3, 'UTC'),
            dream_indexed UInt8 DEFAULT 0
        ) ENGINE = MergeTree()
        ORDER BY (recorded_at, happening_id)
    """)
    _ch_exec("""
        CREATE TABLE IF NOT EXISTS panops.dream_state (
            key        String,
            value      String,
            updated_at DateTime64(3, 'UTC')
        ) ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY key
    """)


def record_resolution(happening, rule_name, log_fn=None):
    """
    Memory cycle — called immediately after a happening resolves.
    Records the rule→outcome pair so the dream cycle can learn from it.
    """
    _ensure_schema()
    hid = happening.get("id", "")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    body = (
        "INSERT INTO panops.consolidation_rewards "
        "(happening_id, rule_name, outcome, recorded_at) FORMAT JSONEachRow\n"
        + json.dumps({"happening_id": hid, "rule_name": rule_name or "",
                      "outcome": "resolved", "recorded_at": now})
    ).encode()
    try:
        req = urllib.request.Request(CH_URL, data=body, method="POST")
        req.add_header("Content-Type",      "text/plain")
        req.add_header("X-ClickHouse-User", os.getenv("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.getenv("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()
        if log_fn:
            log_fn("INFO", f"consolidation: reward recorded hid={hid[:8]} rule={rule_name}")
        try:
            _score_outcome_feedback(happening, rule_name, log_fn=log_fn)
        except Exception as e:
            if log_fn:
                log_fn("WARN", f"consolidation: outcome_feedback: {e}")
        try:
            _ml_judge_resolution(happening, rule_name, log_fn=log_fn)
        except Exception as e:
            if log_fn:
                log_fn("WARN", f"consolidation: ml_judge: {e}")
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: record_resolution: {e}")


def _score_outcome_feedback(happening, rule_name, log_fn=None):
    """Score whether the classifier_route prediction matched the actual remediation rule."""
    hid = happening.get("id", "")
    predicted_route = happening.get("classifier_route", "")
    if not predicted_route or not rule_name:
        return

    def _route_matches(predicted, actual):
        if predicted == actual:
            return True
        p_parts = predicted.split("_")
        a_parts = actual.split("_")
        return len(p_parts) > 0 and p_parts[0] == a_parts[0]

    matched = _route_matches(predicted_route, rule_name)
    score = 1.0 if matched else 0.0

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    try:
        sql = f"ALTER TABLE panops.happenings UPDATE outcome_feedback_score = {score} WHERE id = '{hid}'"
        req = urllib.request.Request(CH_URL, data=sql.encode(), method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("X-ClickHouse-User", os.getenv("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.getenv("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=15) as r:
            r.read()
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: outcome_feedback update score: {e}")

    if not matched:
        body = (
            "INSERT INTO panops.consolidation_rewards "
            "(happening_id, rule_name, outcome, recorded_at) FORMAT JSONEachRow\n"
            + json.dumps({
                "happening_id": hid,
                "rule_name": predicted_route,
                "outcome": "negative_outcome_feedback",
                "recorded_at": now,
            })
        ).encode()
        try:
            req = urllib.request.Request(CH_URL, data=body, method="POST")
            req.add_header("Content-Type", "text/plain")
            req.add_header("X-ClickHouse-User", os.getenv("CH_USER", "default"))
            req.add_header("X-ClickHouse-Key",  os.getenv("CH_PASSWORD", ""))
            with urllib.request.urlopen(req, timeout=15) as r:
                r.read()
            if log_fn:
                log_fn("INFO",
                       f"consolidation: outcome_feedback negative reward hid={hid[:8]} "
                       f"predicted={predicted_route} actual={rule_name}")
        except Exception as e:
            if log_fn:
                log_fn("WARN", f"consolidation: outcome_feedback negative reward: {e}")


def _ml_judge_resolution(happening, rule_name, log_fn=None):
    """
    Offline ML-as-Judge: compare the embedding of the happening description against
    an embedding of the resolution text. Writes ml_judge_score to panops.happenings
    and emits a negative_ml_judge reward when cosine similarity is below the threshold.

    Requires fastembed (loaded by classifier.py). Silently no-ops if unavailable or
    if the happening has no stored embedding yet.
    """
    hid = happening.get("id", "")
    if not hid or not rule_name:
        return

    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import classifier as _clf
    except ImportError:
        if log_fn:
            log_fn("WARN", "consolidation: ml_judge: classifier unavailable")
        return

    if not _clf._HAS_EMBED:
        return

    # Fetch the stored happening embedding (written by embed_and_match at assembly time)
    rows = _ch_query(
        f"SELECT embedding FROM panops.incident_embeddings"
        f" WHERE happening_id = '{hid}'"
        f" ORDER BY embedded_at DESC LIMIT 1"
    )
    if not rows or not rows[0].get("embedding"):
        if log_fn:
            log_fn("INFO", f"consolidation: ml_judge: no embedding for hid={hid[:8]}, skipping")
        return

    happening_vec = rows[0]["embedding"]

    # Embed a short description of the resolution
    domain = happening.get("domain", "")
    resolution_text = f"Resolved by {rule_name} in {domain} domain."
    resolution_vecs = _clf._embed([resolution_text])
    if not resolution_vecs:
        return
    resolution_vec = resolution_vecs[0]

    # fastembed vectors are L2-normalised so dot product = cosine similarity
    dot = sum(a * b for a, b in zip(happening_vec, resolution_vec))
    score = round(max(0.0, min(1.0, float(dot))), 4)

    # Write score to happenings
    _ch_exec(
        f"ALTER TABLE panops.happenings UPDATE ml_judge_score = {score}"
        f" WHERE id = '{hid}'"
    )
    if log_fn:
        log_fn("INFO", f"consolidation: ml_judge hid={hid[:8]} score={score:.3f}")

    # Emit negative reward when prediction was poorly aligned with resolution
    if score < ML_JUDGE_THRESHOLD_POOR:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
        body = (
            "INSERT INTO panops.consolidation_rewards"
            " (happening_id, rule_name, outcome, recorded_at) FORMAT JSONEachRow\n"
            + json.dumps({"happening_id": hid, "rule_name": rule_name or "",
                          "outcome": "negative_ml_judge", "recorded_at": now})
        ).encode()
        try:
            req = urllib.request.Request(CH_URL, data=body, method="POST")
            req.add_header("Content-Type",      "text/plain")
            req.add_header("X-ClickHouse-User", os.getenv("CH_USER", "default"))
            req.add_header("X-ClickHouse-Key",  os.getenv("CH_PASSWORD", ""))
            with urllib.request.urlopen(req, timeout=15) as r:
                r.read()
            if log_fn:
                log_fn("WARN",
                       f"consolidation: ml_judge: poor alignment hid={hid[:8]}"
                       f" score={score:.3f} → negative_ml_judge reward")
        except Exception as e:
            if log_fn:
                log_fn("WARN", f"consolidation: ml_judge: reward insert: {e}")


def _record_negative_rewards(log_fn=None):
    """
    Record negative outcomes for escalated happenings with no reward entry.
    Fixes the success-only bias in consolidation_rewards.
    """
    try:
        rows = _ch_query(
            "SELECT id, classifier_route"
            " FROM panops.happenings"
            " WHERE status = 'escalated'"
            "   AND opened_at > now() - INTERVAL 7 DAY"
            "   AND id NOT IN ("
            "       SELECT happening_id FROM panops.consolidation_rewards"
            "       WHERE outcome = 'escalated'"
            "   )"
        )
        if not rows:
            if log_fn:
                log_fn("INFO", "consolidation: negative rewards — none needed")
            return
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
        inserted = 0
        for row in rows:
            hid       = row.get("id", "")
            inc_type  = row.get("classifier_route", "unknown")
            body = (
                "INSERT INTO panops.consolidation_rewards"
                " (happening_id, rule_name, outcome, recorded_at) FORMAT JSONEachRow\n"
                + json.dumps({
                    "happening_id": hid,
                    "rule_name":    f"{inc_type}:no_resolution",
                    "outcome":      "escalated",
                    "recorded_at":  now,
                })
            ).encode()
            try:
                req = urllib.request.Request(CH_URL, data=body, method="POST")
                req.add_header("Content-Type",      "text/plain")
                req.add_header("X-ClickHouse-User", os.getenv("CH_USER", "default"))
                req.add_header("X-ClickHouse-Key",  os.getenv("CH_PASSWORD", ""))
                with urllib.request.urlopen(req, timeout=15) as r:
                    r.read()
                inserted += 1
            except Exception as e:
                if log_fn:
                    log_fn("WARN", f"consolidation: negative reward insert hid={hid[:8]}: {e}")
        if log_fn:
            log_fn("INFO", f"consolidation: negative rewards — {inserted} escalations recorded")
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: _record_negative_rewards: {e}")


def _reembed_stale_corpus(log_fn=None):
    """Delegate to classifier.reembed_stale_corpus() to fix pre-P2.1 degenerate embeddings."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import classifier as _clf
        n = _clf.reembed_stale_corpus(CH_URL, log_fn=log_fn)
        if log_fn and n:
            log_fn("INFO", f"consolidation: stale corpus reembed — {n} entries refreshed")
    except ImportError:
        if log_fn:
            log_fn("WARN", "consolidation: classifier unavailable, skipping stale reembed")
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: _reembed_stale_corpus: {e}")


def _refresh_cbr_cases(brittleness_scores, log_fn=None):
    """
    Embed resolved happenings not yet in incident_embeddings.
    Budget of 50 slots allocated proportionally by brittleness score.
    Falls back to recency ordering when no scores available.
    """
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import classifier as _clf
    except ImportError:
        if log_fn:
            log_fn("WARN", "consolidation: classifier unavailable, skipping CBR refresh")
        return 0

    BUDGET = 50
    total_embedded = 0

    if brittleness_scores:
        total_score = sum(brittleness_scores.values()) or 1.0
        for inc_type, score in brittleness_scores.items():
            type_budget = min(20, max(1, round(BUDGET * score / total_score)))
            rows = _ch_query(
                "SELECT id, opened_at, closed_at, domain, classifier_route,"
                "       affected_services, drain3_patterns, falco_rules,"
                "       actions_taken, metric_anomalies"
                " FROM panops.happenings"
                f" WHERE status = 'resolved'"
                f"   AND classifier_route = '{inc_type}'"
                "   AND opened_at > now() - INTERVAL 14 DAY"
                "   AND id NOT IN (SELECT happening_id FROM panops.incident_embeddings)"
                " ORDER BY opened_at DESC"
                f" LIMIT {type_budget}"
            )
            for row in rows:
                try:
                    _clf.embed_and_match(CH_URL, row, log_fn=log_fn)
                    total_embedded += 1
                except Exception as e:
                    if log_fn:
                        log_fn("WARN", f"consolidation: embed failed hid={row.get('id','')[:8]}: {e}")
    else:
        # Fallback: recency-ordered, no type filter
        rows = _ch_query(
            "SELECT id, opened_at, closed_at, domain, classifier_route,"
            "       affected_services, drain3_patterns, falco_rules,"
            "       actions_taken, metric_anomalies"
            " FROM panops.happenings"
            " WHERE status = 'resolved'"
            "   AND opened_at > now() - INTERVAL 7 DAY"
            "   AND id NOT IN (SELECT happening_id FROM panops.incident_embeddings)"
            " ORDER BY opened_at DESC LIMIT 50"
        )
        for row in rows:
            try:
                _clf.embed_and_match(CH_URL, row, log_fn=log_fn)
                total_embedded += 1
            except Exception as e:
                if log_fn:
                    log_fn("WARN", f"consolidation: embed failed hid={row.get('id','')[:8]}: {e}")

    if log_fn:
        log_fn("INFO", f"consolidation: CBR refresh — embedded {total_embedded} cases")
    return total_embedded


def _mine_leading_indicators(brittleness_scores, log_fn=None):
    """
    For each resolved incident in the last 7 days, fetch Prometheus metric
    values from LOOKAHEAD_MINUTES before it fired. Compute slope and peak
    Z-score across all instances of each (incident_type, namespace, metric)
    triple. Store indicator thresholds in panops.leading_indicators when the
    signal is strong enough to be predictive.

    Processes high-brittleness types first; skips very-low-brittleness types
    when there are many distinct types to focus Prometheus query budget.
    """
    rows = _ch_query(
        "SELECT classifier_route AS incident_type,"
        "       arrayElement(affected_services, 1) AS svc,"
        "       toUnixTimestamp(opened_at) AS t"
        " FROM panops.happenings"
        " WHERE status = 'resolved'"
        "   AND opened_at > now() - INTERVAL 7 DAY"
        " ORDER BY opened_at DESC LIMIT 200"
    )
    if not rows:
        return

    # Group timestamps by (incident_type, namespace)
    groups = {}
    for row in rows:
        ns = (row.get("svc") or "").split("/")[0]
        if not ns:
            continue
        key = (row["incident_type"], ns)
        groups.setdefault(key, []).append(int(row["t"]))

    # Sort groups by brittleness score descending (most brittle first)
    sorted_groups = sorted(
        groups.items(),
        key=lambda kv: brittleness_scores.get(kv[0][0], 0.0),
        reverse=True,
    )

    # Skip very-low-brittleness types when there are many to process
    distinct_types = len({k[0] for k in groups})
    if brittleness_scores and distinct_types > 10:
        sorted_groups = [
            (key, ts) for key, ts in sorted_groups
            if brittleness_scores.get(key[0], 0.0) >= 0.05
        ]

    indicators_written = 0
    for (incident_type, ns), timestamps in sorted_groups:
        if len(timestamps) < 3:
            continue

        for metric in INDICATOR_METRICS:
            promql = f'{metric}{{namespace="{ns}"}}'
            slopes, peak_zscores = [], []

            for t_incident in timestamps:
                start  = t_incident - LOOKAHEAD_MINUTES * 60
                end    = t_incident - 60
                series = _prom_query_range(promql, start, end)
                if len(series) < 3:
                    continue
                xs = [p[0] for p in series]
                ys = [p[1] for p in series]
                slopes.append(_slope(xs, ys))
                try:
                    mean_y = statistics.mean(ys)
                    std_y  = statistics.stdev(ys)
                    if std_y > 0:
                        peak_zscores.append(
                            max(abs((y - mean_y) / std_y) for y in ys))
                except statistics.StatisticsError:
                    pass

            if len(slopes) < 3:
                continue

            mean_slope = statistics.mean(slopes)
            mean_z     = statistics.mean(peak_zscores) if peak_zscores else 0.0

            if abs(mean_slope) < 1e-9 and mean_z < 1.5:
                continue

            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
            body = (
                "INSERT INTO panops.leading_indicators"
                " (indicator_name, namespace, metric_query, incident_type,"
                "  slope_threshold, zscore_threshold, sample_count, trained_at)"
                " FORMAT JSONEachRow\n"
                + json.dumps({
                    "indicator_name":   f"{metric}:pre_{incident_type}",
                    "namespace":        ns,
                    "metric_query":     promql,
                    "incident_type":    incident_type,
                    "slope_threshold":  round(mean_slope, 6),
                    "zscore_threshold": round(mean_z, 3),
                    "sample_count":     len(slopes),
                    "trained_at":       now,
                })
            ).encode()
            try:
                req = urllib.request.Request(CH_URL, data=body, method="POST")
                req.add_header("Content-Type",      "text/plain")
                req.add_header("X-ClickHouse-User", os.getenv("CH_USER", "default"))
                req.add_header("X-ClickHouse-Key",  os.getenv("CH_PASSWORD", ""))
                with urllib.request.urlopen(req, timeout=15) as r:
                    r.read()
                indicators_written += 1
            except Exception as e:
                if log_fn:
                    log_fn("WARN", f"consolidation: indicator write: {e}")

    if log_fn:
        log_fn("INFO",
               f"consolidation: leading indicators — {indicators_written} thresholds written")


def run_nrem_phase(log_fn=None):
    """
    NREM phase — pure statistical consolidation, no LLM required.
    Computes brittleness scores, records negative rewards, refreshes the
    CBR embedding index with brittleness-weighted allocation, and mines
    Prometheus for leading indicators prioritised by brittleness.
    Also computes rule success rates (P2.2) and recurrence brittleness (P2.3).
    Returns (brittleness_scores, pending_count, recurrence_pairs) for REM.
    """
    if log_fn:
        log_fn("INFO", "consolidation: NREM phase starting")

    brittleness_scores = {}
    try:
        brittleness_scores = _compute_brittleness(log_fn)
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: NREM brittleness error: {e}")

    try:
        _record_negative_rewards(log_fn)
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: NREM negative rewards error: {e}")

    try:
        _compute_rule_success_rates(log_fn)
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: NREM rule success rates error: {e}")

    recurrence_pairs = []
    try:
        recurrence_pairs = _compute_recurrence_brittleness(log_fn)
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: NREM recurrence brittleness error: {e}")

    try:
        _refresh_cbr_cases(brittleness_scores, log_fn)
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: NREM CBR refresh error: {e}")

    try:
        _reembed_stale_corpus(log_fn)
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: NREM stale reembed error: {e}")

    try:
        _mine_leading_indicators(brittleness_scores, log_fn)
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: NREM leading indicators error: {e}")

    # Count pending_synthesis happenings for tracking
    pending_count = 0
    try:
        rows = _ch_query("SELECT count() AS cnt FROM panops.happenings WHERE pending_synthesis = 1")
        if rows:
            pending_count = int(rows[0].get("cnt", 0))
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: NREM pending count error: {e}")

    if log_fn:
        log_fn("INFO",
               f"consolidation: NREM phase complete — {len(brittleness_scores)} types scored, "
               f"{len(recurrence_pairs)} chronic (route,ns) pairs, "
               f"{pending_count} pending synthesis")
    return brittleness_scores, pending_count, recurrence_pairs


def _should_run_rem(brittleness_scores, recurrence_pairs=None, log_fn=None):
    """
    Gate for the REM phase. Returns True if LLM synthesis is warranted.
    Runs when:
      - max brittleness >= 0.3, OR
      - any chronic (route,ns) pair detected (mask-not-fix recurrence), OR
      - it has been more than 7 days since last REM (weekly cadence).
    """
    if recurrence_pairs:
        if log_fn:
            log_fn("INFO",
                   f"consolidation: REM triggered — {len(recurrence_pairs)} chronic (route,ns) pairs")
        return True

    if not brittleness_scores:
        if log_fn:
            log_fn("INFO", "consolidation: REM skipped — no brittleness data")
        return False

    max_score = max(brittleness_scores.values())

    if max_score >= 0.3:
        if log_fn:
            log_fn("INFO", f"consolidation: REM triggered — max brittleness {max_score:.3f}")
        return True

    # Check when REM last ran
    try:
        rows = _ch_query(
            "SELECT value FROM panops.dream_state WHERE key = 'last_rem_run' LIMIT 1"
        )
        if rows:
            last_run_str = rows[0].get("value", "")
            last_run = datetime.fromisoformat(last_run_str.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - last_run).days
            if age_days < 7:
                if log_fn:
                    log_fn("INFO",
                           f"consolidation: REM skipped — low brittleness ({max_score:.3f})"
                           f" and ran {age_days}d ago")
                return False
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"consolidation: REM cadence check: {e}")

    if log_fn:
        log_fn("INFO", f"consolidation: REM triggered — weekly cadence (brittleness {max_score:.3f})")
    return True


def _build_rem_prompt(brittleness_scores, log_fn=None):
    """
    Build the LLM prompt for REM rule synthesis.
    Targets the top-3 most brittle incident types.
    Includes both newly escalated and pending_synthesis happenings.
    Returns (system_msg, user_msg, happening_ids).
    """
    top_types = list(brittleness_scores.keys())[:3]
    sections = []
    happening_ids = []
    for inc_type in top_types:
        rows = _ch_query(
            "SELECT id, domain, classifier_route, falco_rules, sigma_rule_ids,"
            "       drain3_patterns, metric_anomalies, actions_taken"
            " FROM panops.happenings"
            f" WHERE classifier_route = '{inc_type}'"
            "   AND (status = 'escalated' OR pending_synthesis = 1)"
            "   AND opened_at > now() - INTERVAL 30 DAY"
            " ORDER BY opened_at DESC LIMIT 5"
        )
        if not rows:
            continue
        score = brittleness_scores.get(inc_type, 0.0)
        section = f"## {inc_type} (brittleness: {score:.3f})\n"
        for row in rows:
            hid = row.get('id', '')
            happening_ids.append(hid)
            section += (
                f"- id: {hid[:8]}"
                f"  domain: {row.get('domain','')}"
                f"  falco: {row.get('falco_rules','[]')}"
                f"  sigma: {row.get('sigma_rule_ids','[]')}"
                f"  drain3: {row.get('drain3_patterns','[]')}"
                f"  anomalies: {row.get('metric_anomalies','[]')}"
                f"  actions_taken: {row.get('actions_taken','[]')}\n"
            )
        sections.append(section)

    if not sections:
        return None, None, []

    system_msg = (
        "You are PanOps-Brain, an autonomous SRE/SOC operations assistant. "
        "Review the following incident happenings and their outcomes across mixed infrastructure "
        "(Kubernetes, Linux, Windows). Identify patterns, propose runbook improvements, "
        "and suggest remediation strategies. Output structured JSON."
    )
    user_msg = (
        "The following incident types have high escalation rates in the PanOps system. "
        "Propose rules to improve automated detection and remediation.\n\n"
        + "\n".join(sections)
        + '\n\nOutput JSON schema:\n'
        '{"rule_proposals": ['
        '{"type": "sigma|falco|remediator", '
        '"name": "snake_case_rule_name", '
        '"incident_types": ["type1"], '
        '"description": "why this rule helps prevent escalation", '
        '"content": "rule content or pseudocode"}'
        ']}'
    )
    return system_msg, user_msg, happening_ids


def _open_gitlab_mr(proposal, log_fn=None, notify_fn=None):
    """
    Create a GitLab branch, commit a proposed rule file, and open an MR.
    Uses GITLAB_URL, GITLAB_TOKEN, GITLAB_PROJECT_ID env vars.
    One failure does not abort other proposals.
    """
    gitlab_url = os.getenv("GITLAB_URL", "https://gitlab.YOUR_DOMAIN")
    token      = os.getenv("GITLAB_TOKEN", "")
    project_id = os.getenv("GITLAB_PROJECT_ID", "")

    if not token or not project_id:
        if log_fn:
            log_fn("WARN", "consolidation: GITLAB_TOKEN or GITLAB_PROJECT_ID not set, skipping MR")
        return

    rule_type = proposal.get("type", "remediator")
    name      = proposal.get("name", "unnamed_rule").replace(" ", "_")
    content   = proposal.get("content", "")
    desc      = proposal.get("description", "")
    inc_types = proposal.get("incident_types", [])

    type_paths = {
        "sigma":      f"rules/sigma/rules/{name}.yaml",
        "falco":      f"rules/falco/{name}.yaml",
        "remediator": f"rules/remediator/{name}.yaml",
    }
    file_path   = type_paths.get(rule_type, f"rules/remediator/{name}.yaml")
    branch_name = f"dream/{name}"
    proj_enc    = urllib.parse.quote(str(project_id), safe="")
    base_url    = f"{gitlab_url}/api/v4/projects/{proj_enc}"
    headers     = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def _gl_request(method, url, data=None):
        body = json.dumps(data).encode() if data else None
        req  = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read() or b"{}"), r.status
        except urllib.error.HTTPError as e:
            return json.loads(e.read() or b"{}"), e.code

    # Create branch (409 = already exists, that's fine)
    _gl_request("POST", f"{base_url}/repository/branches",
                {"branch": branch_name, "ref": "main"})

    # Commit file
    commit_data = {
        "branch":         branch_name,
        "commit_message": f"dream: propose {rule_type} rule {name}",
        "actions": [{
            "action":    "create",
            "file_path": file_path,
            "content":   content,
        }],
    }
    _, status = _gl_request("POST", f"{base_url}/repository/commits", commit_data)
    if status not in (200, 201):
        if log_fn:
            log_fn("WARN", f"consolidation: MR commit failed for {name} (status {status})")
        return

    # Open MR
    mr_data = {
        "source_branch":        branch_name,
        "target_branch":        "main",
        "title":                f"[PanOps Dream] {name}: {desc[:80]}",
        "description":          (
            f"Generated by PanOps REM cycle\n\n"
            f"**Incident types**: {inc_types}\n\n"
            f"{desc}"
        ),
        "remove_source_branch": False,
    }
    mr_resp, mr_status = _gl_request("POST", f"{base_url}/merge_requests", mr_data)
    if mr_status in (200, 201):
        mr_url = mr_resp.get("web_url", "")
        if log_fn:
            log_fn("INFO", f"consolidation: MR opened: {mr_url}")
        if notify_fn and mr_url:
            try:
                notify_fn("MIXED", f"Dream MR raised: {name}",
                          f"PanOps dream cycle proposed a new rule.\n{desc[:200]}\n\nMR: {mr_url}",
                          route="dream", severity="info")
            except Exception:
                pass
    else:
        if log_fn:
            log_fn("WARN", f"consolidation: MR open failed for {name} (status {mr_status})")


def run_rem_phase(brittleness_scores, recurrence_pairs=None, log_fn=None, notify_fn=None):
    """
    REM phase — LLM-driven rule synthesis, conditional on brittleness.
    Targets the top-3 most brittle incident types, asks the LLM to propose
    new classifier/remediator/Sigma rules, and opens GitLab MRs for each.
    Includes pending_synthesis retries. Skipped entirely if brittleness is low,
    no chronic recurrence pairs, and ran recently.
    Returns (synthesised_count, pending_count) for dream_state tracking.
    """
    if not _should_run_rem(brittleness_scores, recurrence_pairs, log_fn):
        return 0, 0

    if log_fn:
        log_fn("INFO", "consolidation: REM phase starting — LLM rule synthesis")

    system_msg, user_msg, happening_ids = _build_rem_prompt(brittleness_scores, log_fn)
    if not system_msg:
        if log_fn:
            log_fn("INFO", "consolidation: REM — no escalated happenings to synthesise from")
        return 0, 0

    result = _llama_dream_call(system_msg, user_msg, happening_ids=happening_ids, log_fn=log_fn)
    if result is None:
        if log_fn:
            log_fn("WARN", "consolidation: REM synthesis exhausted retries, happenings marked pending")
        pending_count = len(happening_ids)
        return 0, pending_count

    # Clear pending_synthesis for successfully synthesized happenings
    if happening_ids:
        hid_list = "','".join(happening_ids)
        _ch_exec(f"""
            ALTER TABLE panops.happenings UPDATE pending_synthesis = 0
            WHERE id IN ('{hid_list}')
        """)

    proposals = result.get("rule_proposals", [])
    if not isinstance(proposals, list):
        if log_fn:
            log_fn("WARN", "consolidation: REM — unexpected LLM response shape")
        return 0, 0

    if log_fn:
        log_fn("INFO", f"consolidation: REM — {len(proposals)} rule proposals received")

    for proposal in proposals[:5]:
        try:
            _open_gitlab_mr(proposal, log_fn, notify_fn=notify_fn)
        except Exception as e:
            if log_fn:
                log_fn("WARN", f"consolidation: REM MR failed for {proposal.get('name','?')}: {e}")

    synthesised_count = len(happening_ids)
    if log_fn:
        log_fn("INFO", "consolidation: REM phase complete")

    return synthesised_count, 0


def _llama_dream_call(system_msg, user_msg, happening_ids=None, log_fn=None):
    """
    Call llama-server for REM synthesis with 3-attempt retry.
    On all 3 failures, sets pending_synthesis=1 for all happening_ids in this batch.
    Returns result dict or None on failure.
    """
    if happening_ids is None:
        happening_ids = []

    payload = json.dumps({
        "model": "qwen",
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user",   "content": user_msg},
        ],
        "max_tokens": 1024,
        "temperature": 0.3,
        "response_format": {"type": "json_object"},
    }).encode()

    for attempt in range(3):
        try:
            req = urllib.request.Request(
                f"{LLAMA_SERVER_URL}/v1/chat/completions",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as r:
                resp = json.loads(r.read())
            return json.loads(resp["choices"][0]["message"]["content"].strip())
        except Exception as e:
            if attempt == 2:
                # All 3 attempts failed — mark all happenings as pending
                if happening_ids:
                    hid_list = "','".join(happening_ids)
                    _ch_exec(f"""
                        ALTER TABLE panops.happenings UPDATE
                            pending_synthesis = 1
                        WHERE id IN ('{hid_list}')
                    """)
                if log_fn:
                    log_fn("WARN", f"consolidation: pending_synthesis set for {len(happening_ids)} happenings: {e}")
                return None
            if log_fn:
                log_fn("WARN", f"consolidation: synthesis attempt {attempt+1} failed: {e}")
            time.sleep(30)


def run_dream_cycle(log_fn=None, notify_fn=None):
    """
    Offline consolidation — runs nightly in DREAM_START_HOUR–DREAM_END_HOUR UTC.

    Phase 1 — NREM (statistical consolidation, no LLM):
      Computes brittleness scores, records negative rewards, refreshes the CBR
      embedding index with brittleness-weighted allocation, and mines Prometheus
      for leading indicators prioritised by brittleness.

    Phase 2 — REM (LLM synthesis, conditional):
      Uses brittleness scores from NREM to target the top-3 most brittle
      incident types. Asks the LLM to propose new detection/remediation rules
      and opens GitLab MRs for each proposal. Retries synthesis for happenings
      with pending_synthesis flag. Skipped when brittleness is low and the phase
      ran within the last 7 days.

    Writes dream_state with last_rem_run timestamp, synthesis counts, and pending count.
    """
    if log_fn:
        log_fn("INFO", "consolidation: dream cycle starting")
    _ensure_schema()
    brittleness, nrem_pending_count, recurrence_pairs = run_nrem_phase(log_fn)
    synthesised_count, rem_pending_count = run_rem_phase(brittleness, recurrence_pairs, log_fn, notify_fn=notify_fn)

    # Final pending count after REM (may increase if synthesis failed)
    final_pending_count = nrem_pending_count + rem_pending_count

    # Write dream_state for tracking
    now_iso = datetime.now(timezone.utc).isoformat()
    _ch_exec(
        f"INSERT INTO panops.dream_state (key, value, updated_at) VALUES"
        f" ('last_rem_run', '{now_iso}', now64(3)),"
        f" ('last_synthesised_count', '{synthesised_count}', now64(3)),"
        f" ('last_pending_count', '{final_pending_count}', now64(3))"
    )

    if log_fn:
        log_fn("INFO",
               f"consolidation: dream cycle complete — "
               f"synthesised={synthesised_count}, pending={final_pending_count}")


def dream_scheduler(log_fn=None, notify_fn=None):
    """
    Thread loop. Sleeps until the off-peak window opens, runs the dream cycle
    once, then sleeps until tomorrow's window.
    """
    while True:
        now   = datetime.now(timezone.utc)
        start = now.replace(hour=DREAM_START_HOUR, minute=DREAM_START_MINUTE,
                            second=0, microsecond=0)
        end   = now.replace(hour=DREAM_END_HOUR,   minute=DREAM_END_MINUTE,
                            second=0, microsecond=0)

        if now < start:
            sleep_s = (start - now).total_seconds()
        elif now > end:
            tomorrow = start + timedelta(days=1)
            sleep_s  = (tomorrow - now).total_seconds()
        else:
            try:
                run_dream_cycle(log_fn, notify_fn=notify_fn)
            except Exception as e:
                if log_fn:
                    log_fn("ERROR", f"consolidation: unhandled: {e}")
            # Sleep past end of window so we don't re-run today
            sleep_s = max((end - datetime.now(timezone.utc)).total_seconds() + 60, 60)

        time.sleep(max(sleep_s, 60))
