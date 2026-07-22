"""
PanOps Brain — Drain3 Novel Pattern Detector (Step 4)
Enriches the drain3_patterns list produced by the assembler with:

  is_novel:          pattern_id not previously seen (not in qryn.pattern_embeddings)
  is_freq_anomaly:   samples_count in window >> 2-day rolling average for this pattern
  falco_correlated:  Falco events fired in the same namespace within ±5min of the
                     pattern's first appearance

Novel patterns are written into qryn.pattern_embeddings (embedding=[]) so they are
not re-flagged as novel on the next happening. Step 5 fills in the real embeddings.

qryn.patterns TTL is 2 days — novelty check uses pattern_embeddings as long-term store.
"""
import json
import os
import urllib.request
import urllib.parse
from datetime import datetime, timezone


def enrich_drain3(ch_url, loki_url, namespace, window_start_s, window_end_s, log_fn=None):
    """
    Query qryn.patterns for the happening window, enrich with novelty/frequency/
    Falco-correlation flags, register new patterns in qryn.pattern_embeddings,
    and return the enriched list.

    Returns list of dicts:
      {pattern_id, template, samples_count, is_novel, is_freq_anomaly, falco_correlated}
    """
    bucket_start = int(window_start_s) // 600
    bucket_end   = int(window_end_s)   // 600 + 1

    # ── 1. Fetch patterns active in the happening window ─────────────────
    sql_window = f"""
        SELECT
            pattern_id,
            arrayStringConcat(tokens, ' ') AS template,
            sum(samples_count)             AS total_count,
            min(timestamp_s)               AS first_seen_s,
            max(timestamp_s)               AS last_seen_s
        FROM qryn.patterns
        WHERE timestamp_10m >= {bucket_start}
          AND timestamp_10m <= {bucket_end}
        GROUP BY pattern_id, template
        ORDER BY total_count DESC
        LIMIT 50
    """
    window_patterns = _ch_query(ch_url, sql_window, log_fn)
    if not window_patterns:
        return []

    pattern_ids = [int(r["pattern_id"]) for r in window_patterns]

    # ── 2. Novelty check: which pattern_ids are NOT in pattern_embeddings ─
    ids_str     = ",".join(str(pid) for pid in pattern_ids)
    sql_known   = f"""
        SELECT DISTINCT template_id
        FROM qryn.pattern_embeddings
        WHERE template_id IN ({ids_str})
    """
    known_rows  = _ch_query(ch_url, sql_known, log_fn) or []
    known_ids   = {int(r["template_id"]) for r in known_rows}
    novel_ids   = set(pattern_ids) - known_ids

    # ── 3. Frequency anomaly: compare window count vs 2-day rolling avg ──
    sql_baseline = f"""
        SELECT
            pattern_id,
            avg(samples_count) AS avg_count
        FROM qryn.patterns
        WHERE pattern_id IN ({ids_str})
          AND timestamp_10m < {bucket_start}
        GROUP BY pattern_id
    """
    baseline_rows = _ch_query(ch_url, sql_baseline, log_fn) or []
    baselines     = {int(r["pattern_id"]): float(r["avg_count"]) for r in baseline_rows}

    # ── 4. Falco cross-correlation for novel patterns ─────────────────────
    falco_correlated = set()
    if novel_ids and namespace:
        for row in window_patterns:
            pid = int(row["pattern_id"])
            if pid not in novel_ids:
                continue
            first_s = int(row["first_seen_s"])
            if _falco_nearby(loki_url, namespace, first_s - 300, first_s + 300, log_fn):
                falco_correlated.add(pid)

    # ── 5. Register novel patterns in pattern_embeddings (empty embedding) ─
    if novel_ids:
        _register_novel(ch_url, window_patterns, novel_ids, log_fn)

    # ── 6. Build enriched output ──────────────────────────────────────────
    result = []
    for row in window_patterns:
        pid   = int(row["pattern_id"])
        count = int(row["total_count"])
        avg   = baselines.get(pid, 0.0)
        result.append({
            "pattern_id":       pid,
            "template":         row["template"],
            "samples_count":    count,
            "is_novel":         pid in novel_ids,
            "is_freq_anomaly":  avg > 0 and count > avg * 3,
            "falco_correlated": pid in falco_correlated,
        })

    novel_count = len(novel_ids)
    freq_count  = sum(1 for r in result if r["is_freq_anomaly"])
    falco_count = len(falco_correlated)
    if log_fn:
        log_fn("INFO",
               f"drain3: ns={namespace} patterns={len(result)} "
               f"novel={novel_count} freq_anomaly={freq_count} "
               f"falco_correlated={falco_count}")
    return result


# ── Helpers ───────────────────────────────────────────────────────────────

def _ch_query(ch_url, sql, log_fn):
    try:
        data = (sql.strip() + " FORMAT JSON").encode()
        req  = urllib.request.Request(ch_url, data=data, method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read()).get("data", [])
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"drain3 ch_query: {e}")
        return []


def _falco_nearby(loki_url, namespace, start_s, end_s, log_fn):
    """Return True if any Falco event appears for the namespace in [start_s, end_s]."""
    # k8s_ns_name is a stream label promoted by the otelcol transform/falco pipeline
    # from output_fields["k8s.ns.name"] (the affected pod's namespace, not Falco's own).
    # Stream label filter avoids a full | json scan on the 900M+ row samples table.
    logql  = f'{{exporter="OTLP", event_class="runtime-security", job="falco", k8s_ns_name="{namespace}"}}'
    params = {
        "query":     logql,
        "start":     str(start_s * 1_000_000_000),
        "end":       str(end_s   * 1_000_000_000),
        "limit":     "1",
        "direction": "backward",
    }
    url = f"{loki_url}/loki/api/v1/query_range?{urllib.parse.urlencode(params)}"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            body   = json.loads(r.read())
            result = body.get("data", {}).get("result", [])
            return len(result) > 0 and len(result[0].get("values", [])) > 0
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"drain3 falco_nearby: {e}")
        return False


def _register_novel(ch_url, window_patterns, novel_ids, log_fn):
    """Insert placeholder rows for novel pattern_ids into qryn.pattern_embeddings."""
    now  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    rows = []
    for row in window_patterns:
        pid = int(row["pattern_id"])
        if pid in novel_ids:
            rows.append({
                "template_id": pid,
                "template":    row["template"],
                "embedded_at": now,
                "embedding":   [],   # Step 5 fills this in
            })
    if not rows:
        return
    body = (
        "INSERT INTO qryn.pattern_embeddings "
        "(template_id,template,embedded_at,embedding) FORMAT JSONEachRow\n"
        + "\n".join(json.dumps(r) for r in rows)
    ).encode()
    req = urllib.request.Request(ch_url, data=body, method="POST")
    req.add_header("Content-Type", "text/plain")
    req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
    req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
        if log_fn:
            log_fn("INFO", f"drain3: registered {len(rows)} novel pattern(s)")
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"drain3 register_novel: {e}")
