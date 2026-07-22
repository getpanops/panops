"""
PanOps Brain — Similarity Classifier (Step 5)

Embeds happening descriptions using all-MiniLM-L6-v2 (via fastembed/onnxruntime,
no PyTorch dependency) and queries panops.incident_embeddings with cosineDistance()
kNN to find semantically similar past happenings.

Two responsibilities:
  1. embed_and_match(happening_row)  — called during assembly; stores the new
     embedding and returns (similarity_score, matched_incident_id) if a past
     happening is found above the SIMILARITY_THRESHOLD.
  2. backfill_pattern_embeddings()   — called periodically; finds rows in
     qryn.pattern_embeddings with empty arrays and fills them in, enabling
     cross-source cosineDistance queries (Drain3 ↔ happening similarity).
"""
import json
import os
import urllib.request
import urllib.parse
from datetime import datetime, timezone

try:
    from fastembed import TextEmbedding as _TextEmbedding
    _model = _TextEmbedding(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        cache_dir=os.getenv("FASTEMBED_CACHE_PATH") or None,
    )
    _HAS_EMBED = True
except Exception:
    _model = None
    _HAS_EMBED = False

SIMILARITY_THRESHOLD = 0.85   # cosineDistance < 0.15 → known match
KNN_CANDIDATES       = 5      # top-N to inspect before picking the best


def _embed(texts):
    """Return list of 384-dim float lists for each input text."""
    if not _HAS_EMBED or not _model:
        return []
    return [list(map(float, v)) for v in _model.embed(texts)]


# Old degenerate format always contained this literal string; new format uses "Log patterns:"
_STALE_DESC_MARKER = "Metric anomalies:"


def _happening_description(row):
    """
    Build the text embedded for a happening. Uses substantive signal content
    (Drain3 log templates, metric anomaly names) not just labels, so the
    embedding space is non-degenerate and kNN similarity is meaningful.
    """
    ns     = ", ".join(row.get("affected_services") or []) or "unknown"
    domain = row.get("domain", "")
    falco  = ", ".join(row.get("falco_rules") or []) or ""
    sigma  = ", ".join(row.get("sigma_rule_ids") or []) or ""

    # Extract drain3 template text (the actual log message patterns)
    drain3_text = ""
    try:
        patterns = json.loads(row.get("drain3_patterns") or "[]")
        templates = [p.get("template", "") for p in patterns if p.get("template")]
        drain3_text = " | ".join(templates[:5])
    except Exception:
        pass

    # Extract metric anomaly names and z-scores
    anom_text = ""
    try:
        anoms = json.loads(row.get("metric_anomalies") or "[]")
        anom_parts = []
        for a in anoms[:5]:
            name = a.get("metric") or a.get("name") or ""
            zscore = a.get("zscore") or a.get("z_score") or ""
            if name:
                anom_parts.append(f"{name}(z={zscore})" if zscore else name)
        anom_text = ", ".join(anom_parts)
    except Exception:
        pass

    parts = [f"{domain} incident in {ns}."]
    if drain3_text:
        parts.append(f"Log patterns: {drain3_text}.")
    if anom_text:
        parts.append(f"Anomalous metrics: {anom_text}.")
    if falco:
        parts.append(f"Falco: {falco}.")
    if sigma:
        parts.append(f"Sigma: {sigma}.")
    return " ".join(parts)


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
            log_fn("WARN", f"classifier ch_query: {e}")
        return []


def _ch_exec(ch_url, sql, log_fn):
    try:
        req = urllib.request.Request(ch_url, data=sql.strip().encode(), method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=60) as r:
            r.read()
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"classifier ch_exec: {e}")


def embed_and_match(ch_url, happening_row, log_fn=None):
    """
    Embed the happening, store the embedding, and find the nearest neighbour.
    Returns (similarity_score: float|None, matched_id: str|None, route_override: str|None).
    Callers should update the happening row with these values after assembly.
    """
    if not _HAS_EMBED:
        return None, None, None

    description = _happening_description(happening_row)
    vecs = _embed([description])
    if not vecs:
        return None, None, None
    vec = vecs[0]
    happening_id = happening_row["id"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")

    # Store the embedding for this happening
    insert_body = (
        "INSERT INTO panops.incident_embeddings "
        "(happening_id,embedded_at,description_text,embedding) FORMAT JSONEachRow\n"
        + json.dumps({
            "happening_id":    happening_id,
            "embedded_at":     now,
            "description_text": description,
            "embedding":       vec,
        })
    ).encode()
    try:
        req = urllib.request.Request(ch_url, data=insert_body, method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=30) as r:
            r.read()
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"classifier insert embedding: {e}")
        return None, None, None

    # kNN: find closest past happening (excluding self, which won't appear yet
    # since ClickHouse writes are async — safe to query immediately)
    vec_literal = "[" + ",".join(str(f) for f in vec) + "]"
    sql_knn = f"""
        SELECT
            happening_id,
            cosineDistance(embedding, {vec_literal}) AS dist
        FROM panops.incident_embeddings
        WHERE happening_id != '{happening_id}'
        ORDER BY dist ASC
        LIMIT {KNN_CANDIDATES}
    """
    neighbours = _ch_query(ch_url, sql_knn, log_fn)
    if not neighbours:
        return None, None, None

    best = neighbours[0]
    dist = float(best["dist"])
    sim  = round(1.0 - dist, 4)

    if dist < (1.0 - SIMILARITY_THRESHOLD):
        matched_id     = best["happening_id"]
        route_override = "known"
        if log_fn:
            log_fn("INFO",
                   f"classifier: similarity={sim:.3f} → known match {matched_id[:8]}…")
        return sim, matched_id, route_override

    if log_fn:
        log_fn("INFO", f"classifier: best similarity={sim:.3f} → no known match")
    return sim, None, None


def backfill_pattern_embeddings(ch_url, log_fn=None, batch_size=50):
    """
    Find pattern_embeddings rows with empty embedding arrays and fill them in.
    Called periodically from a background thread (not on the hot assembly path).
    """
    if not _HAS_EMBED:
        return

    sql = f"""
        SELECT template_id, template
        FROM qryn.pattern_embeddings
        WHERE length(embedding) = 0
        LIMIT {batch_size}
    """
    rows = _ch_query(ch_url, sql, log_fn)
    if not rows:
        return

    texts    = [r["template"] for r in rows]
    vecs     = _embed(texts)
    if not vecs:
        return

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    insert_rows = []
    for r, vec in zip(rows, vecs):
        insert_rows.append({
            "template_id": int(r["template_id"]),
            "template":    r["template"],
            "embedded_at": now,
            "embedding":   vec,
        })

    body = (
        "INSERT INTO qryn.pattern_embeddings "
        "(template_id,template,embedded_at,embedding) FORMAT JSONEachRow\n"
        + "\n".join(json.dumps(r) for r in insert_rows)
    ).encode()
    req = urllib.request.Request(ch_url, data=body, method="POST")
    req.add_header("Content-Type", "text/plain")
    req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
    req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            r.read()
        if log_fn:
            log_fn("INFO", f"classifier: backfilled {len(insert_rows)} pattern embedding(s)")
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"classifier backfill write: {e}")


def reembed_stale_corpus(ch_url, log_fn=None, batch_size=50):
    """
    Find incident_embeddings rows built with the old degenerate _happening_description
    (identified by the literal "Metric anomalies:" marker it always emitted) and
    re-embed them using the current format built from drain3 templates + signal fields.

    Called from NREM consolidation so the CBR library improves overnight.
    """
    if not _HAS_EMBED:
        return 0

    # Old format always contained "Metric anomalies:" — new format uses "Log patterns:"
    # Using positionCaseInsensitive so the filter is index-friendly
    sql = f"""
        SELECT ie.happening_id,
               h.domain, h.affected_services, h.falco_rules, h.sigma_rule_ids,
               h.drain3_patterns, h.metric_anomalies
        FROM panops.incident_embeddings ie
        JOIN panops.happenings h ON h.id = ie.happening_id
        WHERE positionCaseInsensitive(ie.description_text, '{_STALE_DESC_MARKER}') > 0
        LIMIT {batch_size}
    """
    rows = _ch_query(ch_url, sql, log_fn)
    if not rows:
        return 0

    texts = [_happening_description(r) for r in rows]
    vecs  = _embed(texts)
    if not vecs:
        return 0

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    insert_rows = []
    for r, vec, text in zip(rows, vecs, texts):
        insert_rows.append({
            "happening_id":    r["happening_id"],
            "embedded_at":     now,
            "description_text": text,
            "embedding":       vec,
        })

    body = (
        "INSERT INTO panops.incident_embeddings "
        "(happening_id,embedded_at,description_text,embedding) FORMAT JSONEachRow\n"
        + "\n".join(json.dumps(r) for r in insert_rows)
    ).encode()
    req = urllib.request.Request(ch_url, data=body, method="POST")
    req.add_header("Content-Type", "text/plain")
    req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
    req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            r.read()
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"classifier reembed_stale_corpus write: {e}")
        return 0

    # Delete the old-format rows for the happenings we just re-embedded so they
    # don't accumulate as duplicates (table is plain MergeTree, no auto-dedup).
    ids_csv = ", ".join(f"'{r['happening_id']}'" for r in insert_rows)
    del_sql = (
        f"ALTER TABLE panops.incident_embeddings DELETE "
        f"WHERE happening_id IN ({ids_csv}) "
        f"AND positionCaseInsensitive(description_text, '{_STALE_DESC_MARKER}') > 0"
    ).encode()
    del_req = urllib.request.Request(ch_url, data=del_sql, method="POST")
    del_req.add_header("Content-Type", "text/plain")
    del_req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
    del_req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
    try:
        with urllib.request.urlopen(del_req, timeout=60) as r:
            r.read()
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"classifier reembed_stale_corpus delete: {e}")

    if log_fn:
        log_fn("INFO", f"classifier: re-embedded {len(insert_rows)} stale corpus entries")
    return len(insert_rows)
