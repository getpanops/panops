"""
Drain3 log pattern miner.

Queries ClickHouse directly (bypassing gigapipe) for the previous completed
10-minute bucket, runs Drain3 template mining per namespace, and writes
results into qryn.patterns so the PanOps brain drain3_detector can find novel
log patterns during happenings.

Runs as a Kubernetes CronJob every 10 minutes.
"""
import json
import os
import time
import hashlib
import urllib.request
import urllib.parse

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

CH_URL       = os.environ.get("CH_URL",      "http://observability-clickhouse-clickhouse-headless.observability.svc.cluster.local:8123")
CH_USER      = os.environ.get("CH_USER",     "default")
CH_PASSWORD  = os.environ.get("CH_PASSWORD", "")
LINES_PER_NS = int(os.environ.get("LINES_PER_NS", "2000"))


_PATTERNS_DDL = """
CREATE TABLE IF NOT EXISTS qryn.patterns (
    timestamp_10m    UInt64,
    fingerprint      UInt64,
    timestamp_s      UInt32,
    tokens           Array(String),
    classes          Array(String),
    overall_cost     Float64,
    generalized_cost Float64,
    samples_count    UInt64,
    pattern_id       UInt64,
    iteration_id     UInt64
) ENGINE = MergeTree()
ORDER BY (timestamp_10m, pattern_id)
TTL toDateTime(timestamp_s) + INTERVAL 2 DAY
"""


def _ensure_table():
    req = urllib.request.Request(CH_URL, data=_PATTERNS_DDL.encode(), method="POST")
    req.add_header("X-ClickHouse-User", CH_USER)
    req.add_header("X-ClickHouse-Key",  CH_PASSWORD)
    req.add_header("X-ClickHouse-Database", "qryn")
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()


def _ch_select(sql, params=None, timeout=60):
    """Send a SELECT to ClickHouse HTTP API, return list of dicts (JSONEachRow)."""
    url = CH_URL
    if params:
        qs = urllib.parse.urlencode({f"param_{k}": str(v) for k, v in params.items()})
        url = f"{CH_URL}?{qs}"
    body = (sql.strip() + " FORMAT JSONEachRow").encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("X-ClickHouse-User", CH_USER)
    req.add_header("X-ClickHouse-Key",  CH_PASSWORD)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return [json.loads(line) for line in r.read().decode().splitlines() if line]


def main():
    _ensure_table()
    now_s       = int(time.time())
    prev_bucket = (now_s // 600) - 1
    start_ns    = prev_bucket       * 600 * 1_000_000_000
    end_ns      = (prev_bucket + 1) * 600 * 1_000_000_000

    print(f"Mining bucket {prev_bucket} ({time.strftime('%H:%M', time.gmtime(prev_bucket * 600))} UTC)")

    namespaces = _fetch_namespaces()
    if not namespaces:
        print("No namespaces found in ClickHouse for this window")
        return

    print(f"Namespaces: {namespaces}")

    rows = []
    for ns in namespaces:
        ns_rows = _mine_namespace(ns, start_ns, end_ns, prev_bucket)
        if ns_rows:
            rows.extend(ns_rows)
            print(f"  {ns}: {len(ns_rows)} patterns")

    if not rows:
        print("No patterns produced")
        return

    _insert_patterns(rows)
    print(f"Inserted {len(rows)} pattern rows into qryn.patterns")


def _fetch_namespaces():
    """Return distinct k8s namespace names that have log streams in ClickHouse."""
    sql = """
SELECT DISTINCT val
FROM qryn.time_series_gin
WHERE key = 'k8s_namespace_name'
  AND type = 1
  AND date >= today() - 2
"""
    try:
        rows = _ch_select(sql, timeout=30)
        return [r["val"] for r in rows if r.get("val")]
    except Exception as e:
        print(f"WARN: fetch_namespaces: {e}")
        return []


def _mine_namespace(ns, start_ns, end_ns, bucket):
    """Fetch log lines for a namespace from ClickHouse, run Drain3, return pattern rows."""
    sql = """
WITH fp AS (
    SELECT fingerprint
    FROM qryn.time_series_gin
    WHERE key = 'k8s_namespace_name'
      AND val = {ns:String}
      AND type = 1
      AND date >= today() - 2
)
SELECT timestamp_ns, string
FROM qryn.samples_v3
WHERE fingerprint IN (SELECT fingerprint FROM fp)
  AND timestamp_ns BETWEEN {start_ns:Int64} AND {end_ns:Int64}
  AND string != ''
ORDER BY timestamp_ns DESC
LIMIT {lim:UInt32}
"""
    try:
        rows = _ch_select(sql, params={
            "ns":       ns,
            "start_ns": start_ns,
            "end_ns":   end_ns,
            "lim":      LINES_PER_NS,
        }, timeout=60)
    except Exception as e:
        print(f"WARN: mine_namespace {ns} query failed: {e}")
        return []

    log_lines = [
        (int(r["timestamp_ns"]) // 1_000_000_000, r["string"])
        for r in rows if r.get("string")
    ]
    if not log_lines:
        return []

    cfg = TemplateMinerConfig()
    cfg.drain_depth        = 4
    cfg.drain_sim_th       = 0.4
    cfg.drain_max_children = 100
    cfg.drain_max_clusters = 500

    miner           = TemplateMiner(config=cfg)
    cluster_ts: dict[int, int] = {}

    for ts_s, raw_line in log_lines:
        text = _extract_text(raw_line)
        if not text:
            continue
        result = miner.add_log_message(text)
        cid    = result["cluster_id"]
        if cid not in cluster_ts:
            cluster_ts[cid] = ts_s

    now_s = int(time.time())
    rows  = []
    for cid, cluster in miner.drain.id_to_cluster.items():
        tokens     = cluster.log_template_tokens
        template_s = " ".join(tokens)
        pattern_id = int(hashlib.md5(f"{ns}:{template_s}".encode()).hexdigest()[:16], 16)
        first_seen = cluster_ts.get(cid, now_s)
        rows.append({
            "timestamp_10m":    bucket,
            "fingerprint":      0,
            "timestamp_s":      first_seen,
            "tokens":           tokens,
            "classes":          [],
            "overall_cost":     0,
            "generalized_cost": 0,
            "samples_count":    cluster.size,
            "pattern_id":       pattern_id,
            "iteration_id":     0,
        })
    return rows


def _extract_text(raw_line):
    """Return a clean text string suitable for Drain3 tokenisation."""
    line = raw_line.strip()
    if not line:
        return ""
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            # OTLP envelope: body may itself be a JSON string with msg/message
            body = obj.get("body", "")
            if isinstance(body, str) and body.strip().startswith("{"):
                try:
                    inner = json.loads(body)
                    for key in ("msg", "message", "log", "text", "output"):
                        val = inner.get(key)
                        if isinstance(val, str) and val.strip():
                            return val[:500]
                except Exception:
                    pass
            for key in ("msg", "message", "body", "output", "log", "text"):
                val = obj.get(key)
                if isinstance(val, str) and val.strip():
                    return val[:500]
        except Exception:
            pass
    return line[:500]


def _insert_patterns(rows):
    """Bulk-insert pattern rows into qryn.patterns via ClickHouse HTTP."""
    lines = []
    for r in rows:
        lines.append(json.dumps({
            "timestamp_10m":    r["timestamp_10m"],
            "fingerprint":      r["fingerprint"],
            "timestamp_s":      r["timestamp_s"],
            "tokens":           r["tokens"],
            "classes":          r["classes"],
            "overall_cost":     r["overall_cost"],
            "generalized_cost": r["generalized_cost"],
            "samples_count":    r["samples_count"],
            "pattern_id":       r["pattern_id"],
            "iteration_id":     r["iteration_id"],
        }))

    sql  = ("INSERT INTO qryn.patterns "
            "(timestamp_10m,fingerprint,timestamp_s,tokens,classes,"
            "overall_cost,generalized_cost,samples_count,pattern_id,iteration_id) "
            "FORMAT JSONEachRow\n")
    body = (sql + "\n".join(lines)).encode()

    req = urllib.request.Request(CH_URL, data=body, method="POST")
    req.add_header("Content-Type", "text/plain")
    req.add_header("X-ClickHouse-User", CH_USER)
    req.add_header("X-ClickHouse-Key",  CH_PASSWORD)
    req.add_header("X-ClickHouse-Database", "qryn")

    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()


if __name__ == "__main__":
    main()
