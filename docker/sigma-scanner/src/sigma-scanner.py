#!/usr/bin/env python3
import os, sys, json, re, datetime, time, urllib.request, urllib.parse, hashlib, argparse, logging
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pyyaml required")

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.clickhouse import ClickhouseBackend as ClickHouseBackend
    from sigma.processing.resolver import ProcessingPipelineResolver
    from sigma.processing.pipeline import ProcessingPipeline
    from sigma.exceptions import SigmaError
except ImportError:
    sys.exit("pySigma and pySigma-backend-clickhouse required")

# Environment and configuration
CH_URL        = os.environ.get("CH_URL", "http://observability-clickhouse-clickhouse-headless.observability.svc.cluster.local:8123")
CH_USER       = os.environ.get("CH_USER", "default")
CH_PASSWORD   = os.environ.get("CH_PASSWORD", "")
RULES_DIR     = os.environ.get("RULES_DIR", "/etc/sigma/rules")
HOMELAB_RULES = os.environ.get("HOMELAB_RULES_DIR", "/homelab-rules")
PIPELINE_FILE = os.environ.get("SIGMA_PIPELINE", "/etc/sigma/pipelines/panops-clickhouse.yaml")
LOOK_BACK     = int(os.environ.get("LOOK_BACK_MINUTES", "6"))
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL_S", "300"))

# Handle --update-intel flag
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--update-intel", action="store_true", default=False)
_args, _ = _parser.parse_known_args()

if _args.update_intel:
    _updater = os.path.join(os.path.dirname(__file__), "panops-update-intel.py")
    if os.path.exists(_updater):
        import subprocess
        subprocess.run([sys.executable, _updater, "online", "--rules-dir", RULES_DIR], check=False)
    else:
        print(f"WARN: --update-intel: panops-update-intel.py not found at {_updater}", flush=True)
    sys.exit(0)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS qryn.sigma_matches (
    event_hash UInt64 DEFAULT 0,
    timestamp  DateTime64(9) CODEC(DoubleDelta),
    rule_id    String,
    rule_title String,
    rule_level LowCardinality(String),
    rule_tags  Array(String),
    mitre      LowCardinality(String),
    log_string String,
    labels     String,
    namespace  LowCardinality(String),
    pod_name   String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, rule_level, rule_id)
TTL toDateTime(timestamp) + INTERVAL 30 DAY
SETTINGS ttl_only_drop_parts = 1
"""

INSERT_SQL = (
    "INSERT INTO qryn.sigma_matches "
    "(event_hash,timestamp,rule_id,rule_title,rule_level,rule_tags,mitre,log_string,labels,namespace,pod_name) "
    "FORMAT JSONEachRow\n"
)

# ClickHouse helper functions
def ch_exec(sql):
    """Execute a ClickHouse query without returning results."""
    data = sql.encode()
    req = urllib.request.Request(CH_URL, data=data, method="POST")
    req.add_header("Content-Type", "text/plain")
    req.add_header("X-ClickHouse-User", CH_USER)
    req.add_header("X-ClickHouse-Key", CH_PASSWORD)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read().decode()
    except Exception as e:
        logging.error(f"ch_exec failed: {e}")
        raise

def ch_query(sql):
    """Execute a ClickHouse query and return JSON results."""
    data = (sql.strip() + " FORMAT JSON").encode()
    req = urllib.request.Request(CH_URL, data=data, method="POST")
    req.add_header("Content-Type", "text/plain")
    req.add_header("X-ClickHouse-User", CH_USER)
    req.add_header("X-ClickHouse-Key", CH_PASSWORD)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read()).get("data", [])
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        # ClickHouse returns 404 for UNKNOWN_TABLE — treat as no data, not an error
        if e.code == 404 and "UNKNOWN_TABLE" in body:
            logging.debug(f"ch_query skipped (table not found): {body[:120]}")
            return []
        # 400 = bad SQL (pySigma generated invalid syntax for our schema) — warning only
        if e.code == 400:
            logging.warning(f"ch_query bad SQL (rule may target unsupported schema): {body[:150]}")
            return []
        logging.error(f"ch_query failed: HTTP {e.code}: {body[:200]}")
        raise
    except Exception as e:
        logging.error(f"ch_query failed: {e}")
        raise

def ch_query_raw(sql, start_ns, end_ns):
    """Execute x-panops-chsql with {start_ns}/{end_ns} substituted."""
    filled = sql.replace("{start_ns}", str(start_ns)).replace("{end_ns}", str(end_ns))
    data = filled.strip().encode()
    req = urllib.request.Request(CH_URL, data=data, method="POST")
    req.add_header("Content-Type", "text/plain")
    req.add_header("X-ClickHouse-User", CH_USER)
    req.add_header("X-ClickHouse-Key", CH_PASSWORD)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = json.loads(r.read())
        results = []
        for row in body.get("data", []):
            ts_ns = int(row.get("timestamp_ns", 0))
            results.append({
                "ts_ns":      ts_ns,
                "labels":     "{}",
                "log_string": str(row.get("string", ""))[:4096],
                "namespace":  "",
                "pod_name":   "",
            })
        return results
    except Exception as e:
        logging.warning(f"ch_query_raw failed: {e}")
        return []

# Sigma processing functions
def _optimize_sql(sql):
    """Rewrite pySigma time_series LIKE subquery to use indexed time_series_gin.

    Handles AND-chained LIKE patterns and OR groups with the same key.
    Falls back to original SQL if pattern is unrecognised.
    """
    subq_re = re.compile(
        r'fingerprint IN \(\s*SELECT fingerprint FROM qryn\.time_series\s+WHERE\s+(.*?)\)',
        re.DOTALL | re.IGNORECASE,
    )
    kv_re = re.compile(r"labels LIKE '%\"([^\"]+)\":\"([^\"]+)\"%'")
    or_group_re = re.compile(
        r'\(\s*(?:labels LIKE \'[^\']+\'\s+OR\s+)+labels LIKE \'[^\']+\'\s*\)',
        re.DOTALL,
    )

    match = subq_re.search(sql)
    if not match:
        return sql

    where_clause = match.group(1)
    gin_parts = []
    remainder = where_clause

    for og in or_group_re.finditer(where_clause):
        kvs = kv_re.findall(og.group())
        if not kvs:
            return sql
        keys = {k for k, _ in kvs}
        if len(keys) != 1:
            return sql
        key = list(keys)[0]
        vals_sql = ', '.join(f"'{v}'" for _, v in kvs)
        gin_parts.append(
            f"SELECT fingerprint FROM qryn.time_series_gin\n"
            f"    WHERE key = '{key}' AND val IN ({vals_sql}) AND date >= today() - 1"
        )
        remainder = remainder.replace(og.group(), '')

    for key, val in kv_re.findall(remainder):
        gin_parts.append(
            f"SELECT fingerprint FROM qryn.time_series_gin\n"
            f"    WHERE key = '{key}' AND val = '{val}' AND date >= today() - 1"
        )

    if not gin_parts:
        return sql

    gin_subq = '\nINTERSECT\n'.join(gin_parts)
    optimized = f"fingerprint IN (\n    {gin_subq}\n)"
    result = subq_re.sub(optimized, sql)
    logging.debug("_optimize_sql: rewrote time_series LIKE → time_series_gin")
    return result

def load_pipeline():
    """Load the panops-clickhouse.yaml pipeline."""
    try:
        with open(PIPELINE_FILE) as f:
            pipeline_dict = yaml.safe_load(f)
        return ProcessingPipeline.from_dict(pipeline_dict)
    except Exception as e:
        logging.error(f"Failed to load pipeline from {PIPELINE_FILE}: {e}")
        raise

def load_rules(rules_dir):
    """Load all Sigma rules (standard and correlation) from rules_dir.

    Returns: (standard_rules, correlation_rules)
    - standard_rules: list of (rule_file, rule_data, SigmaCollection or None)
    - correlation_rules: list of (rule_file, rule_data)
    """
    standard_rules = []
    correlation_rules = []

    rules_path = Path(rules_dir)
    if not rules_path.exists():
        logging.warning(f"Rules directory not found: {rules_dir}")
        return standard_rules, correlation_rules

    rule_files = sorted(rules_path.rglob("*.yaml")) + sorted(rules_path.rglob("*.yml"))
    for rule_file in sorted(set(rule_files), key=str):
        try:
            with open(rule_file) as f:
                docs = list(yaml.safe_load_all(f))
        except Exception as e:
            logging.warning(f"Failed to load rule {rule_file}: {e}")
            continue

        for rule_data in docs:
            if not rule_data:
                continue
            try:
                # Check if it's a correlation rule
                if "correlation" in rule_data:
                    correlation_rules.append((str(rule_file), rule_data))
                    logging.info(f"Loaded correlation rule: {rule_file.name}")
                else:
                    # Standard Sigma rule
                    try:
                        rule_text = yaml.dump(rule_data)
                        sigma_col = SigmaCollection.from_yaml(rule_text)
                        standard_rules.append((str(rule_file), rule_data, sigma_col))
                        logging.info(f"Loaded standard rule: {rule_file.name}")
                    except (SigmaError, Exception) as e:
                        logging.warning(f"Failed to parse rule {rule_file.name} as Sigma: {e}")
                        standard_rules.append((str(rule_file), rule_data, None))
            except Exception as e:
                logging.warning(f"Failed to process rule in {rule_file}: {e}")

    return standard_rules, correlation_rules

def compile_rules(standard_rules, pipeline):
    """Compile standard Sigma rules to SQL using the pipeline.

    Returns: list of (rule_data, sql_string) tuples
    """
    compiled = []
    backend = ClickHouseBackend(processing_pipeline=pipeline)

    for rule_file, rule_data, sigma_col in standard_rules:
        # Check for x-panops-chsql escape hatch
        if "x-panops-chsql" in rule_data:
            sql = rule_data["x-panops-chsql"]
            compiled.append((rule_data, sql))
            logging.info(f"Using x-panops-chsql escape hatch for {Path(rule_file).name}")
            continue

        if sigma_col is None:
            logging.warning(f"Skipping {Path(rule_file).name}: no valid Sigma rule")
            continue

        try:
            queries = backend.convert(sigma_col)
            if queries:
                # Use the first query (usually just one per rule)
                sql = queries[0] if isinstance(queries, list) else queries
                compiled.append((rule_data, _optimize_sql(sql)))
            else:
                logging.warning(f"No SQL generated for {Path(rule_file).name}")
        except Exception as e:
            logging.warning(f"Failed to compile {Path(rule_file).name}: {e}")

    return compiled

def event_hash(rule_id, namespace, ts_ns):
    """Stable dedup key: rule + namespace + 1-minute time bucket."""
    minute_bucket = ts_ns // 60_000_000_000
    key = f"{rule_id}:{namespace}:{minute_bucket}"
    return int(hashlib.sha256(key.encode()).hexdigest()[:16], 16) & 0xFFFFFFFFFFFFFFFF

def existing_hashes(hashes, since_ns):
    """Return set of event_hash values already in sigma_matches within the look-back window."""
    if not hashes:
        return set()
    since_dt = datetime.datetime.utcfromtimestamp(since_ns / 1e9).strftime("%Y-%m-%d %H:%M:%S")
    hash_list = ",".join(str(h) for h in hashes)
    try:
        rows = ch_query(
            f"SELECT DISTINCT event_hash FROM qryn.sigma_matches "
            f"WHERE timestamp > toDateTime64('{since_dt}', 9) "
            f"AND event_hash IN ({hash_list})"
        )
        return {int(r["event_hash"]) for r in rows}
    except Exception as e:
        logging.warning(f"Dedup check failed: {e}")
        return set()

def run_detections(compiled_rules, start_ns, end_ns):
    """Run all compiled rules and return matches.

    Returns: list of match dicts ready for insertion into qryn.sigma_matches
    """
    all_matches = []

    for rule_data, sql in compiled_rules:
        rule_id = rule_data.get("id", "unknown")
        rule_title = rule_data.get("title", "unknown")
        rule_level = rule_data.get("level", "unknown")
        rule_tags = rule_data.get("tags", [])
        mitre = next((t for t in rule_tags if re.match(r"attack\.t\d+", t, re.I)), "")

        try:
            # Substitute timespan placeholders
            filled_sql = sql.replace("{start_ns}", str(start_ns)).replace("{end_ns}", str(end_ns))

            matches_raw = ch_query(filled_sql)
            if not matches_raw:
                logging.info(f"Rule {rule_title}: 0 matches")
                continue

            # Process matches: dedup, extract fields, format for insertion
            matches_to_insert = []
            for row in matches_raw:
                # Extract log_string: try multiple possible field names
                log_string = str(row.get("string", row.get("log_string", "")))[:4096]
                ts_ns = int(row.get("timestamp_ns", int(end_ns)))
                namespace = str(row.get("namespace", ""))
                pod_name = str(row.get("pod_name", row.get("pod", "")))

                h = event_hash(rule_id, namespace, ts_ns)
                matches_to_insert.append({
                    "rule_id": rule_id,
                    "rule_title": rule_title,
                    "rule_level": rule_level,
                    "rule_tags": rule_tags,
                    "mitre": mitre,
                    "ts_ns": ts_ns,
                    "log_string": log_string,
                    "namespace": namespace,
                    "pod_name": pod_name,
                    "_hash": h,
                })

            # Dedup
            seen = existing_hashes({m["_hash"] for m in matches_to_insert}, start_ns)
            new_matches = [m for m in matches_to_insert if m["_hash"] not in seen]

            if new_matches:
                logging.info(f"Rule {rule_title}: {len(new_matches)}/{len(matches_to_insert)} new matches")
                all_matches.extend(new_matches)
            else:
                logging.info(f"Rule {rule_title}: {len(matches_to_insert)} matches (all deduped)")

        except Exception as e:
            logging.warning(f"Failed to run rule {rule_title}: {e}")

    return all_matches

def insert_matches(matches):
    """Insert matches into qryn.sigma_matches."""
    if not matches:
        return 0

    try:
        rows = []
        for m in matches:
            ts = datetime.datetime.utcfromtimestamp(m["ts_ns"] / 1e9)
            rows.append({
                "event_hash": m["_hash"],
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S.%f") + "000",
                "rule_id": m["rule_id"],
                "rule_title": m["rule_title"],
                "rule_level": m["rule_level"],
                "rule_tags": m["rule_tags"],
                "mitre": m["mitre"],
                "log_string": m["log_string"],
                "labels": "{}",
                "namespace": m["namespace"],
                "pod_name": m["pod_name"],
            })

        body = INSERT_SQL + "\n".join(json.dumps(r) for r in rows)
        ch_exec(body)
        logging.info(f"Inserted {len(rows)} matches into qryn.sigma_matches")
        return len(rows)
    except Exception as e:
        logging.error(f"Failed to insert matches: {e}")
        raise

# Correlation SQL builders
def _parse_timespan(s):
    """Parse timespan string like '15m', '1h', '24h' to seconds."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if not s or len(s) < 2:
        return 300  # default 5 minutes
    multiplier = int(s[:-1])
    unit = s[-1]
    return multiplier * units.get(unit, 60)

def _parse_condition(condition):
    """Parse condition dict {'gte': 5} to SQL operator and threshold."""
    for op_key, op_sym in [("gte",">="),("gt",">"),("lte","<="),("lt","<"),("eq","=")]:
        if op_key in condition:
            return op_sym, int(condition[op_key])
    raise ValueError(f"Unknown condition: {condition}")

def build_event_count_query(rule_data, start_ns, end_ns):
    """Build event_count correlation SQL."""
    corr = rule_data.get("correlation", {})
    ref_rules = corr.get("rules", [])
    group_by_fields = corr.get("group-by", [])
    timespan_s = _parse_timespan(corr.get("timespan", "300s"))
    condition = corr.get("condition", {})

    rule_list = ", ".join(f"'{r}'" for r in ref_rules)
    group_cols = ", ".join(group_by_fields) if group_by_fields else "rule_id"
    op, threshold = _parse_condition(condition)

    return f"""
        SELECT rule_id, {group_cols}, count() as cnt,
               min(timestamp) as first_seen, max(timestamp) as last_seen,
               any(namespace) as namespace
        FROM qryn.sigma_matches
        WHERE rule_id IN ({rule_list})
          AND timestamp BETWEEN fromUnixTimestamp64Nano({start_ns - timespan_s*1_000_000_000})
                           AND fromUnixTimestamp64Nano({end_ns})
        GROUP BY rule_id, {group_cols}
        HAVING cnt {op} {threshold}
        FORMAT JSON
    """

def build_value_count_query(rule_data, start_ns, end_ns):
    """Build value_count correlation SQL."""
    corr = rule_data.get("correlation", {})
    ref_rules = corr.get("rules", [])
    group_by_fields = corr.get("group-by", [])
    timespan_s = _parse_timespan(corr.get("timespan", "300s"))
    condition = corr.get("condition", {})
    count_field = condition.get("field", "log_string")

    rule_list = ", ".join(f"'{r}'" for r in ref_rules)
    group_cols = ", ".join(group_by_fields) if group_by_fields else "rule_id"
    op, threshold = _parse_condition({k: v for k, v in condition.items() if k != "field"})

    return f"""
        SELECT rule_id, {group_cols}, uniqExact({count_field}) as ucount,
               min(timestamp) as first_seen, max(timestamp) as last_seen,
               any(namespace) as namespace
        FROM qryn.sigma_matches
        WHERE rule_id IN ({rule_list})
          AND timestamp BETWEEN fromUnixTimestamp64Nano({start_ns - timespan_s*1_000_000_000})
                           AND fromUnixTimestamp64Nano({end_ns})
        GROUP BY rule_id, {group_cols}
        HAVING ucount {op} {threshold}
        FORMAT JSON
    """

def build_temporal_query(rule_data, start_ns, end_ns):
    """Build temporal correlation SQL."""
    corr = rule_data.get("correlation", {})
    ref_rules = corr.get("rules", [])
    group_by_fields = corr.get("group-by", [])
    timespan_s = _parse_timespan(corr.get("timespan", "300s"))

    rule_list = ", ".join(f"'{r}'" for r in ref_rules)
    required = len(ref_rules)
    group_cols = ", ".join(group_by_fields) if group_by_fields else "rule_id"

    return f"""
        SELECT {group_cols}, uniqExact(rule_id) as rule_count,
               min(timestamp) as first_seen, max(timestamp) as last_seen,
               any(namespace) as namespace
        FROM qryn.sigma_matches
        WHERE rule_id IN ({rule_list})
          AND timestamp BETWEEN fromUnixTimestamp64Nano({start_ns - timespan_s*1_000_000_000})
                           AND fromUnixTimestamp64Nano({end_ns})
        GROUP BY {group_cols}
        HAVING rule_count >= {required}
        FORMAT JSON
    """

def run_correlation_rule(corr_rule, start_ns, end_ns):
    """Run a single correlation rule and return matches."""
    corr = corr_rule.get("correlation", {})
    ctype = corr.get("type", "event_count")

    try:
        if ctype == "event_count":
            sql = build_event_count_query(corr_rule, start_ns, end_ns)
        elif ctype == "value_count":
            sql = build_value_count_query(corr_rule, start_ns, end_ns)
        elif ctype == "temporal":
            sql = build_temporal_query(corr_rule, start_ns, end_ns)
        else:
            logging.warning(f"Unknown correlation type: {ctype}")
            return []

        matches_raw = ch_query(sql)
        if not matches_raw:
            return []

        # Convert correlation matches to sigma_matches format
        matches = []
        rule_title = corr_rule.get("title", f"corr_{ctype}")
        rule_id = f"corr_{re.sub(r'[^a-z0-9_]', '_', rule_title.lower())}"
        rule_level = corr_rule.get("level", "medium")
        rule_tags = corr_rule.get("tags", [])
        mitre = next((t for t in rule_tags if re.match(r"attack\.t\d+", t, re.I)), "")

        for row in matches_raw:
            ts_ns = int(row.get("timestamp", row.get("last_seen", end_ns))) if isinstance(row.get("last_seen"), (int, float)) else end_ns
            namespace = str(row.get("namespace", ""))
            summary = json.dumps(row)

            h = event_hash(rule_id, namespace, ts_ns)
            matches.append({
                "rule_id": rule_id,
                "rule_title": rule_title,
                "rule_level": rule_level,
                "rule_tags": rule_tags,
                "mitre": mitre,
                "ts_ns": ts_ns,
                "log_string": summary[:4096],
                "namespace": namespace,
                "pod_name": row.get("pod_name", ""),
                "_hash": h,
            })

        return matches
    except Exception as e:
        logging.warning(f"Correlation rule {corr_rule.get('title', 'unknown')} failed: {e}")
        return []

# Main scan loop
def main():
    logging.info("sigma-scanner starting")

    try:
        ch_exec(CREATE_TABLE)
        logging.info("Initialized qryn.sigma_matches table")
    except Exception as e:
        logging.error(f"Failed to initialize sigma_matches table: {e}")
        sys.exit(1)

    try:
        pipeline = load_pipeline()
        logging.info(f"Loaded pipeline from {PIPELINE_FILE}")
    except Exception as e:
        logging.error(f"Failed to load pipeline: {e}")
        sys.exit(1)

    while True:
        start_cycle = time.time()
        end_ns = int(start_cycle * 1e9)
        start_ns = int((start_cycle - LOOK_BACK * 60) * 1e9)

        try:
            # Load rules: homelab custom rules first, then community rules
            standard_rules, correlation_rules = load_rules(HOMELAB_RULES)
            comm_std, comm_corr = load_rules(RULES_DIR)
            standard_rules   += comm_std
            correlation_rules += comm_corr
            logging.info(f"Loaded {len(standard_rules)} standard rules, {len(correlation_rules)} correlation rules")

            # Compile and run standard rules
            compiled = compile_rules(standard_rules, pipeline)
            matches = run_detections(compiled, start_ns, end_ns)

            # Insert standard rule matches
            inserted = 0
            if matches:
                inserted = insert_matches(matches)

            # Run correlation rules
            corr_matches = []
            for rule_file, corr_rule in correlation_rules:
                cmatch = run_correlation_rule(corr_rule, start_ns, end_ns)
                corr_matches.extend(cmatch)

            if corr_matches:
                insert_matches(corr_matches)
                logging.info(f"Inserted {len(corr_matches)} correlation rule matches")

            logging.info(f"Scan cycle complete: {inserted} standard + {len(corr_matches)} correlation matches")

        except Exception as e:
            logging.error(f"Scan cycle failed: {e}", exc_info=True)

        elapsed = time.time() - start_cycle
        sleep_time = max(0, SCAN_INTERVAL - elapsed)
        if sleep_time > 0:
            logging.info(f"Sleeping for {sleep_time:.1f}s until next scan cycle")
            time.sleep(sleep_time)

if __name__ == "__main__":
    main()
