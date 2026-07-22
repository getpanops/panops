import os
import urllib.request
import sys

CH_URL = os.environ["CH_URL"]

STATEMENTS = [
    # panops database
    "CREATE DATABASE IF NOT EXISTS panops",

    # Happenings: composite incident envelopes assembling all signals
    # from a correlated time window across SOC/SRE/NOC domains.
    """
    CREATE TABLE IF NOT EXISTS panops.happenings (
        id                   UUID DEFAULT generateUUIDv4(),
        opened_at            DateTime64(9),
        closed_at            Nullable(DateTime64(9)),
        window_start         DateTime64(9),
        window_end           DateTime64(9),
        affected_services    Array(String),
        domain               LowCardinality(String),
        classifier_route     LowCardinality(String),
        similarity_score     Nullable(Float32),
        matched_incident_id  Nullable(UUID),
        status               LowCardinality(String),
        outcome              LowCardinality(String),
        runbook_ref          Nullable(String),
        falco_rules          Array(String),
        sigma_rule_ids       Array(String),
        yara_matches         Array(String),
        drain3_patterns      String,
        metric_anomalies     String,
        metric_correlations  String,
        actions_taken        String
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMM(opened_at)
    ORDER BY (opened_at, domain, status)
    TTL toDateTime(opened_at) + INTERVAL 365 DAY
    """,

    # 384-dim all-MiniLM-L6-v2 embeddings for similarity search
    """
    CREATE TABLE IF NOT EXISTS panops.incident_embeddings (
        happening_id     UUID,
        embedded_at      DateTime64(9) DEFAULT now64(),
        description_text String,
        embedding        Array(Float32)
    ) ENGINE = MergeTree()
    ORDER BY (happening_id, embedded_at)
    TTL toDateTime(embedded_at) + INTERVAL 365 DAY
    """,

    # Learned metric correlation pairs — builds automatically after each resolved incident
    """
    CREATE TABLE IF NOT EXISTS panops.metric_correlations (
        discovered_at  DateTime64(9) DEFAULT now64(),
        service_a      String,
        service_b      String,
        metric_a       String,
        metric_b       String,
        lag_seconds    Int32,
        pearson_r      Float32,
        granger_p      Nullable(Float32),
        incident_count UInt32 DEFAULT 1,
        last_seen_at   DateTime64(9) DEFAULT now64()
    ) ENGINE = ReplacingMergeTree(last_seen_at)
    ORDER BY (service_a, service_b, metric_a, metric_b, lag_seconds)
    """,

    # Per-action outcome log for self-improving remediation rules
    """
    CREATE TABLE IF NOT EXISTS panops.remediation_outcomes (
        happening_id     UUID,
        recorded_at      DateTime64(9) DEFAULT now64(),
        rule_name        LowCardinality(String),
        command          String,
        command_output   String,
        outcome          LowCardinality(String),
        duration_seconds Float32
    ) ENGINE = MergeTree()
    ORDER BY (recorded_at, happening_id)
    TTL toDateTime(recorded_at) + INTERVAL 365 DAY
    """,

    # qryn database (created by gigapipe on first write; we ensure it exists here)
    "CREATE DATABASE IF NOT EXISTS qryn",

    # Embeddings for qryn Drain3 templates — enables cross-source cosineDistance
    # queries between log patterns and incident embeddings in a single SQL JOIN.
    """
    CREATE TABLE IF NOT EXISTS qryn.pattern_embeddings (
        template_id  UInt64,
        template     String,
        embedded_at  DateTime64(9) DEFAULT now64(),
        embedding    Array(Float32)
    ) ENGINE = ReplacingMergeTree(embedded_at)
    ORDER BY template_id
    """,

    # Embeddings for sigma_matches rows — enables semantic similarity queries
    # between Sigma rule matches and happenings across the same vector space.
    """
    CREATE TABLE IF NOT EXISTS qryn.sigma_embeddings (
        sigma_timestamp  DateTime64(9),
        rule_id          String,
        embedded_at      DateTime64(9) DEFAULT now64(),
        description_text String,
        embedding        Array(Float32)
    ) ENGINE = MergeTree()
    ORDER BY (sigma_timestamp, rule_id)
    TTL toDateTime(sigma_timestamp) + INTERVAL 30 DAY
    """,

    # Dream state: NREM inference mesh state persistence
    """
    CREATE TABLE IF NOT EXISTS panops.dream_state (
        key         String,
        value       String,
        updated_at  DateTime64(9) DEFAULT now64()
    ) ENGINE = ReplacingMergeTree(updated_at)
    ORDER BY key
    """,

    # Investigation traces: agent audit trail for phase/step/tool activity
    """
    CREATE TABLE IF NOT EXISTS panops.investigation_traces (
        id              UUID DEFAULT generateUUIDv4(),
        happening_id    UUID,
        flow_run_id     String DEFAULT '',
        phase           LowCardinality(String),
        step            UInt8 DEFAULT 0,
        tool_name       String DEFAULT '',
        tool_input      String DEFAULT '',
        tool_output     String DEFAULT '',
        model_output    String DEFAULT '',
        created_at      DateTime64(9) DEFAULT now64()
    ) ENGINE = MergeTree()
    ORDER BY (happening_id, phase, step)
    """,

    # Agent memory: persistent cross-cycle LLM memory with TTL
    """
    CREATE TABLE IF NOT EXISTS panops.agent_memory (
        id                  UUID DEFAULT generateUUIDv4(),
        written_at          DateTime64(9) DEFAULT now64(),
        scope               LowCardinality(String),
        scope_key           String,
        content             String,
        source_happening_id UUID,
        ttl_days            UInt16 DEFAULT 90
    ) ENGINE = MergeTree()
    ORDER BY (scope, scope_key, written_at)
    TTL toDateTime(written_at) + toIntervalDay(ttl_days)
    """,

    # Postmortem runbooks: learned remediation steps from resolved incidents
    """
    CREATE TABLE IF NOT EXISTS panops.postmortem_runbooks (
        id UUID DEFAULT generateUUIDv4(),
        happening_id UUID,
        created_at DateTime64(3, 'UTC') DEFAULT now64(3),
        drain3_template String,
        domain LowCardinality(String),
        runtime LowCardinality(String),
        commands String,
        raw_paste String,
        notes String,
        created_by String
    ) ENGINE = MergeTree()
    ORDER BY (created_at, happening_id)
    """,

    # Assembler heartbeats: dead-man's switch for pipeline health monitoring
    """
    CREATE TABLE IF NOT EXISTS panops.component_heartbeats (
        recorded_at DateTime64(9, 'UTC') DEFAULT now64(),
        component   String,
        status      String,
        detail      String
    ) ENGINE = MergeTree()
    ORDER BY (component, recorded_at)
    TTL toDateTime(recorded_at) + INTERVAL 30 DAY
    """,

    # Deploy events: Flux and GitLab deploy events for correlation with happenings
    """
    CREATE TABLE IF NOT EXISTS panops.deploy_events (
        event_time    DateTime64(3),
        source        LowCardinality(String),
        event_type    LowCardinality(String),
        namespace     String,
        resource_name String,
        revision      String,
        status        LowCardinality(String),
        actor         String,
        message       String
    ) ENGINE = MergeTree()
    ORDER BY (event_time, source, namespace)
    TTL toDateTime(event_time) + INTERVAL 30 DAY
    """,

    # Security anomalies: Z-score anomalies from the anomaly-detector CronJob
    """
    CREATE TABLE IF NOT EXISTS qryn.security_anomalies (
        detected_at DateTime64(3),
        metric_name LowCardinality(String),
        description String,
        current_value Float64,
        baseline_avg Float64,
        deviation_ratio Float64,
        hour_bucket DateTime64(3)
    ) ENGINE = MergeTree()
    ORDER BY (detected_at, metric_name)
    TTL toDateTime(detected_at) + INTERVAL 30 DAY
    """,

    # Consolidation rewards: per-rule outcome signal for learning loop
    """
    CREATE TABLE IF NOT EXISTS panops.consolidation_rewards (
        happening_id String,
        rule_name    String,
        outcome      String,
        recorded_at  DateTime64(3, 'UTC'),
        dream_indexed UInt8 DEFAULT 0
    ) ENGINE = MergeTree()
    ORDER BY (recorded_at, happening_id)
    """,

    # Leading indicators: trained precursor metric patterns for pre-alert detection
    """
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
    """,

    # Schema migrations: columns added at runtime that must exist for new installs
    "ALTER TABLE panops.happenings ADD COLUMN IF NOT EXISTS pending_synthesis UInt8 DEFAULT 0",
    "ALTER TABLE panops.happenings ADD COLUMN IF NOT EXISTS validation_streak Int32 DEFAULT 0",
    "ALTER TABLE panops.happenings ADD COLUMN IF NOT EXISTS outcome_feedback_score Float32 DEFAULT -1",
]

# Applied best-effort: qryn.time_series only exists after gigapipe writes its first row
OPTIONAL_STATEMENTS = [
    "ALTER TABLE qryn.time_series ADD INDEX IF NOT EXISTS labels_token labels TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4",
    "ALTER TABLE qryn.time_series MATERIALIZE INDEX labels_token",
]

def ch_exec(sql):
    data = sql.strip().encode()
    req = urllib.request.Request(CH_URL, data=data, method="POST")
    req.add_header("Content-Type", "text/plain")
    req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
    req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()

errors = 0
for i, stmt in enumerate(STATEMENTS, 1):
    label = stmt.strip().splitlines()[0][:80]
    try:
        ch_exec(stmt)
        print(f"[{i}/{len(STATEMENTS)}] OK: {label}", flush=True)
    except Exception as e:
        print(f"[{i}/{len(STATEMENTS)}] FAIL: {label}\n  {e}", file=sys.stderr, flush=True)
        errors += 1

if errors:
    print(f"\n{errors} statement(s) failed", file=sys.stderr, flush=True)
    sys.exit(1)
print(f"\nAll {len(STATEMENTS)} statements succeeded", flush=True)

for i, stmt in enumerate(OPTIONAL_STATEMENTS, 1):
    label = stmt.strip().splitlines()[0][:80]
    try:
        ch_exec(stmt)
        print(f"[opt {i}] OK: {label}", flush=True)
    except Exception as e:
        print(f"[opt {i}] SKIP: {label}\n  {e}", flush=True)
