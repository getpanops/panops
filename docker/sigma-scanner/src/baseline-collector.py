#!/usr/bin/env python3
"""
baseline-collector: Computes hourly security metric counts, stores them in
ClickHouse, then runs ADTK statistical anomaly detection against the 30-day
history.

Detectors (applied independently, any hit emits an anomaly):
  IQR          — spike outside median ± 1.5×IQR (replaces the old 3× ratio)
  LevelShift   — rolling median shifted upward vs prior window
  Persist      — value stays persistently above rolling median for ≥2h

Falls back to the simple 3× ratio check if ADTK/pandas are unavailable.
Requires at least MIN_BASELINE_POINTS historical points before any detection runs.
"""
import os, sys, json, datetime, time, urllib.request, urllib.parse

LOKI_URL            = os.environ.get("LOKI_URL",  "http://gigapipe.observability.svc.cluster.local:3100")
CH_URL              = os.environ.get("CH_URL",    "http://observability-clickhouse-clickhouse-headless.observability.svc.cluster.local:8123")
MIN_BASELINE_POINTS = int(os.environ.get("MIN_BASELINE_POINTS", "10"))
IQR_C               = float(os.environ.get("IQR_C",     "1.5"))
LEVEL_SHIFT_C       = float(os.environ.get("LEVEL_SHIFT_C", "6.0"))
PERSIST_C           = float(os.environ.get("PERSIST_C",  "3.0"))
FALLBACK_RATIO      = float(os.environ.get("FALLBACK_RATIO", "3.0"))

try:
    import pandas as pd
    from adtk.detector import InterQuartileRangeAD, LevelShiftAD, PersistAD
    from adtk.data import validate_series
    ADTK_AVAILABLE = True
except ImportError:
    ADTK_AVAILABLE = False
    print("WARN: adtk/pandas not available — falling back to ratio check", flush=True)

METRICS = [
    {
        "name": "falco_critical_per_hour",
        "description": "Falco Critical/Emergency events",
        "logql": 'sum(count_over_time({source="security/falco",falco_priority=~"Critical|Emergency"}[1h]))',
    },
    {
        "name": "falco_all_per_hour",
        "description": "All Falco events",
        "logql": 'sum(count_over_time({source="security/falco"}[1h]))',
    },
    {
        "name": "audit_writes_per_hour",
        "description": "K8s audit write events",
        "logql": 'sum(count_over_time({job="kubernetes/audit"}[1h]))',
    },
    {
        "name": "audit_exec_per_hour",
        "description": "kubectl exec / pod shell access events",
        "logql": 'sum(count_over_time({job="kubernetes/audit"} |= "pods/exec" [1h]))',
    },
    {
        "name": "sigma_matches_per_hour",
        "description": "Sigma rule matches (from scanner)",
        "logql": 'sum(count_over_time({namespace="security"} |= `"sigma_match": true` [1h]))',
    },
]

CREATE_BASELINES = """
CREATE TABLE IF NOT EXISTS qryn.security_baselines (
    hour_bucket    DateTime,
    metric_name    LowCardinality(String),
    value          Float64,
    day_of_week    UInt8,
    hour_of_day    UInt8
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(hour_bucket)
ORDER BY (metric_name, hour_bucket)
TTL hour_bucket + INTERVAL 90 DAY
SETTINGS ttl_only_drop_parts = 1
"""

CREATE_ANOMALIES = """
CREATE TABLE IF NOT EXISTS qryn.security_anomalies (
    detected_at     DateTime,
    metric_name     LowCardinality(String),
    description     String,
    current_value   Float64,
    baseline_avg    Float64,
    deviation_ratio Float64,
    hour_bucket     DateTime
) ENGINE = MergeTree()
ORDER BY (detected_at, metric_name)
TTL detected_at + INTERVAL 30 DAY
SETTINGS ttl_only_drop_parts = 1
"""


def ch_exec(sql):
    data = sql.encode()
    req = urllib.request.Request(CH_URL, data=data, method="POST")
    req.add_header("Content-Type", "text/plain")
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def ch_query_tsv(sql):
    data = (sql + " FORMAT TabSeparated").encode()
    req = urllib.request.Request(CH_URL, data=data, method="POST")
    req.add_header("Content-Type", "text/plain")
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def loki_count(logql, start_ns, end_ns):
    params = urllib.parse.urlencode({
        "query": logql,
        "start": str(start_ns),
        "end":   str(end_ns),
        "step":  "3600",
        "limit": "1",
    })
    url = f"{LOKI_URL}/loki/api/v1/query_range?{params}"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            data = json.loads(r.read())
    except Exception as e:
        print(f"  WARN loki query failed: {e}", flush=True)
        return 0.0
    results = data.get("data", {}).get("result", [])
    if not results:
        return 0.0
    values = results[0].get("values", [])
    return float(values[-1][1]) if values else 0.0


def load_history(metric_name, days=30):
    """
    Load up to `days` days of hourly baseline data from CH.
    Returns a list of (datetime, float) tuples ordered by time.
    """
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    sql = (
        f"SELECT hour_bucket, value FROM qryn.security_baselines "
        f"WHERE metric_name = '{metric_name}' "
        f"AND hour_bucket >= '{cutoff}' "
        f"ORDER BY hour_bucket"
    )
    try:
        raw = ch_query_tsv(sql).strip()
        if not raw:
            return []
        rows = []
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) != 2:
                continue
            dt = datetime.datetime.strptime(parts[0].strip(), "%Y-%m-%d %H:%M:%S")
            rows.append((dt, float(parts[1].strip())))
        return rows
    except Exception as e:
        print(f"  WARN load_history failed for {metric_name}: {e}", flush=True)
        return []


def emit_anomaly(metric_name, description, current_value, baseline_avg, deviation_ratio, hour_start):
    event = {
        "security_anomaly":  True,
        "metric_name":       metric_name,
        "description":       description,
        "current_value":     current_value,
        "baseline_avg":      round(baseline_avg, 2),
        "deviation_ratio":   round(deviation_ratio, 2),
        "hour_bucket":       hour_start.isoformat() + "Z",
    }
    print(json.dumps(event), flush=True)
    safe_desc = description.replace("'", "")
    anom_sql = (
        f"INSERT INTO qryn.security_anomalies "
        f"(detected_at, metric_name, description, current_value, baseline_avg, deviation_ratio, hour_bucket) "
        f"VALUES (now(), '{metric_name}', '{safe_desc}', "
        f"{current_value}, {baseline_avg:.4f}, {deviation_ratio:.4f}, "
        f"'{hour_start.strftime('%Y-%m-%d %H:%M:%S')}')"
    )
    try:
        ch_exec(anom_sql)
    except Exception as e:
        print(f"  ERROR inserting anomaly: {e}", file=sys.stderr, flush=True)


def detect_adtk(metric_name, history, current_ts, current_value):
    """
    Run ADTK detectors on the full history (including the current point).
    Returns (is_anomalous, fired_detectors, baseline_avg, deviation_ratio).
    """
    # Build series: existing history + current point
    all_points = history + [(current_ts, current_value)]
    index = [p[0] for p in all_points]
    values = [p[1] for p in all_points]

    try:
        ts = pd.Series(values, index=pd.DatetimeIndex(index), dtype=float)
        ts = ts.sort_index()
        # Fill any gaps in the hourly index with NaN so ADTK sees a regular series
        full_index = pd.date_range(start=ts.index[0], end=ts.index[-1], freq="h")
        ts = ts.reindex(full_index)
        ts = validate_series(ts)
    except Exception as e:
        print(f"  WARN adtk series build failed: {e}", flush=True)
        return False, [], 0.0, 0.0

    baseline_avg = float(ts.iloc[:-1].dropna().mean()) if len(ts) > 1 else 0.0
    deviation_ratio = (current_value / baseline_avg) if baseline_avg > 0 else float("inf")

    fired = []
    detectors = [
        ("IQR",         InterQuartileRangeAD(c=IQR_C)),
        ("LevelShift",  LevelShiftAD(c=LEVEL_SHIFT_C, side="positive")),
        ("Persist",     PersistAD(c=PERSIST_C, side="positive")),
    ]
    for det_name, detector in detectors:
        try:
            result = detector.fit_detect(ts)
            # Check if the last (current) non-NaN point is flagged
            last_val = result.iloc[-1] if not result.empty else False
            if bool(last_val):
                fired.append(det_name)
        except Exception as e:
            print(f"  WARN {det_name} detector failed: {e}", flush=True)

    return bool(fired), fired, baseline_avg, deviation_ratio


def detect_ratio_fallback(history, current_value, hour_start, dow, hod):
    """Simple 3× ratio check against same dow+hod average (original Phase 6 logic)."""
    same_slot = [v for (dt, v) in history if dt.weekday() == dow and dt.hour == hod]
    if not same_slot:
        return False, 0.0, 0.0
    avg_val = sum(same_slot) / len(same_slot)
    if avg_val == 0:
        ratio = float("inf") if current_value > 5 else 0.0
    else:
        ratio = current_value / avg_val
    return ratio >= FALLBACK_RATIO, avg_val, ratio


def main():
    print("baseline-collector starting", flush=True)
    print(f"  adtk_available={ADTK_AVAILABLE} iqr_c={IQR_C} level_shift_c={LEVEL_SHIFT_C} persist_c={PERSIST_C}", flush=True)

    for ddl in [CREATE_BASELINES, CREATE_ANOMALIES]:
        try:
            ch_exec(ddl)
        except Exception as e:
            print(f"ERROR: cannot init table: {e}", file=sys.stderr, flush=True)
            sys.exit(1)

    now        = datetime.datetime.utcnow()
    hour_end   = now.replace(minute=0, second=0, microsecond=0)
    hour_start = hour_end - datetime.timedelta(hours=1)
    start_ns   = int(hour_start.timestamp() * 1e9)
    end_ns     = int(hour_end.timestamp()   * 1e9)
    dow        = hour_start.weekday()
    hod        = hour_start.hour

    print(f"measuring {hour_start.isoformat()}Z (dow={dow} hod={hod})", flush=True)

    for m in METRICS:
        name  = m["name"]
        value = loki_count(m["logql"], start_ns, end_ns)
        print(f"  {name} = {value:.0f}", flush=True)

        insert = (
            f"INSERT INTO qryn.security_baselines "
            f"(hour_bucket, metric_name, value, day_of_week, hour_of_day) VALUES "
            f"('{hour_start.strftime('%Y-%m-%d %H:%M:%S')}', '{name}', {value}, {dow}, {hod})"
        )
        try:
            ch_exec(insert)
        except Exception as e:
            print(f"  ERROR inserting baseline: {e}", file=sys.stderr, flush=True)
            continue

        history = load_history(name, days=30)
        # Exclude the current point we just inserted (history query is pre-insert aligned)
        history = [(dt, v) for (dt, v) in history if dt < hour_start]

        if len(history) < MIN_BASELINE_POINTS:
            print(f"  {name}: skip detection ({len(history)} < {MIN_BASELINE_POINTS} points)", flush=True)
            continue

        if ADTK_AVAILABLE:
            is_anom, fired, baseline_avg, ratio = detect_adtk(name, history, hour_start, value)
            if is_anom:
                desc = (
                    f"{m['description']}: {value:.0f} events this hour vs "
                    f"{baseline_avg:.1f} avg (ratio={ratio:.1f}x, detectors={','.join(fired)}, "
                    f"n={len(history)})"
                )
                emit_anomaly(name, desc, value, baseline_avg, ratio, hour_start)
            else:
                print(f"  {name}: no anomaly (adtk, baseline_avg={baseline_avg:.1f}, ratio={ratio:.2f}x)", flush=True)
        else:
            is_anom, baseline_avg, ratio = detect_ratio_fallback(history, value, hour_start, dow, hod)
            if is_anom:
                desc = (
                    f"{m['description']}: {value:.0f} events this hour vs "
                    f"{baseline_avg:.1f} avg (ratio={ratio:.1f}x, detector=ratio-fallback, "
                    f"n={len(history)})"
                )
                emit_anomaly(name, desc, value, baseline_avg, ratio, hour_start)
            else:
                print(f"  {name}: no anomaly (ratio fallback, baseline_avg={baseline_avg:.1f}, ratio={ratio:.2f}x)", flush=True)

    print("baseline-collector done", flush=True)


if __name__ == "__main__":
    main()
