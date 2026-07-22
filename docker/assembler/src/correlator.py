"""
PanOps Brain — Metric Correlator (Step 3)
Discovers co-moving metric pairs over a happening window using scipy cross-correlation.
Called from the assembler during happening assembly; writes pairs to panops.metric_correlations
and returns them for inclusion in the happening's metric_correlations field.

Requires: scipy, numpy (pip-installed at container startup).
"""
import json
import os
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone

try:
    import numpy as np
    from scipy.signal import correlate, correlation_lags
    _HAS_SCIPY = True
except ImportError:
    _HAS_SCIPY = False

# Curated PromQL expressions for per-namespace SRE signal discovery.
# Each returns a scalar aggregate (sum across pods) → single time series per metric.
_DISCOVERY_QUERIES = [
    ("cpu_rate",      'sum(rate(container_cpu_usage_seconds_total{{namespace="{ns}",container!=""}}[5m]))'),
    ("memory_bytes",  'sum(container_memory_working_set_bytes{{namespace="{ns}",container!=""}})'),
    ("restarts",      'sum(kube_pod_container_status_restarts_total{{namespace="{ns}"}})'),
    ("net_rx_rate",   'sum(rate(container_network_receive_bytes_total{{namespace="{ns}"}}[5m]))'),
    ("net_tx_rate",   'sum(rate(container_network_transmit_bytes_total{{namespace="{ns}"}}[5m]))'),
    ("fs_read_rate",  'sum(rate(container_fs_reads_bytes_total{{namespace="{ns}"}}[5m]))'),
    ("fs_write_rate", 'sum(rate(container_fs_writes_bytes_total{{namespace="{ns}"}}[5m]))'),
]

# Minimum correlation coefficient to record as a relationship.
PEARSON_THRESHOLD = 0.7
# Maximum lag to scan (seconds).
MAX_LAG_S = 300
# Step between Prometheus samples (seconds); 20 points over a 10-min window.
STEP_S = 30


def _prom_range(prom_url, promql, start_ts, end_ts, step=STEP_S):
    params = {
        "query": promql,
        "start": str(int(start_ts)),
        "end":   str(int(end_ts)),
        "step":  str(step),
    }
    url = f"{prom_url}/api/v1/query_range?{urllib.parse.urlencode(params)}"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            body = json.loads(r.read())
        results = body.get("data", {}).get("result", [])
        if not results:
            return None
        values = results[0].get("values", [])
        if len(values) < 4:
            return None
        return np.array([float(v[1]) for v in values])
    except Exception:
        return None


def _pearson_at_lag(a, b, lag_samples):
    """Pearson r between a and b shifted by lag_samples (b leads a when lag > 0)."""
    if lag_samples == 0:
        x, y = a, b
    elif lag_samples > 0:
        x, y = a[lag_samples:], b[:-lag_samples]
    else:
        l = -lag_samples
        x, y = a[:-l], b[l:]
    if len(x) < 4:
        return 0.0
    mx, my = x.mean(), y.mean()
    sx, sy = x.std(), y.std()
    if sx < 1e-9 or sy < 1e-9:
        return 0.0
    return float(np.dot(x - mx, y - my) / (len(x) * sx * sy))


def correlate_metrics(prom_url, ch_url, namespace, service_a, window_start_ts, window_end_ts, log_fn=None):
    """
    Discover correlated metric pairs for a namespace over the happening window.
    Returns list of dicts: {a, b, lag_s, r} with |r| > PEARSON_THRESHOLD.
    Also writes pairs to panops.metric_correlations for learning-mode accumulation.
    """
    if not _HAS_SCIPY:
        if log_fn:
            log_fn("WARN", "correlator: scipy/numpy not available, skipping")
        return []

    if not namespace:
        return []

    # Fetch all discovery series for this namespace
    series = {}
    for metric_name, tmpl in _DISCOVERY_QUERIES:
        promql = tmpl.format(ns=namespace)
        vec = _prom_range(prom_url, promql, window_start_ts, window_end_ts)
        if vec is not None:
            series[metric_name] = vec

    if len(series) < 2:
        return []

    names = list(series.keys())
    max_lag_samples = MAX_LAG_S // STEP_S
    found = []

    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            na, nb = names[i], names[j]
            a, b = series[na], series[nb]
            # Align lengths (different scrape timing can produce off-by-one)
            min_len = min(len(a), len(b))
            a, b = a[:min_len], b[:min_len]

            best_r, best_lag = 0.0, 0
            for lag in range(-max_lag_samples, max_lag_samples + 1):
                r = _pearson_at_lag(a, b, lag)
                if abs(r) > abs(best_r):
                    best_r, best_lag = r, lag

            if abs(best_r) >= PEARSON_THRESHOLD:
                found.append({
                    "a":      na,
                    "b":      nb,
                    "lag_s":  best_lag * STEP_S,
                    "r":      round(best_r, 4),
                })

    if found and ch_url:
        _write_correlations(ch_url, namespace, service_a, found, log_fn)

    return found


def _write_correlations(ch_url, namespace, service_a, pairs, log_fn):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    rows = []
    for p in pairs:
        rows.append({
            "discovered_at":  now,
            "service_a":      service_a or namespace,
            "service_b":      namespace,
            "metric_a":       p["a"],
            "metric_b":       p["b"],
            "lag_seconds":    p["lag_s"],
            "pearson_r":      p["r"],
            "granger_p":      None,
            "incident_count": 1,
            "last_seen_at":   now,
        })
    body = (
        "INSERT INTO panops.metric_correlations "
        "(discovered_at,service_a,service_b,metric_a,metric_b,lag_seconds,pearson_r,granger_p,incident_count,last_seen_at) "
        "FORMAT JSONEachRow\n"
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
            log_fn("INFO", f"correlator: wrote {len(rows)} pair(s) for ns={namespace}")
    except Exception as e:
        if log_fn:
            log_fn("WARN", f"correlator: write failed: {e}")
