# Quant-Style Signals for Infrastructure Observability

## Concept

Financial time-series analysis libraries were built to detect regime changes,
momentum shifts, and anomalies in continuous numerical streams — which is
structurally identical to what infrastructure metrics are. Pod CPU, memory RSS,
request latency, error rate, and log pattern frequency are all tick streams with
trends, volatility regimes, and mean-reversion behaviour.

The key insight is that these indicators provide a **schema-independent, LLM-writable
representation** for precursor rules. Rather than asking an LLM to emit raw PromQL
(which requires exact metric name knowledge and hallucinates), the LLM can express
a discovered correlation as a named indicator with parameters:

```
RSI(14) on container_memory_working_set_bytes > 70, sustained 5m
```

A dumb evaluator can compute this against any metric without reasoning. The LLM's
job is to discover *which indicator, on which metric, at what threshold* correlates
with incidents — a reasoning task it's well-suited for.

## Relevant Libraries

| Library | Strength |
|---|---|
| `pandas-ta` | 130+ TA indicators, pandas-native |
| `ta-lib` | C-backed, faster, battle-tested in quant |
| `statsmodels` | ARIMA, STL decomposition, stationarity tests |
| `hurst` | Hurst exponent — distinguishes trend from noise |
| `arch` | Volatility modelling (GARCH) — detects variance regime shifts |
| `adtk` | Anomaly detection toolkit, composable transformers |

## Example Signals

### 1. RSI on memory growth (momentum)

**What it captures:** Memory RSS climbing steadily but not yet at the limit.
RSI > 70 means recent growth is dominant — the metric is overbought relative to
its recent history.

```python
# pandas-ta
df["mem_rsi"] = ta.rsi(df["memory_working_set_bytes"], length=14)
# Fire when RSI > 70 sustained for 5+ minutes
precursor = (df["mem_rsi"] > 70).rolling("5min").min() == 1
```

**Infrastructure meaning:** Pod is leaking memory with momentum. Not yet
OOM-adjacent but trending there. Preemptive action: raise memory limit MR,
or schedule extra pod replica.

---

### 2. Bollinger Band breach on request latency (variance regime)

**What it captures:** Latency suddenly outside its normal variance band — even
if still within SLO, this is a regime change.

```python
# Upper band = mean + 2*stddev over rolling 20-period window
bbands = ta.bbands(df["p99_latency_ms"], length=20, std=2)
precursor = df["p99_latency_ms"] > bbands["BBU_20_2.0"]
```

**Infrastructure meaning:** Something changed upstream (dependency slowdown,
noisy neighbour, connection pool saturation). Fires before the SLO breach, not
after.

---

### 3. MACD crossover on pod restart count (trend + momentum)

**What it captures:** Restart count is a monotonically increasing counter. MACD
on the *rate of change* (delta) detects when restarts are accelerating — the
signal line crossing the MACD line means acceleration is increasing.

```python
restarts_delta = df["restart_count"].diff()
macd = ta.macd(restarts_delta, fast=6, slow=13, signal=5)
# Signal line crossover = accelerating restart rate
precursor = (macd["MACD_6_13_5"] > macd["MACDs_6_13_5"]) & \
            (macd["MACD_6_13_5"].shift(1) <= macd["MACDs_6_13_5"].shift(1))
```

**Infrastructure meaning:** Pod is entering a crashloop — not just restarting,
but restarting *faster*. Fires on the second or third restart when the
acceleration is detectable, rather than waiting for CrashLoopBackOff status.

---

### 4. Hurst exponent on CPU usage (trend vs noise)

**What it captures:** Hurst > 0.5 means the series is trending (persistent),
< 0.5 means it's mean-reverting. CPU spikes are usually transient (H < 0.5);
a growing load problem is persistent (H > 0.6).

```python
from hurst import compute_Hc
H, c, _ = compute_Hc(df["cpu_usage_seconds"].tail(100))
is_trending = H > 0.6
```

**Infrastructure meaning:** Distinguishes "momentary spike, ignore" from
"load is genuinely growing, act." Reduces false positives on transient bursts
that resolve themselves.

---

### 5. STL decomposition on log pattern frequency (anomaly vs seasonality)

**What it captures:** Some log patterns are diurnal (more errors at peak hours).
STL separates trend + seasonal + residual. Anomaly detection on the residual
catches genuine spikes while ignoring predictable daily patterns.

```python
from statsmodels.tsa.seasonal import STL
stl = STL(df["log_pattern_count"], period=1440)  # 1440 = minutes per day
result = stl.fit()
# Z-score on residual, not raw count
residual_z = (result.resid - result.resid.mean()) / result.resid.std()
precursor = residual_z > 3.0
```

**Infrastructure meaning:** "This error log appeared 50 times" is meaningless
without knowing it appears 40 times every weekday at 09:00. The residual Z-score
fires only when the count is anomalous *relative to the expected pattern*.

---

## Implementation Path (when ready)

1. **NREM writes precursor fingerprints** to `panops.precursor_signals` when
   happenings close — stores the N-minute lead-up metric series alongside the
   outcome.

2. **Dream cycle (LLM)** mines closed happenings, identifies which
   indicator/threshold combinations had high precision (fired before crash,
   didn't fire without crash). Writes rules to `panops.precursor_rules`.

3. **Prefect evaluator flow** (15-min interval) computes indicators against
   live Prometheus data, scores against stored rules, fires preemptive happenings
   above 0.85 confidence.

4. **Confidence gate is high** (0.85 vs 0.70 for post-hoc runbooks). Preemptive
   actions are additive only (scale out, raise limit MR) — never drain or
   terminate, so a wrong call is low blast radius.

5. **Feedback loop**: dream cycle reviews which preemptive rules fired and
   whether the metric trajectory after action suggests the crash was averted
   (continued climbing before action, flattened after). Refines thresholds.

## Status

Deferred — post-mortem runbook generation and deep RCA are higher priority.
Revisit when dream cycle is producing quality runbooks and incident corpus
is large enough to backtest precursor rules.
