# DevSecOps Metrics Specification
## Instrumented, Statistical, Rolling-Baseline Approach

**Status:** Design / Pre-implementation  
**Related:** `docs/panops-autoops-spec.md`, `k8s/panops/`, `k8s/security/`  
**Sessions contributing:** PanOps Brain session (2026-07-03)

---

## Why Not Just DORA

The DORA Four Keys (deployment frequency, lead time, change failure rate, time to restore)
are useful as a **delivery spine** — they turn speed and stability into comparable numbers.
But they have two documented problems:

1. **Survey-derived, not instrumentally measured.** The original DORA research benchmarks
   came from self-reported survey data, not direct pipeline telemetry. The numbers are
   fine as direction indicators but poor as absolute targets.

2. **Measure outputs, not process.** Knowing your MTTR is 45 minutes doesn't tell you
   where in the incident lifecycle the time went. Knowing your change failure rate is 8%
   doesn't tell you which pipeline stage is failing to catch the problem. More fine-grained
   in-process metrics are needed to actually improve.

**For a homelab with low deployment frequency** (infrastructure config changes, not frequent
app releases), deployment frequency as a raw count is nearly meaningless. The signal we
actually care about is: *when changes happen, are they safe, fast to propagate, and fast
to recover from when they go wrong?*

**The approach here:** collect the DORA Four Keys from actual pipeline telemetry (not
surveys), plus security-specific derivatives, plus quality gate metrics. Apply the same
rolling-baseline Z-score normalization already used in Phase 6 anomaly detection. Alert
when a metric degrades from *its own baseline*, not from an arbitrary industry benchmark.
This makes the metrics self-calibrating and meaningful regardless of activity volume.

---

## Metric Set

### Domain: Delivery (DORA)

| Metric | Definition | Data source |
|--------|-----------|-------------|
| **Lead time for changes** | git commit timestamp → Flux kustomization reconciled (Ready=True) | Flux events in Loki → ClickHouse |
| **Deployment frequency** | Count of successful Flux reconciliations per namespace per week | Flux events |
| **Change failure rate** | Flux reconcile events that correlate with an PanOps happening opening within 4h, as % of total reconciles | Flux events + panops.happenings JOIN |
| **Time to restore** | PanOps `opened_at` → `closed_at` for happenings with `outcome = 'resolved'` | panops.happenings (already stored) |

Time to restore is **already being measured** — PanOps happenings have `opened_at` and
`closed_at` timestamps. No additional collection needed.

Lead time requires ingesting Flux events. Flux emits Kubernetes events when a
kustomization reconciles; these appear in Loki via the Alloy log collector.

### Domain: Security

| Metric | Definition | Data source |
|--------|-----------|-------------|
| **MTTD (Mean Time to Detect)** | Falco/Sigma event timestamp → PanOps happening `opened_at` | Loki Falco events + panops.happenings |
| **MTTR (Security)** | PanOps happening `opened_at` → `closed_at` for SOC domain happenings | panops.happenings |
| **Critical vulnerability exposure window** | Trivy VulnerabilityReport created → image updated (Renovate MR merged) | Trivy operator events + GitLab API |
| **False positive rate** | Happenings with `classifier_route = 'known'` that resolved with no actions taken / total happenings | panops.happenings |
| **Gate bypass rate** | MRs merged without CI pipeline passing / total MRs merged | GitLab API |
| **PanOps availability** | Ratio of 5-min windows with a heartbeat happening / total windows | panops.happenings WHERE classifier_route = 'heartbeat' |

The false positive rate is a proxy for how well PanOps suppression is working — if known
happenings keep opening that don't need action, either the signals are noisy or the
classifier is miscategorising.

Gate bypass rate is a security posture metric: every bypass is a change that went
unvalidated. It should trend toward zero as CI matures.

### Domain: Code Quality (Current Gap)

No CI pipeline testing currently exists for this homelab. This entire domain is a gap.
Metrics become available as CI jobs are added.

| Metric | Definition | Prerequisite |
|--------|-----------|-------------|
| **CI gate failure rate** | Pipeline runs that fail at each job / total runs | Any CI |
| **Test coverage** | % of Python scripts with unit tests | Tests added |
| **Lint pass rate** | % of commits where linting passes without fixing | Linting job |
| **`kustomize build` failure rate** | MRs where kustomize build fails / total MRs | Already in CI (soft) |
| **Trivy config scan severity trend** | CRITICAL + HIGH findings per kustomization over time | Trivy config job (soft) → hard |

These metrics become tracking targets once the CI pipeline is hardened (see
`docs/panops-autoops-spec.md` → "CI Pipeline as Auto-Merge Safety Gate").

---

## Statistical Normalization

Raw metric values are not useful as absolute numbers in a low-volume homelab. Instead,
compute rolling statistics and track *deviation from self-baseline*, identical to how
Phase 6 baseline anomaly detection works for security metrics.

For each metric, maintain:
- `rolling_mean_7d` — 7-day rolling mean
- `rolling_std_7d` — 7-day rolling standard deviation
- `rolling_mean_28d` — 28-day rolling mean (slower-moving trend)
- `z_score` — `(current_value - rolling_mean_7d) / rolling_std_7d`

**Alert thresholds:**
- `z_score > 2.0` — degradation from recent baseline (warn)
- `z_score > 3.0` — significant degradation (alert to #noc or #sre)
- Sustained degradation: z_score > 2.0 for > 3 consecutive collection windows

This means: if your time-to-restore is normally 8 minutes and suddenly it's 45 minutes,
that's a meaningful signal regardless of whether 45 minutes is "good" by some industry
benchmark.

---

## Data Collection Architecture

### New Table: `qryn.devsecops_metrics`

```sql
CREATE TABLE qryn.devsecops_metrics (
    collected_at    DateTime64(3),
    domain          Enum('delivery', 'security', 'quality'),
    metric_name     String,
    namespace       String,          -- empty string for cluster-wide metrics
    value           Float64,
    unit            String,          -- 'seconds', 'count', 'ratio', 'percent'
    rolling_mean_7d Float64,
    rolling_std_7d  Float64,
    z_score         Float64,
    metadata        String           -- JSON: context fields per metric type
) ENGINE = MergeTree
  PARTITION BY toYYYYMM(collected_at)
  ORDER BY (domain, metric_name, namespace, collected_at)
  TTL collected_at + INTERVAL 1 YEAR;
```

### New CronJob: `devsecops-collector`

Runs hourly in the `observability` namespace. Queries:
- Loki for Flux reconcile events → lead time, deploy frequency
- `panops.happenings` → time to restore, MTTR, false positive rate, availability
- GitLab API → MR pipeline status, bypass rate, CVE exposure window (via Renovate MR merge timestamps)
- Trivy VulnerabilityReports → exposure window complement

Writes derived metrics to `qryn.devsecops_metrics`.

### Grafana Dashboard: DevSecOps Pulse

One dashboard, three row groups (Delivery / Security / Quality). Each metric shown as:
- Current value (last collection window)
- 7-day sparkline
- Z-score badge (green/amber/red)

This dashboard is the productisation-ready interface — when the homelab becomes a
portfolio reference, this is what shows that the system is measurably working.

---

## Modularisation / Feature Flags

When productising, all metric collection should be opt-in per domain and per metric.
A ConfigMap in the collector namespace controls what is collected:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: devsecops-metrics-config
  namespace: observability
data:
  config.yaml: |
    domains:
      delivery:
        enabled: true
        metrics:
          lead_time: true
          deploy_frequency: true
          change_failure_rate: true
          time_to_restore: true       # free if panops is deployed
      security:
        enabled: true
        metrics:
          mttd: true
          mttr: true
          vuln_exposure_window: true  # requires Trivy + Renovate
          false_positive_rate: true   # requires panops
          gate_bypass_rate: false     # requires GitLab API token
          panops_availability: true     # requires panops heartbeat
      quality:
        enabled: false                # no CI yet
```

The collector reads this at startup and skips disabled metrics. Adding a new metric is
adding a flag here + the collection logic — no structural changes.

---

## Relationship to CI Pipeline and PanOps

These three concerns are a triangle, not independent:

```
CI Pipeline ──────────────────────────────── PanOps AutoOps
    │  gate_bypass_rate feeds security metrics  │
    │  change_failure_rate needs both            │
    └──────────── DevSecOps Metrics ────────────┘
                 (measurement layer)
```

- **Change failure rate** is only computable once CI emits pipeline events AND PanOps has
  happenings to correlate against. It's the metric that most directly measures whether
  the CI gates are working.

- **Gate bypass rate** is a leading indicator for future change failure rate — every bypass
  is a future incident waiting to happen.

- **PanOps availability** (heartbeat-based) feeds the self-monitoring loop described in
  `docs/panops-autoops-spec.md`.

Build them together, not separately.

---

## Implementation Notes

**Minimum viable start (no new infrastructure):**

Several metrics can be derived from what already exists before building the collector:

| Metric | Query today |
|--------|------------|
| Time to restore | `SELECT avg(date_diff('second', opened_at, closed_at)) FROM panops.happenings WHERE outcome = 'resolved'` |
| MTTR (security) | Same, filtered to `domain = 'SOC'` |
| PanOps availability | `SELECT count() FROM panops.happenings WHERE classifier_route = 'heartbeat' AND opened_at > now64() - INTERVAL 1 HOUR` (once heartbeat is implemented) |
| False positive rate | `SELECT countIf(actions_taken = '[]') / count() FROM panops.happenings WHERE classifier_route = 'known'` |

These can be one-off Grafana panels wired to ClickHouse today. The collector CronJob
is the hardening step that adds rolling baselines and Z-scores.

**GitLab API dependency:**

Gate bypass rate and CVE exposure window both need a GitLab API token in the collector.
This is the same token needed for PanOps GitLab MR client (see autoops spec). Implement
once, share between both.

**Flux event ingestion:**

Lead time and deploy frequency require Flux events from Loki. Flux emits structured log
lines when a kustomization reconciles (`Applied revision`, `Reconciliation finished`).
The devsecops-collector can query Loki's query_range API for these directly — no new
log pipeline changes needed.
