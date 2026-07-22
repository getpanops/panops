# PanOps Brain — Design Specification

## Vision

A Kubernetes-native autonomous operations system that correlates signals across security
(SOC), reliability (SRE), and network (NOC) domains, classifies composite incidents
("happenings"), remediates known patterns without human involvement, and learns from
every resolved incident. Statistics and CPU ML are the primary intelligence layer; a
tiny local LLM is the fallback for genuinely novel cases only.

This is Phase 7 of the unified SRE+SOC observability platform
(see `docs/sre-soc-productization.md` for prior phases).

---

## Competitive Position

Nothing in open source combines all of:
- Security signals (Falco + Sigma + YARA) + SRE signals (metrics + logs) + NOC signals
  (Cilium/Hubble) into a single correlated incident object
- Statistics-primary intelligence (no LLM API dependency)
- Self-hosted, air-gappable, privacy-preserving
- Self-improving incident store (no model retraining)
- Kubernetes-native remediation executor

Closest comparators:
- **Dynatrace Davis** — best-in-class ML correlation but closed, SaaS, expensive, data leaves cluster
- **Robusta Holmes** — Kubernetes-native but LLM-first (requires OpenAI/Claude API)
- **Keptn** — SRE automation but scoped to deployment pipelines only
- **VictoriaMetrics AD** — good stats anomaly detection but metrics-only, no correlation

The non-LLM-primary angle is a genuine differentiator: deterministic, auditable,
fast (milliseconds vs seconds), free at scale, and no hallucination risk in remediation.

---

## Core Concepts

### Happening

A **happening** is the unit of work — a composite incident envelope assembling all
signals from a correlated time window. Distinct from "event" (already used by
Kubernetes) and "alert" (a single rule firing).

Fields:
```json
{
  "id": "uuid",
  "opened_at": "ISO8601",
  "closed_at": "ISO8601 | null",
  "time_window": {"start": "ISO8601", "end": "ISO8601"},
  "affected_services": ["namespace/deployment", ...],
  "signals": {
    "falco_rules": ["rule name", ...],
    "sigma_rule_ids": ["id", ...],
    "yara_matches": ["rule", ...],
    "drain3_patterns": [{"template_id": int, "count": int, "is_novel": bool}, ...],
    "metric_anomalies": [{"metric": "name", "deviation_ratio": float}, ...],
    "metric_correlations": [{"a": "metric", "b": "metric", "lag_s": int, "r": float}, ...]
  },
  "domain": "SOC | SRE | NOC | MIXED",
  "classifier_route": "known | structured | novel | escalate",
  "similarity_score": float,
  "matched_incident_id": "uuid | null",
  "status": "open | remediating | validating | resolved | escalated",
  "actions_taken": [{"command": str, "output": str, "timestamp": str}, ...],
  "outcome": "resolved | failed | escalated | false_positive",
  "runbook_ref": "path/to/runbook.md | null"
}
```

Stored in ClickHouse: `panops.happenings`

---

## Architecture

```
[Signal Sources]
  Prometheus metrics ─────────────────────────────────────┐
  Loki (container logs via Alloy) ──── Drain3 patterns ───┤
  Falco events ───────────────────────────────────────────┤
  Sigma matches (sigma_matches table) ────────────────────┤
  YARA matches (pod logs) ────────────────────────────────┤
  Baseline anomalies (security_anomalies table) ──────────┘
                                                          ↓
                                       [Happening Assembler]
                              Triggered by: Grafana webhook OR polling
                              sigma_matches / security_anomalies tables
                              - Queries Prometheus for metric context
                              - Queries Loki for Drain3 pattern delta
                              - Queries Falco/Sigma/YARA signals
                              - Runs metric correlator
                              - Writes happening to panops.happenings

                                                          ↓
                                       [Classifier Pipeline]
                              Fast path (rule-based, <1ms):
                                Falco CRITICAL → SOC branch
                                OOMKill / probe failure → SRE branch
                                Cilium drop spike → NOC branch
                              Slow path (similarity, ~50ms):
                                Embed happening description
                                kNN against panops.incident_embeddings
                                If score > threshold → known path

                                                          ↓
                        ┌─────────────────────────────────┤
                        ↓           ↓           ↓         ↓
                   [SOC]       [SRE]        [NOC]    [Novel]
                 Talon runs   kubectl +    CNP/      Structured
                 already;     k8s client   Cilium    fallbacks →
                 label/       actions      actions   LLM Job if
                 terminate                           still unresolved

                        └──────────────┬──────────────────┘
                                       ↓
                                [Validation Loop]
                         Poll Prometheus/Loki until condition
                         clears (or timeout → escalate)
                                       ↓
                                [Incident Store]
                         Write outcome + actions taken
                         Template-fill runbook entry
                         Update embedding index
```

---

## Components

### 1. Metric Correlator

**Libraries:** `scipy`, `numpy`, `stumpy`

**Discovery mode** (no pre-setup, reactive during happening window):
1. Query Prometheus for all metrics in affected namespace over T±10min
2. `scipy.signal.correlate` with lag scan 0–300s — finds which metrics co-move with offset
3. `stumpy` Matrix Profile across metric vectors — finds co-moving subsequences without pairwise enumeration
4. `statsmodels` Granger causality on top correlated pairs — provides causal direction

**Learning mode** (builds over time):
- After each resolved incident, store correlated pairs + lags in `panops.metric_correlations`
- Weight by incident frequency — known service relationships emerge automatically
- Subsequent happenings can skip discovery for known service pairs

No correlation schemas need to be defined in advance.

### 2. Drain3 Integration

qryn's built-in Drain3 already populates `qryn.patterns`. The happening assembler:
- Queries pattern frequency in the happening window vs 7-day baseline
- Flags novel templates (not seen before) → high-signal input to novel branch
- Flags frequency anomalies per template → metric-like signal for correlation
- Cross-correlates novel patterns with Falco events in same namespace within ±5min

### 3. Happening Assembler

Python service (long-running Deployment in `panops` namespace).
Trigger sources:
- **Grafana webhook** — fires on any alert state change
- **Polling** — `SELECT` from `sigma_matches` / `security_anomalies` every 60s for new rows

Assembly steps:
1. Open happening with trigger signal + timestamp
2. Determine affected namespace/service from signal context
3. Query Prometheus (metric anomalies in window)
4. Query Loki (Drain3 patterns, novel templates)
5. Query ClickHouse (sigma_matches, security_anomalies, yara matches)
6. Run metric correlator
7. Write happening to `panops.happenings`
8. Send to classifier

### 4. Classifier Pipeline

**Rule-based fast path** (explicit routing table):
```python
rules = [
    (lambda h: any(s in FALCO_CRITICAL_RULES for s in h.signals.falco_rules), "SOC"),
    (lambda h: "OOMKilled" in h.signals.drain3_patterns, "SRE"),
    (lambda h: h.signals.sigma_rule_ids, "SOC"),
    (lambda h: h.signals.metric_anomalies and not h.signals.falco_rules, "SRE"),
]
```

**Similarity slow path:**
- Model: `sentence-transformers/all-MiniLM-L6-v2` (~22MB, fast CPU)
- Input: brief text description of happening (affected service + signal summary)
- Vector stored in ClickHouse: `panops.incident_embeddings` (Float32 array column)
- kNN via ClickHouse `cosineDistance()` function — exact brute-force, fast enough at homelab scale
- Threshold: 0.85 similarity → "known" route

**Output:** route + confidence + matched_incident_id (if known)

### 5. Remediation Executor

**Structured rules** (covers ~70% of recurring incidents):
```python
REMEDIATION_RULES = {
    "probe_timeout": adjust_probe_timeout,      # e.g. a slow-starting app service
    "oom_killed": increase_memory_limit,
    "crashloop_config": restart_with_logging,
    "pvc_near_full": expand_pvc,
    "image_pull_backoff": check_registry_credentials,
}
```

**Known incident match:** load `actions_taken` from matched incident, replay in order.

**Novel path (LLM Job):**
- Kubernetes Job: load Qwen2.5-3B Q4_K_M via llama.cpp
- Prompt: structured JSON with happening + top-3 similar past incidents + available actions
- Output: `{diagnosis, steps[], validation_query, confidence}`
- Only acts if confidence > threshold; otherwise escalates

**Safety guardrails:**
- Never touch `kube-system`, `flux-system`, `cilium-spire`, `cert-manager` namespaces
- Never delete PVCs
- Never modify more than 1 replica at a time
- Dry-run all kubectl commands first; abort if dry-run output is unexpected
- Hard timeout: abort remediation after 10 minutes regardless of state

### 6. Validation Loop

After each remediation action, poll for up to 30 minutes:
- Prometheus: check the deviating metrics returned to baseline
- Loki: check the error patterns stopped appearing
- Kubernetes: check pods are Running/Ready

Success condition: all triggering signals clear for 10 consecutive minutes.
Failure condition: timeout or new signals appear → mark escalated.

### 7. Incident Store + Runbook Writer

**ClickHouse tables:**
- `panops.happenings` — full happening objects (JSON)
- `panops.incident_embeddings` — Float32 array per happening for kNN
- `panops.metric_correlations` — learned service metric relationships
- `panops.remediation_outcomes` — action→outcome pairs for learning

**Runbook writer** (template-based, no LLM needed for known cases):
```
## [Alert Name] — Auto-generated runbook

**First seen:** {date}  **Times resolved:** {count}

### What fires this
{signal_summary}

### Automatic remediation
{actions_taken rendered as numbered steps}

### Validation
{validation_query}

### Escalation
If automatic remediation fails, see: {related_runbook}
```

Written to `docs/runbooks/auto/` — separate from hand-written runbooks in `docs/runbooks/`.

---

## LLM Integration (Novel Branch Only)

**Model choice:** Qwen2.5-3B-Instruct Q4_K_M (~2.0GB RAM)
- Better than Gemma for structured JSON output at this size
- Fast enough on CPU: ~4-6 tok/s, 200-token plan in ~40s
- Acceptable latency for background remediation

**Deployment:** Kubernetes Job (not long-running — load → infer → write → exit)
- Avoids keeping 2GB resident in RAM permanently
- 2 Jobs can run in parallel: ~4GB total, feasible on this cluster
- Image: custom, llama.cpp + quantized model baked in or loaded from PVC

**Prompt contract:**
```json
{
  "system": "You are a Kubernetes operations assistant. Output only valid JSON matching the schema.",
  "happening": {<happening object>},
  "similar_incidents": [{<past happening>}, ...],
  "available_actions": ["kubectl rollout restart", "kubectl patch", ...],
  "output_schema": {
    "diagnosis": "str",
    "steps": [{"command": "str", "expected_output": "str"}],
    "validation_query": "str (PromQL or LogQL)",
    "confidence": "float 0-1",
    "runbook_entry": "str (markdown)"
  }
}
```

---

## Implementation Order

1. **ClickHouse schema** — `panops` database, happenings/embeddings/correlations tables
2. **Happening assembler** — Deployment + Grafana webhook receiver, assembly pipeline
3. **Metric correlator** — scipy/stumpy, runs as part of assembly
4. **Drain3 integration** — novel pattern detection feeding into assembler
5. **Classifier** — rule-based fast path first, similarity slow path after data accumulates
6. **Remediation executor** — structured rules only initially (safe, no LLM needed)
7. **Validation loop** — Prometheus/Loki polling
8. **Incident store + runbook writer** — ClickHouse writes + Jinja2 templates
9. **LLM Job** — Qwen2.5-3B, novel branch only, after everything else is solid

Steps 1–8 are fully non-LLM. Step 9 is additive.

---

## Namespace + Flux Kustomization

New namespace: `panops`
Flux kustomization: `k8s/panops/` added to `k8s/flux/apps.yaml`
Dependencies: `observability` (ClickHouse), `cilium`, `falco`

---

## Vector Storage — ClickHouse Only (No Separate Vector DB)

All embeddings live in ClickHouse alongside the signal data. Reasons:

1. **Cross-domain joins in single SQL**: `JOIN panops.incident_embeddings ON ... JOIN qryn.sigma_matches ON ...` — no application-level stitching across two systems.
2. **Already deployed**: qryn already stores everything in ClickHouse. `panops` is just another database on the same cluster.
3. **Scale**: homelab incident volume (tens to hundreds/month) makes exact `cosineDistance()` kNN instant — approximate indices not needed.
4. **Unified embedding space**: `all-MiniLM-L6-v2` maps all text (Drain3 templates, Falco rule names, Sigma rule descriptions, happening summaries) into the same 384-dimensional space. This enables cross-source similarity queries — e.g. "find Drain3 patterns semantically similar to this Falco alert" — discovering relationships never explicitly defined. These are stored as Float32 arrays in tables alongside their source data.

ClickHouse tables for embeddings:
- `panops.incident_embeddings` — one row per happening
- `qryn.pattern_embeddings` — one row per unique Drain3 template (populated incrementally)
- `qryn.sigma_embeddings` — one row per sigma_matches entry (for cross-signal similarity)

Cross-source query example:
```sql
SELECT p.template, cosineDistance(p.embedding, h.embedding) AS dist
FROM qryn.pattern_embeddings p, panops.incident_embeddings h
WHERE h.id = 'some-happening-uuid'
ORDER BY dist ASC LIMIT 10
```

---

## Existing Stack Integration Points

| Component | Role in PanOps Brain |
|---|---|
| `qryn.patterns` | Drain3 pattern source; `qryn.pattern_embeddings` extends it |
| `qryn.sigma_matches` | Sigma signal source; `qryn.sigma_embeddings` extends it |
| `qryn.security_anomalies` | Baseline anomaly signal source |
| `qryn.security_baselines` | Baseline data for metric comparison |
| Grafana alerting | Webhook trigger for happening assembly |
| Falco Talon | SOC branch already handles terminate/label |
| `docs/runbooks/` | Source for known remediation steps (hand-written) |
| `docs/runbooks/auto/` | Destination for auto-generated runbooks |
| ClickHouse (existing) | `panops` DB + embedding columns on existing qryn tables |
