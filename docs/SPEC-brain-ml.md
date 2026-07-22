# PanOps Brain — ML Self-Improvement & LLM Integration Spec

## Philosophy

PanOps is built around a two-tier intelligence model:

- **ML tier** (always-on, sub-ms, CPU-only): handles the 90% case — known patterns, structured signals, learned remediations. Never needs a GPU or external API.
- **LLM tier** (on-demand, novel cases only): handles the 10% the ML tier can't pattern-match. A small local CPU model (e.g. Phi-3-mini quantized to 4-bit) or a remote API call, used sparingly.

The self-improvement loop means the LLM tier is called *less* over time, not more. Every novel incident the LLM resolves becomes a CBR case by the next morning, reducing the LLM's future load. The ML tier absorbs increasing surface area while the LLM handles a shrinking frontier.

The analogy that captures this: the ML stack is the reflex arc — fast, automatic, proven. The LLM is the frontal cortex — slow, deliberate, handles novelty. The "mecha-SRE" frame: the LLM is already expert-grade; the ML augmentations make it faster, more consistent, and increasingly autonomous.

### Stability, robustness, and resilience

These three properties are related but distinct, and PanOps targets all three at different layers:

- **Stability**: the system holds a functional state under small fluctuations. → Validation streak (10 consecutive clean polls = stable).
- **Robustness**: the system keeps working despite noise, drift, or partial failure. → Dedup window, stabilization wait, IMMEDIATE_RULES bypass, RBAC guardrails.
- **Resilience**: the system absorbs a shock, reorganises internally, and recovers adaptive performance. → The dream cycle.

Stability and robustness are properties of the live path. Resilience is a property of the offline loop. A system that only has the first two will eventually encounter an incident it cannot classify, exhaust its rule set, and escalate — because it has no mechanism to grow. The dream cycle is what keeps the live path from drifting toward states it cannot escape.

This framing is grounded in recent computational neuroscience work (Wang & Li, *Brain Medicine*, 2026) showing that sleep in biological networks is specifically a resilience mechanism — not rest or housekeeping — and that artificial networks trained continuously without offline phases develop pathological drift. The lesson for PanOps: the dream cycle is not optional housekeeping. It is the mechanism that keeps the live path adaptive.

---

## Architecture

```
                         ┌─────────────────────────────────────────┐
                         │           LIVE PATH (always-on)         │
  Grafana/Falco/Sigma     │                                         │
  ──────────────────►    │  Assembler → Drain3 → Classifier        │
                         │                 │                        │
                         │         similarity ≥ 0.85               │
                         │         ──────────────────► CBR replay   │
                         │                 │                        │
                         │         0.65 ≤ sim < 0.85               │
                         │         ──────────────────► CBR + bandit │
                         │                 │                        │
                         │         sim < 0.65                       │
                         │         ──────────────────► LLM tier     │
                         │                 │                        │
                         │  Stabilization window (k8s-resolvable)  │
                         │  → Remediator → Validation loop         │
                         └──────────────┬──────────────────────────┘
                                        │ on resolve
                                        ▼
                         ┌─────────────────────────────────────────┐
                         │     MEMORY CYCLE (continuous)           │
                         │                                         │
                         │  record_resolution()                    │
                         │  → panops.consolidation_rewards           │
                         │    (rule_name, outcome, happening_id)   │
                         └──────────────┬──────────────────────────┘
                                        │ nightly
                                        ▼
                         ┌─────────────────────────────────────────┐
                         │     DREAM CYCLE (02:00–04:00 UTC)       │
                         │                                         │
                         │  0. Brittleness scoring                │
                         │     per incident type:                  │
                         │     score = escalation_rate ×          │
                         │            (1 - mean_similarity)        │
                         │     → allocates replay budget below     │
                         │                                         │
                         │  1. CBR refresh (weighted)             │
                         │     embed new resolved happenings       │
                         │     prioritised by brittleness score    │
                         │     → incident_embeddings (FAISS)       │
                         │                                         │
                         │  2. Leading indicator mining            │
                         │     weighted by brittleness score       │
                         │     slope + Z-score per metric/ns       │
                         │     → leading_indicators table          │
                         │                                         │
                         │  3. XGBoost rule selector retrain      │
                         │     features: domain, ns, hour, freq   │
                         │     target: rule → success/fail         │
                         │     → model file on shared volume       │
                         │                                         │
                         │  4. Bandit noise injection             │
                         │     small weight perturbation to        │
                         │     prevent exploitation convergence    │
                         │                                         │
                         │  5. Gap analysis                       │
                         │     escalated happenings, no runbook   │
                         │     → LLM synthesis queue              │
                         │                                         │
                         │  6. LLM synthesis (if model available) │
                         │     reads gap list, writes runbook      │
                         │     drafts → CBR picks up next night   │
                         └──────────────┬──────────────────────────┘
                                        │ trained thresholds
                                        ▼
                         ┌─────────────────────────────────────────┐
                         │   PROACTIVE POLL (every POLL_INTERVAL)  │
                         │                                         │
                         │  query leading_indicators               │
                         │  vs current Prometheus metrics          │
                         │  if threshold exceeded:                 │
                         │    → pre-emptive Matrix alert           │
                         │    → create pre-emptive happening       │
                         └─────────────────────────────────────────┘
```

---

## Phases

### Phase A — Memory + Dream cycle (IMPLEMENTED, extensions pending)

**Status**: core deployed in `consolidation.py`. Two extensions needed (see below).

- `record_resolution()` fires after every happening closes → `panops.consolidation_rewards`
- Dream cycle scheduled 02:00–04:00 UTC:
  - CBR refresh: embeds newly resolved happenings into `incident_embeddings`
  - Leading indicator mining: slope + Z-score over pre-incident Prometheus data → `panops.leading_indicators`
  - Gap analysis: logs escalated happenings with no runbook
- Stabilization window: 3-minute wait before k8s-resolvable remediations (OOM, crashloop, probe timeout)

**LLM dependency**: none.

#### Extension A1 — Fix reward signal bias

**Problem**: `record_resolution()` only fires when a happening resolves. Escalated happenings never write a reward entry. XGBoost and the bandit therefore train only on success cases, developing a systematic blind spot for the failure mode — they will systematically underestimate how often certain incident types escalate.

**Fix**: also call `record_outcome()` when a happening escalates, with `outcome='escalated'` and `reward=0`. This gives the training set both success and failure signal for every incident type that has been observed.

**Implementation**: in `_run_validation_loop`, the escalation branch (`_ch_update status=escalated`) should call `consolidation.record_resolution(happening, rule_used, log_fn)` with the outcome field set appropriately. Rename `record_resolution` → `record_outcome` to reflect that it captures both paths.

#### Extension A2 — Weighted replay (brittleness scoring)

**Problem**: the dream cycle currently replays incidents uniformly — the 50 most recent resolved happenings get embedded regardless of whether they represent a new or a well-understood pattern. This wastes replay budget on easy cases and underserves brittle ones.

**Principle**: from neuroscience research on sleep consolidation, offline replay is steered toward the most brittle subnetworks, not distributed uniformly. Memory consolidation during sleep prioritises events that are novel, emotionally significant, or represent gaps in existing knowledge.

**Design**: compute a `brittleness_score` per incident type during the dream cycle:

```
brittleness_score = escalation_rate × (1 - mean_similarity)
```

- `escalation_rate`: fraction of happenings of this type that escalated rather than resolved
- `mean_similarity`: average CBR similarity score at classification time (low = classifier uncertain)

High brittleness = the system struggles to classify AND struggles to resolve. The dream cycle allocates replay budget, leading indicator mining time, and LLM synthesis slots proportionally to brittleness. An incident type with `brittleness_score = 0` (always resolves, always recognised) gets no dream-cycle attention. An incident type with `brittleness_score = 1.0` gets the full budget.

**New table**: `panops.brittleness_scores` (see data model).

---

### Phase B — Proactive alerting from leading indicators

**Trigger**: `leading_indicators` table has ≥ 10 samples for a given `(incident_type, namespace, metric)` triple.

**Mechanism**: poll loop queries current Prometheus metrics for each indicator. If the live slope or Z-score exceeds the trained threshold, PanOps fires a pre-emptive happening tagged `pre_emptive=true` with `status=monitoring`. No remediation runs yet — the assembler watches whether the predicted incident materialises within the lookahead window.

**Outcome tracking**: if the incident fires within the window, the indicator is confirmed; if not, false-positive is recorded and threshold is raised. This is the feedback loop that self-calibrates indicator sensitivity.

**LLM dependency**: none. Thresholds are statistical; calibration is outcome-driven.

**New table**: `panops.leading_indicator_outcomes (indicator_name, namespace, predicted_at, incident_fired bool, incident_hid String)`.

---

### Phase C — Contextual bandit rule selection

**What**: replace the static `REMEDIATION_RULES` dispatch dict with a bandit that learns which rule to apply given the context. The bandit observes features (namespace, domain, incident_type, hour_of_day, day_of_week, previous_rule_success_rate) and selects a rule. Reward = 1 if validation streak completes within 10 minutes, 0 if it escalates.

**Implementation**: Vowpal Wabbit (`pip install vowpalwabbit`) in the assembler image. VW runs a contextual bandit (`--cb_explore_adf`) with epsilon-greedy exploration. Model is serialised to a shared volume and updated online after each resolution.

**Fallback**: if VW is not available, static dispatch continues unchanged. The bandit is purely additive.

**Drift prevention via dream-cycle noise injection**: a continuously updated bandit without periodic resets will converge — it will exploit a small set of rules that worked recently and stop exploring alternatives, even as incident patterns evolve. This is the ML equivalent of what the Wang & Li paper describes as networks "running away into pathological activity" under continuous training.

During the dream cycle, after XGBoost retrains, the bandit receives a small scheduled perturbation: exploration epsilon is temporarily raised for incident types with high `brittleness_score`, and weights for underused rules are nudged upward. This is not random noise — it is directed toward the brittle subnetworks. After 24 hours of live operation, the perturbation is applied again. This keeps the bandit from over-converging while still respecting the reward signal from real outcomes.

**LLM dependency**: none.

**New table**: `panops.bandit_rewards (context_features JSON, rule_name String, reward Float32, recorded_at DateTime)`.

---

### Phase D — LLM tier integration

**Trigger conditions** (any one sufficient):

1. CBR classifier returns `similarity < 0.65` (no close historical match)
2. Gap analysis queue has entries the dream cycle couldn't resolve via template
3. Bandit has tried ≥ 3 rules for the same happening and all failed

**Model options** (in preference order for homelab CPU):

| Model | Size (Q4) | RAM | Latency (CPU) | Notes |
|---|---|---|---|---|
| Phi-3-mini | ~2.2 GB | ~3 GB | 5–15s | Best quality/CPU tradeoff |
| Phi-3.5-mini | ~2.4 GB | ~3.5 GB | 8–20s | Slightly better reasoning |
| Qwen2.5-3B | ~2.0 GB | ~3 GB | 5–12s | Strong at structured output |

Served via `llama.cpp` HTTP server as a sidecar or DaemonSet pod (one replica per node, shared via headless service). This avoids cold-start per inference — the model stays warm in RAM.

**LLM call contract**:

```
Input:
  happening: {domain, classifier_route, drain3_patterns, falco_rules,
              metric_anomalies, affected_services}
  similar_past: top-3 CBR matches with similarity scores and actions_taken
  available_rules: list of REMEDIATION_RULES keys
  runbook_snippets: top-3 BM25 matches from docs/runbooks/

Output (JSON):
  {
    "proposed_rule": "<rule_name or null>",
    "proposed_command": "<kubectl command if rule=null>",
    "confidence": 0.0–1.0,
    "reasoning": "<one sentence>",
    "new_runbook_entry": "<markdown or null>"
  }
```

**Feedback loop**: if `proposed_rule` resolves the happening (validation streak completes), the resolved happening is tagged `llm_assisted=true` and added to the CBR refresh queue. By the next dream cycle it is embedded and available as a CBR case — future similar incidents no longer reach the LLM.

**LLM for dream cycle synthesis**: during the dream cycle (off-peak, not on the live path), the LLM reads gap analysis entries and writes full runbook drafts. These are committed to `docs/runbooks/auto/` via a GitLab API call. BM25 index is rebuilt after commit so they're immediately queryable.

**Guardrails**:
- LLM output with `confidence < 0.5` → chatops escalation only, no auto-execution
- LLM never has cluster write access directly; it proposes, remediator executes
- All LLM-proposed actions are logged to `panops.remediation_outcomes` with `source=llm`

---

### Phase E — XGBoost rule selector (dream cycle retrain)

**What**: supervised model trained from `panops.remediation_outcomes`. Feature matrix per incident: `[domain_hash, ns_hash, incident_type_hash, hour_of_day, day_of_week, drain3_template_count, falco_rule_count, anomaly_count, previous_attempt_count]`. Target: did this rule succeed for this incident class?

**Retrain schedule**: nightly in dream cycle after CBR refresh (so new cases are already in the training set).

**How it integrates**: the bandit (Phase C) uses XGBoost scores as a prior when choosing rules, rather than starting from uniform. XGBoost provides the "what worked historically"; the bandit provides the "explore to discover better options."

**Implementation**: `scikit-learn` or `xgboost` package in the assembler image. Model serialised to `/models/rule_selector.pkl` on an emptyDir or PVC shared between dream cycle and live path.

**LLM dependency**: none.

---

## Data model

### New tables (all in `panops` database)

```sql
-- Phase A (implemented)
CREATE TABLE panops.consolidation_rewards (
    happening_id  String,
    rule_name     String,
    outcome       String,          -- 'resolved' | 'escalated' | 'failed'
    recorded_at   DateTime64(3, 'UTC'),
    dream_indexed UInt8 DEFAULT 0
) ENGINE = MergeTree() ORDER BY (recorded_at, happening_id);

CREATE TABLE panops.leading_indicators (
    indicator_name   String,
    namespace        String,
    metric_query     String,
    incident_type    String,
    slope_threshold  Float64,
    zscore_threshold Float64,
    sample_count     UInt32,
    trained_at       DateTime64(3, 'UTC')
) ENGINE = ReplacingMergeTree(trained_at)
  ORDER BY (indicator_name, namespace, incident_type);

-- Phase A extension (brittleness scoring)
CREATE TABLE panops.brittleness_scores (
    incident_type      String,
    namespace          String,
    escalation_rate    Float32,   -- fraction of happenings that escalated
    mean_similarity    Float32,   -- avg CBR similarity at classification time
    brittleness_score  Float32,   -- escalation_rate × (1 - mean_similarity)
    sample_count       UInt32,
    computed_at        DateTime64(3, 'UTC')
) ENGINE = ReplacingMergeTree(computed_at)
  ORDER BY (incident_type, namespace);

-- Phase B
CREATE TABLE panops.leading_indicator_outcomes (
    indicator_name  String,
    namespace       String,
    predicted_at    DateTime64(3, 'UTC'),
    incident_fired  UInt8,         -- 0/1
    incident_hid    String
) ENGINE = MergeTree() ORDER BY (predicted_at, indicator_name);

-- Phase C
CREATE TABLE panops.bandit_rewards (
    context_features String,       -- JSON blob
    rule_name        String,
    reward           Float32,
    recorded_at      DateTime64(3, 'UTC')
) ENGINE = MergeTree() ORDER BY (recorded_at, rule_name);
```

### Existing tables consumed

| Table | Used by |
|---|---|
| `panops.happenings` | all phases |
| `panops.remediation_outcomes` | Phase C/E training |
| `panops.incident_embeddings` | CBR classifier, Phase A refresh |

---

## Non-goals

- The LLM does not have direct cluster access. It proposes; the remediator executes with the same guardrails as every other rule.
- The dream cycle does not retrain itself on synthetic data. All training is from real incident outcomes only.
- No external ML APIs (OpenAI, etc.) — everything runs in-cluster. Remote API is a fallback for the LLM tier if the local model is unavailable, not the primary path.
- The bandit does not explore rules with `risk_tier=high` without a confidence threshold. Exploration is bounded to safe rules.

---

## Implementation order

```
Phase A  (done)     → SOC shakedown
Phase B             → proactive alerting poll, threshold calibration
Phase C             → VW bandit, requires ~20 resolved incidents to train
Phase D             → LLM sidecar, llama.cpp DaemonSet, inference contract
Phase E             → XGBoost, feeds Phase C prior
```

Phase B can run in parallel with the SOC shakedown since it only reads data. Phases C–E gate on having enough real incident history in ClickHouse to train meaningfully — roughly 2–4 weeks of live traffic is the practical minimum.
