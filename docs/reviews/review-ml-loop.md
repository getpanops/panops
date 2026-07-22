# PanOps Self-Improvement Loop — Adversarial Review

Reviewed: `~/Git/panops/docker/assembler/src/{consolidation.py,classifier.py,drain3_detector.py,remediator.py,assembler.py}` + live ClickHouse (`observability-clickhouse-clickhouse-0-0-0`), data window 2026-07-03→2026-07-08 (~5 days, 920 happenings).

## Live data snapshot (ground truth)

| table | rows | notes |
|---|---|---|
| panops.happenings | 920 | 887 resolved, 0 currently escalated, 27 open, 6 dismissed(test) |
| panops.incident_embeddings | 977 | 0 empty vectors — embedding generation technically works |
| panops.consolidation_rewards | 656 | 651 `resolved`, 5 `escalated`; `dream_indexed` = 0 for **100%** of rows |
| panops.dream_state | 7 | 2 real REM runs, both `last_synthesised_count=0` |
| panops.postmortem_runbooks | **0** | feature never used in production |
| panops.leading_indicators | **1** | mining almost never produces output |
| panops.remediation_outcomes | 348 | |
| classifier_route distribution | 895/920 (97%) = `known` | `novel`=4, `structured`=15, `test`=6 |
| similarity_score histogram | 866/900 scored happenings = **1.00**; only 34 below 0.9 | see Finding 1 |

---

## Finding 1 — CRITICAL: Embedding text is too coarse to produce real semantic similarity

**What**: `classifier.py:41-55` (`_happening_description`) builds the embedded text from only `domain`, `affected_services` (namespace), a comma-joined `falco_rules` list (almost always `"none"`), `sigma_rule_ids` (almost always `"none"`), and a bare *count* of metric anomalies. It deliberately excludes `drain3_patterns` (the actual log/alert template text), `alertname`, and any error message content — the fields that would actually distinguish one incident from another.

Live evidence: 866 of ~900 scored happenings have `similarity_score = 1.0` (rounded histogram: 0.7→2, 0.8→3, 0.9→29, 1.0→866). Sampling matched chains (e.g. `9d3748bc-…` → domain `SRE`, `affected_services=['panops']`, `drain3_patterns=[{"template":"Pod CrashLoopBackOff"}]`) shows the CBR match chain is really matching on the coarse tuple *(domain, namespace, "none", "none", anomaly-count)* — not on what actually happened. Two unrelated CrashLoopBackOff root causes in the same namespace are embedded identically.

**Why it undermines learning**: The CBR "similarity" signal is not doing semantic work — it degenerates into a lookup key on `(domain, namespace)`. This means:
- Replaying `matched_actions` from the "most similar" past incident is really just "replay whatever we last did in this namespace," which is a much weaker prior than the system claims.
- Genuinely novel incidents in a well-trodden namespace will be misclassified as `known` (route_override) and get the wrong runbook replayed, since the embedding can't tell them apart.
- The 384-dim MiniLM model is wasted — you're paying embedding cost for a signal a hash-based lookup would give you for free.

**Fix**: Embed `drain3_patterns[*].template`, `falco_rules`, `sigma_rule_ids`, and the alert `summary`/`description` text verbatim (truncated), not just their presence/count. Concretely, extend `_happening_description` to include the actual template strings:
```python
templates = "; ".join(p.get("template","") for p in json.loads(row.get("drain3_patterns") or "[]"))
return f"{domain} incident in {ns}. Trigger: {templates or 'unknown'}. Falco: {falco}. Sigma: {sigma}. Anomalies: {n_anom}."
```
Then re-embed the existing 977 rows (one-off backfill) and watch the similarity histogram spread out. Add a unit test asserting similarity between two happenings with different `drain3_patterns` templates is measurably < 0.99.

---

## Finding 2 — CRITICAL: Reward signal is write-only; nothing reads `consolidation_rewards` back into a decision

**What**: `consolidation.py:175-200` (`record_resolution`) and `:203-253` (`_record_negative_rewards`) INSERT into `panops.consolidation_rewards`. The `dream_indexed UInt8 DEFAULT 0` column exists specifically to mark rows as "consumed by the dream cycle" (`consolidation.py:161`, also in schema at `deploy/kustomize/components/panops/assembler/assembler-cm.yaml:1534`) — live data shows **0 of 656 rows have `dream_indexed=1`**. A repo-wide grep for `consolidation_rewards` (outside its own definition/insert/dedup-check in `consolidation.py`) returns nothing — no SELECT anywhere aggregates `outcome` by `rule_name` to compute a per-rule success rate, and no code path reads `dream_indexed`.

**Why it undermines learning**: This is the textbook "reward computed and never read" failure mode named in the task brief. `_compute_brittleness` (Finding 4) uses `panops.happenings.status`, not `consolidation_rewards`, to score escalation rate — so the reward table isn't even the input to the one statistical process that exists. Nothing ranks `REMEDIATION_RULES` by historical success, nothing demotes a rule with a bad track record, nothing weights CBR replay by whether the matched action actually worked long-term. The reward table is pure audit log today.

**Fix**: Two changes close the loop:
1. Compute a per-`rule_name` success rate from `consolidation_rewards` (`outcome IN ('resolved') / count()`) inside `_compute_brittleness` or a new `_compute_rule_confidence()`, and set `dream_indexed=1` via `ALTER TABLE ... UPDATE` after each NREM pass consumes a batch (the column already exists for exactly this).
2. In `remediator.py:remediate_and_validate`, when multiple `REMEDIATION_RULES` candidates could apply (there's already a priority chain of `if/elif` at lines ~825-855), break ties or override the static priority using this per-rule confidence score instead of hardcoded elif ordering. This is the single highest-leverage change to make the loop actually adaptive.

---

## Finding 3 — HIGH: Success signal can be gamed by "resolves-then-recurs" masking; no root-cause confirmation

**What**: `_signals_clear` (`remediator.py:606-654`) declares a happening resolved when, over a `CLEAR_STREAK_REQUIRED`-poll window: no new `security_anomalies`, no new `sigma_matches` in the namespace, and all pods are `Running/Succeeded/Completed`. It does **not** check whether the original triggering symptom (the specific alert, the specific metric anomaly, the specific drain3 template) has actually stopped recurring over a longer horizon — only that the namespace looks quiet right now.

Live evidence: `classifier_route='known'` accounts for 895/920 happenings (97%), spread across many namespaces (`panops`=63, `ns-a`=55, `ns-b`=34, `ns-c`=32, `ns-d`=32, `ns-e`=31, `default`=31, `security`=27, `ns-f`=19) — i.e. the same handful of namespaces are repeatedly generating "CrashLoopBackOff"-type happenings that get `known`-routed, replayed, and marked `resolved`, over and over, across a 5-day window, with `happenings_escalated=0`. This is consistent with either (a) a genuinely effective remediation loop, or (b) the same underlying misconfiguration recurring and being superficially quieted each time (pod restart → briefly Running → CLEAR_STREAK_REQUIRED met → "resolved") without the root cause being fixed. The system currently cannot distinguish these two cases because `record_resolution` and brittleness scoring only see "resolved" vs "escalated," never "resolved N times for the same underlying cause within window W."

**Why it undermines learning**: A remediation that masks the same defect repeatedly generates a stream of positive rewards and drives brittleness for that incident type to 0 — which is exactly the wrong signal; it should trend the type toward "chronically recurring, root cause never fixed" and trigger REM synthesis, but the escalation-rate metric can't see recurrence, only the escalate/resolve outcome of each individual happening.

**Fix**: Add a recurrence check to `_compute_brittleness` (or a parallel `_compute_recurrence`): group resolved happenings by `(classifier_route, affected_services)` and flag a type as brittle if the same rule/route fires ≥N times within a rolling window (e.g. 3 times in 24h for the same namespace+drain3 template) even if each individual instance "resolved." Feed this into the REM gate (`_should_run_rem`) as an OR condition alongside `max_score >= 0.3`, so chronically-masked issues get escalated to LLM synthesis (and a GitLab MR proposing a durable fix) even though the escalation-rate metric alone stays flat.

---

## Finding 4 — HIGH: Brittleness scoring is currently structurally starved (0 escalations recorded in the live window)

**What**: `_compute_brittleness` (`consolidation.py:104-137`) computes `score = escalated_count / total_count` per `classifier_route`, over a 30-day window, requiring ≥3 happenings/type. Live: `happenings_escalated = 0` for the entire dataset (887 resolved / 920 total, 27 still open, 6 dismissed test rows). This exactly matches the manually-run output cited in the task ("brittleness top-3: [(known,0.0),(test,0.0),(novel,0.0)]").

**Why it undermines learning**: With escalation rate permanently at (or near) 0, `_should_run_rem`'s primary trigger (`max_score >= 0.3`) can essentially never fire — REM only ever runs on the 7-day fallback timer (confirmed: `dream_state` shows exactly 2 REM runs, both `last_synthesised_count=0`, i.e. they ran on the timer and found nothing to synthesize). NREM's headline statistic is not "nothing to learn yet," it's "the only input signal it watches (escalation) never occurs in this environment," which combined with Finding 3 (masking) means brittleness is measuring the wrong thing for a system whose remediations mostly "succeed" by the shallow definition in `_signals_clear`.

**Fix**: This is the same root cause as Finding 3 — pair the fix there with lowering brittleness's total-count floor consideration, or blend `escalation_rate` with `recurrence_rate` and `mean_time_between_recurrence` as a composite brittleness score. Also consider tracking `mean(validation_streak resets)` per type — a happening that flaps in and out of "clear" repeatedly during its own validation loop before finally settling is a weaker resolution than one that clears on the first streak, and that signal is already computed (`clear_streak` resets in `_run_validation_loop`) but discarded, never written anywhere.

---

## Finding 5 — MEDIUM: Postmortem-driven learning is a real, well-designed mechanism but is currently dead code in practice

**What**: `remediator.py:520-605` (`_fetch_postmortem_runbook`, `_rule_postmortem_learned`) correctly prefers a learned postmortem runbook over the static rule chain when a matching `drain3_template`+`domain` entry exists (`remediator.py:~855-860` in `remediate_and_validate`), with a sane fallback to the original rule if the postmortem produces no actions. This is good design. Live: `panops.postmortem_runbooks = 0` rows — no human has ever completed the postmortem-paste workflow, so the entire mechanism, while correctly wired, has contributed zero remediation decisions to date.

**Why it undermines learning**: Not a code defect — a data/adoption gap. But it means one of the five "self-improvement" mechanisms named in the task brief is currently 100% theoretical in this deployment.

**Fix**: Lower the friction to seed it: add a `/postmortem/suggest` endpoint that, after any `escalated` happening, auto-drafts a postmortem template pre-filled with the drain3 pattern, affected namespace, and timeline, and pings the on-call human via the existing Matrix notification path (`_notify` in `assembler.py`) asking them to fill in the resolution — rather than requiring the human to remember the workflow exists.

---

## Finding 6 — MEDIUM: `leading_indicators` is written but has no consumer anywhere in the codebase

**What**: `_mine_leading_indicators` (`consolidation.py:321-419`) fits slope/z-score thresholds per `(metric, namespace, incident_type)` and writes them to `panops.leading_indicators`. `grep -rn leading_indicators` across the whole repo shows it appears only in its own definition/writer in `consolidation.py`, plus doc/spec files and the ConfigMap that carries the same source — **no code path ever reads `panops.leading_indicators` to pre-emptively fire an alert or gate a remediation**. Live: 1 row total after 5+ days, because the write path requires ≥3 timestamped incidents per (type, namespace) group with `abs(mean_slope) >= 1e-9 or mean_z >= 1.5` — a reasonable statistical bar, but moot if nothing consumes the output.

**Why it undermines learning**: This is the predictive/precursor half of the design (mining leading indicators before incidents happen) and it's entirely inert — computed, stored, never actioned. This overlaps with the "PanOps predictive precursor signals" item already in project memory as a future goal; this review confirms the groundwork (the table and the miner) already exists but is orphaned.

**Fix**: Add a scheduled job (or extend the existing Prometheus rule generator, if one exists) that reads `panops.leading_indicators` and materializes a Prometheus recording/alerting rule per row (`{metric_query} > {slope_threshold}` style pre-alert), or at minimum surfaces "predicted incident risk" in the `/decisions` endpoint so a human sees it. Without a consumer this table should arguably not be written at all — better to disable `_mine_leading_indicators` until Finding 2's rule-confidence work lands, to avoid presenting a "predictive ML" capability that does nothing.

---

## Finding 7 — LOW: Statistical thresholds are simple but defensible, not "magic numbers" — brittleness formula is sound in isolation

**What**: `_compute_brittleness` uses a plain escalation-rate ratio with a minimum-sample floor of 3 — standard, interpretable, no false precision. `_mine_leading_indicators`'s `PEARSON_THRESHOLD`/z-score cutoffs and the `SIMILARITY_THRESHOLD = 0.85` in `classifier.py` are reasonable, commented, single-purpose constants, not deeply tuned magic numbers. The REM gate (`max_score >= 0.3 OR 7 days elapsed`) is a sensible, auditable circuit breaker against LLM-call cost, not an arbitrary trigger.

**Why it (doesn't) undermine learning**: Flagging only because the task asked to adversarially probe statistical soundness — there is nothing broken here per se. The Z-score/slope approach is legitimate for small-N leading-indicator mining; ADTK (already queued in project memory as a Phase 6 candidate) would improve seasonality-awareness once there's enough data volume (see Finding 8) to make seasonality relevant, but is not a soundness bug today.

**Fix (uplift, not bug fix)**: Adopt ADTK once `panops.happenings` accumulates >30 days of history for the metrics feeding `_mine_leading_indicators`, per the already-queued follow-up. No action needed before then.

---

## Finding 8 — LOW: Data volume is thin — 5 days, 920 happenings, 97% single route

**What**: `min(opened_at)`/`max(opened_at)` = 2026-07-03 → 2026-07-08 (~5 days). `classifier_route='known'` = 97% of traffic. Only 4 `novel` and 15 `structured` happenings in the whole window.

**Why it undermines learning**: The 30-day brittleness window and 14-day CBR refresh window (`_refresh_cbr_cases`, `opened_at > now() - INTERVAL 14 DAY`) are currently seeing less than half their intended lookback. `novel`/`structured` sample sizes (4, 15) are below or barely at the brittleness floor (needs ≥3, technically passes but is statistically fragile — a single flaky day could flip the ratio). This isn't a code bug, it's an evaluation-readiness gap: it's too early to judge whether the loop "works" from outcome data alone, and the review above had to lean on code-path tracing (Findings 1, 2, 6) rather than outcome trends because outcome trends don't exist yet at this volume.

**Fix**: Not urgent — flagging so a re-review at 30+ days doesn't mistake "not enough data yet" for "loop still cosmetic." Track `count(DISTINCT classifier_route, affected_services)` growth over time as a leading indicator of whether the corpus is diversifying past the 8-namespace CrashLoopBackOff pattern currently dominating it.

---

## What's genuinely well-designed (not just criticism)

- **CBR retrieval is actually consulted at decision time**, not just logged: `assembler.py:847-876` calls `classifier.embed_and_match`, applies `route_override`, and — critically — `assembler.py:874-889` fetches the matched incident's `actions_taken` and threads it into `remediator.remediate_and_validate(row, matched_acts, log)`, which replays those exact rules by name (`remediator.py:800-812`). This is a real closed loop for the classification→remediation path; it just needs Finding 1's fix to make the "similar" judgment mean something.
- **REM synthesis produces a real, reviewable artifact**: `_open_gitlab_mr` (`consolidation.py:~591-666`) turns LLM rule proposals into an actual GitLab branch + commit + MR (capped at top-5 proposals per cycle), landing in `rules/{sigma,falco,remediator}/`. This is human-in-the-loop by construction — the LLM never merges its own rules — and is a legitimately good architecture for AI-suggested rule changes.
- **Validation is not instantaneous**: `_run_validation_loop` requires `CLEAR_STREAK_REQUIRED` consecutive clean polls before declaring `resolved`, not a single check — this is a real (if incomplete, see Finding 3) defense against reward hacking via flapping.
- **Postmortem replay has a safe fallback**: if a learned runbook returns no actions, it falls back to the static rule (`remediator.py:~893-899`) rather than silently doing nothing.
- **`known`-route replay only executes named functions from a fixed `REMEDIATION_RULES` dict** (`remediator.py:800-812`) — CBR/postmortem-learned content can never inject arbitrary shell/kubectl commands, only select among a whitelisted, human-authored rule set. Good security boundary given the LLM/embedding path is in the loop.

---

## Capability Uplift — top changes to make the loop genuinely effective

1. **Fix the embedding text** (Finding 1) — include actual drain3 template / alert content in `_happening_description`, re-embed the 977 existing rows. This is the single change most likely to make CBR similarity mean something; everything downstream (route_override, matched-action replay) inherits its quality from this.
2. **Close the reward loop** (Finding 2) — compute per-rule success rate from `consolidation_rewards`, mark `dream_indexed=1` on consumption, and use the confidence score to break ties / override the static `if/elif` rule-selection chain in `remediate_and_validate`. Ship an offline eval harness that replays `panops.happenings` history against candidate rule orderings before any change to that chain goes live, so rule-confidence changes are backtested, not YOLO'd into production remediation.
3. **Add recurrence-aware brittleness** (Findings 3 & 4) — group by `(classifier_route, affected_services)` and flag chronic re-triggering even when each instance "resolves," so masking doesn't hide as a healthy metric. This is the fix that would make the REM gate actually fire on real problems instead of only on the 7-day timer.
4. **Give `leading_indicators` a consumer, or stop writing it** (Finding 6) — either materialize the mined thresholds into Prometheus pre-alert rules / surface them in `/decisions`, or disable the miner. Half-built predictive telemetry that nothing reads is worse than not having it, because it looks like a capability that isn't there.
5. **Lower the activation energy on postmortem learning** (Finding 5) — auto-draft a postmortem template on every `escalated` happening and push it to the human via the existing Matrix channel, instead of requiring the human to remember the workflow exists. At 0 rows today, this is the fastest path to a second real data source for `remediate_and_validate`'s decision logic besides CBR.

Also worth adding regardless of priority: expose `validation_streak` reset counts (already computed, currently discarded in `_run_validation_loop`) as a "resolution confidence" field on each happening — it's a free, already-computed signal that directly measures how convincingly a remediation actually worked, and would strengthen both Finding 2's rule-confidence score and Finding 3's masking detector.
