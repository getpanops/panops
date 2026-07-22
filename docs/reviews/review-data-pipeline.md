# PanOps Data Pipeline — Adversarial Review

Reviewed: `~/Git/panops/docker/assembler/src/{assembler,correlator,drain3_detector,classifier,consolidation,remediator}.py`,
`~/Git/panops/clickhouse/schema/create-schema.py`, `~/Git/homelab/k8s/panops/manifests/clickhouse-schema/schema-sql-cm.yaml`,
plus live cluster (`panops` and `observability` namespaces, ClickHouse `panops`/`qryn` databases).

Live cluster time at review: **2026-07-09 22:06 UTC** (ClickHouse `timezone()` = UTC, consistent with app's `datetime.now(timezone.utc)` usage — no TZ mismatch found).

---

## Finding 1 — CRITICAL: entire upstream detection pipeline has been silent for 5+ days; `panops.happenings` has produced nothing new for 25h, while the pipeline looks "alive"

**What (live evidence):**
```
qryn.sigma_matches:      35,630 rows, but max(timestamp) = 2026-07-05 04:38:31 (5 days stale)
qryn.security_anomalies: 0 rows EVER (min/max = 1970-01-01)
qryn.patterns:           0 rows EVER (min/max = 1970-01-01)
panops.happenings:         max(opened_at) = 2026-07-08 21:17:12 (25h stale)
panops.component_heartbeats: max(recorded_at) = 2026-07-09 22:03:39 (fresh, 3 min ago)
```
`drain3-miner` CronJob (`kubectl logs drain3-miner-29727240-8vxpv`):
```
Mining bucket 2972723 (21:50 UTC)
No namespaces found in Loki for this window
```
Job exits 0 (`Completed`) every 10 minutes, forever, having written zero rows to `qryn.patterns` — a **silently-successful no-op**. Combined with `security_anomalies` having zero rows since table creation, and `sigma_matches` dead for 5 days, the picture is: assembler's `_poll_sigma()`/`_poll_anomalies()` (`assembler.py:1671-1709`) have nothing to find, so `assemble()` never fires, so nothing gets written — this is **not a quiet cluster**, it's three independent upstream feeders (Sigma correlation → `qryn.sigma_matches`, anomaly detector → `qryn.security_anomalies`, `drain3-miner` → `qryn.patterns`) that are broken or misconfigured (Loki/gigapipe label mismatch for drain3-miner; sigma/anomaly writers not investigated further, out of assembler's code but upstream of it).

**Failure scenario:** A real Falco/Sigma-worthy security event or SRE anomaly occurs right now. Nothing gets assembled, no Matrix/webhook notification fires, no remediation runs. The only thing that looks healthy is `component_heartbeats`, which merely proves the assembler process is alive — it says nothing about whether it is actually assembling anything. Anyone checking "is PanOps up?" via heartbeats alone would get a false green light for 5+ days.

**Constructive fix:**
1. Split the heartbeat into a **liveness** signal (process alive — already have this) and an **ingest activity** signal: extend `_write_heartbeat()` (`assembler.py:1715-1732`) to include `last_sigma_row_age_s`, `last_anomaly_row_age_s`, `last_pattern_row_age_s`, `happenings_last_24h` computed from a lightweight `SELECT max(...)` against each upstream table.
2. Add a Grafana/Alertmanager alert (a real dead-man's-switch, see Capability Uplift #2) that fires when `component_heartbeats` is fresh but `qryn.sigma_matches`/`qryn.security_anomalies`/`qryn.patterns` haven't advanced in > 2× their expected cadence — this is exactly the "alive but not ingesting" state currently invisible.
3. Fix `drain3-miner`'s Loki namespace-discovery query (whatever selector produces "No namespaces found" — likely a stream-label mismatch, same class of bug as the `k8s_ns_name` comment in `drain3_detector.py:139-141` referencing an otelcol-promoted label that may not exist for all pipelines).

---

## Finding 2 — HIGH: `correlator.py` writes to `panops.metric_correlations` are guaranteed to throw (`NameError: name 'os' is not defined`) — confirmed live (table has 0 rows, ever)

**What:** `correlator.py` imports only `json, time, urllib.request, urllib.parse, datetime` (lines 9-13) — **no `import os`**. `_write_correlations()` (`correlator.py:139-172`) references `os.environ.get("CH_USER", "default")` and `os.environ.get("CH_PASSWORD", "")` at lines 163-164, **outside** the `try:` block that starts at line 165. Every time `correlate_metrics()` finds ≥1 correlated pair (`correlator.py:133-134`) it calls `_write_correlations()`, which raises `NameError` before the request is even sent.

**Live evidence:** `panops.metric_correlations` — `count() = 0`, `max(last_seen_at) = 1970-01-01` — i.e. it has *never* successfully written a row, consistent with a 100%-reproducible bug rather than "no correlations found."

**Failure scenario:** The exception is swallowed by the caller's blanket `except Exception as _e: log("WARN", f"correlator error: {_e}")` in `assembler.py:833-834` (inside the background `_run_correlator` thread), so it produces a one-line WARN log buried among thousands of other lines and never surfaces. The entire "Step 3: metric correlator" feature — cross-metric relationship discovery meant to feed CBR/consolidation — has been non-functional since the code was written, invisibly.

**Constructive fix:** `import os` in `correlator.py`. Additionally, harden the pattern generally: move the header-building block inside the `try`, and add a unit test / CI smoke test that imports each of `correlator.py`, `classifier.py`, `drain3_detector.py` and calls their top-level functions with a mock ClickHouse to catch `NameError`/`ImportError` before deploy — this exact class of bug (module-level symbol used but not imported) is trivially caught by `pyflakes`/`ruff --select F821` in CI, which apparently isn't running on this file.

---

## Finding 3 — HIGH: watchdog can force a self-inflicted crashloop when upstream deps (Loki/ClickHouse) are slow, because `assemble()` runs synchronously inside the poll loop for every matched namespace

**What:** `poll_loop()` (`assembler.py:1834-1856`) calls `_poll_sigma()` synchronously every `POLL_INTERVAL` (default 60s). `_poll_sigma()` (`assembler.py:1671-1689`) iterates every distinct namespace with new sigma matches and calls `assemble(...)` **synchronously, in the poll-loop thread**, once per namespace (`assembler.py:1685`). `assemble()` performs multiple sequential blocking HTTP calls per invocation: `gather_sigma` (CH, 30s timeout), `gather_anomalies` (CH, 30s), `enrich_drain3`/`gather_drain3` (multiple CH queries + a Loki call with 10-15s timeout each), two `_find_open_happening` dedup queries (CH, 30s each), the insert (CH, 30s), and — synchronously, not backgrounded — `classifier.embed_and_match` (CH insert + kNN query, ~50ms claimed but includes a CH round trip). Only the correlator, remediator, LLM job, and notifications are backgrounded (`threading.Thread(..., daemon=True)`).

The watchdog (`assembler.py:1734-1741`) exits the process (`os._exit(1)`) if `_last_poll_time` goes stale by `POLL_INTERVAL * 3` = **180s**. `_last_poll_time` is only updated once per poll-loop iteration (`assembler.py:1840`), *before* `_poll_sigma()`/`_poll_anomalies()` run — so if those calls collectively take longer than 180s (e.g. Loki/gigapipe degraded and every `loki_query_range`/`_falco_nearby` call eats its full 10-15s timeout, multiplied across N namespaces with matches in one tick), the next loop iteration never starts in time and the watchdog kills the pod.

**Failure scenario (matches the known "gigapipe probe death spiral" / "probe-timeout routes as crashloop" incidents in project memory):** Gigapipe/Loki degrades (slow, not fully down). Each `gather_drain3`/`_falco_nearby` call now takes its full 10-15s timeout instead of failing fast. If sigma matches span even 10-15 distinct namespaces in one poll tick, cumulative latency exceeds 180-225s → watchdog fires → assembler restarts → in-flight remediation/validation threads are killed mid-flight (daemon threads die with the process) → any happening stuck in `remediating`/`validating` relies on `_resume_open_validations()` at next startup, which only resumes if `opened_at > now() - 2h` and does not re-run remediation actions that were interrupted before they executed. The system's own timeout/retry machinery amplifies a slow dependency into a hard outage.

**Constructive fix:**
1. Run each `assemble()` call spawned from `_poll_sigma()`/`_poll_anomalies()` in a bounded worker pool (reuse the existing `_CORRELATOR_SEM`-style pattern: a `threading.Semaphore(N)` gate) instead of sequentially in the poll-loop thread, so one slow namespace can't starve the watchdog heartbeat.
2. Update `_last_poll_time[0]` immediately after `time.sleep(POLL_INTERVAL)` (already done at line 1840) **and again** after each sub-poll returns, or better: have the watchdog check a heartbeat that `_poll_sigma`/`_poll_anomalies` touch per-namespace-processed, not just once per full cycle — so a legitimately-in-progress-but-slow poll doesn't look "stalled."
3. Tighten `loki_query_range`/`_prom_range`/CH timeouts and add a circuit breaker per external dependency (mirror the existing LLM circuit breaker pattern at `assembler.py:126-131`) so a degraded Loki gets skipped after N consecutive timeouts instead of eating its full timeout budget on every single call.

---

## Finding 4 — HIGH: schema drift — three live tables are not defined in the canonical `create-schema.py`, and columns are added ad hoc at runtime with no migration tracking

**What:** Live `panops` database tables (`SHOW TABLES`): `agent_memory, component_heartbeats, consolidation_rewards, dream_state, happenings, incident_embeddings, investigation_traces, leading_indicators, metric_correlations, postmortem_runbooks, remediation_outcomes`.

`~/Git/panops/clickhouse/schema/create-schema.py` (the repo's stated source of truth) creates: `happenings, incident_embeddings, metric_correlations, remediation_outcomes, qryn.pattern_embeddings, qryn.sigma_embeddings, dream_state, investigation_traces, agent_memory, postmortem_runbooks` — **missing `component_heartbeats`, `consolidation_rewards`, `leading_indicators`** entirely.

- `component_heartbeats` **is** defined in `~/Git/homelab/k8s/panops/manifests/clickhouse-schema/schema-sql-cm.yaml` (line ~123) but **not** in the panops repo's `create-schema.py` — the two repos' schema files have drifted from each other (violates the documented "panops = source of truth, homelab = deployment, both must stay in sync" workflow).
- `consolidation_rewards` and `leading_indicators` exist in neither schema file — they are created **lazily at runtime** by `consolidation.py:_ensure_schema()` (lines 141-172), called from `record_resolution()` and `run_dream_cycle()`. If `_ensure_schema()` never runs (e.g. no happening has ever resolved, or the dream cycle hasn't fired yet on a fresh cluster), these tables silently don't exist and any read against them fails.
- `panops.happenings.validation_streak` (`Int32 DEFAULT 0`) is added by `assembler.py:_ensure_validation_streak_column()` (lines 1779-1795) at every startup via `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` — this column is **not** present in `create-schema.py` at all, only in this one-off runtime migration.
- `panops.happenings.pending_synthesis` (`UInt8 DEFAULT 0`) *is* tracked as a migration statement inside `create-schema.py` (line 173) but is a bolt-on `ALTER` rather than being folded into the base `CREATE TABLE`, so anyone reading the `CREATE TABLE panops.happenings` block alone would miss two real columns (`validation_streak`, `pending_synthesis`) that the code (`_run_validation_loop`, `run_rem_phase`) depends on.

**Failure scenario:** A fresh environment (disaster recovery, new cluster, the sanitized `homelab-demo` portfolio copy in project memory) runs `create-schema.py` and gets a "successfully initialized" pipeline that is missing 3 tables and 1 column. `consolidation.py`'s dream cycle silently no-ops (`_ensure_schema()` covers it), but anything that assumes `component_heartbeats` exists before the assembler's own startup path creates it (e.g. an external monitoring query) breaks with "table doesn't exist," and diagnosing this requires reading three different files instead of one.

**Constructive fix (see also Capability Uplift #1):**
1. Consolidate every `CREATE TABLE`/`ALTER TABLE ADD COLUMN` currently scattered across `create-schema.py`, `assembler.py:_ensure_validation_streak_column`, and `consolidation.py:_ensure_schema` into `create-schema.py` as the single source, each statement idempotent (`IF NOT EXISTS`) as they already are.
2. Delete `_ensure_validation_streak_column()` and `_ensure_schema()`'s `CREATE TABLE` calls from the hot-path Python modules — keep only reads/writes there, not DDL. DDL belongs in one place run once at deploy time (the existing `panops-schema-init-v2` Job in `k8s/panops` is exactly the right hook — extend it, don't duplicate logic in-process).
3. Add a CI check that diffs `~/Git/panops/clickhouse/schema/create-schema.py` against `~/Git/homelab/k8s/panops/manifests/clickhouse-schema/schema-sql-cm.yaml` and fails the build if they've drifted (they are supposed to be the same content per the deployment workflow, and currently are not).

---

## Finding 5 — MEDIUM/HIGH: SQL injection surface on the (optionally unauthenticated) postmortem HTTP endpoints via inconsistent, hand-rolled string escaping

**What:** `assembler.py` builds every ClickHouse statement via raw f-string interpolation (no parameterized queries — the CH HTTP `/` endpoint used by `ch_query`/`ch_exec` doesn't support bind parameters in this client). Two different escaping conventions are used inconsistently:
- Doubling: `f"'{s.replace(chr(39), chr(39)*2)}'"` in `_merge_happening`/`_find_open_happening` (`assembler.py:460, 483`).
- Backslash-escaping: `.replace("'", "\\'")` in `_postmortem_detail`, `_postmortem_parse`, `_postmortem_save` (`assembler.py:1489, 1524, 1590-1596`).

ClickHouse string literals use C-style backslash escaping. A payload containing a literal backslash immediately before a quote (e.g. `created_by = "\\' ; ATTACH TABLE ..." `) survives a naive `.replace("'", "\\'")` as `\\\'` — three characters where the first two (`\\`) resolve to a single literal backslash and the following `'` then **closes the string literal early**, letting the remainder of the attacker-controlled string execute as SQL. This applies to `_postmortem_save` (`assembler.py:1573-1616`), which accepts `created_by`, `notes`, `raw_paste`, `domain`, `runtime`, `commands` from an **HTTP POST body** and inserts them almost directly into `INSERT INTO panops.postmortem_runbooks ... VALUES (...)`.

Compounding factor: `_check_postmortem_auth()` (`assembler.py:152-174`) returns `True` (auth disabled) whenever `POSTMORTEM_PASSWORD` is unset — i.e. **auth is opt-in, not opt-out**. If the Helm/Kustomize deployment doesn't set `POSTMORTEM_PASSWORD`, every postmortem endpoint (`GET /postmortem`, `POST /postmortem/{id}/parse`, `POST /postmortem/{id}/save`) is open to anything with network access to the pod, and `ch_exec`/`ch_query` run as `CH_USER` (defaults to `default`, ClickHouse's admin account) with no query restrictions — a successful injection can `DROP TABLE`, exfiltrate other databases, etc.

**Failure scenario:** Anyone with cluster network access (a compromised low-privilege pod, a misconfigured NetworkPolicy) POSTs a crafted `created_by` field to `/postmortem/{id}/save` and gets arbitrary SQL execution against the `default` ClickHouse user — a lateral-movement/data-integrity risk in a system whose entire job is being the incident-response source of truth.

**Constructive fix:**
1. Verify whether the CH HTTP interface supports parameterized queries via `param_<name>` placeholders (it does, since ClickHouse 21.11: `SELECT {name:String}` + `param_name=value` as a query-string/header param) and switch `ch_query`/`ch_exec`/`ch_insert_happening` to use them instead of string interpolation — this closes the injection class entirely rather than patching individual escape calls.
2. Until that lands, centralize escaping into one `_ch_escape(s: str) -> str` helper used everywhere (correct backslash-then-quote order: escape `\` first, then `'`), and delete the doubling-based escaping so there's only one code path to audit.
3. Make `POSTMORTEM_PASSWORD` mandatory at startup (fail fast, same pattern as the existing fatal ClickHouse/Kubernetes startup checks in `_startup_health_check`) rather than silently defaulting to open.

---

## Finding 6 — MEDIUM: unbounded background-thread creation on hot paths (no backpressure)

**What:** Several `threading.Thread(..., daemon=True).start()` call sites in `assembler.py` have no concurrency limit, unlike the metric correlator which is explicitly gated by `_CORRELATOR_SEM = threading.Semaphore(4)` (`assembler.py:109`, used at line 826):
- `_deferred_llm_call` threads (`assembler.py:903-907`) — one per novel/escalate happening, each **sleeps `K8S_GRACE_S` (default 300s)** before doing any work, and there is no cap on how many can be in flight simultaneously.
- `_remediator.remediate_and_validate` threads (`assembler.py:889-893`) — one per structured/known happening.
- Matrix/webhook notification threads (`_send_notification`, `assembler.py:267-290`) — one thread per Matrix room, plus one per configured webhook target, per happening.
- `ThreadingHTTPServer` itself spawns a new OS thread per inbound HTTP connection with no pool cap (default Python behavior) — `/webhook` handling spawns yet another thread per call (`assembler.py:1451`).

**Failure scenario:** A genuine alert storm (e.g. a cluster-wide outage triggers dozens of Grafana alerts + sigma matches across many namespaces within a few minutes) creates dozens-to-hundreds of concurrently sleeping/blocked threads (300s LLM grace sleeps stack on top of remediation/validation loops that themselves sleep in polling loops — `_wait_for_self_heal` and `_run_validation_loop` both `time.sleep()` in their own thread for minutes). Python threads are relatively cheap but not free; combined with each holding open sockets/timeouts against CH/Loki/K8s API, this is exactly the kind of load spike that could tip into the watchdog crashloop described in Finding 3, and is unobservable — there's no metric for "how many background threads are currently alive."

**Constructive fix:**
1. Bound the LLM-job and remediation threadpools the same way the correlator already is (`threading.Semaphore` or, better, replace ad hoc `threading.Thread` fan-out with a bounded `concurrent.futures.ThreadPoolExecutor` sized via env var).
2. Expose `threading.active_count()` (or a per-category counter) in the heartbeat row / a `/metrics` endpoint so thread growth is visible before it becomes an incident.
3. Consider replacing the 300s `time.sleep()` grace period in `_deferred_llm_call` with a scheduled re-check (e.g. re-enqueue via the existing poll loop) rather than parking a live thread for 5 minutes per happening.

---

## Finding 7 — LOW/MEDIUM: `_find_open_happening` dedup relies on ClickHouse `ALTER TABLE ... UPDATE` mutations, which are asynchronous — merge can lag behind the next dedup read

**What:** `_merge_happening()` (`assembler.py:478-500`) uses `ALTER TABLE panops.happenings UPDATE ...`. ClickHouse mutations of this form are **asynchronous background operations**, not applied atomically/immediately — `SELECT` queries against the table (including the very next `_find_open_happening` call) may or may not observe the mutation depending on when ClickHouse's mutation queue processes it (typically seconds, but can back up under load or during merges). The dedup logic assumes `ORDER BY opened_at DESC LIMIT 1` plus array-membership checks (`has(sigma_rule_ids, ...)`) will reflect the merge from moments ago.

**Failure scenario:** Two Falco events for the same rule fire in quick succession in the same namespace. The first creates a happening; the second correctly merges into it via `_merge_happening`. A third event arrives before the mutation has actually applied — `_find_open_happening` still sees the pre-merge row (correct, since the row itself, e.g. `status`/`window_end`, is unaffected until the mutation lands) — this specific case is probably fine because the *existence* check doesn't depend on the mutated columns. Bigger risk: if `window_end` (used to bound the dedup lookup to the last 30 minutes, `assembler.py:467`) hasn't been advanced yet by a pending mutation, a 4th event arriving just past the original `window_end` could fail the dedup window check and open a **duplicate** happening for signals that should have merged.

**Constructive fix:** Either (a) issue `ALTER TABLE ... UPDATE ... SETTINGS mutations_sync = 1` for the merge path specifically (small tables, low volume — synchronous mutation cost is acceptable here) so the merge is guaranteed visible before the lock releases, or (b) redesign dedup state to not depend on mutation visibility at all — e.g. keep an in-memory (or Redis-backed, for multi-replica future-proofing) "open happening per namespace+rule" map that's authoritative for the 30-minute merge window, with ClickHouse as the durable log rather than the read-path source of truth.

---

## Finding 8 — LOW: dream-cycle scheduler ran outside its configured window (unexplained, worth instrumenting)

**What:** `dream_scheduler()` (`consolidation.py:830-856`) computes `sleep_s` so `run_dream_cycle()` should only execute between `DREAM_START_HOUR:MINUTE` (16:30 UTC) and `DREAM_END_HOUR:MINUTE` (18:30 UTC). Live logs from the current assembler pod (started `2026-07-09T11:18:03Z`) show a full dream cycle running at `2026-07-09T12:47:20Z` — over 3.5 hours before the configured window opens — followed by a second, correctly-timed run at `16:30:00`.

**Likely explanation:** the 12:47 run was very probably a manual trigger via `POST /dream` or `GET /test/nrem` (both call the same `run_dream_cycle`/`run_nrem_phase` functions and produce identical log lines — `"consolidation: dream cycle starting"` is indistinguishable between a scheduled run and a manual test-endpoint invocation). This is plausible given this appears to be a review/testing session, but as written there is **no way to tell from the logs alone** whether a given dream-cycle run was scheduled or manually triggered — worth closing off as a debugging/observability gap regardless of the actual cause here.

**Constructive fix:** Tag dream-cycle log lines and the `dream_state` row with a `trigger` field (`scheduled` | `manual_dream_endpoint` | `manual_test_nrem`) so operators can distinguish real nightly runs from ad hoc test invocations when auditing brittleness scores / GitLab MR history.

---

## What's done well

- **Startup health checks are correctly tiered**: ClickHouse and Kubernetes API failures are fatal (`sys.exit(1)`), Loki/Matrix failures are non-fatal warnings (`assembler.py:_startup_health_check`) — sensible criticality ranking.
- **Watchdog dead-man's-switch exists at all** (`assembler.py:_watchdog`, `_write_heartbeat`) — many comparable homegrown pipelines have no self-restart mechanism; this one does, even though Finding 3 shows it can be tripped by the wrong cause.
- **Validation-loop resume on restart is already implemented** (`_resume_open_validations`, `assembler.py:1797-1832`, using the `validation_streak` checkpoint column) — this appears to directly address the "validation persistence on pod restart" gap noted in prior project memory; it isn't perfect (doesn't re-run interrupted remediation actions, only resumes validation) but the core mechanism is in place and correctly scoped to a 2-hour window to avoid resurrecting ancient state.
- **LLM circuit breaker** (`assembler.py:126-131`, `_call_llm_server` exception path) correctly rate-limits and escalates via notification when the LLM backend is unhealthy, preventing thread pile-up on `_llm_call`'s 120s timeout from turning into an unbounded retry storm — a good pattern that Finding 6 recommends extending to Loki/CH dependencies too.
- **`_wait_for_self_heal` / k8s self-heal grace period** (`remediator.py:697-728`, `K8S_GRACE_S`) is a genuinely good design choice — deferring both remediation and LLM diagnosis to let Kubernetes' own controllers recover first reduces noisy/unnecessary intervention, and the outcome is explicitly recorded (`k8s_self_heal` rule) for CBR learning.
- **Second dedup check under a per-namespace lock** (`assembler.py:800-813`) correctly closes the TOCTOU race between the first (unlocked, fast-fail) dedup check and the insert — the two-phase-check pattern is the right shape, even though Finding 7 shows the underlying data source (async mutations) can still occasionally violate the invariant it's protecting.

---

## Capability Uplift (structural recommendations)

1. **Schema migrations as code.** Replace the current three-way split (`create-schema.py`, `schema-sql-cm.yaml`, ad hoc in-process `ALTER`/`CREATE` calls in `assembler.py` and `consolidation.py`) with a single ordered, checksummed migration list (even a simple `migrations/0001_*.sql`, `0002_*.sql` directory applied by the existing `panops-schema-init` Job, tracked in a `panops.schema_migrations` table) that both repos consume identically. Add CI drift-check (Finding 4).

2. **A real dead-man's-switch alert on ingest, not just process liveness.** `component_heartbeats` currently only proves the assembler process is scheduling loop iterations — it says nothing about whether upstream signal sources are producing data or whether `assemble()` is actually firing. Wire a Grafana/Alertmanager rule against `max(qryn.sigma_matches.timestamp)`, `max(qryn.security_anomalies.detected_at)`, `max(qryn.patterns.timestamp_10m)`, and `max(panops.happenings.opened_at)` each compared to their expected cadence, and page on staleness. This would have caught Finding 1 five days ago instead of during a manual review.

3. **Structured pipeline SLOs.** Define and track (in Grafana, backed by the existing ClickHouse tables — no new infra needed): p50/p95 time from signal detection (`qryn.sigma_matches.timestamp`) to happening creation (`panops.happenings.opened_at`); poll-loop tick duration distribution (log it from `poll_loop()` directly — currently unmeasured, which is exactly what made Finding 3's root cause invisible); LLM job success/circuit-breaker-open ratio; remediation success/escalation ratio per rule (partially exists via `_compute_brittleness`, but not exposed as a live dashboard, only consumed internally by the dream cycle).

4. **Backpressure and bounded concurrency everywhere threads fan out.** Extend the `_CORRELATOR_SEM` pattern (Finding 6) to LLM jobs and remediation threads; replace the poll loop's synchronous per-namespace `assemble()` calls (Finding 3) with a bounded worker pool so a slow dependency degrades throughput instead of triggering a watchdog-induced crashloop.

5. **Parameterized ClickHouse queries.** The single biggest correctness *and* security lever available: migrating `ch_query`/`ch_exec`/`ch_insert_happening` (and their duplicated copies in `correlator.py`, `drain3_detector.py`, `classifier.py`, `consolidation.py`, `remediator.py` — five near-identical hand-rolled HTTP+auth-header helper functions) to a single shared module with parameterized-query support would simultaneously close the SQL injection surface (Finding 5), eliminate the escaping inconsistency, and remove ~150 lines of duplicated boilerplate across six files.

---

## Ranked summary

| # | Severity | Finding |
|---|----------|---------|
| 1 | CRITICAL | Upstream detection pipeline (qryn.sigma_matches/security_anomalies/patterns) silent 5+ days; happenings stopped 25h ago; heartbeat gives false all-clear |
| 2 | HIGH | `correlator.py` missing `import os` → every metric-correlation write throws, `panops.metric_correlations` has 0 rows ever |
| 3 | HIGH | Synchronous `assemble()` calls inside poll loop + fixed watchdog threshold → self-inflicted crashloop under slow Loki/CH (matches known "gigapipe death spiral" incident) |
| 4 | HIGH | Schema drift: `component_heartbeats`/`consolidation_rewards`/`leading_indicators` missing from `create-schema.py`; `validation_streak` column only exists via runtime ALTER |
| 5 | MEDIUM/HIGH | SQL injection surface on postmortem endpoints (backslash-escape bypass) + auth opt-in-not-opt-out |
| 6 | MEDIUM | Unbounded thread fan-out for LLM jobs/remediation/notifications, no concurrency cap or visibility |
| 7 | LOW/MEDIUM | Dedup merge relies on async ClickHouse mutations that may not be visible to the very next dedup read |
| 8 | LOW | Dream-cycle scheduled vs manual-trigger runs are logically indistinguishable in logs |
