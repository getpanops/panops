# Observability Scaling — P0A.2b Workstream (gigapipe/ClickHouse)

**Audience:** execution agent (Sonnet), fresh session. Self-contained.
**Parent:** `docs/HARDENING_PLAN.md` (this is the detail behind task P0A.2b / #335).
**Produced:** 2026-07-10 after an architecture review with the operator.

---

## 0. Context & the core decision

PanOps stores logs+metrics (traces/profiling later) in **one ClickHouse** (the `qryn` database), fronted by **gigapipe** (ex-qryn): a stateless Go shim exposing Loki **LogQL** / Prometheus **PromQL** / Tempo APIs by translating them to ClickHouse SQL. Ingest path: otelcol → gigapipe → ClickHouse (`qryn.time_series`, `qryn.time_series_gin`, `qryn.samples_v3`, `qryn.metrics_15s`).

**The problem (see `docs/reviews/review-data-pipeline.md` + memory `project_panops_hardening_execution`):** the pipeline is starved because gigapipe query calls **time out** (`[PQRC002] query timed out in expression evaluation`) on both the log path (drain3-miner) and the metric path (correlator, Grafana `node_memory_*`). Root causes, in order of impact:
1. **Unbounded data volume / cardinality** — `samples_v3` ≈ 2.5B rows, `metrics_15s` ≈ 2.3B rows.
2. **Disk contention** — the ClickHouse OSD shares a disk with etcd on a control-plane node. **OFF-LIMITS to fix structurally** per operator (too risky). We work *around* it by cutting I/O.
3. **gigapipe's generic SQL generation** — the query-language converter is a real ceiling; it emits scan-heavy SQL versus a hand-tuned native query.

**Operator constraints (hard):** single datastore (no VictoriaMetrics/second TSDB); FOSS; no JVM; no vendor cost. Keep qryn's genuine value (ingest/format conversion + LogQL/PromQL compat so community Loki/Prometheus dashboards "just work").

**Guiding principle for this workstream:** *Demote gigapipe to "ingest writer + compatibility endpoint." Move PanOps' hot query paths to native ClickHouse SQL (the sigma-scanner already does this). Reduce data at the edge, downsample metrics, tier cold data, and tune ClickHouse to read less off the contended disk.* This keeps the single-store vision and unblocks ingest without a migration.

**Strategic exit (documented, not executed):** if after this workstream the gigapipe converter is still the ceiling for the human/dashboard side, the natural convergence is **ClickStack** (OTel → ClickHouse → HyperDX) — ClickHouse Inc's official FOSS, no-JVM, single-store, *native* (no converter) observability stack. Do NOT migrate now; revisit only if Step 0's diagnostic + how much we end up hand-rolling proves the shim is a permanent limiter. Decision gate in §9.

---

## 1. Do NOT break

- The sigma-scanner (security ns) and the PanOps assembler already query ClickHouse natively and work — mirror their pattern, don't disturb them.
- gigapipe's ingest path and LogQL/PromQL endpoints must keep working (community dashboards depend on them).
- `qryn.*` is gigapipe's schema — treat it as an interface. Verify column names live (`DESCRIBE`) before writing queries; pin the gigapipe version so schema doesn't shift under native queries. Any `ALTER TABLE` on `qryn.*` (skip indexes) may be reset by a gigapipe upgrade — document them as re-appliable.
- The correlator's PromQL is convenient; prefer making it cheap (rollups) over rewriting it, unless Step 0 shows the converter itself is the cost.

---

## 2. Step 0 — Diagnose the ceiling BEFORE spending (do first)

Goal: know whether timeouts are ClickHouse-scan-bound (disk/cardinality) or gigapipe-conversion-bound (Go eval). This decides emphasis.

- Pick a namespace + 10-min window. Run the **native SQL** equivalent of a drain3 log fetch directly via `clickhouse-client` and time it; run the **same** via gigapipe `/loki/api/v1/query_range` and time it. Compare.
- Same for a metric: native SQL against `metrics_15s` for `node_memory_MemAvailable_bytes` vs gigapipe `/api/v1/query_range` PromQL.
- Inspect `clickhouse-client -q "SELECT query_duration_ms, read_rows, read_bytes, memory_usage, query FROM system.query_log WHERE type='QueryFinish' AND event_time > now()-3600 ORDER BY query_duration_ms DESC LIMIT 20"`.
- **DoD:** a one-paragraph verdict: scan-bound vs converter-bound, with numbers. If ClickHouse native is fast but gigapipe slow → converter is the ceiling (raises priority of native-query migration + the ClickStack gate). If ClickHouse native is also slow → disk/cardinality dominates (raises priority of Steps 3–6).

---

## 3. Step 1 — drain3-miner → native ClickHouse SQL (IMMEDIATE UNBLOCK)

This fixes the P0A.2 blocker directly: drain3-miner times out because it goes through gigapipe LogQL. Query ClickHouse directly instead (like the sigma-scanner).

Files: `~/Git/panops/docker/drain3-miner/miner.py` (`_fetch_namespaces`, `_mine_namespace`). Reference the sigma-scanner's CH query code in `~/Git/panops/docker/sigma-scanner/src/sigma-scanner.py` for the exact HTTP-to-ClickHouse pattern (auth headers, params).

**First, discover the schema** (do not trust the templates blindly):
```
clickhouse-client -q "DESCRIBE qryn.time_series_gin"      # label inverted index
clickhouse-client -q "DESCRIBE qryn.samples_v3"           # log lines / metric samples
clickhouse-client -q "SELECT DISTINCT type FROM qryn.samples_v3 LIMIT 10"   # which type() = logs
```
Expected shape (verify): `time_series_gin(date, key, val, fingerprint, type)`, `samples_v3(fingerprint, timestamp_ns, string, value, type)` — logs carry `string`, metrics carry `value`.

**Replace `_fetch_namespaces`** (slow label-values scan) with an indexed query:
```sql
SELECT DISTINCT val
FROM qryn.time_series_gin
WHERE key = 'k8s_namespace_name'
  AND date >= today() - 1
```
**Replace `_mine_namespace`'s LogQL query** with fingerprint-resolve + samples-fetch:
```sql
WITH fp AS (
  SELECT fingerprint FROM qryn.time_series_gin
  WHERE key = 'k8s_namespace_name' AND val = {ns:String}
    AND date >= today() - 1
)
SELECT timestamp_ns, string
FROM qryn.samples_v3
WHERE fingerprint IN (fp)
  AND timestamp_ns BETWEEN {start_ns:UInt64} AND {end_ns:UInt64}
  AND string != ''
ORDER BY timestamp_ns DESC
LIMIT {lim:UInt32}
```
Use bound params (`param_ns=` etc.) — never f-string interpolation. Keep the drain3 tokenisation + `qryn.patterns` insert logic unchanged (already fixed: table self-provisions, `k8s_namespace_name` label). Rebuild the drain3-miner image (GitLab CI, `build-drain3-miner`) and run a manual Job.

**DoD:** a manual `drain3-miner` Job completes without timeouts and `SELECT count() FROM qryn.patterns` grows; `panops.happenings` begins advancing again (combined with the assembler's enrich_drain3 reading `qryn.patterns`).

---

## 4. Step 2 — Edge reduction (OTTL in otelcol) — highest leverage, lowest risk

Cut data before storage. Files: the otelcol/alloy config in `~/Git/homelab/k8s/.../observability/` (otelcol-node/cluster config CMs). Use OTTL (otelcol-native; VRL is Vector-only, not used here).

- **Drop low-value logs**: kube probe/health-check lines, chatty sidecars, known-noise patterns — `filter` processor with OTTL conditions.
- **Reduce metric cardinality** (the #1 query killer): drop high-cardinality labels (pod hashes, container IDs, ephemeral IPs) via `transform`/`metricstransform`; drop unused metric series entirely.
- **Sample** high-volume debug logs.
- Keep security-relevant logs at full fidelity (they get tiered in Step 5, not dropped).

**DoD:** measured drop in `samples_v3`/`metrics_15s` ingest rate (compare `SELECT count() ... WHERE timestamp_ns > now()-…` before/after) and in active label cardinality (`SELECT uniq(fingerprint) FROM qryn.time_series WHERE date=today()`).

---

## 5. Step 3 — Metric rollups + raw TTL (fix the PromQL path)

Long-range PromQL is slow because it scans 2.3B raw 15s rows. Provide coarser rollups + expire raw.

- Create `AggregatingMergeTree` rollup MVs at 1m/5m/1h off `metrics_15s` (or the base metric table). Verify whether gigapipe's PromQL can be pointed at coarser tables; **if the converter can't use custom rollups**, move the *correlator's* metric queries to native SQL against the rollups (Step 1 pattern) and leave gigapipe for human dashboards.
- Aggressive **raw TTL**: e.g. `metrics_15s` raw retained 24–72h, rollups retained longer. Set via `ALTER TABLE ... MODIFY TTL` (confirm gigapipe won't fight it; qryn has its own retention settings — prefer configuring retention through gigapipe if exposed).

**DoD:** `node_memory_*` PromQL (or its native-SQL replacement) returns sub-second over a 6h range; raw table row count stops climbing unbounded.

---

## 6. Step 4 — Skip indexes + compression + partition pruning (read less off the contended disk)

- **Bloom-filter data-skipping index** on the label columns used for filtering. If `time_series_gin` is already the label index this may be moot; for `samples_v3` selective log reads, ensure the `fingerprint IN (…)` path prunes. Add `INDEX ... TYPE bloom_filter` where a full column scan is happening (guided by Step 0 `read_rows`).
- **Compression codecs**: verify/add `DoubleDelta`/`Delta` on timestamp columns, `Gorilla`/`ZSTD` on float `value`, `ZSTD` on log `string`. Smaller on-disk = less I/O = directly mitigates the disk contention. `ALTER TABLE ... MODIFY COLUMN ... CODEC(...)`.
- **PARTITION BY day** + minmax on time so queries prune partitions (verify qryn's existing partitioning).
- Document every `qryn.*` ALTER as re-appliable after a gigapipe upgrade.

**DoD:** for a representative selective query, `read_rows` in `system.query_log` drops by an order of magnitude vs Step 0 baseline.

---

## 7. Step 5 — Verify/tune S3 tiering (operator says already wired)

ClickHouse↔Ceph S3 plumbing exists (`clickhouse-s3-creds`, S3 egress CNP, backups to `s3.YOUR_DOMAIN` port 7480 per `feedback_ceph_rgw_port`).

- Confirm the `storage_policy` has hot(local)+cold(s3) volumes and that `qryn.*` tables have `TTL timestamp + INTERVAL <N> DAY TO VOLUME 's3'`. `SELECT * FROM system.storage_policies`; check `SELECT table, disk_name, sum(bytes_on_disk) FROM system.parts GROUP BY table, disk_name` to see hot vs S3 distribution.
- Tune the hot window: keep a small hot window in MergeTree (fast detection), tier full-fidelity older data to S3 (SIEM-safe retention, still transparently queryable). This is *better than downsampling for security logs* — keeps evidence, shrinks hot scans.

**DoD:** old parts show on the `s3` disk; hot-window queries are fast; a historical query still returns (from S3).

---

## 8. Step 6 — ClickHouse query governance + cache RAM (stop the death-spiral; spend RAM to save disk)

- **Governance** (profile/user settings on the CHI): `max_execution_time`, `max_memory_usage`, `max_concurrent_queries`, `max_threads`. Make heavy queries **fail fast** instead of piling up — this alone likely ends the cascading timeout death-spiral.
- **Caches**: raise `mark_cache_size` and `uncompressed_cache_size` — trades the operator's RAM bump directly against disk reads (correct direction given disk is the constraint; ClickHouse is C++, not a JVM RAM hog).
- Consider `async_insert` + batch tuning if ingest creates many small parts (reduces merge pressure competing with reads) — a lighter alternative to introducing NATS.
- Optional topology: gigapipe is stateless → split **reader/writer** replicas to isolate query load from ingest. (Do NOT add ClickHouse replicas/shards on the same contended Ceph — that multiplies contention; horizontal scaling waits for isolated disks.)

**DoD:** under a burst of concurrent queries, ClickHouse rejects/limits gracefully (no node-wide stall); cache hit ratio (`system.events` MarkCacheHits) is high.

---

## 9. Step 7 — Grafana native ClickHouse datasource (human side, gradual)

- Add the official Grafana ClickHouse datasource; build/critical panels in native SQL; keep gigapipe LogQL/PromQL datasource for borrowed community dashboards.
- Over time gigapipe demotes to ingest + compat. No big-bang.

**DoD:** the key operational dashboards render on native ClickHouse SQL with sub-second panels.

---

## 10. Decision gate — ClickStack (revisit AFTER Steps 0–6)

Adopt ClickStack (OTel → ClickHouse → HyperDX) **only if** all hold after this workstream:
- Step 0 shows the gigapipe converter (not ClickHouse) is still the ceiling for the human/dashboard path, AND
- You find yourself rewriting most panels/queries in native SQL anyway (so the "LogQL/PromQL compat" benefit has eroded), AND
- Traces/profiling roadmap makes HyperDX's native correlation UX worth the migration.

If adopted, the cost is: re-point otelcol to ClickStack's OTel-native schema, **rewrite PanOps assembler/sigma/drain3 queries** against it, lose LogQL/PromQL community-dashboard compat, operate HyperDX. Because Steps 1/3/9 already move you native, the migration is *smaller* by then than it looks today. Until the gate trips, stay on qryn-as-ingest + native hot paths.

---

## 11. Suggested order (by leverage × urgency)

1. **Step 0** diagnostic (cheap, decides everything).
2. **Step 1** drain3 → native SQL (revives ingest *now* — the actual blocker).
3. **Step 2** OTTL edge reduction (stops growth; biggest structural win).
4. **Step 6** query governance + cache RAM (stabilise; stop death-spiral).
5. **Step 4** skip indexes/compression + **Step 3** rollups/TTL (make existing data cheap).
6. **Step 5** verify/tune S3 tiering (shrink hot set, keep SIEM fidelity).
7. **Step 7** native Grafana datasource (gradual).
8. **§10** ClickStack gate — only if evidence demands.

Every step: verify against the live cluster with a ClickHouse query or a synthetic event, not a green pod. Preserve §1.
