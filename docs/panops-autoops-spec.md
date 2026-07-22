# PanOps AutoOps Specification
## Safe and Reliable Non-LLM Remediation — Design Reference

**Status:** Design / Pre-implementation  
**Related:** `docs/panops-brain-design.md`, `k8s/panops/`  
**Sessions contributing:** PanOps Brain build session (2026-07-02), Renovate/auto-merge session (TBD)

---

## What We Are Building

PanOps is not an LLM-driven ops tool. The LLM (Qwen2.5-3B) is an **additive branch** that fires only for `novel` and `escalate` routes — events the deterministic system has never seen. The core pipeline is:

```
Signal ingestion (Falco / Sigma / Loki / Prometheus)
    → Happening assembly (10-min correlated window)
    → Embedding + kNN similarity (all-MiniLM-L6-v2, cosineDistance)
    → Rule-based fast-path classification
    → Structured remediation (kubectl, GitLab MR)
    → Validation loop (10 consecutive clean polls)
    → Matrix notification (gated by domain + route)
```

Everything up to and including the validation loop is deterministic and explainable. The system gets smarter over time through the **known path**: once a happening has been seen and successfully resolved, future similar happenings (cosine similarity ≥ 0.85) replay the working fix without re-deriving it.

This is distinct from "AI-assisted ops" or "ChatOps". The goal is **autonomous, auditable remediation** with a human only in the loop for genuinely novel situations.

---

## Current State (2026-07-02)

### Working

- Happening assembly from Sigma matches + security anomalies + Grafana webhooks
- all-MiniLM-L6-v2 embeddings stored in ClickHouse; kNN similarity matching
- 4 structured remediation rules: `probe_timeout`, `oom_killed`, `crashloop_config`, `image_pull_backoff`
- Known path: replays prior successful kubectl commands for matched happenings
- Validation loop: 10 clean polls → resolved; 30min timeout → escalated
- Falco Talon enforcement for high-confidence SOC events
- Matrix routing: #noc / #sre / #soc with domain-based gating; known SRE events suppressed
- LLM Job (Qwen2.5-3B Q4_K_M) spawned for novel/escalate routes

### Known Gaps (Prioritised)

| # | Gap | Risk to automate | Priority |
|---|-----|-----------------|----------|
| 1 | OOMKill: restart without root-cause analysis | Low (additive) | High |
| 2 | Signal matching: brittle string-contains | Low | High |
| 3 | CrashLoop: restart without differentiation | Medium | Medium |
| 4 | PVC expansion: no support | Low (additive) | Medium |
| 5 | Deduplication: multiple happenings for same open event | Low | Medium |
| 6 | ImagePullBackOff: no registry health check | Low | Low |
| 7 | Escalation path: escalated happenings go quiet | Low | Low |
| 8 | Network policy auto-fixes | **High** | **Deliberately left manual** |

---

## Gap 1: OOMKill Remediation

### Problem

Current `_rule_oom_killed` does `rollout restart`, which doesn't fix the underlying cause. The pod will OOMKill again if the limit is genuinely too low.

### Proposed Tiered Response

**Tier 1 — First occurrence:** restart only (current behaviour). Record the happening.

**Tier 2 — Recurring (≥3 OOMKills for this deployment in 7 days):**

1. Pull memory metrics from Prometheus:
   - `container_memory_working_set_bytes` over the past 7 days for the affected container
   - Fit a linear trend to detect growth vs flat-near-limit

2. Classify the pattern:
   - **Flat near limit (undersized):** usage consistently near or at limit, no growth trend
   - **Growing (possible leak):** usage grows monotonically before hitting limit

3. **If undersized:**
   - Read VPA recommendation if available (`verticalPodAutoscalers` resource for the deployment)
   - Proposed new limit = `max(vpa_target, peak_usage * 1.3)` rounded up to nearest 64Mi
   - Raise a GitLab MR (see Cross-cutting: GitLab MR Client) updating `resources.limits.memory`
   - Notify #sre: OOMKill count, current limit, proposed limit, VPA recommendation if present

4. **If growing/leak:**
   - Do NOT raise a limit MR — increasing the limit masks the bug
   - Notify #sre: OOMKill count, memory trend summary, "possible leak — investigate"
   - Spawn LLM job to analyse recent logs for the namespace (even if route is not novel)

### VPA Integration

Run VPA in `Off` mode (Recommender only — no automatic pod eviction):

```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: <deployment-name>
  namespace: <namespace>
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: <deployment-name>
  updatePolicy:
    updateMode: "Off"
```

PanOps reads recommendations via the Kubernetes API:
```python
vpa = custom_api.get_namespaced_custom_object(
    "autoscaling.k8s.io", "v1", namespace, "verticalpodautoscalers", name
)
recommendation = vpa["status"]["recommendation"]["containerRecommendations"][0]
target_memory = recommendation["target"]["memory"]
```

VPA in `Off` mode does not conflict with Flux or HPA. The Recommender builds a histogram over days/weeks — more accurate than a single Prometheus range query.

VPA CRs should be added for workloads known to OOMKill (e.g. memory-heavy application server and worker deployments).

### Why Not Patch In-Cluster?

PanOps could patch `resources.limits.memory` directly on the Deployment in-cluster. Flux would reconcile it back within minutes. The change would not persist.

This forces the GitLab MR path, which is correct: the git repo is the source of truth.

### Renovate / Auto-Merge Integration

PanOps MRs and Renovate MRs share the same merge mechanism: GitLab's native
`merge_when_pipeline_succeeds`. The CI pipeline is the trust boundary for both.

**Renovate is not involved in PanOps MR lifecycle.** PanOps raises MRs directly via
the GitLab MR client (see Cross-cutting section) and sets `merge_when_pipeline_succeeds`
at creation time. Renovate handles image updates; PanOps handles resource and config
corrections. The CI gate is what makes both safe.

**Gate criteria for PanOps resource-only MRs** (current baseline, will tighten as CI matures):
- `kustomize build` succeeds (conformance check)
- Trivy config scan passes at CRITICAL severity
- A CI job parses the `panops-metadata` block and verifies the MR is purely additive:
  only `resources.limits.memory`, `resources.requests.memory`, or PVC `spec.storage`
  changed, and only on the declared namespace/deployment

**Auto-merge ceiling:** per-tier, not global. Mirrors the Renovate tier model:
- `kube-system`, `flux-system`, `spire`, `cilium` namespaces: **never** auto-merge
- Everything else: auto-merge if CI passes and change is additive
- Memory ceiling: 4Gi — above this, PanOps notifies #sre and leaves the MR open for human review
- PVC ceiling: 50Gi — same principle

**The `panops-metadata` CI job** should be a fast, dependency-free Python script that:
1. Parses the metadata block from the PR description (available via `github.event.pull_request.body`)
2. Checks `change_type` is in the allowed set (`memory_limit`, `pvc_size`)
3. Diffs the branch against main and asserts only the declared field changed
4. Exits non-zero if the scope exceeds what the metadata claims — blocks merge

This prevents a bug in PanOps from sneaking through an inadvertently broad change under
the guise of a targeted fix.

---

## Gap 2: Signal Matching

### Problem

Rule selection in `_rule_oom_killed`, `_rule_crashloop_config` etc. uses `any(substring in pattern for pattern in drain3_patterns)`. This is fragile: a new log template phrasing ("OOM killer invoked" vs "OOMKilled") would miss the rule.

### Proposed Approach

**Short term:** Replace string-contains with a lookup table in ClickHouse:

```sql
CREATE TABLE panops.signal_rule_map (
    signal_pattern String,      -- regex or exact match
    signal_source Enum('falco','drain3','sigma','anomaly'),
    rule_name String,
    confidence Float32,
    created_at DateTime
) ENGINE = MergeTree ORDER BY (signal_source, rule_name);
```

Seed with known patterns; PanOps matches against this table rather than inline strings. New patterns can be added without redeploying.

**Medium term:** Use the existing embedding space. The all-MiniLM-L6-v2 model already embeds Drain3 templates and happening descriptions in the same 384-dim space. A cosineDistance query from the remediation rule's canonical description (e.g., "container killed due to exceeding memory limit") to the Drain3 template embedding will surface the right rule even with novel phrasing.

This turns rule matching into the same similarity search already used for happening deduplication — one unified mechanism.

---

## Gap 3: CrashLoop Differentiation

### Problem

`_rule_crashloop_config` does `rollout restart deployment`, which only helps if the crash was transient (e.g., a dependency not yet ready at startup). It does nothing for config errors, missing secrets, or dependency failures.

### Proposed Tiered Response

After detecting a CrashLoop signal:

1. Pull the last 50 log lines from the crashing container via Loki
2. Classify the crash reason:
   - **Dependency not ready:** log contains "connection refused", "dial tcp", "ECONNREFUSED" → restart once, if still crashing after 5min → notify
   - **Missing secret/config:** log contains "env var not found", "no such file", "secret ... not found" → extract the missing key name, notify #sre with the specific missing value
   - **Application error / panic:** anything else → notify #sre with log excerpt, do NOT restart repeatedly (masks bugs)

3. Track restart count per deployment per hour in ClickHouse. If > 5 restarts in 1 hour from PanOps: stop restarting, escalate.

---

## Gap 4: PVC Expansion

### Problem

When a PVC approaches capacity (Grafana alert `soc-pvc-capacity` fires), PanOps has no remediation. PVC expansion is one of the safest possible automated changes — it is purely additive and Kubernetes supports online expansion for RBD/CephFS StorageClasses.

### Proposed Approach

When a PVC capacity alert fires:

1. Check `StorageClass.allowVolumeExpansion = true` (rbd-nvme, rbd-hdd, cephfs all support this in this cluster)
2. Calculate new size: `current_size * 1.5` rounded up to nearest Gi
3. Raise GitLab MR updating the PVC manifest's `spec.storage` request
4. Notify #sre with current usage %, current size, proposed size

Unlike memory limits, PVC expansion MRs are extremely low-risk and would be strong auto-merge candidates (see Renovate session notes).

**Do not patch the PVC in-cluster directly** — same Flux reconciliation problem as memory limits.

---

## Gap 5: Happening Deduplication

### Problem

Grafana fires repeated webhooks for the same alert at `repeat_interval` (currently 4h for SRE, 4h for SOC). Each webhook creates a new happening even if the original is still open and being remediated.

### Proposed Fix

Before assembling a new happening, check ClickHouse for an open happening with the same primary signal in the same namespace within the last 2 hours:

```sql
SELECT id FROM panops.happenings
WHERE status NOT IN ('resolved', 'escalated')
  AND has(falco_rules, '<rule>') -- or sigma_rule_ids
  AND has(affected_services, '<namespace>')
  AND opened_at > now64() - INTERVAL 2 HOUR
LIMIT 1
```

If found: update the existing happening's `window_end` rather than creating a duplicate. This also prevents the Matrix notification from firing again for the same event.

---

## Gap 6: ImagePullBackOff — Registry Health Check

### Problem

Current remediation annotates deployments to trigger a re-pull. This is correct for transient registry connectivity issues but useless if the image tag no longer exists.

### Proposed Enhancement

Before annotating:

1. Extract the image reference from the pod spec
2. Check registry reachability (HEAD request to the registry API, with Kubernetes pull secret)
3. If registry unreachable → transient, annotate and retry
4. If registry reachable but image 404 → tag deleted or wrong; notify #sre, do NOT annotate (retry loop would be pointless)

---

## Gap 7: Escalation Path

### Problem

When a happening times out to `escalated` after 30 minutes, PanOps marks it in ClickHouse and logs it, but the Matrix notification is whatever was sent at assembly time. There is no "this has been trying to fix itself for 30 minutes and failed" signal.

### Proposed Fix

When `_ch_update(hid, {"status": "'escalated'"})` is called in the remediator validation loop:

1. Send a Matrix notification to the appropriate room:
   ```
   [ESCALATED] <alert name> — namespace
   Auto-remediation failed after 30min.
   Happening: <id[:8]>
   Actions attempted: <count>
   ```
2. For SOC escalations: also send to #noc as a cross-channel signal

---

## Cross-Cutting: GitLab MR Client

Gaps 1 and 4 both require raising GitLab MRs. This is a single capability to implement once:

### Required

- GitLab personal access token (or project token) with `api` scope, stored as SOPS secret in panops namespace
- `GITLAB_URL`, `GITLAB_TOKEN`, `GITLAB_PROJECT_ID` env vars on the assembler

### Logic

```python
def raise_mr(title, description, file_path, new_content, branch_prefix):
    # 1. Create branch from main
    branch = f"{branch_prefix}-{datetime.now().strftime('%Y%m%d-%H%M')}"
    gl_api("POST", f"/projects/{PROJECT_ID}/repository/branches",
           {"branch": branch, "ref": "main"})

    # 2. Get current file (need SHA for update)
    f = gl_api("GET", f"/projects/{PROJECT_ID}/repository/files/{quote(file_path, safe='')}",
               params={"ref": "main"})

    # 3. Update file on branch
    gl_api("PUT", f"/projects/{PROJECT_ID}/repository/files/{quote(file_path, safe='')}",
           {"branch": branch, "content": new_content,
            "commit_message": title, "encoding": "text",
            "last_commit_id": f["last_commit_id"]})

    # 4. Open MR
    mr = gl_api("POST", f"/projects/{PROJECT_ID}/merge_requests",
                {"source_branch": branch, "target_branch": "main",
                 "title": title, "description": description,
                 "remove_source_branch": True})
    return mr["web_url"]
```

File path resolution: derive from namespace + kind + name by searching the repo tree via GitLab API or maintaining a `panops.resource_paths` table populated by a periodic sync job.

### MR Description Template

```markdown
## PanOps Auto-Remediation MR

**Happening ID:** {happening_id}
**Signal:** {signal_description}
**Trigger:** {oom_count} OOMKills in 7 days / PVC at {pct}% capacity
**Change:** {field} {old_value} → {new_value}

<!-- panops-metadata
happening_id: {happening_id}
change_type: {memory_limit|pvc_size}
namespace: {namespace}
deployment: {deployment}
old_value: {old_value}
new_value: {new_value}
vpa_target: {vpa_target|null}
-->
```

The `panops-metadata` block is machine-readable for CI gate validation.

---

## Cross-Cutting: CI Pipeline as Auto-Merge Safety Gate

Both Renovate and PanOps raise MRs and want them to merge without human involvement
when safe. The CI pipeline is the single trust boundary that makes this possible.
The same `.github/workflows/ci.yml` jobs gate both: Renovate image update MRs and PanOps
resource/config correction MRs go through identical CI, with some jobs conditionally
skipped based on what changed.

### Current Baseline

- `kustomize build` conformance — catches broken manifests, missing resources, bad patches
- YARA scan — catches inadvertent credential or signature embedding
- Trivy config scan — `allow_failure: true` currently, targeting hardening to a hard fail

This is enough to block broken or dangerous manifests. It is not enough to trust
unreviewed image updates on fabric or platform components.

### Progression to Full Automerge

The path from "apps only" to "everything automerges" tracks CI capability, not time:

| Stage | Gate additions | Unlocks |
|-------|---------------|---------|
| **Now** | kustomize conformance + YARA | Applications automerge |
| **Kubeconform** | Validate against live CRD schemas — catches API version drift and deprecated fields | Platform automerge candidate |
| **Hard Trivy** | Trivy config scan promoted from `allow_failure` to hard fail on CRITICAL/HIGH | Platform automerge |
| **kubectl diff** | Compare branch against live cluster — surfaces unexpected drift | k8s-fabric automerge candidate |
| **Smoke tests** | Health endpoint checks for apps post-Flux-sync | Confidence in rollback time |
| **Staging deploy** | vcluster or shadow namespace — Renovate deploys there first, CI smoke-tests, then promotes to production | k8s-fabric automerge with high confidence |

Fabric components (Cilium, SPIRE, Ceph CSI) should retain a 7-day `minimumReleaseAge`
even when all CI stages are green. Some failure modes (CNI regressions, SPIRE trust
bundle issues) only surface under real workload over time and cannot be caught in a test run.

### MR Type Routing in CI

Not all MRs need the same jobs. CI should inspect what changed and the MR source to
apply targeted checks:

```yaml
# .github/workflows/ci.yml sketch
kubeconform:
  rules:
    - if: contains(github.event.pull_request.labels.*.name, 'renovate')

panops-scope-check:
  # Parses panops-metadata block: only declared field changed, value within ceiling
  rules:
    - if: contains(github.event.pull_request.labels.*.name, 'panops')

trivy-config:
  rules:
    - changes:
        - k8s/**/*
```

The `panops-scope-check` job is the key safety rail for autonomous remediation MRs.
It parses the `panops-metadata` block from `github.event.pull_request.body` and diffs
the branch against main to assert:
- Only the declared field changed (`memory_limit`, `pvc_size`, etc.)
- The change is additive (new value ≥ old value — no reductions)
- The new value is within the configured ceiling
- The namespace is not in the blocked list (`kube-system`, `flux-system`, `spire`, `cilium`)

A bug in PanOps that produces an overly broad change cannot bypass this job to automerge.

### The Additive Change Principle

The safety envelope for automerge is: **only additive, bounded changes**.

| Change type | Additive? | Auto-merge safe? |
|-------------|-----------|-----------------|
| Image tag bump (apps) | Yes, with rollback | Yes, with CI gate |
| Memory limit increase | Yes (additive headroom) | Yes, with ceiling |
| PVC size increase | Yes (storage only grows) | Yes, with ceiling |
| Image tag bump (fabric) | Risky | Only after staging |
| Memory limit decrease | No (may cause OOMKill) | Never |
| NetworkPolicy change | No (may block traffic) | Never |
| RBAC change | No (may break auth) | Never |
| Resource deletion | No | Never |

PanOps remediation rules should only ever produce additive changes. Anything in the
"Never" category must notify #sre and leave the MR open — PanOps raises it, but does
not set `merge_when_pipeline_succeeds`.

### Connection to PanOps Brain

The CI pipeline and PanOps auto-remediation are two arms of the same goal: autonomous,
auditable GitOps. The convergence point:

1. PanOps detects a problem and determines the fix
2. PanOps raises a MR with `panops-metadata` block and `merge_when_pipeline_succeeds` set
3. CI validates scope and safety bounds via `panops-scope-check`
4. GitLab merges automatically when pipeline passes
5. Flux reconciles the change to the cluster
6. PanOps validation loop confirms the problem resolved and closes the happening

Every action has a git commit, an MR, and a happening record in ClickHouse. The human
is only in the loop for novel situations, scope violations, or changes the CI gate
cannot safely validate. This is the same model as Renovate for dependency updates —
the git history is the audit trail.

---

## PanOps Self-Healing

The system healer must be self-healing. PanOps currently logs to stdout and writes to ClickHouse, but nothing monitors whether it is actually running and polling. If the assembler crashes or the poll loop stalls, the failure is silent — alerts stop arriving and you don't know why.

### Heartbeat Mechanism

The assembler writes a `heartbeat` row to `panops.happenings` every 5 minutes with `classifier_route = 'heartbeat'` and `status = 'resolved'`. A Grafana alert fires if no heartbeat row appears in 15 minutes:

```sql
-- Grafana alert: panops-heartbeat-missing
SELECT count() FROM panops.happenings
WHERE classifier_route = 'heartbeat'
  AND opened_at > now64() - INTERVAL 15 MINUTE
-- fires if result = 0
```

This is the simplest possible dead-man's switch. It covers assembler crash, pod eviction, ClickHouse connectivity loss, and poll loop hang simultaneously — any of these stops the heartbeat.

### Poll Loop Watchdog

A second daemon thread in the assembler tracks `last_poll_time`. If `now - last_poll_time > 3 × POLL_INTERVAL`, the watchdog calls `os._exit(1)`. Kubernetes restarts the pod. This prevents a silent stuck state where the process is running but the poll loop is blocked (e.g., on a hung ClickHouse query).

### LLM Job Circuit Breaker

Track LLM job failures in a module-level counter. If > 3 jobs fail within 1 hour, stop spawning new LLM jobs and send a single #noc notification: "LLM job circuit open — novel happenings will not receive LLM analysis until manually reset." Reset on next assembler restart. Prevents runaway Job creation when the model PVC is unavailable or the image is broken.

### Grafana Alerts for PanOps Namespace

Add to `grafana-alerting-rules`:
- `panops-assembler-down` — deployment unavailable for > 2 minutes
- `panops-heartbeat-missing` — no heartbeat in 15 minutes (as above)
- `panops-llm-jobs-failing` — > 3 failed LLM Jobs in 1h (from kube_job_failed metric)

These alerts route to #noc, not #sre or #soc, since PanOps failure is infrastructure, not an application or security event.

### Startup Health Check

On assembler startup, before entering the poll loop, run a connectivity check:
- ClickHouse: execute `SELECT 1`
- Loki: HEAD request to `/ready`
- Matrix: GET `/versions` on the homeserver
- Kubernetes API: list pods in panops namespace (validates RBAC)

Log each result. If ClickHouse or Kubernetes API fail, exit immediately (pod will restart and retry). If Loki or Matrix fail, log a warning and continue — degraded mode is better than no mode.

**See also:** `docs/devsecops-metrics-spec.md` — the heartbeat metric feeds into PanOps self-availability tracking.

---

## Implementation Order

When ready to implement, suggested sequence:

1. **Self-healing** — heartbeat, watchdog, startup health check; no new dependencies, highest trust multiplier
2. **Deduplication** (Gap 5) — low effort, prevents noise
3. **Escalation notifications** (Gap 7) — low effort, high value
4. **GitLab MR client** — cross-cutting enabler for Gaps 1 and 4
5. **OOMKill tiered response + VPA** (Gap 1) — highest value remediation improvement
6. **PVC expansion MRs** (Gap 4) — once MR client exists, this is small
7. **CrashLoop differentiation** (Gap 3) — requires Loki log pull in remediation path
8. **Signal matching rewrite** (Gap 2) — correctness improvement, medium effort
9. **ImagePullBackOff registry check** (Gap 6) — nice to have

Renovate/auto-merge integration should be designed and merged in parallel with or just before step 3 (GitLab MR client), so the first MR PanOps raises is already eligible for auto-merge.

---

## Future Architecture: Temporal Workflow Engine

**Not needed now. Revisit when building multi-step remediation workflows (Gap 1 Tier 2, Gap 3, Gap 4).**

[Temporal](https://temporal.io) is a durable execution platform for long-running, stateful workflows.
The self-healing patterns (Thread 1) and deduplication (Thread 2) don't need it — they're in-process
checks that complete in milliseconds. But the multi-step remediation workflows have a different shape:

| Workflow | Steps | External waits | Crash-safe? |
|----------|-------|---------------|-------------|
| OOMKill Tier 1 (restart) | 1 | none | fine without Temporal |
| OOMKill Tier 2 (GitLab MR) | ~10 | CI pipeline (minutes-hours) | **needs Temporal** |
| CrashLoop differentiation | 4-6 | log fetch, recovery window | **needs Temporal** |
| PVC expansion MR | 6 | CI pipeline | **needs Temporal** |

Without Temporal, multi-step workflows use ClickHouse status fields + the poll loop to fake durable
state. This works but is fragile: if the assembler crashes mid-workflow, the in-progress state is
lost and the workflow either stalls or re-runs incorrectly.

**What Temporal replaces:**
- ClickHouse `remediation_outcomes` status polling → Temporal workflow history
- Manual retry logic in Python → Temporal activity retry policies
- Kubernetes Jobs for async work → Temporal activities
- "Wait for CI pipeline" poll loop → Temporal timer + signal from GitLab webhook

**Deployment:** Temporal server as a K8s Deployment, backed by the existing CloudNativePG Postgres
cluster. Temporal worker runs alongside the assembler (same pod or sidecar). Python SDK is mature.
The assembler's existing background threading model maps cleanly to Temporal activities.

**When to introduce:** at the first multi-step remediation workflow — OOMKill Tier 2 is the clearest
case. At that point, introduce Temporal and convert the MR client to a Temporal workflow. The simpler
Tier 1 restart stays as a direct call.

---

## Assessment Notes

> **[FOR DEEP ASSESSMENT SESSION — Fable/Opus recommended]**
>
> Questions worth a dedicated architectural review:
>
> 1. **Completeness of the non-LLM coverage envelope:** Are there classes of incidents that are fundamentally un-automatable without LLM reasoning, or just ones we haven't written rules for yet? Where is the actual ceiling?
>
> 2. **The known-path learning rate:** cosine similarity ≥ 0.85 is conservative. As the incident database grows, what threshold tuning is needed? Should thresholds be per-domain?
>
> 3. **VPA + GitOps tension at scale:** `Off` mode means git and reality diverge for resource requests too (VPA Recommender sets requests, not just limits, and Initial mode applies them). Is there a cleaner reconciliation story?
>
> 4. **Safety envelope for MR auto-merge:** What is the right set of constraints such that an auto-merged MR can never make things worse? Memory limit increases are additive. PVC expansions are additive. What else is in this category?
>
> 5. **The SOC auto-remediation question:** Currently all SOC happenings are notify-only (Talon handles enforcement). Are there SOC events where PanOps could take safe automated action? E.g., automatically quarantining a pod (network policy) when a crypto miner is detected — but this is exactly the "network policy auto-fix" marked high-risk above. How do we reason about where that line is?
>
> 6. **Observability of PanOps itself:** PanOps logs to stdout and writes to ClickHouse. What monitors PanOps? If the assembler crashes or the poll loop stalls, the failure is silent. A self-monitoring loop (Grafana alert on panops pod restarts + a "heartbeat" happening every N minutes) would make the system trustworthy enough to leave unattended.
