# PanOps Inference Mesh — Design Specification

## Overview

This spec covers the evolution of PanOps's LLM tier from a single fragile instance to a
resilient, multi-node inference mesh with structured agent orchestration, shared memory,
and lifecycle-managed workflow execution.

It extends `SPEC-brain-ml.md` (LLM tier architecture) and `panops-brain-design.md` (overall
system design). All components must ship in both the Docker Compose single-node stack
(`deploy/`) and the Kubernetes multi-node stack (`k8s/` in homelab repo).

---

## Motivation

The LLM tier has never successfully executed in production. Two bugs blocked it:

1. **Missing CNP egress rule** — assembler could not reach llama-server (fixed: `37f6e33`)
2. **No retry on synthesis failure** — dream cycle silently drops runbooks on any timeout

Beyond these bugs, the single-instance architecture has structural weaknesses:
- RWOP PVC + RollingUpdate strategy → downtime on every deployment
- Model load takes 20-40s → liveness probe kills mid-load if anything restarts
- Dream cycle and active incident both contend for the same instance
- No auditability of agent reasoning steps
- No persistent memory across dream cycles

The inference mesh addresses all of these.

---

## Architecture

```
                        ┌─────────────────────────────────────────────┐
                        │              INFERENCE MESH                  │
                        │                                              │
  assembler             │   panops-agent-0 (node 1)                     │
  (investigation ──────►│   panops-agent-1 (node 2)  ◄── Prefect flows  │
   request)             │   panops-agent-2 (node 3)                     │
                        │         │                                    │
                        │   CephFS RWX PVC (model file, shared)       │
                        │   llama-server sidecar per agent pod         │
                        │         │                                    │
                        │   MCP tools layer                           │
                        │   ├── agent_memory (ClickHouse-backed)      │
                        │   ├── query_happenings                      │
                        │   └── read_runbook                          │
                        └─────────────────────────────────────────────┘
                                  │
                        ClickHouse panops.* (audit trail, memory, rewards)
```

### Key design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Model storage | CephFS RWX PVC | Single model file, all pods mount read-only; avoids per-pod download |
| Deployment topology | DaemonSet (one pod per node) | Guaranteed spread; natural K8s failover via Service |
| Agent framework | Custom phased protocol | ReAct unreliable at 3B; LangGraph too heavy; deterministic transitions needed |
| Lifecycle orchestration | Prefect self-hosted | Replaces ad-hoc threads; gives retry semantics, scheduling, audit UI |
| Memory | ClickHouse `panops.agent_memory` | Already present; consistent with rest of system; shared across all pods |
| Single-node compat | Docker Compose profile | Prefect + agent + llama-server all in compose; CephFS replaced by bind mount |

---

## Component 1: Model Mesh (DaemonSet + CephFS)

### Storage

- Provision a CephFS StorageClass PVC (`cephfs-nvme` or equivalent) with `ReadWriteMany`
- Size: 10Gi (headroom for model upgrades)
- A one-shot `model-download` Job populates the PVC on first deploy
- All agent pods mount the PVC read-only at `/models`

### DaemonSet

```
panops-agent DaemonSet
  ├── container: panops-agent (phased investigation protocol, MCP client)
  │     image: panops-agent:latest
  │     port: 8081 (HTTP investigation API)
  │     env: LLAMA_URL=http://localhost:8080
  └── container: llama-server (sidecar)
        image: ghcr.io/ggerganov/llama.cpp:server
        port: 8080
        volumeMount: /models (readOnly)
        resources:
          requests: cpu=500m, memory=2500Mi
          limits:   cpu=4, memory=4Gi
```

Sidecar pattern collocates llama-server with the agent on each node. The agent calls
`localhost:8080` — no network hop, no CNP needed for model inference.

### Service

Standard ClusterIP Service selecting the DaemonSet pods. The assembler and Prefect flows
call the Service; K8s round-robins across healthy pods. Unhealthy pods (model still
loading) are excluded automatically via readiness probe.

### Startup probe (llama-server)

```yaml
startupProbe:
  httpGet:
    path: /v1/models
    port: 8080
  failureThreshold: 30   # 30 × 10s = 5 minutes max load time
  periodSeconds: 10
```

Separate from liveness probe. Pod is not killed during model load; once startup passes,
liveness takes over with tighter parameters.

### Retry / pending_synthesis

The consolidation module's `run_nrem_phase` must be refactored:

- Per-happening synthesis is wrapped in retry logic (3 attempts, 30s backoff)
- On exhausted retries: write `pending_synthesis = true` to `panops.happenings`
- A `pending_synthesis_retry` Prefect flow runs daily at 03:00 UTC (after dream cycle),
  picks up all `pending_synthesis = true` rows, retries synthesis
- `dream_state` table is created by schema-init, not lazily — add to schema init job

---

## Component 2: Prefect Lifecycle Orchestration

### Deployment

Self-hosted Prefect server in k8s (`panops` namespace). Prefect workers run as a Deployment,
connected to the server via API. Flows are defined in the `panops-agent` image and deployed
as Prefect deployments pointing at the worker pool.

For Docker Compose: Prefect server + worker as services in `deploy/docker-compose.yml`
under an `orchestration` profile.

### Flows

| Flow | Trigger | Schedule | Description |
|---|---|---|---|
| `investigate_incident` | assembler webhook (via HTTP trigger) | reactive | Full phased investigation for a happening |
| `dream_cycle` | Prefect schedule | 02:00 UTC daily | NREM consolidation, leading indicators, gap synthesis |
| `pending_synthesis_retry` | Prefect schedule | 03:00 UTC daily | Retry happenings with `pending_synthesis=true` |
| `model_health_check` | Prefect schedule | every 15 min | Ping all mesh pods, log to `component_heartbeats` |

### Concurrency

- `dream_cycle` and `pending_synthesis_retry`: concurrency limit 1 (never overlap)
- `investigate_incident`: concurrency limit 3 (one per mesh node)
- Model health check: concurrency limit 1

### Assembler integration

The assembler's `_call_llm_server` is replaced by an HTTP call to Prefect's flow run
trigger API. The assembler fires `investigate_incident` and writes the flow run ID to
the happening record. Status polling uses the Prefect API rather than internal state.

---

## Component 3: panops-agent (Phased Investigation Protocol)

### Image

New Docker image: `docker/agent/` in the panops repo.

```
docker/agent/
  ├── Dockerfile
  ├── requirements.txt        (openai, mcp, httpx, structlog)
  └── src/
      ├── agent.py            (HTTP server, flow entrypoint)
      ├── protocol.py         (phased investigation state machine)
      ├── tools.py            (tool implementations)
      └── mcp_client.py       (MCP server connections)
```

### Phased Investigation Protocol

Deterministic phase transitions. The model operates within each phase; code decides
when to advance.

```
Phase 1 — TRIAGE
  Input:  happening record (domain, signals, drain3_patterns, affected_services)
  Model call: classify incident type → select investigation_plan from bounded set
  Plans:  oom_investigation | crashloop_investigation | probe_investigation |
          security_investigation | novel_investigation
  Exit:   always advances to GATHER (plan selection is the only decision)

Phase 2 — GATHER
  Input:  investigation_plan + available tools
  Model calls: up to MAX_GATHER_STEPS=5, tool selection from plan's allowed_tools
  Tools per plan are bounded (e.g. oom_investigation: [query_happenings, read_runbook,
          query_memory, get_similar_incidents])
  Exit conditions (deterministic):
    - budget exhausted (5 calls)
    - model returns no tool_call (signals sufficient evidence)
  On exit: advance to SYNTHESISE

Phase 3 — SYNTHESISE
  Input:  all gathered evidence + original happening
  Model call: single structured output call
  Output schema:
    diagnosis: str
    steps: list[str]
    confidence: float [0,1]
    runbook_entry: str
    memory_note: str | null   (if worth remembering for future cycles)
  Exit: always advances to VALIDATE

Phase 4 — VALIDATE (deterministic, no model call)
  if confidence >= 0.70:
    write runbook_entry to CH
    if memory_note: write to panops.agent_memory
    status → 'resolved' or 'validating'
  elif confidence >= 0.50:
    status → 'escalated' (human review, Haiku fallback if available)
    write pending note to CH
  else:
    status → 'escalated'
    pending_synthesis = true (retry next cycle with more context)
```

Every phase boundary is written to ClickHouse as an audit record. The full trace
(triage decision, each tool call + result, synthesis output, validation outcome) is
stored in a new `panops.investigation_traces` table.

### HTTP API

```
POST /invoke
  body: { "happening_id": "uuid", "flow_run_id": "prefect-uuid" }
  response: { "status": "ok", "phase": "TRIAGE" }  (async, Prefect polls)

GET /health
  response: { "status": "ok", "llama": "ready|loading|down" }
```

---

## Component 4: Memory MCP Server

### Storage

New ClickHouse table `panops.agent_memory`:

```sql
CREATE TABLE panops.agent_memory (
    id          UUID DEFAULT generateUUIDv4(),
    written_at  DateTime64(9) DEFAULT now64(),
    scope       LowCardinality(String),  -- 'global' | 'incident_type' | 'service'
    scope_key   String,                  -- e.g. 'oom_investigation' or 'app-a'
    content     String,
    source_happening_id UUID,
    ttl_days    UInt16 DEFAULT 90
) ENGINE = MergeTree()
ORDER BY (scope, scope_key, written_at)
TTL written_at + INTERVAL ttl_days DAY;
```

### MCP server

Thin Python process (`docker/memory-mcp/`) implementing the MCP protocol over stdio
or HTTP. Tools exposed:

| Tool | Description |
|---|---|
| `memory_read(scope, scope_key, limit)` | Fetch recent memories for a scope |
| `memory_write(scope, scope_key, content, source_happening_id)` | Store a memory note |
| `memory_search(query, limit)` | FTS search across all memories |

In k8s: runs as a sidecar in each agent pod (localhost access, no CNP needed).
In Docker Compose: runs as a sidecar service.

The memory server connects to ClickHouse via the existing `CH_URL` / `CH_PASSWORD`
env vars. All three agent pods share the same ClickHouse table — memory is global
across the mesh.

---

## Schema additions (schema-init job)

```sql
-- dream_state (was missing, caused NREM to fail silently)
CREATE TABLE IF NOT EXISTS panops.dream_state (
    key         String,
    value       String,
    updated_at  DateTime64(9) DEFAULT now64()
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY key;

-- investigation traces (full agent audit trail)
CREATE TABLE IF NOT EXISTS panops.investigation_traces (
    id              UUID DEFAULT generateUUIDv4(),
    happening_id    UUID,
    flow_run_id     String,
    phase           LowCardinality(String),
    step            UInt8,
    tool_name       String DEFAULT '',
    tool_input      String DEFAULT '',
    tool_output     String DEFAULT '',
    model_output    String DEFAULT '',
    created_at      DateTime64(9) DEFAULT now64()
) ENGINE = MergeTree()
ORDER BY (happening_id, phase, step);

-- agent memory
CREATE TABLE IF NOT EXISTS panops.agent_memory ( ... ); -- see above
```

---

## Docker Compose compatibility

All new components ship with Compose service definitions under `deploy/`:

```yaml
# deploy/docker-compose.inference.yml  (included via --file flag or extends)
services:
  llama-server:
    image: ghcr.io/ggerganov/llama.cpp:server
    volumes:
      - ./models:/models:ro
    command: --model /models/Qwen2.5-3B-Instruct-Q4_K_M.gguf --port 8080 --host 0.0.0.0

  panops-agent:
    build: ../docker/agent
    environment:
      LLAMA_URL: http://llama-server:8080
      CH_URL: http://clickhouse:8123
    depends_on: [llama-server, memory-mcp]
    ports: ["8081:8081"]

  memory-mcp:
    build: ../docker/memory-mcp
    environment:
      CH_URL: http://clickhouse:8123

  prefect-server:
    image: prefecthq/prefect:3-latest
    command: prefect server start --host 0.0.0.0
    ports: ["4200:4200"]

  prefect-worker:
    build: ../docker/agent       # flows defined in agent image
    command: prefect worker start --pool panops-local
    environment:
      PREFECT_API_URL: http://prefect-server:4200/api
    depends_on: [prefect-server, panops-agent]
```

Single-node installs use `docker compose -f docker-compose.yml -f docker-compose.inference.yml up`.

---

## Implementation Order & Micro-tasks

See `docs/tasks/` for individual task files.

---

## Definition of Done

- [ ] 3× llama-server instances running across all nodes, confirmed via `kubectl get pods -n panops -o wide`
- [ ] Dream cycle completes with >0 runbooks synthesised
- [ ] `pending_synthesis` retry flow processes at least one real pending row
- [ ] `investigate_incident` Prefect flow run visible in Prefect UI for a real happening
- [ ] Agent investigation trace written to `panops.investigation_traces` for at least one happening
- [ ] Agent memory written and read back across two separate dream cycles
- [ ] All components functional in Docker Compose single-node stack
- [ ] Test harness `test_05_llm.py` tier 2 passes against live cluster
