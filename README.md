# PanOps

[![CI](https://github.com/getpanops/panops/actions/workflows/ci.yml/badge.svg)](https://github.com/getpanops/panops/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Unified SRE/SOC/NOC operations platform for Kubernetes.

Combines Sigma/YARA/Falco detection, ClickHouse-backed correlation, case-based reasoning, an optional LLM diagnosis layer, and autonomous remediation into a single deployable stack. Runs entirely offline — no telemetry, no external dependencies at runtime.

## Quick Start

```bash
# Core stack (detection + alerting, no ML or LLM)
cd deploy/docker-compose
cp .env.example .env && nano .env
docker compose up -d

# + ML (CBR similarity matching + dream cycle rule synthesis)
docker compose -f docker-compose.yml -f docker-compose.ml.yml up -d

# + LLM (BYO external API or local llama.cpp)
docker compose -f docker-compose.yml -f docker-compose.ml.yml -f docker-compose.llm.yml up -d
```

Grafana available at `http://localhost:3000`. Assembler API at `http://localhost:8080`.

## Architecture

```
signals ──► assembler ──► happenings (ClickHouse)
              │                │
        classify+correlate   dream cycle
        [Sigma/YARA/Falco]   (NREM rule synthesis)
        [drain3 log patterns]
        [metric anomalies]
              │
         [CBR kNN]  ← optional ML tier
         [LLM]      ← optional LLM tier
              │
        remediator ──► kubectl / flux / winrm
              │
        notifications ──► Matrix / Slack / Teams / webhook
```

## Components

| Component | Purpose |
|-----------|---------|
| `assembler` | Core brain: classifies, correlates, deduplicates, remediates |
| `sigma-scanner` | Polls ClickHouse for Sigma rule matches |
| `drain3-miner` | Mines log templates from Loki into ClickHouse |
| `intel-updater` | Pulls YARA/Sigma intel bundles from OCI registry |
| `memory-mcp` | FTS5-backed persistent memory for AI agents (ML tier) |
| `agent` | Conversational interface to PanOps via MCP (LLM tier) |

## Repository Layout

```
docker/          Dockerfiles + Python source for each component
rules/
  sigma/         Sigma detection rules + panops-clickhouse pipeline
  yara/          YARA rules for container image and log scanning
  falco/         Falco custom rules
  pyrra/         SLO definitions (Pyrra format)
grafana/
  alert-rules/   Grafana alert rule groups (YAML provisioning)
  dashboards/    Grafana dashboard JSON
clickhouse/
  schema/        ClickHouse schema (happenings, embeddings, rewards, etc.)
deploy/
  docker-compose/ Three-tier compose stack (core / ml / llm)
  kustomize/     Kubernetes manifests (Flux/Kustomize)
docs/            Architecture specs, runbooks, AIOps analysis
tools/           gen-assembler-cm.py, panops-bundle airgap script
tests/           Integration test harness
```

## Remediation Modes

Set `AUTO_REMEDIATION_MODE` on the assembler:

| Mode | Behaviour |
|------|-----------|
| `off` | Classify and notify only |
| `dry-run` | Run rules but skip all Kubernetes API writes (default) |
| `limited` | Only rules with `allowed_namespaces` set |
| `full` | Full autonomous remediation |

## CI

Images are built and pushed to `ghcr.io/getpanops/panops/*:latest` on every push to `main`.
Detection rules are validated on every pull request.

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml).
