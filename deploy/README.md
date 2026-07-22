# PanOps Deployment Guide

Two deployment paths: **Kubernetes** (full stack) or **Docker Compose** (standalone host, reduced feature set).

---

## Kubernetes

### Prerequisites

| Prerequisite | Minimum version | Notes |
|---|---|---|
| Kubernetes | 1.29 | Talos recommended |
| Cilium CNI | 1.16 | NetworkPolicy + Gateway API required |
| cert-manager | 1.14 | Used by ClickHouse operator webhook |
| Flux | 2.3 | Optional — for GitOps path only |
| S3-compatible store | — | For ClickHouse backups + log retention |

### Required secrets

`configure.py` generates all secrets from `values.yaml`. If you manage secrets externally (Vault, SOPS, External Secrets Operator), create these manually before applying:

**Namespace: `observability`**

| Secret name | Keys | Purpose |
|---|---|---|
| `clickhouse-password` | `password` | ClickHouse default user password |
| `clickhouse-s3-credentials` | `access_key_id`, `secret_access_key`, `endpoint`, `bucket` | S3 for log retention + backup |
| `coroot-clickhouse` | `password` | Coroot → ClickHouse access |
| `grafana-admin-credentials` | `admin-user`, `admin-password` | Grafana login |
| `grafana-smtp-credentials` | `host`, `user`, `password`, `from_address`, `from_name` | Email alerts (optional) |
| `grafana-oidc-credentials` | `oauth-client-id`, `oauth-client-secret` | SSO (optional) |

**Namespace: `security`**

| Secret name | Keys | Purpose |
|---|---|---|
| `clickhouse-password` | `password` | Same password as observability |

**Namespace: `panops`**

| Secret name | Keys | Purpose |
|---|---|---|
| `clickhouse-password` | `password` | Same password as observability |

**Namespace: `falco`**

| Secret name | Keys | Purpose |
|---|---|---|
| `falco-talon-config` | `config.yaml` | Talon listen address + config |

### Configure and deploy

```bash
# 1. Create your values file
cp deploy/values.yaml.example deploy/values.yaml
$EDITOR deploy/values.yaml

# 2. Generate secrets + overlay
python3 deploy/configure.py

# 3. Apply operators (CRDs + controllers)
kubectl apply -k deploy/kustomize/operators/
kubectl wait --for=condition=Available deployment \
  -n clickhouse-operator-system -l app=clickhouse-operator --timeout=120s
kubectl wait --for=condition=Available deployment \
  -n falco -l app.kubernetes.io/name=falco-operator --timeout=120s

# 4. Apply the stack
kubectl apply -k deploy/kustomize/overlays/default/
```

### GitOps (Flux)

```bash
# Edit the repo URL in:
#   deploy/flux/gitrepository.yaml
kubectl apply -f deploy/flux/gitrepository.yaml
kubectl apply -f deploy/flux/kustomizations.yaml
```

Point `path:` in `kustomizations.yaml` at `./deploy/kustomize/overlays/default` once you've committed your generated overlay (without secrets — those stay gitignored).

---

## Docker Compose

Suitable for a single Docker host. Runs: ClickHouse, Gigapipe (Loki+Prometheus → ClickHouse), otelcol-contrib, Grafana, Pyrra (SLOs), PanOps assembler, Sigma scanner. Optional: PanOps agent. No standalone Prometheus — Gigapipe provides both APIs backed by ClickHouse, the same as the Kubernetes deployment.

**Not included vs Kubernetes:** Falco + Talon (kernel-level), Coroot (eBPF dependency), KeeperCluster HA.

```bash
cd deploy/docker-compose
cp .env.example .env
$EDITOR .env
# To include the agent, memory-mcp, and Prefect, add -f flags:
docker compose -f docker-compose.yml -f docker-compose.inference.yml -f docker-compose.memory-mcp.yml -f docker-compose.agent.yml -f docker-compose.prefect.yml up -d
# Or without agent/Prefect:
docker compose up -d
docker compose logs -f panops-assembler
```

| Service | Port | URL |
|---|---|---|
| Grafana | 3000 | `http://localhost:3000` |
| Pyrra SLO UI | 9099 | `http://localhost:9099` |
| Gigapipe (Loki/Prometheus) | 3100 | `http://localhost:3100` |
| otelcol OTLP gRPC | 4317 | `otelcol:4317` |
| otelcol OTLP HTTP | 4318 | `http://localhost:4318` |
| otelcol self-metrics | 8888 | `http://localhost:8888/metrics` |
| Prefect Server | 4200 | `http://localhost:4200` |
| PanOps assembler | 8080 | `http://localhost:8080` |
| PanOps agent | 8081 | `http://localhost:8081` |
| Memory MCP | 8082 | `http://memory-mcp:8082` (internal) |

Configure Grafana to send alerts to `http://panops-assembler:8080/webhook` using the JSON webhook contact point.

SLO definitions live in `rules/pyrra/`. Pyrra queries Gigapipe's PromQL endpoint to compute burn rates on-the-fly — no separate rule-generation step or recording rules needed.

---

## Architecture overview

```
otelcol-contrib (DaemonSet / container)
  ├── pod/container logs → Gigapipe (ClickHouse Loki-compatible)
  ├── host/node metrics → Gigapipe (Prometheus-compatible)
  └── Falco JSON events with MITRE enrichment (cluster only)

ClickHouse
  ├── panops.happenings            incident records
  ├── panops.remediation_outcomes  per-action audit log
  ├── qryn.sigma_matches         Sigma rule hits
  └── qryn.security_anomalies    statistical anomalies

Grafana → alert rules → PanOps assembler (SRE/SOC/MIXED)
        → alert rules → matrix-webhook-noc (NOC direct)

Falco + Talon       runtime threat detection + automated response
Sigma scanner       polls ClickHouse for rule matches
YARA scanner        DaemonSet scanning container image layers
Baseline collector  builds statistical ClickHouse baselines

PanOps assembler
  ├── classifies: domain (SRE/SOC/NOC/MIXED) + route (structured/known/novel/escalate)
  ├── deduplicates: 30-minute happening window
  ├── remediates: AUTO_REMEDIATION_MODE gate (default: dry-run)
  ├── notifies: Matrix rooms (SRE/SOC/NOC)
  └── novel/escalate → LLM worker job (Qwen2.5-3B)

Pyrra               SLO tracking + burn-rate alerting (k8s operator or filesystem mode)
Coroot              automatic service dependency mapping (Kubernetes only)
Blackbox exporter   external endpoint probing
```

## Customisation

All options are in `deploy/values.yaml`. Re-run `python3 deploy/configure.py` after any change to regenerate the overlay.

Key options:

| Option | Default | Description |
|---|---|---|
| `domain` | `example.com` | Base domain for HTTPRoutes |
| `storageClass` | `local-path` | PVC storage class |
| `panops.remediationMode` | `dry-run` | `off` / `dry-run` / `limited` / `full` |
| `matrix.enabled` | `false` | Enable Matrix alert routing |
| `grafana.smtp.enabled` | `false` | Enable email alerts |
| `grafana.oidc.enabled` | `false` | Enable SSO |
| `unifi.enabled` | `false` | Enable UniFi Poller metrics |
