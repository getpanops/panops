# Unified SRE + SOC + NOC Observability Platform — SDD

## Vision

A fully FOSS, self-hosted observability platform that replaces Datadog, Splunk, and Dynatrace for
infrastructure at homelab-to-SME scale. Single GitOps-deployed bundle covering the full NOC/SRE/SOC
triad: availability monitoring, SLO tracking, threat detection, compliance scanning, and automated
validation of the detection stack itself.

Productized in a later iteration as a standalone repo. This iteration closes the gap between
"deployed components" and "coherent product."

---

## Architecture

```
                         ┌─────────────────────────────────┐
                         │         Data Sources             │
                         │  Pods · Nodes · Audit · Suricata │
                         │  Falco · Tetragon · Blackbox     │
                         │  Hubble · Coroot · kube-bench    │
                         └────────────────┬────────────────-┘
                                          │ logs / metrics / traces
                                          ▼
                         ┌────────────────────────────────-─┐
                         │              Alloy               │
                         │  node DaemonSet + cluster agent  │
                         │  drop/filter stages before ingest│
                         └────────────────┬────────────────-┘
                                          │ Loki push / prom remote_write
                                          ▼
                         ┌───────────────────────────────────┐
                         │            gigapipe               │
                         │  qryn: Loki + PromQL + Tempo      │
                         │  ──────────────────────────────   │
                         │           ClickHouse              │
                         │   hot (local PVC) / cold (RGW S3) │
                         └──────┬──────────────┬────────────-┘
                                │              │
                    ┌───────────▼──┐    ┌──────▼──────────────┐
                    │  prometheus- │    │       Coroot         │
                    │    ruler     │    │  APM + service map   │
                    │ (evaluates   │    │  → remote_write back │
                    │ PrometheusR- │    │    into gigapipe     │
                    │   ules →     │    └─────────────────────-┘
                    │ gigapipe)    │
                    └──────────────┘
                                          │
                                          ▼
                         ┌───────────────────────────────────┐
                         │             Grafana               │
                         │  dashboards · alerting · SLOs     │
                         │  datasources: Loki, Prometheus,   │
                         │  Coroot (all → gigapipe)          │
                         └──────────────┬────────────────────┘
                                        │ webhook
                                        ▼
                         ┌──────────────────────────────────-┐
                         │         matrix-webhook            │
                         │   SRE Alerts room / SOC Alerts    │
                         └───────────────────────────────────┘
```

---

## Component Inventory

### Current (deployed)

| Component | Namespace | Role | Notes |
|---|---|---|---|
| gigapipe (qryn) | observability | Unified signals backend | Loki+PromQL+Tempo → ClickHouse |
| ClickHouse | observability | Storage | 180Gi PVC, 2-day TTL on all tables |
| Grafana | observability | Dashboards + alerting | Config via ConfigMaps |
| Alloy node DaemonSet | observability | Log + metric collection | Drop filters for noise reduction |
| Alloy cluster agent | observability | Cluster-level scraping | kubelet, audit, blackbox (planned) |
| prometheus-ruler | observability | Recording rule evaluator | Stateless, 2h local TSDB, remote_write to gigapipe |
| Sloth | observability | SLO rule generator | **To be replaced by Pyrra** |
| Coroot | observability | APM + service map | CR named `platform`, standalone UI at coroot.YOUR_DOMAIN |
| matrix-webhook | observability | Alert delivery | SRE + SOC Matrix rooms |
| Falco | falco-operator | Runtime threat detection | **Moving to security namespace** |
| Falco Talon | falco-operator | Auto-response | **Moving to security namespace** |
| Trivy | trivy-system | Vuln scanning | **Moving to security namespace** |
| Tetragon | kube-system | eBPF kernel tracing | DaemonSet, 3 TracingPolicies active |
| Suricata | hypervisors | Network IDS | EVE JSON → rsyslog → Alloy → Loki |
| Network poller | observability | Network-device metrics | **Optional add-on, excluded from product manifest** |

### Planned (this iteration)

| Component | Namespace | Role |
|---|---|---|
| Pyrra | observability | SLO management + UI (replaces Sloth) |
| blackbox-exporter | observability | Synthetic HTTP/TCP/ICMP probes |
| YARA scanner | security | File/memory malware scanning on nodes |
| kube-bench | security | CIS benchmark CronJob |
| Atomic Red Team jobs | validation | Detection stack validation |
| Canary service | validation | SLO pipeline synthetic testing |

---

## Namespace Layout

| Namespace | Contents | Product / Optional |
|---|---|---|
| observability | gigapipe, ClickHouse, Grafana, Alloy, Coroot, Pyrra, blackbox, matrix-webhook, prometheus-ruler | Product |
| security | Falco, Talon, Trivy, YARA, kube-bench | Product |
| kube-system | Tetragon, Cilium, Alloy node DS | Product (platform-level) |
| validation | ART jobs, canary service, SLO tests | Product (opt-in) |
| observability (network-poller) | Network-device metrics poller | **Optional** — opt-in add-on |

---

## Data Flows

### Log pipeline
```
Pod stdout → Alloy node DS → loki.process (drop/filter) → gigapipe Loki API → ClickHouse samples_v3
Suricata EVE JSON → rsyslog → Alloy syslog receiver → gigapipe → ClickHouse
kube-apiserver audit → Alloy file reader → audit_filter (drop read-only) → gigapipe
Tetragon log file → Alloy file reader → tetragon_filter → gigapipe
Falco JSON → Alloy pod scraper → falco pipeline (JSON parse, label promote) → gigapipe
kube-bench JSON → Alloy pod scraper → gigapipe
YARA matches → DaemonSet stdout → Alloy pod scraper → gigapipe
```

### Metrics pipeline
```
kubelet → Alloy node DS → gigapipe prom remote_write → ClickHouse metrics_15s
blackbox-exporter → Alloy cluster agent scrape → gigapipe
Coroot node-agent → Coroot platform → gigapipe remote_write (coroot_* metrics)
Network poller → Alloy cluster agent scrape → gigapipe
Hubble → Alloy cluster agent scrape → gigapipe
prometheus-ruler → evaluates PrometheusRules → gigapipe (recording rule results)
```

### Alert pipeline
```
gigapipe ← Grafana (PromQL/LogQL queries on schedule)
Grafana alert rule fires → Alertmanager → routes to SRE Alerts or SOC Alerts contact point
Contact point → matrix-webhook → Matrix room
Contact point → email (critical only, 30m sustained)
Falco event → Talon → kill/isolate action (auto-response, no human needed)
```

### SLO pipeline
```
Pyrra ServiceLevelObjective CR → Pyrra operator → PrometheusRule CRDs
prometheus-ruler watches PrometheusRule CRDs → evaluates burn rate PromQL against gigapipe
→ remote_writes slo:* recording rule results back into gigapipe
Grafana reads slo:* metrics → SLO dashboards + burn rate alert rules
```

---

## Interface Contracts

| Producer | Consumer | Protocol | Endpoint |
|---|---|---|---|
| Alloy | gigapipe (logs) | HTTP POST | `:3100/loki/api/v1/push` |
| Alloy | gigapipe (metrics) | HTTP POST | `:3100/api/prom/push` |
| prometheus-ruler | gigapipe (read) | PromQL HTTP | `:3100/api/prom/api/v1/query_range` |
| prometheus-ruler | gigapipe (write) | remote_write | `:3100/api/prom/push` |
| Coroot | gigapipe (read) | PromQL HTTP | `:3100` |
| Coroot | gigapipe (write) | remote_write | `:3100/api/prom/push` |
| Grafana | gigapipe | Loki + PromQL | `:3100` |
| Grafana | matrix-webhook | HTTP webhook | `:8080/grafana` |
| Falco | Talon | HTTP | `:2803` |
| Suricata | rsyslog | file tail | `/var/log/suricata/eve.json` |
| rsyslog | Alloy | UDP syslog | `alloy-node:514` |
| ClickHouse | Ceph RGW | S3 API | `rgw.YOUR_DOMAIN:443` (cold tier) |

---

## Homelab vs Product Boundary

The product manifest is everything **except**:
- Network poller (network-device-specific) — an optional add-on that lives in a separate kustomization component
- Hypervisor-level Ansible roles (Suricata, auditd, rsyslog) — documented as "bring your own host agent"
- Any hardcoded domain names (`YOUR_DOMAIN`) — parameterised via vars in the product repo

Everything else in `k8s/observability/`, `k8s/security/`, `k8s/tetragon/`, and `k8s/validation/`
is product-generic and ships in the standalone repo.

---

## Phase Breakdown

### Phase 0 — Housekeeping
*Prerequisite for everything else. Namespace rename touches CNPs and Alloy labels that later phases depend on.*

- Consolidate Falco + Talon + Trivy into `security` namespace
- Replace Sloth with Pyrra; verify SLO recording rules regenerate

### Phase 1 — SRE/NOC Completeness
*Fills the availability monitoring gap. Blackbox is the most impactful missing primitive.*

- Blackbox exporter (synthetic probes + probe-down alerts)
- awesome-prometheus-alerts rule groups (node, k8s, cert-manager)
- Email contact point re-enabled (critical-only, 30m sustained)
- Network-poller dashboards + alerts (optional module)

### Phase 2 — Storage + Network Visibility
*Extends data longevity and adds network observability layer.*

- ClickHouse S3 cold tiering via Ceph RGW
- Cilium/Hubble metrics dashboards

### Phase 3 — SOC Completeness
*Closes detection coverage gaps and adds structured threat intelligence.*

- Suricata IDS dashboard
- Sigma→LogQL translation pipeline (community ruleset → Grafana alert rules)
- MITRE ATT&CK heatmap (coverage vs gaps)

### Phase 4 — Validation Framework
*Answers "does our monitoring actually work?" before a real incident does.*

- Atomic Red Team Jobs (simulate ATT&CK techniques, verify alerts fire)
- kube-bench CronJob (CIS benchmark, regression detection)
- Synthetic SLO failure tests (end-to-end alert pipeline verification)

### Phase 5 — Extended Detection
*Lower priority; adds depth to the security layer.*

- YARA scanning DaemonSet (file/memory malware detection)

---

## Acceptance Criteria (per phase)

**Phase 0 done when:**
- `kubectl get pods -n security` shows Falco, Talon, Trivy all Running
- `falco-operator` and `trivy-system` namespaces no longer exist
- Pyrra UI accessible at pyrra.YOUR_DOMAIN; all 4 SLO burn rate recording rules present in gigapipe
- Zero Grafana alert rules referencing old namespace labels

**Phase 1 done when:**
- Blackbox probes for all key services appear in gigapipe; probe-down alert fires on a deliberately stopped service
- New alert rules appear in Grafana without duplicating existing ones
- Test email delivered via Grafana alert test button
- Network-device dashboards show live data; WAN-down alert wired

**Phase 2 done when:**
- ClickHouse `system.disks` shows both `hot` and `cold` (S3) disks
- A forced TTL expiry (or manual OPTIMIZE) moves parts to S3; queries return correct results across both tiers
- Hubble dashboard shows live policy verdict data

**Phase 3 done when:**
- Suricata dashboard shows events from at least one triggered signature in last 24h
- At least 10 Sigma-derived LogQL alert rules active in Grafana
- ATT&CK heatmap renders with coverage/gap colouring sourced from live Loki data

**Phase 4 done when:**
- Each ART Job triggers its expected Falco/Tetragon alert (verifiable in Loki)
- kube-bench CronJob runs and results appear in Grafana dashboard
- Error injection test triggers SLO burn rate alert within expected window; Matrix notification received

**Phase 5 done when:**
- YARA DaemonSet running on all nodes; test match (known-bad YARA string dropped in /tmp) triggers SOC alert

---

## Future Iterations

- **Correlation + derivative metrics**: stddev baselines, anomaly scoring, leading indicators from the accumulated data
- **Pyrra ruler consolidation**: drop prometheus-ruler once gigapipe's built-in ruler or Pyrra covers evaluation natively
- **ClickHouse → gigapi migration path**: evaluate DuckDB+Parquet as hot/warm store once gigapi matures
- **SOAR layer**: Talon covers basic auto-response; graduate to full playbook orchestration (Shuffle/n8n) when multi-operator or compliance requirements emerge
- **Standalone product repo**: extract generic manifests, parameterise domains, write operator guide
