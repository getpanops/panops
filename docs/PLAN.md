# PanOps — What Remains

Last audited: 2026-07-13. Previous plans (HARDENING_PLAN.md, productisation/META.md,
productisation/phase-*.md, docs/tasks/) removed after confirming implementation status
against live code.

---

## Verified done (removed from backlog)

These were listed as outstanding in prior plans but confirmed implemented:

- CI CM drift gate (`validate-assembler-cm` job in `.github/workflows/ci.yml`)
- Degenerate embeddings fix (`_happening_description` includes drain3, sigma, anomaly content)
- Reward loop (`consolidation_rewards` → NREM → `dream_state` → `_effective_rule` deprioritises)
- Recurrence brittleness (`_compute_recurrence_brittleness` groups by route+namespace)
- Kill switch (`kill-switch-cm.yaml` + file-read on every action)
- YARA-X migration (`yr` baked into sigma-scanner image, no runtime download)
- intel-updater fix (`pull-oci` mode, no `--online` in manifests)
- Generic outbound webhooks (slack/teams/generic fan-out via `WEBHOOK_URLS`)
- Compose cleanup (clean 6-service stack)
- SOC shakedown (`test_03_soc.py` — 6 tests covering Falco→SOC, Sigma, YARA paths)
- memory-mcp (complete, deployed as sidecar in model-mesh)
- panops-agent (complete, deployed as sidecar in model-mesh)
- Windows Sigma rules + WinRM remediator (`rules/sigma/rules/windows/`, `_exec_winrm()`)
- Native ClickHouse Grafana datasource (provisioned in CM, panels not yet migrated)
- Dry-run pre-flight for all mutating remediator actions
- Deploy event ingestion pipeline (`panops.deploy_events`, `/deploy-event` endpoint, Flux notifications)
- Prefect removed — dream cycle self-schedules via assembler thread; `flows/` dir and prefect dep deleted from agent image
- Schema source gaps — `deploy_events` and `security_anomalies` already present in `create-schema.py` (confirmed)
- Dead-man's switch — `panops-happenings-stale` alert already in `grafana-alerting-rules-cm.yaml` (confirmed)
- VAP gap — `vap-ns-guard.yaml` already covers CREATE + DELETE + UPDATE on pods/deployments/jobs/configmaps (confirmed)
- pySigma cutover — CronJob already uses `ghcr.io/getpanops/panops/sigma-scanner:latest` with standard Sigma YAML rules and panops-clickhouse pipeline (confirmed)
- `_rule_flux_rollback` and `_rule_upsize` remediator rules
- Flux GitLab Receiver (push/merge → immediate reconcile)
- P0B remediation safety (guarded executor, parameterised CH queries, token validation, WinRM allowlist)

---

## Remaining tasks

### 5. Outcome feedback scoring — MEDIUM
The highest remaining gap from the Google AIOps comparison. When the LLM diagnoses an
incident and it resolves, no evaluation is performed on whether the diagnosis was correct.

Architecture (offline-first):
- Primary judge: does the resolution outcome (`rule_name`, `actions_taken`) embed close
  to the LLM's predicted route in CBR space?
- Secondary: Z-score of outcome vs similar past incidents
- Only escalate to LLM when ML signal is ambiguous or no close CBR match
- Feed discrepancies (predicted ≠ actual) as negative signal to the dream cycle

---

### 7. Airgap OCI supply chain — LOW
`tools/panops-bundle` is a single bash script. The full P3 vision (OCI-packaged intel,
`yr`, GGUF model, base images — cosign-signed, pulled from GHCR or internal mirror) is
not implemented. Needs a separate `panops-supply` repo with GitHub Actions.

---

### 8. Observability scaling steps 1-6 — LOW (as-needed)
Step 7 (native CH datasource) is deployed. Steps 1-6 are performance improvements:
- Step 1: drain3-miner → native CH SQL (DONE — drain3-miner was rewritten)
- Step 2: OTTL edge reduction in otelcol
- Step 3: Metric rollups + raw TTL
- Step 4: Skip indexes + compression
- Step 5: S3 tiering verification
- Step 6: Query governance + cache RAM tuning

Only relevant if query performance degrades again. Full details: `docs/OBSERVABILITY_SCALING.md`.

---

### 9. Windows k8s deployment — LOW (when Windows VMs exist)
WinRM remediator code and Windows Sigma rules are complete. Missing: homelab manifests
for a Windows agent pod that can reach Windows hosts via WinRM. Blocked on Windows VMs
being provisioned.

---

## Reference docs (keep)

- `docs/OBSERVABILITY_SCALING.md` — detailed scaling steps with DoD criteria
- `docs/SPEC-brain-ml.md` — ML architecture spec
- `docs/SPEC-inference-mesh.md` — inference mesh architecture
- `docs/productisation/SPEC.md` — OSIX knowledge architecture
- `docs/reviews/` — adversarial review evidence
- `docs/runbooks/` — operational runbooks
