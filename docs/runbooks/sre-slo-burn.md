# SRE: SLO Error Budget Burn

**Alert:** `slo-canary-fast-burn` (and Pyrra-generated burn alerts) | **Severity:** Warning/Critical

## What fired

An SLO is burning error budget faster than sustainable:
- **Fast burn** (critical): burn rate will exhaust 30-day budget in ~1 hour
- **Slow burn** (warning): burn rate will exhaust 30-day budget in ~3 days

## Triage

```bash
# Which SLO is burning?
# Check alert labels: slo=<name>, severity=critical/warning

# For canary SLO (custom rule):
kubectl exec -n observability $(kubectl get pod -n observability -l app=gigapipe -o jsonpath='{.items[0].metadata.name}') -- \
  sh -c 'wget -qO- "http://localhost:3100/api/v1/query?query=probe_success%7Binstance%3D%22canary-service%22%7D"'

# For Pyrra SLOs:
kubectl get servicelevelobjective -A
```

## Investigation by SLO

| SLO | Target | Indicator | Service |
|-----|--------|-----------|---------|
| app-a-availability | 99.5% | probe_success | App A |
| app-b-availability | 99% | probe_success | App B |
| app-c-availability | 99% | probe_success | App C |
| app-d-availability | 99% | probe_success | App D |
| coredns-availability | 99.9% | SERVFAIL ratio | CoreDNS |

For probe-based SLOs, start with [sre-blackbox-probe-down](sre-blackbox-probe-down.md).

For CoreDNS SLO:
```bash
kubectl get pod -n dns-system
kubectl logs -n dns-system -l k8s-app=coredns --since=10m | grep -i "error\|servfail"
```

## Budget tracking

Pyrra dashboard: Grafana → SRE Alerts → SLO overview panel.

Fast burn = page + investigate immediately. Slow burn = investigate within business hours, trend is concerning.
