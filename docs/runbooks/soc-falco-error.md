# SOC: Falco Error Priority Sustained

**Alert:** `soc-falco-error` | **Severity:** Warning | **Source:** Falco runtime security

## What fired

More than 3 Falco `Error`-priority events in 5 minutes for the same rule. Error priority is below Critical but above Warning — sustained firing suggests either an active threat or an overly sensitive rule.

## Triage

```bash
kubectl logs -n security -l app.kubernetes.io/name=falco --since=15m \
  | python3 -c "import sys,json; [print(l.strip()) for l in sys.stdin if '\"Error\"' in l]" | head -20
```

Determine the `falco_rule` from the alert label and assess:
- Is this the same event repeating (single actor, automated tool)?
- Is it spreading across different pods/namespaces?

## Common Error-Priority Rules

| Rule | Likely cause | Action |
|------|-------------|--------|
| Write below binary dir | Package manager in container | Investigate or exception |
| Read sensitive file | App reading own config | Check path, add exception if legitimate |
| System binary executed by non-root | Build/init scripts | Review or exception |

## Remediation

If active threat → escalate to [soc-falco-critical](soc-falco-critical.md) runbook.

If noisy rule → add scoped exception to `k8s/falco/manifests/falco-custom-rules-cr.yaml` referencing the specific container and binary path.
