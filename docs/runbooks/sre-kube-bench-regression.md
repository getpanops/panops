# SRE: kube-bench CIS Failed Check Regression

**Alert:** `sre-kube-bench-regression` | **Severity:** Warning

## What fired

The number of CIS benchmark failures has increased compared to 24 hours ago — a recent change introduced a new security posture regression.

## Triage

```bash
# Get latest kube-bench output
kubectl logs -n validation -l app=kube-bench --since=26h | grep '"status":"FAIL"' | \
  python3 -c "import sys,json; [print(json.loads(l)['test_number'], json.loads(l)['test_desc']) for l in sys.stdin if 'FAIL' in l]"
```

## Investigation

Compare today's failures against yesterday's:
```bash
# Loki query for today's failures
# {instance=~"validation/kube-bench.*"} |= '"status":"FAIL"' | json | line_format "{{.test_number}} {{.test_desc}}"

# Compare git log for changes in the last 24h
git log --since="24 hours ago" --oneline
```

New failures likely correlate with a recent Flux reconciliation. Check which kustomization reconciled around the time the regression appeared.

## Common regression sources

| Check ID | Description | Likely cause |
|----------|-------------|-------------|
| 1.2.x | API server flags | kube-apiserver config change |
| 4.1.x | Worker node config | kubelet config / Talos patch |
| 5.x | Kubernetes policies | PSA/PSS policy removed |

## Remediation

1. Identify the specific failed check IDs
2. Correlate with recent git commits
3. Revert or fix the offending config
4. Re-run kube-bench to confirm resolution: `kubectl delete job -n validation kube-bench && kubectl apply -f k8s/validation/manifests/kube-bench/`
