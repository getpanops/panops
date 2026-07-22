# SRE: Pod OOMKilled

**Alert:** `sre-pod-oomkill` | **Severity:** Warning

## What fired

A container was killed by the kernel OOM killer — it exceeded its memory limit.

## Triage

```bash
kubectl get pod -A | grep -v Running | grep -v Completed
kubectl describe pod -n <namespace> <pod> | grep -A5 "Last State"
```

## Investigation

```bash
# Check memory limit vs actual usage trend
kubectl top pod -n <namespace> <pod>

# Recent OOMKill events
kubectl get events -n <namespace> --sort-by='.lastTimestamp' | grep OOM

# Memory usage history (Prometheus/Grafana)
# container_memory_working_set_bytes{namespace="<ns>", pod="<pod>"} over 24h
```

## Remediation

**Immediate:** Pod will restart automatically (Kubernetes restarts OOMKilled pods). Verify it came back healthy.

**Fix memory limit:**
```bash
# Find the deployment/statefulset and increase limits
kubectl edit deployment -n <namespace> <name>
# resources.limits.memory: increase by 25-50%
```

**If repeated OOMKills:** investigate for memory leak — heap dump, container restart policy (consider `LimitRange` with higher defaults for the namespace).

## Related

Repeated OOMKills on the same pod → check if `sre-pod-crashloop` also fired.
