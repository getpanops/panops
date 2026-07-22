# SRE: Pod CrashLoopBackOff

**Alert:** `sre-pod-crashloop` | **Severity:** Warning

## What fired

A pod has restarted more than 5 times in the last hour.

## Triage

```bash
kubectl get pod -A | grep CrashLoop
kubectl describe pod -n <namespace> <pod> | grep -E "Restart Count|Last State|Exit Code|Reason"
```

Exit code interpretation:
- `1` — application error (check logs)
- `137` — OOMKilled → [sre-pod-oomkill](sre-pod-oomkill.md)
- `143` — SIGTERM (graceful shutdown that wasn't — check liveness probe)
- `2` — misuse of shell builtins (config/entrypoint issue)

## Investigation

```bash
# Previous container logs (before restart)
kubectl logs -n <namespace> <pod> --previous | tail -50

# Current logs
kubectl logs -n <namespace> <pod> | tail -30

# Events
kubectl get events -n <namespace> --sort-by='.lastTimestamp' | grep <pod>
```

## Common causes and fixes

| Cause | Fix |
|-------|-----|
| Missing ConfigMap/Secret | Check volume mounts: `kubectl describe pod` |
| OOMKilled | Raise memory limit |
| Failing liveness probe | Extend `timeoutSeconds`/`initialDelaySeconds` |
| Application startup error | Check app logs for panic/fatal |
| Image pull failure | Check imagePullPolicy and registry credentials |

## If crashing immediately on start

```bash
# Override entrypoint to debug
kubectl run debug --image=<same-image> -it --rm -- sh
```
