# SOC: Container Escape Attempt

**Alert:** `soc-falco-critical` (falco_rule matching escape/chroot patterns) | **Severity:** Critical | **MITRE:** T1611

## What fired

A container escape technique was detected — typically `chroot /proc/1/root` (host filesystem access), nsenter, or privileged capability abuse.

## Immediate triage

```bash
kubectl logs -n security -l app.kubernetes.io/name=falco --since=15m \
  | python3 -c "import sys,json; [print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin if 'scape' in l.lower() or 'hroot' in l]"
```

Key question: did the process gain access to the host PID namespace or host filesystem?

## Investigation

```bash
# Was the pod running privileged?
kubectl get pod -n <namespace> <pod> -o jsonpath='{.spec.containers[*].securityContext}'

# Did it have hostPID or hostNetwork?
kubectl get pod -n <namespace> <pod> -o jsonpath='{.spec.hostPID} {.spec.hostNetwork}'

# Check host node for unexpected processes
ssh <node> "ps aux | grep -v '\[' | sort -k3 -rn | head -20"
```

## Containment

A successful escape means the node may be compromised:
```bash
# Immediately cordon — no new pods
kubectl cordon <node>

# Delete the offending pod
kubectl delete pod -n <namespace> <pod> --grace-period=0

# Drain remaining pods from node
kubectl drain <node> --ignore-daemonsets --delete-emptydir-data
```

If node-level access is confirmed → consider reprovisioning the node (Talos: `talosctl reset`).

## Prevention

- Enforce `restricted` Pod Security Standard across non-system namespaces
- Tetragon policy to block `nsenter` and `chroot /proc/1/root` at syscall level
