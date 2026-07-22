# SOC: Drop and Execute New Binary in Container

**Alert:** `soc-falco-critical` (falco_rule=Drop and execute new binary in container) | **Severity:** Critical | **MITRE:** T1059

## What fired

A binary was written to a container filesystem and then executed. This is a high-fidelity indicator of post-exploitation — attacker dropped a tool (reverse shell, miner, pivot binary) and ran it.

**Known false positive:** some apps write temporary helper binaries to `/tmp/<app>-*` — add a per-workload exception in `falco-custom-rules-cr.yaml`.

## Immediate triage

```bash
# Get the full Falco event
kubectl logs -n security -l app.kubernetes.io/name=falco --since=15m \
  | python3 -c "import sys,json; [print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin if 'Drop and execute' in l]"
```

Key fields to extract: `container.name`, `proc.exepath`, `proc.cmdline`, `k8s.pod.name`, `k8s.ns.name`.

## Investigation

```bash
# Check what the binary was and what it did
kubectl exec -n <namespace> <pod> -- ls -la <proc.exepath directory>
kubectl exec -n <namespace> <pod> -- cat /proc/<pid>/cmdline 2>/dev/null | tr '\0' ' '

# Look for outbound connections
kubectl exec -n <namespace> <pod> -- ss -tnp
kubectl exec -n <namespace> <pod> -- netstat -tnp 2>/dev/null
```

Check Hubble for unexpected egress from the pod in the past 30 minutes.

## Containment

```bash
# Isolate pod from network immediately
kubectl label pod -n <namespace> <pod> network-policy=isolated

# Preserve forensic state before killing
kubectl exec -n <namespace> <pod> -- tar czf /tmp/forensics.tar.gz /proc/self/fd /tmp /var/tmp 2>/dev/null
kubectl cp <namespace>/<pod>:/tmp/forensics.tar.gz ./forensics-$(date +%s).tar.gz

# Then delete
kubectl delete pod -n <namespace> <pod> --grace-period=0
```

## False positive handling

If this fires for a legitimate workload, add an exception to `k8s/falco/manifests/falco-custom-rules-cr.yaml`:
```yaml
- name: <workload_exception>
  fields: [container.name, proc.exepath]
  comps: [=, startswith]
  values:
    - [<container-name>, <path-prefix>]
```
