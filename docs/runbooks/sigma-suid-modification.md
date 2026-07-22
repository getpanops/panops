# SOC: SUID/SGID Bit Modification

**Alert:** `sigma-suid-modification` | **Severity:** High | **MITRE:** T1548.001

## What fired

`chmod +s` on an executable found in pod logs — setting SUID/SGID is a persistence and privilege escalation technique.

## Triage

```bash
# LogQL: {job="loki.source.kubernetes.pods"} |= "chmod +s"
```

Identify the file that was chmod'd and the container it occurred in.

## Investigation

```bash
# Find SUID files in the container
kubectl exec -n <namespace> <pod> -- find / -perm /6000 -type f 2>/dev/null | grep -v proc

# Check if the binary is a known tool
kubectl exec -n <namespace> <pod> -- file <binary>
```

SUID on a shell binary (`bash`, `sh`, `python`) = immediate privilege escalation risk.

## Containment

```bash
# Remove SUID immediately if possible
kubectl exec -n <namespace> <pod> -- chmod -s <binary>

# If escalation is suspected, delete the pod
kubectl delete pod -n <namespace> <pod> --grace-period=0
```

Check the container's base image — SUID binaries installed at image build time are an image hygiene issue, not an active threat. Active threat = SUID set at runtime.
