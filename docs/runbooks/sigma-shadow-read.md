# SOC: Credential File Read Attempt

**Alert:** `sigma-shadow-read` | **Severity:** High | **MITRE:** T1003.008

## What fired

`cat /etc/shadow` or similar access to `/etc/shadow` or `/etc/passwd` found in pod logs.

## Triage

```bash
# LogQL: {job="loki.source.kubernetes.pods"} |= "/etc/shadow" |= "cat"
```

Determine:
- Is this in a system namespace running a legitimate check (e.g. security scanner)?
- Is this in a workload namespace where it has no business?

## Investigation

```bash
kubectl exec -n <namespace> <pod> -- id
kubectl exec -n <namespace> <pod> -- cat /etc/shadow 2>&1 | head -3
```

If running as root and the shadow file is readable, check if the process also has network access to exfiltrate credentials.

## Remediation

- If container reads its own `/etc/shadow` and is not root-dependent: enforce `runAsNonRoot: true`
- If host shadow access: container escape in progress → [soc-falco-escape](soc-falco-escape.md)
- Rotate any hashed credentials that were exposed
