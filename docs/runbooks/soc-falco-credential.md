# SOC: Credential File Access in Container

**Alert:** `soc-falco-critical/error` (falco_rule matching credential/shadow/passwd patterns) | **Severity:** High | **MITRE:** T1003.008

## What fired

A process inside a container attempted to read `/etc/shadow`, `/etc/passwd`, or another credential store. Containers should never need host credential files.

## Immediate triage

```bash
kubectl logs -n security -l app.kubernetes.io/name=falco --since=15m \
  | python3 -c "import sys,json; [print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin if 'shadow' in l or 'passwd' in l or 'redential' in l]"
```

Key fields: `fd.name` (which file was read), `proc.cmdline`, `container.name`.

## Investigation

```bash
# Was the file read from the container's own /etc or the host?
# /etc/shadow in a container = usually container's own (less critical)
# /proc/1/root/etc/shadow = host filesystem read (critical)

kubectl exec -n <namespace> <pod> -- ls -la /etc/shadow /etc/passwd 2>/dev/null
```

Determine:
1. Is this a container running as root reading its own `/etc`? (lower risk, but still investigate)
2. Did it access host credentials via `/proc/1/root`? (critical — escape in progress)

## Remediation

```bash
# Rotate any credentials the container had access to
# Check what secrets are mounted
kubectl get pod -n <namespace> <pod> -o jsonpath='{.spec.volumes}'

# Rotate Kubernetes secrets if compromised
kubectl create secret generic <name> --from-literal=key=<new-value> --dry-run=client -o yaml | kubectl apply -f -
```

Force re-authentication for any service accounts associated with the pod.

## Escalation

If host credential access confirmed → treat as node compromise. Rotate all service account tokens on the node.
