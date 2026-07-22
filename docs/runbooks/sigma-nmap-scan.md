# SOC: Network Scanning Tool Detected

**Alert:** `sigma-nmap-scan` | **Severity:** Warning | **MITRE:** T1046

## What fired

`nmap -sV` or similar in pod logs — network reconnaissance tool executed inside a container.

## Triage

```bash
# LogQL: {job="loki.source.kubernetes.pods"} |= "nmap " |= "-sV"
```

Is this:
- A legitimate security scan job (e.g. scheduled vulnerability assessment)?
- An attacker performing internal reconnaissance post-compromise?

## Investigation

```bash
kubectl get pod -n <namespace> <pod> -o jsonpath='{.metadata.labels}'
kubectl exec -n <namespace> <pod> -- ps aux | grep nmap
kubectl exec -n <namespace> <pod> -- cat /proc/<nmap-pid>/cmdline | tr '\0' ' '
```

Check Hubble for the source pod's recent outbound connections — what did nmap scan?

## Remediation

- If unauthorized: delete pod, investigate how nmap got installed
- If authorized scan job: exception the pod label/namespace in the Sigma rule
- Block nmap installation via OPA/Kyverno image policy if not needed
