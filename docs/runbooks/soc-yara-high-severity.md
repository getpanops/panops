# SOC: YARA High-Severity Match Detected

**Alert:** `soc-yara-high-severity` | **Severity:** Critical | **MITRE:** T1505.003

## What fired

A YARA rule classified as high-severity (e.g. `WebShell`) matched a file in the cluster. This indicates a known-bad file pattern — web shell, dropper, or established malware signature.

## Immediate triage (act within 5 min)

```bash
# Get match details from yara-scanner logs
kubectl logs -n security -l app=yara-scanner --since=30m | grep "yara_match" | tail -20
```

Extract: matched rule name, file path, pod name, namespace.

## Investigation

```bash
# Examine the matched file
kubectl exec -n <namespace> <pod> -- cat <matched_file_path>
kubectl exec -n <namespace> <pod> -- ls -la <directory>

# Check how the file got there
kubectl exec -n <namespace> <pod> -- stat <matched_file_path>

# Look for other suspicious files in the same directory
kubectl exec -n <namespace> <pod> -- find /var/www /tmp /dev/shm -newer /etc/passwd -type f 2>/dev/null
```

## Containment

```bash
# Preserve evidence
kubectl exec -n <namespace> <pod> -- cat <matched_file_path> > ./evidence-$(date +%s).txt

# Isolate pod
kubectl delete pod -n <namespace> <pod> --grace-period=0

# If web-accessible service — check ingress logs for access to the file path
```

## Escalation

High-severity YARA match = likely active compromise. Initiate incident response. Check for other pods in the namespace that may have been reached from the affected pod.
