# SOC: Suspicious Reverse Shell Detected

**Alert:** `sigma-reverse-shell` | **Severity:** Critical | **MITRE:** T1059.004

## What fired

Pattern `bash -i >& /dev/tcp/...` found in pod logs — classic bash reverse shell one-liner.

## Immediate triage

```bash
# Find the pod and log context
# LogQL in Grafana Explore:
# {job="loki.source.kubernetes.pods"} |= "bash -i" |= ">&" |= "/dev/tcp"
```

Extract the destination IP/host from the `/dev/tcp/<host>/<port>` pattern — this is the attacker's C2 server.

## Investigation

```bash
# Check current outbound connections from the pod
kubectl exec -n <namespace> <pod> -- ss -tnp

# Look for other indicators in Falco
kubectl logs -n security -l app.kubernetes.io/name=falco --since=30m | grep <pod-name>
```

Block the C2 IP at the perimeter immediately if identified.

## Containment

```bash
kubectl delete pod -n <namespace> <pod> --grace-period=0
```

Review Hubble flows for the pod to identify what data may have been exfiltrated.

## Notes

This is a log-pattern detection — it fires on the *command string* appearing in logs, which means it may catch injection attempts that were logged but not successfully executed. Confirm whether the shell actually connected before escalating to full IR.
