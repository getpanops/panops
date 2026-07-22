# SRE: Node Memory Pressure

**Alert:** `sre-node-memory` | **Severity:** Warning

## What fired

A node's memory utilisation exceeded 90%.

## Triage

```bash
kubectl top nodes
kubectl describe node <node> | grep -A10 "Conditions:\|Allocated resources:"
```

## Investigation

```bash
# Find memory-hungry pods on the node
kubectl top pod -A --sort-by=memory | head -15

# Check for OOMKill events in last hour
kubectl get events -A --sort-by='.lastTimestamp' | grep OOMKill | tail -10

# Node memory detail
kubectl exec -n kube-system $(kubectl get pod -n kube-system -l k8s-app=metrics-server -o jsonpath='{.items[0].metadata.name}') \
  -- sh -c "cat /proc/meminfo" 2>/dev/null || ssh <node> "free -h && cat /proc/meminfo | head -20"
```

## Remediation

**If OOMKills are happening:** raise limits on offending pods (see [sre-pod-oomkill](sre-pod-oomkill.md))

**If no single pod is the cause:**
```bash
# Evict lower-priority pods to free memory
kubectl drain <node> --ignore-daemonsets --delete-emptydir-data --dry-run
```

**If sustained pressure across all nodes:** cluster is undersized for current workload — review pod resource requests.

**Emergency:** if node enters `MemoryPressure` condition, Kubernetes will begin evicting BestEffort and Burstable pods automatically.
