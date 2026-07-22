# SRE: PVC Near Capacity

**Alert:** `sre-pvc-capacity` | **Severity:** Warning

## What fired

A PersistentVolumeClaim is above 85% full.

## Triage

```bash
kubectl get pvc -A
kubectl exec -n <namespace> <pod> -- df -h | grep -v tmpfs
```

Prometheus query to find which PVC:
```
kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes > 0.85
```

## Common culprits

| Namespace | PVC | Likely cause |
|-----------|-----|-------------|
| app-b | repo-data | Repository growth |
| observability | clickhouse-data | Log/metrics retention |
| media-platform | media-storage | Media file accumulation |
| app-a | postgres-data | Database growth |

## Remediation

**Option 1: Expand the PVC (Ceph RBD supports online resize)**
```bash
kubectl patch pvc <name> -n <namespace> \
  -p '{"spec":{"resources":{"requests":{"storage":"<new-size>Gi"}}}}'
# Verify resize
kubectl get pvc -n <namespace> <name>
```

**Option 2: Clean up data**
```bash
# ClickHouse — drop old partitions
kubectl exec -n observability observability-clickhouse-clickhouse-0-0-0 -- \
  clickhouse-client -q "SELECT partition, sum(bytes_on_disk) FROM system.parts WHERE database='qryn' GROUP BY partition ORDER BY partition"

# Application data — run app-specific housekeeping (example)
kubectl exec -n <app-namespace> <app-pod> -- <app-cleanup-command>
```

**Option 3: Adjust retention policy** (for observability data)
Reduce `LABELS_DAYS` or `SAMPLES_DAYS` in the gigapipe deployment.
