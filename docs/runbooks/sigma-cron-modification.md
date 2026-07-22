# SOC: Cron Job Modification

**Alert:** `sigma-cron-modification` | **Severity:** Warning | **MITRE:** T1053

## What fired

`echo ... >> /etc/crontab` or similar crontab write found in pod logs — persistence mechanism adding a recurring scheduled task.

## Triage

```bash
# LogQL: {job="loki.source.kubernetes.pods"} |= "/etc/crontab" |= "echo"
```

Containers normally have no reason to modify crontab. This is suspicious unless the container is a backup or maintenance tool that explicitly manages cron.

## Investigation

```bash
kubectl exec -n <namespace> <pod> -- cat /etc/crontab
kubectl exec -n <namespace> <pod> -- crontab -l 2>/dev/null
kubectl exec -n <namespace> <pod> -- ls /etc/cron.d/ /var/spool/cron/
```

What command is scheduled? When does it run? Does it phone home or download anything?

## Remediation

```bash
# Remove the cron entry
kubectl exec -n <namespace> <pod> -- crontab -r

# If persistence is confirmed
kubectl delete pod -n <namespace> <pod> --grace-period=0
```

Note: in containerised workloads, cron modifications don't survive pod restart. The threat is primarily persistence during the pod's lifetime or if host cron is reachable.
