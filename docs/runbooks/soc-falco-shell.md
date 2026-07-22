# SOC: Terminal Shell in Container

**Alert:** `soc-falco-critical` (falco_rule=Terminal shell in container) | **Severity:** Critical | **MITRE:** T1059.004

## What fired

An interactive shell was spawned inside a running container. Legitimate workloads do not open TTYs — this strongly indicates hands-on-keyboard access by an attacker or unauthorized `kubectl exec`.

## Immediate triage

```bash
# Get full event context
kubectl logs -n security -l app.kubernetes.io/name=falco --since=15m \
  | python3 -c "import sys,json; [print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin if 'Terminal shell' in l]"
```

Key fields: `user.name`, `proc.cmdline`, `k8s.pod.name`, `k8s.ns.name`.

## Investigation

```bash
# Check audit logs for who exec'd in
kubectl logs -n observability -l app=alloy-node --since=30m 2>/dev/null | grep "pods/exec" | tail -10

# Or query Loki for k8s audit logs with pod exec
# LogQL: {job="kubernetes/audit"} |= "pods/exec" | json | line_format "{{.user_username}} exec'd into {{.objectRef_namespace}}/{{.objectRef_name}}"
```

Determine:
1. Was this an authorized `kubectl exec` (check `user.name` in audit)?
2. Was it spawned by a running process inside the container (malware)?

## Containment

If unauthorized:
```bash
# Terminate the shell session (kills the exec)
# Grafana alert label contains the pod — cordon if node access suspected
kubectl delete pod -n <namespace> <pod> --grace-period=0
kubectl cordon <node>  # if node-level access is suspected
```

## Escalation

Unauthorized shell access with non-admin user → full incident response. Collect audit trail from `{job="kubernetes/audit"}` in Loki before pod deletion.
