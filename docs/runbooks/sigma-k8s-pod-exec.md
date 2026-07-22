# SOC: Kubernetes Pod Exec Access

**Alert:** `sigma-k8s-pod-exec` | **Severity:** Warning | **MITRE:** T1059

## What fired

`pods/exec` found in k8s audit logs — someone used `kubectl exec` or equivalent API call to get a shell into a running pod.

## Triage

Query Loki for the full audit event:
```
{job="kubernetes/audit"} |= "pods/exec" | json
```

Key fields: `user.username`, `objectRef.namespace`, `objectRef.name`, `responseStatus.code`.

## Assessment

| User | Target namespace | Action |
|------|-----------------|--------|
| Your admin user | Any | Authorized — close alert |
| CI service account | app namespace | Verify CI pipeline purpose |
| Unknown user | Any | Escalate immediately |
| Any user | kube-system | High suspicion, investigate |

## Investigation

```bash
# Who has exec permission?
kubectl auth can-i create pods/exec -A --as <username>

# Recent exec events
# Loki query: {job="kubernetes/audit"} |= "pods/exec" | json | line_format "{{.user_username}} → {{.objectRef_namespace}}/{{.objectRef_name}} @ {{.requestReceivedTimestamp}}"
```

## Remediation

If unauthorized:
- Revoke RBAC binding for the user/service account
- Audit what the user did during the exec session (Falco logs for that pod/timerange)
- Consider adding Kyverno/OPA policy to alert on exec to sensitive namespaces
