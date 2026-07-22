# SOC: Falco Critical/Emergency Event

**Alert:** `soc-falco-critical` | **Severity:** Critical | **Source:** Falco runtime security

## What fired

A Falco rule at `Critical` or `Emergency` priority triggered. These are the highest-confidence detections — binary drops, kernel exploits, container escapes, or privilege escalation.

## Immediate triage (< 5 min)

```bash
# Identify the rule and affected pod
kubectl logs -n security -l app.kubernetes.io/name=falco --since=10m | grep -i "critical\|emergency" | tail -20

# Check what pod triggered it
kubectl get pod -A | grep <pod-name>
```

Check Grafana → SOC Alerts → Falco for `falco_rule` and `falco_priority` labels on the active alert.

## Investigation

```bash
# Full Falco event context
kubectl logs -n security -l app.kubernetes.io/name=falco --since=30m \
  | python3 -c "import sys,json; [print(json.dumps(json.loads(l), indent=2)) for l in sys.stdin if 'Critical' in l or 'Emergency' in l]"

# Pod forensics
kubectl describe pod -n <namespace> <pod>
kubectl get events -n <namespace> --sort-by='.lastTimestamp'
```

See rule-specific runbooks:
- Binary drop → [soc-falco-binary-drop](soc-falco-binary-drop.md)
- Shell in container → [soc-falco-shell](soc-falco-shell.md)
- Container escape → [soc-falco-escape](soc-falco-escape.md)
- Credential access → [soc-falco-credential](soc-falco-credential.md)

## Containment

If the pod is compromised:
```bash
# Label pod for Talon quarantine (if Talon is configured)
kubectl label pod -n <namespace> <pod> response=quarantine

# Or cordon the node if node-level compromise suspected
kubectl cordon <node>
```

## Escalation

- Confirmed compromise → incident response, preserve pod forensics before deletion
- False positive → add exception to `k8s/falco/manifests/falco-custom-rules-cr.yaml`
