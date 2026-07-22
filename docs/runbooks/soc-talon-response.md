# SOC: Falco Talon Automated Response Triggered

**Alert:** `soc-talon-response` | **Severity:** Warning | **Source:** Falco Talon

## What fired

Talon executed an automated response action (pod termination, label, network isolation) in response to a Falco event.

## Immediate check

```bash
# See what Talon did
kubectl logs -n security -l app=falco-talon --since=30m | grep -i "trigger\|action\|pod" | tail -20

# Check for recently deleted pods
kubectl get events -A --sort-by='.lastTimestamp' | grep -i "kill\|delet" | tail -10
```

## Verify response was appropriate

1. Check which Falco rule triggered Talon (correlate timestamps in Falco logs)
2. Confirm the pod that was targeted matches the Falco event context
3. Verify the action taken (kill vs label vs network isolation)

## If response was incorrect (false positive)

```bash
# If a legitimate pod was killed, restart its controller
kubectl rollout restart deployment/<name> -n <namespace>

# Review and tighten Talon action rules to prevent recurrence
# Talon config: k8s/security/manifests/talon/
```

## Post-incident

If Talon correctly killed a compromised pod:
- Review the original Falco rule that fired
- Check for lateral movement from the pod before it was killed (Hubble flows)
- Verify the deployment came back clean
