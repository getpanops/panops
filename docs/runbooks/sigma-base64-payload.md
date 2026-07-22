# SOC: Base64-Encoded Payload Execution

**Alert:** `sigma-base64-payload` | **Severity:** High | **MITRE:** T1059, T1027

## What fired

`base64 -d | bash` or similar in pod logs — a common obfuscation technique to deliver and execute payloads while evading string-based detection.

## Triage

```bash
# LogQL: {job="loki.source.kubernetes.pods"} |= "base64 -d" |= "bash"
```

Identify the full command line — what was the base64 string? Decode it:
```bash
echo "<base64_string>" | base64 -d
```

## Investigation

If the decoded payload reveals a reverse shell, dropper, or miner — escalate immediately:
- Reverse shell → [sigma-reverse-shell](sigma-reverse-shell.md)
- Binary dropper → [soc-falco-binary-drop](soc-falco-binary-drop.md)

```bash
kubectl exec -n <namespace> <pod> -- ps aux
kubectl exec -n <namespace> <pod> -- ss -tnp
```

## Containment

```bash
kubectl delete pod -n <namespace> <pod> --grace-period=0
```

Review how the base64 payload arrived — log injection via web request, environment variable, or mounted secret.
