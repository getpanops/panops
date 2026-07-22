# SOC: Container Escape via Chroot

**Alert:** `sigma-chroot-escape` | **Severity:** Critical | **MITRE:** T1611

## What fired

`chroot /proc/1/root` pattern in pod logs — this technique mounts the host root filesystem inside a container, breaking out of the container boundary.

## Immediate action

This is a confirmed or in-progress container escape. Act immediately.

```bash
# Cordon the node immediately
kubectl cordon <node>

# Identify and kill the pod
kubectl delete pod -n <namespace> <pod> --grace-period=0
```

## Investigation

```bash
# Get Falco context for the same event
kubectl logs -n security -l app.kubernetes.io/name=falco --since=15m | grep -i "chroot\|escape"

# Check if attacker reached the host filesystem
# Look for new files on the node
ssh <node> "find / -newer /etc/passwd -maxdepth 3 -type f 2>/dev/null | grep -v proc | grep -v sys"
```

## Containment

If host access is confirmed:
1. Drain and cordon the node
2. Check all other pods on the node for lateral movement
3. Consider node reprovision: `talosctl reset --nodes <ip> --graceful=false`
4. Rotate all service account tokens that had pods on that node

## Related

See also [soc-falco-escape](soc-falco-escape.md) for Falco-detected escape variants.
