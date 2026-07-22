# SRE: Blackbox Probe Down

**Alert:** `blackbox-probe-down` | **Severity:** Critical

## What fired

A blackbox HTTP probe has been failing for 2+ minutes. The `instance` label identifies the target.

## Triage

```bash
# Step 1: direct probe to bypass stale Prometheus data
BB_POD=$(kubectl get pod -n observability -l app=blackbox-exporter -o jsonpath='{.items[0].metadata.name}')
TARGET_URL="<from alert instance label — e.g. app-a>"
kubectl exec -n observability $BB_POD -- \
  wget -T10 -qSO- "http://localhost:9115/probe?target=<target-url>&module=http_2xx" 2>&1 | grep "probe_success"
```

`probe_success=1` → stale alert, will auto-clear on next scrape.  
`probe_success=0` → target is genuinely down. Continue below.

```bash
# Step 2: test the target URL directly from the blackbox pod
kubectl exec -n observability $BB_POD -- wget -T10 -qSO- "<target-url>" 2>&1 | head -3
```

If `wget download timed out`: **CNP block** (most likely cause — see CNP section below).  
If HTTP 4xx/5xx: **application-level failure** (see per-target table).

## Per-target investigation

| Instance | URL | Namespace | Port mapping |
|----------|-----|-----------|--------------|
| app-a | `http://app-a-server.app-a.svc.cluster.local:80/-/health/ready/` | app-a | svc:80 → pod:9000 |
| app-b | `http://app-b-web.app-b.svc.cluster.local:8080/-/health` | app-b | svc:8080 → pod:8080 |
| app-c | `http://app-c.app-c.svc.cluster.local:8008/health` | app-c | svc:8008 → pod:8008 |
| grafana | `http://grafana.observability.svc.cluster.local:80/api/health` | observability | — |
| coroot | `http://platform-coroot.observability.svc.cluster.local:8080/` | observability | — |
| pyrra | `http://pyrra-api.observability.svc.cluster.local:9099/` | observability | — |
| canary-service | `http://canary-service.validation.svc.cluster.local:80/` | validation | — |
| gigapipe | TCP `gigapipe.observability.svc.cluster.local:3100` | observability | — |

## CNP diagnosis

When `wget` times out from the blackbox pod, the packet is being dropped by Cilium policy. Two possible sides:

**Egress block (blackbox CNP):** the blackbox exporter is not allowed to egress to the target.
```bash
# Check blackbox egress BPF policy
BB_EP=$(kubectl exec -n kube-system ds/cilium -- \
  cilium-dbg endpoint list 2>/dev/null | grep blackbox-exporter | awk '{print $1}')
kubectl exec -n kube-system ds/cilium -- \
  cilium-dbg bpf policy get $BB_EP 2>/dev/null | grep -A5 "<target-namespace>"
```

**IMPORTANT — socket-level DNAT:** Cilium's kube-proxy replacement does DNAT at the socket level,
before TC egress policy evaluation. For services where `svc:port → pod:port` (e.g. app-a 80→9000),
the egress policy must allow the **pod port** (9000), not just the service port (80). Add both to
`k8s/observability/manifests/blackbox/blackbox-cnp.yaml`.

**Ingress block (target namespace CNP):** the target namespace is not allowing the blackbox pod in.
```bash
# Check if target's ingress CNP includes observability/blackbox-exporter
kubectl get cnp -n <target-namespace> -o yaml | grep -A5 "blackbox\|observability"
```

The target CNP must have:
```yaml
- fromEndpoints:
  - matchLabels:
      k8s:io.kubernetes.pod.namespace: observability
      k8s:app: blackbox-exporter
  toPorts:
  - ports:
    - port: "<pod-port>"
      protocol: TCP
```

Note: use `k8s:app: blackbox-exporter` (with `k8s:` prefix) for `fromEndpoints.matchLabels`. Bare
`app:` without the prefix causes silent selector mismatch and traffic is dropped.

**Confirm the fix worked with Hubble:**
```bash
# Watch for DENIED flows while running a test from the blackbox pod
kubectl exec -n kube-system ds/cilium -- \
  hubble observe --from-pod observability/$(kubectl get pod -n observability -l app=blackbox-exporter \
  -o jsonpath='{.items[0].metadata.name}') --type drop --last 20 2>/dev/null
```

## Common causes and fixes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `wget: download timed out` | CNP egress block on blackbox pod | Add pod-port to blackbox-cnp.yaml egress for target namespace |
| `wget: download timed out` | CNP ingress block on target pod | Add `k8s:app: blackbox-exporter` fromEndpoints rule to target ingress CNP |
| HTTP 403 | Auth required (some apps gate `/-/readiness`) | Switch to unauthenticated endpoint (`/-/health`) |
| HTTP 503 | Target application unhealthy | Check `kubectl get pod`, `kubectl describe pod`, `kubectl logs` |
| Pod restarting | CrashLoop | See [sre-pod-crashloop](sre-pod-crashloop.md) |
| `probe_success=0` but direct test passes | Stale Prometheus metric | Wait for next Alloy scrape (60s), or check if probe target URL changed |

## Auto-remediation viability

Blackbox probe failures are **poor candidates for auto-remediation** because the failure mode is
underdetermined: a timeout from the blackbox pod could mean CNP misconfiguration, genuine service
outage, or the probe target changing in a way that requires a human fix (e.g. auth endpoint change).

PanOps should classify these as **escalate** (not known or remediate), notify #sre with the instance
name and a direct test command, and leave the fix to a human. Auto-resolving a CNP block by widening
policy is outside the additive change principle.

The one safe automated action: if `probe_success` recovers within 5 minutes with no human action,
log it as transient and suppress future noise for that instance for 30 minutes.
