# Observability Extended Coverage
## Beyond Kubernetes: Hypervisors, Network, and End-User Devices

**Status:** Design / Pre-implementation  
**Related:** `docs/observability-platform-sdd.md`, `docs/panops-autoops-spec.md`

---

## Scope

The current observability stack (Alloy → Loki/ClickHouse/Prometheus, Falco, Hubble) provides
deep instrumentation for Kubernetes workloads. This document covers extending that coverage to:

- Hypervisor hosts (e.g. node-01/node-02/node-03)
- Network layer (gateway/router and switches)
- End-user devices (future)

The goal is a unified topology graph and event stream across all layers so PanOps and alerting
decisions can account for the full causal chain — not just what's happening in K8s.

---

## Key Constraint: eBPF Portability

**Hubble is Cilium-only and K8s-only.** It is not a standalone eBPF tool. Hubble exposes flow
data generated as a side-effect of Cilium enforcing network policy. Without Cilium as the CNI,
there is no Hubble. Cannot be used on hypervisors or network appliances.

**Coroot node-agent** is eBPF-at-kernel but designed around K8s concepts (pod/namespace labelling).
Running it on a bare hypervisor host is unsupported and produces degraded data.

**eBPF itself is portable to any Linux host with a modern kernel.** Debian-based hypervisor hosts
have full eBPF capability. A proprietary locked-down network appliance running vendor firmware —
eBPF is not viable.

The instrumentation approach must differ per layer.

---

## Layer: Hypervisor Hosts

Debian-based hypervisor hosts run standard Linux. All eBPF tooling works.

### Security events
- **Falco** — provisioned via configuration management. Runs in eBPF mode on the hypervisor host,
  covers syscall-level events for host processes AND provides some visibility into workloads
  running in VMs (via the host kernel's view). For important non-K8s VMs, run a Falco or
  Tetragon agent inside the VM itself.
- **Tetragon standalone** — Isovalent designed Tetragon to run outside K8s. Same enforcement
  and observability capability as in-cluster but as a standalone systemd service. More powerful
  than Falco for enforcement (BPF LSM SIGKILL). Worth evaluating as the hypervisor host security
  agent alongside or instead of Falco.

### Metrics and logs
- **Alloy** — already planned. node_exporter-style metrics (CPU, memory, disk, network
  interfaces) plus log collection from `/var/log/` and journald.

### Network flows (VM-to-VM and VM-to-external)
All inter-VM traffic on the hypervisor transits the Linux bridge (`vmbr0`, `vmbr1`, etc.). This means
an eBPF program or packet accounting daemon attached to the bridge interface can observe
everything without touching the VMs.

**Recommended: `pmacctd` (pmacct daemon)**
- Attaches to bridge interfaces via AF_PACKET or eBPF
- Generates IPFIX/NetFlow records (src IP, dst IP, port, bytes, packets, protocol)
- Near-zero overhead, production-grade, well-maintained
- Output: send to `goflow2` collector → ClickHouse, or directly via pmacct's ClickHouse plugin

This is the hypervisor-layer equivalent of Hubble flows.

### VM placement topology
- **Hypervisor REST API** — knows which VMs are on which hypervisor node, their resource
  allocation, and storage layout.
- A CronJob or Alloy custom scraper hitting the hypervisor API every minute writes
  `vm_id → hypervisor_node` edges to the `topology.edges` table.

---

## Layer: Network (gateway/router)

The network gateway runs proprietary firmware. eBPF is not viable — kernel version is uncertain,
no package manager, the vendor does not expose kernel-level access. SSH works but is limited.

### Traffic flows
- **NetFlow/IPFIX export** — native in most gateways: enable NetFlow in the network monitoring
  settings. Gives L3 flow data (src/dst IP, port, bytes, packets, protocol) for all traffic the
  gateway routes (WAN-facing and inter-VLAN).
- Collect with `goflow2` (modern, JSON output, low overhead) running on a K8s pod or a small VM.
  goflow2 → ClickHouse via Alloy or direct insert.

### Device health
- **SNMP v3** — interface counters, uptime, CPU/memory on the gateway. Standard Alloy scrape.

### Security events
- **Syslog** — DHCP leases, firewall drops, IDS events, authentication failures.
  Configure the gateway's syslog export → Alloy → Loki.

### Client/device topology
- **Network controller API** (poller pattern) — scrapes the network controller API for:
  - Which client device is associated with which AP
  - Which VLAN each client is on
  - Signal strength, data rate (useful for "is this a connectivity issue or an app issue")
  - Device list with MAC, IP, hostname
  
  This is the "end-user device topology" layer — not deep instrumentation but enough to build
  `device → AP → VLAN` edges in the topology graph. Also enables "which user's device is this
  IP?" lookups when correlating alerts.

---

## Unified Topology Graph

All layers write to a single `topology.edges` table in ClickHouse:

```sql
CREATE TABLE topology.edges (
    observed_at   DateTime64(3),
    source_type   Enum('pod','namespace','node','hypervisor','vm','switch','device'),
    source_id     String,
    target_type   Enum('pod','namespace','node','hypervisor','vm','switch','device'),
    target_id     String,
    edge_type     Enum('calls','runs_on','backs','allows','associated_with'),
    port          UInt16 DEFAULT 0,
    data_source   Enum('hubble','cnp','pmacctd','netflow','hypervisor-api','network-api','snmp'),
    byte_count    UInt64 DEFAULT 0
) ENGINE = ReplacingMergeTree(observed_at)
  ORDER BY (source_type, source_id, target_type, target_id, port);
```

For the traversal depth needed (2-3 hops: "which pods are affected if this hypervisor
node goes down"), ClickHouse self-joins are sufficient. A graph DB (Memgraph etc.) is not
needed until arbitrary-depth traversal or graph algorithms (shortest path, community detection)
become a requirement.

---

## Coverage Summary

| Layer | Tool | Flow data | Security | Topology | Status |
|-------|------|-----------|----------|----------|--------|
| K8s pods | Hubble (Cilium) | ✓ policy-level | Falco + Tetragon | CNPs + K8s API | Live |
| K8s nodes | Alloy + Tetragon | via Hubble | Falco | Node labels | Live |
| Hypervisor hosts | Alloy + Falco/Tetragon | pmacctd on vmbr* | Falco/Tetragon | Hypervisor API | Queued |
| Non-K8s VMs | Alloy + Falco in-VM | pmacctd (host view) | Falco in-VM | Hypervisor API | Queued |
| Network (gateway) | SNMP + syslog | NetFlow/IPFIX via goflow2 | syslog FW logs | Controller API | Queued |
| End-user devices | Controller API (passive) | — | — | device→VLAN | Future |

---

## Implementation Priority

1. **Hypervisor Falco** — provisioned via configuration management. Highest
   security value, lowest effort to add to an existing role.
2. **Hypervisor pmacctd** — network flows from VM bridges. Small config-management task per host.
3. **Hypervisor API scraper** — VM placement topology. One CronJob or Alloy scrape config.
4. **goflow2 collector + gateway NetFlow** — L3 flows from the network layer. One new K8s
   deployment for the collector, one config change on the gateway.
5. **Network controller API scraper** — client/device topology. A poller or a small custom scraper.
6. **`topology.edges` ClickHouse table** — the unified sink. Implement alongside the first
   data source that needs it.
7. **Tetragon standalone on hypervisor hosts** — evaluate as upgrade to Falco if enforcement is needed
   at the hypervisor layer.

---

## Graph DB Revisit Trigger

Add Memgraph (or equivalent) if any of the following become true:
- Need arbitrary-depth traversal (>3 hops) in alert suppression logic
- Need graph algorithms (PageRank for blast radius scoring, shortest path for lateral movement)
- The `topology.edges` self-join queries become too slow or complex to maintain

At homelab scale with the current use cases, ClickHouse adjacency tables are sufficient.
