# PanOps Productisation — Main Technical Spec

Reference this alongside the per-phase specs. Contains cross-cutting data models, API contracts, and env var registry.

---

## New ClickHouse Tables

### `panops.postmortem_runbooks`

```sql
CREATE TABLE IF NOT EXISTS panops.postmortem_runbooks (
    id UUID DEFAULT generateUUIDv4(),
    happening_id UUID,
    created_at DateTime64(3, 'UTC') DEFAULT now64(3),
    drain3_template String,
    domain LowCardinality(String),
    runtime LowCardinality(String),
    commands String,
    raw_paste String,
    notes String,
    created_by String
) ENGINE = MergeTree()
ORDER BY (created_at, happening_id);
```

`commands` field JSON schema:
```json
[
  {
    "command": "kubectl rollout restart deployment/{service} -n {namespace}",
    "expected_output": "deployment.apps/{service} restarted",
    "description": "Restart the affected deployment"
  }
]
```

Available `{placeholder}` tokens: `{namespace}`, `{service}`, `{deployment}`, `{pod}`, `{host}`, `{ip}`.

---

## New Environment Variables

### assembler.py

| Variable | Default | Description |
|---|---|---|
| `WEBHOOK_URLS` | `""` | Comma-separated `provider:url` pairs. Providers: `slack`, `teams`, `generic`. Matrix is separate. |
| `POSTMORTEM_USERNAME` | `""` | Basic auth username for `/postmortem/*` endpoints |
| `POSTMORTEM_PASSWORD` | `""` | Basic auth password (bcrypt-hashed at startup) |
| `LDAP_URL` | `""` | If set, enables LDAP auth for postmortem endpoints (future) |

### remediator.py

| Variable | Default | Description |
|---|---|---|
| `WINRM_USERNAME` | `""` | WinRM service account username |
| `WINRM_PASSWORD` | `""` | WinRM password |
| `WINRM_TRANSPORT` | `ntlm` | Auth transport: `ntlm`, `kerberos`, `certificate` |

### sigma-scanner / intel-updater

| Variable | Default | Description |
|---|---|---|
| `INTEL_BUNDLE_PATH` | `""` | Path to apply a pre-packaged intel bundle on startup |
| `INTEL_AUTO_UPDATE` | `false` | If `true`, pull updates on each scanner start |
| `GITHUB_TOKEN` | `""` | Optional: rate-limit bypass for GitHub release downloads |

---

## Notification Provider Protocol

### `WEBHOOK_URLS` parsing

Parsed at module load time in `assembler.py`:
```python
_WEBHOOKS = []  # list of (provider, url) tuples
for entry in os.getenv("WEBHOOK_URLS", "").split(","):
    entry = entry.strip()
    if ":" in entry:
        provider, url = entry.split(":", 1)
        _WEBHOOKS.append((provider.strip(), url.strip()))
```

### Payload formats

**slack:**
```json
{
  "blocks": [
    {"type": "header", "text": {"type": "plain_text", "text": "[{domain}] {title}"}},
    {"type": "section", "text": {"type": "mrkdwn", "text": "{body}"}},
    {"type": "context", "elements": [{"type": "mrkdwn", "text": "route: {route} | severity: {severity}"}]}
  ]
}
```

**teams:**
```json
{
  "type": "message",
  "attachments": [{
    "contentType": "application/vnd.microsoft.card.adaptive",
    "content": {
      "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
      "type": "AdaptiveCard",
      "version": "1.4",
      "body": [
        {"type": "TextBlock", "text": "[{domain}] {title}", "weight": "bolder"},
        {"type": "TextBlock", "text": "{body}", "wrap": true},
        {"type": "TextBlock", "text": "route: {route}", "isSubtle": true}
      ]
    }
  }]
}
```

**generic:**
```json
{
  "domain": "SRE",
  "title": "OOMKill in gitlab",
  "body": "...",
  "route": "known",
  "severity": "warning",
  "timestamp": "2026-07-09T12:00:00Z"
}
```

### `_send_notification` signature

```python
def _send_notification(domain: str, title: str, body: str,
                       route: str = "", severity: str = "warning") -> None:
    # sends to all configured providers (Matrix + WEBHOOK_URLS)
    # non-blocking: each provider sent in a daemon thread
    # errors are logged but never raised
```

---

## Postmortem Auth Protocol

```python
import base64, bcrypt, os

_PM_HASH = None  # set at module load

def _init_postmortem_auth():
    global _PM_HASH
    pw = os.getenv("POSTMORTEM_PASSWORD", "")
    if pw:
        _PM_HASH = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

def _check_postmortem_auth(handler) -> bool:
    if not _PM_HASH:
        return True  # no auth configured — open (document clearly)
    auth_header = handler.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        handler.send_response(401)
        handler.send_header("WWW-Authenticate", 'Basic realm="PanOps Postmortem"')
        handler.end_headers()
        return False
    try:
        credentials = base64.b64decode(auth_header[6:]).decode()
        username, password = credentials.split(":", 1)
        expected_user = os.getenv("POSTMORTEM_USERNAME", "")
        if username != expected_user:
            raise ValueError
        if not bcrypt.checkpw(password.encode(), _PM_HASH):
            raise ValueError
        return True
    except Exception:
        handler.send_response(401)
        handler.send_header("WWW-Authenticate", 'Basic realm="PanOps Postmortem"')
        handler.end_headers()
        return False
```

**Future LDAP path:** when `LDAP_URL` is set, `_check_postmortem_auth` swaps in `ldap.initialize(LDAP_URL).simple_bind_s(dn, password)` without changing any call sites.

---

## Runtime Dispatch Table

In `remediator.py`:

```python
RUNTIMES = {
    "kubectl":    _exec_kubectl,
    "shell":      _exec_shell,
    "ansible":    _exec_ansible,
    "winrm":      _exec_winrm,
    "powershell": _exec_winrm,  # alias
}

def _exec_postmortem_command(cmd_entry: dict, happening: dict, log_fn) -> dict:
    runtime = cmd_entry.get("runtime", "shell")
    command = _substitute_tokens(cmd_entry["command"], happening)
    executor = RUNTIMES.get(runtime, _exec_shell)
    output = executor(command, happening, log_fn)
    return {"command": command, "output": output, "runtime": runtime}
```

Token substitution:
```python
def _substitute_tokens(template: str, happening: dict) -> str:
    services = happening.get("affected_services") or [""]
    first = services[0]
    ns = first.split("/")[0] if "/" in first else first
    svc = first.split("/")[1] if "/" in first else first
    return (template
        .replace("{namespace}", ns)
        .replace("{service}", svc)
        .replace("{deployment}", svc)
        .replace("{pod}", svc)
        .replace("{host}", ns)
        .replace("{ip}", ""))
```

---

## OSIX — Operational Signature Information eXpression

PanOps knowledge packs extend the STIX (Structured Threat Information eXpression) model to cover the full operational knowledge space. STIX describes what attackers do. OSIX describes what failure looks like, why, and how to recover from it.

An operational signature answers four questions:

| Question | Data | Sources |
|---|---|---|
| What does healthy look like? | SLO definitions, baseline metric ranges, normal log patterns | Pyrra, OpenSLO, monitoring mixins |
| What does sick look like? | Prometheus alert rules, Sigma rules, drain3 patterns, YARA matches | Awesome-prometheus-alerts, kubernetes-mixin, SigmaHQ |
| What fixes it? | Runbook steps, parameterized remediation commands, Ansible playbooks | containersolutions/runbooks, postmortem_runbooks CH table |
| How do you know you're better? | Validation queries (PromQL, LogQL, PowerShell), SLO recovery checks | Pyrra SLO burn rate, postmortem validation_query field |

This structure maps directly onto PanOps' data model:
- "sick" → `panops.happenings` (drain3_patterns, sigma_rule_ids, falco_rules, yara_matches)
- "fixes it" → `panops.postmortem_runbooks` (commands, runtime)
- "better" → `panops.happenings.validation_query` + LLM validation loop in remediator.py

**OpenTelemetry Semantic Conventions as the naming layer:**

Portable ops signatures require consistent field names across platforms and sources. OTel semantic conventions provide this: `service.name`, `host.name`, `k8s.namespace.name`, `process.command_line`, `os.type` etc. are the same attribute names whether the telemetry comes from a Linux host, a Windows server, or a Kubernetes pod. All pySigma pipeline field mappings target OTel semconv attribute paths.

| OTel semconv attribute | Use in PanOps |
|---|---|
| `service.name` | Primary identifier in `affected_services` and Sigma field mappings |
| `host.name` | WinRM target host; Linux shell executor host |
| `k8s.namespace.name` | `{namespace}` token in postmortem commands |
| `k8s.pod.name` | `{pod}` token |
| `process.command_line` | Process-based Sigma rule field (`CommandLine` in Windows Sigma mapped here) |
| `process.executable.path` | YARA scan and process-based detection |
| `os.type` | Platform inference in `_infer_platform()` |
| `event.name` | Windows Event Log classification |

The `otel_semconv` knowledge pack (see phase-2c.md) downloads the full semconv YAML spec as a reference. The pySigma pipeline files are the runtime artefacts that implement the mapping.

---

## Intel Bundle Manifest Schema

Two knowledge categories in every bundle: security intelligence (what attackers do) and operational signatures (what failure looks like and how to fix it).

```json
{
  "version": "2026-07",
  "created_at": "2026-07-09T00:00:00Z",
  "security": {
    "sigmahq_core":              {"commit": "abc123", "rule_count": 2847},
    "elastic_detection_rules":   {"commit": "def456", "rule_count": 1104},
    "yara_forge_full":           {"release": "v2026.07.1", "rule_count": 412},
    "signature_base":            {"commit": "ghi789", "rule_count": 128},
    "et_open_suricata":          {"version": "2026-07-09", "rule_count": 38000},
    "mitre_attack_enterprise":   {"version": "14.1"},
    "mitre_attack_ics":          {"version": "9.0"},
    "mitre_d3fend":              {"version": "0.13.0-BETA-3"},
    "nvd_cve_recent":            {"feed": "90d", "cve_count": 1204}
  },
  "operations": {
    "awesome_prometheus_alerts":  {"commit": "jkl012", "rule_count": 923},
    "kubernetes_mixin":           {"commit": "mno345"},
    "node_exporter_mixin":        {"commit": "pqr678"},
    "etcd_mixin":                 {"commit": "stu901"},
    "pyrra_slo_examples":         {"commit": "vwx234"},
    "openslo_examples":           {"commit": "yza567"},
    "k8s_runbooks":               {"commit": "bcd890", "runbook_count": 47},
    "otel_semconv":               {"release": "v1.26.0"}
  },
  "files": {
    "sigma/community/": "sha256:...",
    "yara/forge/": "sha256:...",
    "suricata/et-open.rules": "sha256:...",
    "prometheus/awesome-alerts/": "sha256:...",
    "runbooks/kubernetes/": "sha256:...",
    "semconv/": "sha256:..."
  }
}
```

Stored in `panops.dream_state` key `intel_manifest` (JSON string value) after each apply.

---

## pySigma ClickHouse Backend Integration

Library: `pySigma-backend-clickhouse` (clicksiem fork — `pip install pySigma-backend-clickhouse`)

Standard rule conversion:
```python
from sigma.collection import SigmaCollection
from sigma.backends.clickhouse import ClickHouseBackend
from sigma.processing.resolver import ProcessingPipelineResolver

pipeline_resolver = ProcessingPipelineResolver()
# load pipeline from rules/sigma/pipelines/panops-clickhouse.yaml
backend = ClickHouseBackend(processing_pipeline=pipeline)

collection = SigmaCollection.from_yaml(rule_yaml)
queries = backend.convert(collection)  # list of SQL strings
```

For escape-hatch rules with `x-panops-chsql`, bypass the backend entirely:
```python
rule_data = yaml.safe_load(rule_yaml)
if "x-panops-chsql" in rule_data:
    sql = rule_data["x-panops-chsql"].format(start_ns=start_ns, end_ns=end_ns)
    results = ch_query_raw(sql)
```

---

## YARA-X Binary Usage

YARA-X CLI binary is `yr`. Replaces `yara` 1:1 for scan operations:

```sh
# Old (yara):
yara /rules/rules.yar /scan-path/file

# New (yr):
yr scan --rules /rules/rules.yar /scan-path/file
```

Output format differs slightly — YARA-X outputs JSON by default (`--output-format json`). The DaemonSet shell loop must be updated to parse JSON output instead of the plain-text `rule_name file_path` format.

```sh
yr scan --rules /rules/rules.yar --output-format json /scan-path/
```

Output JSON structure:
```json
[{"rule": "Reverse_Shell_Indicators", "path": "/scan-path/tmp/evil.sh", "meta": {}}]
```

---

## Sigma Correlation Engine (Phase 2b)

Two-pass evaluation within each scanner run:

**Pass 1:** Evaluate all non-correlation rules → insert into `qryn.sigma_matches`

**Pass 2:** For each correlation rule, build a ClickHouse aggregation over `qryn.sigma_matches` within `timespan`:

```python
def _build_correlation_sql(corr_rule: dict, start_ns: int, end_ns: int) -> str:
    ctype = corr_rule["correlation"]["type"]
    ref_rules = corr_rule["correlation"]["rules"]
    group_by = corr_rule["correlation"].get("group-by", [])
    timespan = _parse_timespan(corr_rule["correlation"]["timespan"])  # → seconds
    condition = corr_rule["correlation"]["condition"]
    
    if ctype == "event_count":
        return _sql_event_count(ref_rules, group_by, timespan, condition, start_ns, end_ns)
    elif ctype == "value_count":
        field = condition["field"]
        return _sql_value_count(ref_rules, group_by, field, timespan, condition, start_ns, end_ns)
    elif ctype == "temporal":
        return _sql_temporal(ref_rules, group_by, timespan, start_ns, end_ns)
```

Correlation matches inserted into `qryn.sigma_matches` with:
- `rule_id` = `corr_{correlation_rule_title_slug}`
- `rule_level` = correlation rule's level
- `log_string` = summary of matched events
