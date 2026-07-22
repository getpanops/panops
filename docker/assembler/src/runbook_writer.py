"""
PanOps Brain — Runbook Writer (Step 8)
Called after a happening resolves. Generates a Markdown runbook entry
from the happening data and writes it to docs/runbooks/auto/ in the
repo checkout (mounted as a volume or written via kubectl).

For homelab: writes to a ConfigMap that gets committed by a GitOps
sidecar pattern — or, more practically, logs the runbook content so
it can be committed manually / by a future CronJob.

Template-based only (no LLM). LLM runbook generation for novel cases
is Step 9 (additive, later).
"""
import json
import os
import re
import urllib.request
from datetime import datetime, timezone

CH_URL = os.getenv("CH_URL", "")

RUNBOOK_TEMPLATE = """\
## {title}

**Auto-generated** | First seen: {first_seen} | Times resolved: {times_resolved}

### What fires this

{signal_summary}

### Domain

`{domain}` — Classifier route: `{route}`

### Affected services

{services}

### Automatic remediation steps

{steps}

### Validation

Signals clear when:
- No new `security_anomalies` rows for the affected namespace in 60s windows
- No new `sigma_matches` for the namespace in 60s windows
- All affected namespace pods Running/Ready

Resolution requires 10 consecutive clean 60s polls (≈10 minutes clear).

### Escalation

If automatic remediation fails after 30 minutes, the happening is marked
`escalated`. Check Matrix alerts and investigate manually.
Runbook location: `docs/runbooks/auto/{filename}`
"""


def _ch_query(sql):
    if not CH_URL:
        return []
    try:
        data = (sql.strip() + " FORMAT JSON").encode()
        req  = urllib.request.Request(CH_URL, data=data, method="POST")
        req.add_header("Content-Type", "text/plain")
        req.add_header("X-ClickHouse-User", os.environ.get("CH_USER", "default"))
        req.add_header("X-ClickHouse-Key",  os.environ.get("CH_PASSWORD", ""))
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read()).get("data", [])
    except Exception:
        return []


def _count_prior_resolutions(falco_rules, sigma_ids):
    """How many times has a similar happening been resolved before?"""
    if falco_rules:
        rule = falco_rules[0].replace("'", "''")
        rows = _ch_query(f"""
            SELECT count() AS n FROM panops.happenings
            WHERE outcome = 'resolved'
              AND has(falco_rules, '{rule}')
        """)
    elif sigma_ids:
        rule = sigma_ids[0].replace("'", "''")
        rows = _ch_query(f"""
            SELECT count() AS n FROM panops.happenings
            WHERE outcome = 'resolved'
              AND has(sigma_rule_ids, '{rule}')
        """)
    else:
        return 1
    return int(rows[0]["n"]) if rows else 1


def _format_steps(actions_taken_json):
    try:
        actions = json.loads(actions_taken_json or "[]")
    except Exception:
        return "_No automated actions recorded._"
    if not actions:
        return "_No automated actions recorded._"
    lines = []
    for i, act in enumerate(actions, 1):
        cmd  = act.get("command", "")
        out  = act.get("output", "").strip()[:200]
        lines.append(f"{i}. `{cmd}`")
        if out:
            lines.append(f"   ```\n   {out}\n   ```")
    return "\n".join(lines)


def _format_signals(happening):
    parts = []
    falco = happening.get("falco_rules") or []
    sigma = happening.get("sigma_rule_ids") or []
    try:
        anomalies = json.loads(happening.get("metric_anomalies") or "[]")
    except Exception:
        anomalies = []
    try:
        drain3 = json.loads(happening.get("drain3_patterns") or "[]")
    except Exception:
        drain3 = []

    if falco:
        parts.append("**Falco rules:** " + ", ".join(f"`{r}`" for r in falco))
    if sigma:
        parts.append("**Sigma matches:** " + ", ".join(f"`{r}`" for r in sigma))
    if anomalies:
        metrics = ", ".join(f"`{a['metric']}` (×{a.get('deviation_ratio','?'):.1f}σ)"
                            for a in anomalies[:5])
        parts.append(f"**Metric anomalies:** {metrics}")
    novel = [p for p in drain3 if p.get("is_novel")]
    if novel:
        parts.append(f"**Novel log patterns:** {len(novel)} new Drain3 template(s)")
    return "\n".join(parts) if parts else "_No structured signals recorded._"


def write_runbook(happening, log_fn=None):
    """
    Generate and log a runbook entry for a resolved happening.
    In the current implementation, writes to stdout so operators can
    commit it manually; a future GitOps sidecar or CronJob can automate
    the commit step.
    """
    hid      = happening.get("id", "unknown")
    falco    = happening.get("falco_rules") or []
    sigma    = happening.get("sigma_rule_ids") or []
    domain   = happening.get("domain", "MIXED")
    route    = happening.get("classifier_route", "structured")
    services = happening.get("affected_services") or []
    opened   = happening.get("opened_at", "")

    # Build title from most specific signal available
    if falco:
        title    = falco[0]
        filename = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") + ".md"
    elif sigma:
        title    = f"Sigma: {sigma[0]}"
        filename = re.sub(r"[^a-z0-9]+", "-", sigma[0].lower()).strip("-") + ".md"
    else:
        title    = f"{domain} incident in {', '.join(services) or 'unknown'}"
        filename = f"{domain.lower()}-{hid[:8]}.md"

    times_resolved = _count_prior_resolutions(falco, sigma)
    steps          = _format_steps(happening.get("actions_taken", "[]"))
    signal_summary = _format_signals(happening)
    services_str   = "\n".join(f"- `{s}`" for s in services) or "_unknown_"

    runbook = RUNBOOK_TEMPLATE.format(
        title=title,
        first_seen=opened[:10],
        times_resolved=times_resolved,
        signal_summary=signal_summary,
        domain=domain,
        route=route,
        services=services_str,
        steps=steps,
        filename=filename,
    )

    # Dedent the template (it's indented inside the Python string)
    import textwrap
    runbook = textwrap.dedent(runbook)

    if log_fn:
        log_fn("INFO", f"runbook: {filename} ({times_resolved} resolution(s))")
    print(f"\n=== AUTO-RUNBOOK: docs/runbooks/auto/{filename} ===\n{runbook}\n===END===\n",
          flush=True)
    return filename, runbook
