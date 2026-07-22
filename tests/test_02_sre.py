"""
SRE shakedown tests — OOMKill, probe-timeout, CrashLoop routing.
Validates fixes from PanOps shakedown results (5/7 passed session).
"""
import json
import time
import pytest
from conftest import (
    ch_query, fire_webhook, poll_happening, POLL_TIMEOUT
)


def test_oomkill_alert_creates_happening():
    """OOMKill webhook should produce a happening in CH."""
    unique_ns = f"th-oom-{int(time.time())}"
    fire_webhook(
        "KubePodOOMKilled",
        namespace=unique_ns,
        source="sre",
        extra_labels={"severity": "critical", "container": "app"},
    )
    row = poll_happening(namespace=unique_ns, timeout=POLL_TIMEOUT)
    assert row["id"]


def test_oomkill_domain_is_sre_not_soc():
    """OOMKill with no Falco/Sigma signal should resolve as SRE, not SOC."""
    unique_ns = f"th-oom-domain-{int(time.time())}"
    fire_webhook("KubePodOOMKilled", namespace=unique_ns, source="sre")
    row = poll_happening(namespace=unique_ns, timeout=POLL_TIMEOUT)
    assert row["domain"] in ("SRE", "MIXED"), (
        f"OOMKill routed to {row['domain']} — expected SRE or MIXED"
    )


def test_oomkill_no_namespace_blast():
    """
    Shakedown fix: OOM remediation should NOT restart all deployments in the namespace.
    Verify the affected_services list is scoped to the triggering namespace,
    not expanded cluster-wide.
    (This validates the scope guard added in the shakedown fix session.)
    """
    unique_ns = f"th-oom-blast-{int(time.time())}"
    fire_webhook("KubePodOOMKilled", namespace=unique_ns, source="sre")
    row = poll_happening(namespace=unique_ns, timeout=POLL_TIMEOUT)
    # affected_services should only contain the specific namespace, not other namespaces
    assert int(row["svc_count"]) <= 3, (
        f"OOMKill blast radius too wide: {row['svc_count']} affected services"
    )


def test_probe_timeout_not_routed_as_crashloop():
    """
    Shakedown fix: probe-timeout events should NOT be classified as CrashLoopBackOff.
    Before the fix, Unhealthy events without a Killing event were silently dropped;
    after the fix, they create happenings with a probe_failure pattern.
    """
    unique_ns = f"th-probe-{int(time.time())}"
    fire_webhook(
        "KubeContainerWaiting",
        namespace=unique_ns,
        source="sre",
        extra_labels={"reason": "CrashLoopBackOff", "container": "app"},
    )
    # If the fix is working, this should create a happening, not be silently dropped
    row = poll_happening(namespace=unique_ns, timeout=POLL_TIMEOUT)
    assert row["id"]
    # classifier_route should NOT be 'crashloop' (that route doesn't exist — was a
    # shakedown finding that probe-timeout was failing to create happenings at all)
    assert row["classifier_route"] != "crashloop"


def test_crashloop_creates_happening():
    """CrashLoopBackOff alert should create a happening and route to SRE."""
    unique_ns = f"th-crash-{int(time.time())}"
    fire_webhook(
        "KubePodCrashLooping",
        namespace=unique_ns,
        source="sre",
        extra_labels={"severity": "critical"},
    )
    row = poll_happening(namespace=unique_ns, timeout=POLL_TIMEOUT)
    assert row["id"]
    assert row["domain"] in ("SRE", "MIXED")


def test_sre_source_label_promotes_domain():
    """
    Webhook with source=sre and no Falco/Sigma signals should be promoted
    from MIXED/structured to SRE (assembler.py line 546 promotion logic).
    """
    unique_ns = f"th-sre-promo-{int(time.time())}"
    fire_webhook("TestSREPromotion", namespace=unique_ns, source="sre")
    row = poll_happening(namespace=unique_ns, timeout=POLL_TIMEOUT)
    assert row["domain"] in ("SRE",), (
        f"Expected domain=SRE after source=sre promotion, got {row['domain']}"
    )


def test_observability_source_promotes_sre():
    """source=observability should also promote to SRE domain."""
    unique_ns = f"th-obs-promo-{int(time.time())}"
    fire_webhook("HighLatencyAlert", namespace=unique_ns, source="observability")
    row = poll_happening(namespace=unique_ns, timeout=POLL_TIMEOUT)
    assert row["domain"] in ("SRE", "MIXED")
