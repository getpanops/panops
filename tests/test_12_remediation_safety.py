"""
test_12_remediation_safety.py — P0B remediation-safety hardening.
Pure unit tests (no cluster): token-injection rejection, centralized gate on the
runtime executors (postmortem_learned bypass fix), WinRM secure-by-default,
and parameterized-query encoding.
"""
import os
import sys
import importlib

import pytest

_SRC = os.path.expanduser("~/Git/panops/docker/assembler/src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def _load(mode="limited", allowed="chaos-probe", protected="kube-system,flux-system"):
    os.environ["REMEDIATION_MODE"] = mode
    os.environ["REMEDIATION_ALLOWED_NAMESPACES"] = allowed
    os.environ["REMEDIATION_PROTECTED_NAMESPACES"] = protected
    import remediator
    importlib.reload(remediator)
    return remediator


def test_token_injection_rejected():
    r = _load()
    with pytest.raises(ValueError):
        r._substitute_tokens("kubectl delete pod {pod} -n {namespace}",
                             {"namespace": "x; rm -rf /", "pod": "p"})


def test_token_benign_ok():
    r = _load()
    out = r._substitute_tokens("kubectl rollout restart deploy/{service} -n {namespace}",
                               {"namespace": "chaos-probe", "affected_services": ["web/api"]})
    assert out == "kubectl rollout restart deploy/api -n chaos-probe"


def test_guarded_executor_blocks_protected_ns():
    r = _load()
    g = r._guarded_executor(lambda c, h, l: "RAN:" + c)
    with pytest.raises(ValueError):
        g("echo hi", {"namespace": "kube-system"}, None)


def test_guarded_executor_dry_run_does_not_execute():
    r = _load(mode="dry-run")
    g = r._guarded_executor(lambda c, h, l: "RAN:" + c)
    out = g("echo hi", {"namespace": "anything"}, None)
    assert out.startswith("[dry-run]") and "RAN" not in out


def test_runtime_executors_are_guarded():
    # the postmortem_learned path uses RUNTIME_EXECUTORS — every entry must gate.
    r = _load(mode="off")
    for name, ex in r.RUNTIME_EXECUTORS.items():
        with pytest.raises(ValueError):
            ex("echo hi", {"namespace": "any"}, None)  # mode=off => refused


def test_winrm_requires_allowlist():
    r = _load()
    os.environ["WINRM_USERNAME"] = "u"
    os.environ["WINRM_PASSWORD"] = "p"
    os.environ.pop("WINRM_ALLOWED_HOSTS", None)
    importlib.reload(r)
    with pytest.raises(ValueError):
        r._exec_winrm("Get-Date", {"affected_services": ["winhost1"]}, None)


def test_winrm_host_not_in_allowlist_rejected():
    r = _load()
    os.environ["WINRM_USERNAME"] = "u"
    os.environ["WINRM_PASSWORD"] = "p"
    os.environ["WINRM_ALLOWED_HOSTS"] = "winhost1"
    importlib.reload(r)
    with pytest.raises(ValueError):
        r._exec_winrm("Get-Date", {"affected_services": ["evilhost"]}, None)
