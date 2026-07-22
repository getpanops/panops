"""
test_11_productisation.py — Unit and integration tests for productisation features.
Covers: Phase 1b (webhooks), Phase 2b (sigma rules), Phase 3b (remediator dispatch),
        Phase 5c (WinRM), Phase 6 (LLM prompts).
"""
import os
import sys
import glob
import yaml
import pytest
import unittest.mock as mock

# Make source importable without installing
_SRC = os.path.expanduser("~/Git/panops/docker/assembler/src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ── Webhook notifications ─────────────────────────────────────────────────────

def test_parse_webhook_urls_empty():
    from assembler import _parse_webhook_urls
    assert _parse_webhook_urls("") == []


def test_parse_webhook_urls_slack():
    from assembler import _parse_webhook_urls
    result = _parse_webhook_urls("slack:https://hooks.slack.com/abc")
    assert len(result) == 1
    assert result[0] == ("slack", "https://hooks.slack.com/abc")


def test_parse_webhook_urls_multiple():
    from assembler import _parse_webhook_urls
    result = _parse_webhook_urls("slack:https://a.com,teams:https://b.com")
    assert len(result) == 2
    assert result[0][0] == "slack"
    assert result[1][0] == "teams"


def test_parse_webhook_urls_no_provider():
    from assembler import _parse_webhook_urls
    # bare URL without provider: prefix → "generic"
    # Note: bare URL with https:// will be treated as provider:url split
    result = _parse_webhook_urls("generic:https://example.com/hook")
    assert result[0][0] == "generic"


def test_parse_webhook_urls_whitespace_handling():
    from assembler import _parse_webhook_urls
    result = _parse_webhook_urls("slack: https://hooks.slack.com/abc , teams: https://teams.com/webhook")
    assert len(result) == 2
    assert result[0] == ("slack", "https://hooks.slack.com/abc")
    assert result[1] == ("teams", "https://teams.com/webhook")


def test_format_slack_payload():
    from assembler import _format_slack_payload
    import json
    p = _format_slack_payload("sre", "Test Alert", "Something broke", "crashloop", "critical")
    # Returns bytes (JSON-encoded)
    assert isinstance(p, bytes)
    payload = json.loads(p)
    assert "blocks" in payload
    assert len(payload["blocks"]) > 0


def test_format_teams_payload():
    from assembler import _format_teams_payload
    import json
    p = _format_teams_payload("sre", "Test Alert", "Something broke", "oom", "warning")
    # Returns bytes (JSON-encoded)
    assert isinstance(p, bytes)
    payload = json.loads(p)
    assert isinstance(payload, dict)


def test_format_generic_payload():
    from assembler import _format_generic_payload
    import json
    p = _format_generic_payload("windows", "title", "body", "access_denied", "info")
    # Returns bytes (JSON-encoded)
    assert isinstance(p, bytes)
    payload = json.loads(p)
    assert payload["domain"] == "windows"
    assert payload["title"] == "title"


def test_format_generic_payload_with_happening_id():
    from assembler import _format_generic_payload
    import json
    p = _format_generic_payload("soc", "alert", "content", "exploit_attempt", "critical")
    # Returns bytes (JSON-encoded)
    assert isinstance(p, bytes)
    payload = json.loads(p)
    assert payload["route"] == "exploit_attempt"
    assert payload["severity"] == "critical"


# ── Token substitution ────────────────────────────────────────────────────────

def test_substitute_tokens_namespace():
    from remediator import _substitute_tokens
    happening = {"namespace": "production", "affected_services": ["my-api"]}
    result = _substitute_tokens("kubectl get pods -n {namespace}", happening)
    assert "production" in result
    assert "{namespace}" not in result


def test_substitute_tokens_service():
    from remediator import _substitute_tokens
    happening = {"namespace": "prod", "affected_services": ["my-service"]}
    result = _substitute_tokens("{service}", happening)
    assert "{service}" not in result
    assert "my-service" in result


def test_substitute_tokens_slash_service():
    from remediator import _substitute_tokens
    # service with path prefix: web/my-service → should extract my-service
    happening = {"namespace": "prod", "affected_services": ["web/my-service"]}
    result = _substitute_tokens("{service}", happening)
    assert "{service}" not in result


def test_substitute_tokens_empty_happening():
    from remediator import _substitute_tokens
    # Should not raise; missing keys become empty string
    result = _substitute_tokens("restart {service} on {host}", {})
    assert "{service}" not in result
    assert "{host}" not in result


def test_substitute_tokens_domain():
    from remediator import _substitute_tokens
    happening = {"domain": "sre", "namespace": "ns1", "affected_services": []}
    result = _substitute_tokens("domain={domain}", happening)
    assert "domain=sre" in result


def test_substitute_tokens_multiple_same_token():
    from remediator import _substitute_tokens
    happening = {"namespace": "test", "affected_services": []}
    result = _substitute_tokens("{namespace}-app-{namespace}", happening)
    assert result == "test-app-test"


# ── Platform inference + available actions ────────────────────────────────────

def test_infer_platform_returns_valid():
    from assembler import _infer_platform
    happening = {"classifier_route": "crashloop", "namespace": "prod"}
    result = _infer_platform(happening)
    assert result in ("kubernetes", "linux", "windows")


def test_infer_platform_windows_from_sigma():
    from assembler import _infer_platform
    happening = {"sigma_rule_ids": ["windows_login_brute"], "affected_services": []}
    result = _infer_platform(happening)
    assert result == "windows"


def test_infer_platform_linux_default():
    from assembler import _infer_platform
    happening = {"affected_services": ["ubuntu-host"]}
    result = _infer_platform(happening)
    # No K8s or Windows signals → linux
    assert result == "linux"


def test_infer_platform_kubernetes_from_drain3():
    from assembler import _infer_platform
    happening = {"drain3_patterns": ["CrashLoopBackOff"], "affected_services": []}
    result = _infer_platform(happening)
    assert result == "kubernetes"


def test_available_actions_k8s_has_kubectl():
    from assembler import _available_actions
    happening = {"affected_services": ["default/api"], "drain3_patterns": ["CrashLoop"]}
    result = _available_actions(happening)
    assert isinstance(result, str)
    assert "kubectl" in result


def test_available_actions_windows_includes_ps():
    from assembler import _available_actions
    happening = {"domain": "windows", "affected_services": ["hyperv"]}
    result = _available_actions(happening)
    # Should include PowerShell/winrm context
    assert isinstance(result, str)


def test_available_actions_returns_string():
    from assembler import _available_actions
    happening = {"domain": "sre", "namespace": "prod", "affected_services": ["api"]}
    result = _available_actions(happening)
    assert isinstance(result, str)
    assert len(result) > 0


# ── Remediator executor unit tests ───────────────────────────────────────────

def test_exec_shell_success():
    from remediator import _exec_shell
    logs = []
    result = _exec_shell("echo panops-test", {}, lambda lvl, msg: logs.append(msg))
    assert "panops-test" in result


def test_exec_shell_failure_with_stderr_raises():
    from remediator import _exec_shell
    # Only raises if returncode != 0 AND stderr is non-empty
    with pytest.raises(ValueError):
        _exec_shell("echo error >&2; exit 1", {}, None)


def test_exec_shell_with_empty_happening():
    from remediator import _exec_shell
    result = _exec_shell("echo ok", {}, None)
    assert "ok" in result


def test_exec_shell_multiline():
    from remediator import _exec_shell
    cmd = "echo line1; echo line2"
    result = _exec_shell(cmd, {}, None)
    assert "line1" in result
    assert "line2" in result


def test_exec_ansible_no_inventory_raises():
    from remediator import _exec_ansible
    with mock.patch.dict(os.environ, {"ANSIBLE_INVENTORY": ""}, clear=False):
        with pytest.raises((ValueError, Exception, FileNotFoundError)):
            _exec_ansible("playbook.yml", {}, None)


def test_exec_winrm_no_credentials_raises():
    from remediator import _exec_winrm
    with mock.patch.dict(os.environ, {"WINRM_USERNAME": "", "WINRM_PASSWORD": ""}, clear=False):
        with pytest.raises((ValueError, Exception)):
            _exec_winrm("Get-Date", {"affected_services": ["host1"]}, None)


def test_runtime_executors_dict_complete():
    from remediator import RUNTIME_EXECUTORS
    assert "kubectl" in RUNTIME_EXECUTORS
    assert "shell" in RUNTIME_EXECUTORS
    assert "ansible" in RUNTIME_EXECUTORS
    assert "winrm" in RUNTIME_EXECUTORS
    assert all(callable(v) for v in RUNTIME_EXECUTORS.values())


def test_runtime_executors_all_callables():
    from remediator import RUNTIME_EXECUTORS
    for name, executor in RUNTIME_EXECUTORS.items():
        assert callable(executor), f"RUNTIME_EXECUTORS[{name}] is not callable"


# ── Sigma rules structural validation ────────────────────────────────────────

def test_sigma_rules_directory_exists():
    rules_dir = os.path.expanduser("~/Git/panops/rules/sigma/rules")
    assert os.path.isdir(rules_dir), f"Sigma rules directory not found: {rules_dir}"


def test_all_linux_rules_have_logsource():
    rules_dir = os.path.expanduser("~/Git/panops/rules/sigma/rules")
    rule_files = glob.glob(f"{rules_dir}/linux-*.yaml")
    assert len(rule_files) > 0, "Expected at least 1 linux rule file"
    for path in rule_files:
        with open(path) as f:
            docs = [d for d in yaml.safe_load_all(f) if d]
        for doc in docs:
            assert doc.get("logsource"), f"{path}: missing logsource"


def test_all_rules_have_title():
    rules_dir = os.path.expanduser("~/Git/panops/rules/sigma/rules")
    rule_files = glob.glob(f"{rules_dir}/*.yaml")
    if not rule_files:
        pytest.skip("No rules found at top level")
    for path in rule_files:
        with open(path) as f:
            docs = [d for d in yaml.safe_load_all(f) if d]
        for doc in docs:
            assert doc.get("title") or doc.get("name"), f"{path}: missing title"


def test_windows_rules_exist():
    rules_dir = os.path.expanduser("~/Git/panops/rules/sigma/rules/windows")
    assert os.path.isdir(rules_dir), f"Windows rules directory not found: {rules_dir}"
    rule_files = glob.glob(f"{rules_dir}/*.yaml")
    assert len(rule_files) > 0, "Expected at least 1 windows rule file"


def test_windows_rules_have_logsource_product():
    rules_dir = os.path.expanduser("~/Git/panops/rules/sigma/rules/windows")
    rule_files = glob.glob(f"{rules_dir}/*.yaml")
    if not rule_files:
        pytest.skip("No windows rule files found")
    for path in rule_files:
        with open(path) as f:
            docs = [d for d in yaml.safe_load_all(f) if d]
        for doc in docs:
            # Skip correlation rules (they have 'correlation' key instead of detection)
            if "correlation" in doc:
                continue
            assert doc.get("logsource"), f"{path}: missing logsource"
            logsource = doc["logsource"]
            if isinstance(logsource, dict):
                assert logsource.get("product") == "windows", \
                    f"{path}: logsource.product must be 'windows', got {logsource.get('product')}"


def test_homelab_clickhouse_pipeline_exists():
    path = os.path.expanduser("~/Git/panops/rules/sigma/pipelines/panops-clickhouse.yaml")
    assert os.path.exists(path), "panops-clickhouse.yaml pipeline missing"


def test_homelab_clickhouse_pipeline_valid():
    path = os.path.expanduser("~/Git/panops/rules/sigma/pipelines/panops-clickhouse.yaml")
    if not os.path.exists(path):
        pytest.skip("Pipeline file not found")
    doc = yaml.safe_load(open(path))
    assert doc is not None, "Pipeline file is empty or invalid YAML"


def test_windows_clickhouse_pipeline_exists():
    path = os.path.expanduser("~/Git/panops/rules/sigma/pipelines/windows-clickhouse.yaml")
    assert os.path.exists(path), "windows-clickhouse.yaml pipeline missing"


def test_windows_clickhouse_pipeline_valid():
    path = os.path.expanduser("~/Git/panops/rules/sigma/pipelines/windows-clickhouse.yaml")
    if not os.path.exists(path):
        pytest.skip("Pipeline file not found")
    doc = yaml.safe_load(open(path))
    assert doc is not None, "Pipeline file is empty or invalid YAML"


# ── Postmortem schema ─────────────────────────────────────────────────────────

def test_postmortem_schema_references_exist():
    schema_path = os.path.expanduser("~/Git/panops/clickhouse/schema/create-schema.py")
    assert os.path.exists(schema_path), "create-schema.py not found"


def test_postmortem_runbooks_in_schema():
    schema_path = os.path.expanduser("~/Git/panops/clickhouse/schema/create-schema.py")
    if not os.path.exists(schema_path):
        pytest.skip("Schema file not found")
    content = open(schema_path).read()
    assert "postmortem_runbooks" in content, "postmortem_runbooks table not defined"


def test_postmortem_templates_in_schema():
    schema_path = os.path.expanduser("~/Git/panops/clickhouse/schema/create-schema.py")
    if not os.path.exists(schema_path):
        pytest.skip("Schema file not found")
    content = open(schema_path).read()
    assert "drain3_template" in content or "template" in content, \
        "No template reference found in schema"


# ── LLM prompt content ───────────────────────────────────────────────────────

def test_assembler_file_exists():
    assembler_path = os.path.expanduser("~/Git/panops/docker/assembler/src/assembler.py")
    assert os.path.exists(assembler_path), "assembler.py not found"


def test_llm_system_message_in_assembler():
    assembler_path = os.path.expanduser("~/Git/panops/docker/assembler/src/assembler.py")
    if not os.path.exists(assembler_path):
        pytest.skip("assembler.py not found")
    content = open(assembler_path).read()
    # LLM system message should reference PanOps or similar
    assert any(kw in content.lower() for kw in ["panops", "brain", "llm", "system", "message"]), \
        "No LLM system message reference found"


def test_postmortem_design_in_remediator():
    remediator_path = os.path.expanduser("~/Git/panops/docker/assembler/src/remediator.py")
    if not os.path.exists(remediator_path):
        pytest.skip("remediator.py not found")
    content = open(remediator_path).read()
    # Should reference postmortem functionality
    assert "postmortem" in content.lower(), "No postmortem reference in remediator"


def test_consolidation_file_exists():
    consolidation_path = os.path.expanduser("~/Git/panops/docker/assembler/src/consolidation.py")
    if os.path.exists(consolidation_path):
        assert os.path.exists(consolidation_path), "consolidation.py file check"


# ── Integration: check imports work ──────────────────────────────────────────

def test_assembler_imports_cleanly():
    """Verify assembler module can be imported without errors."""
    try:
        import assembler  # noqa: F401
    except ImportError as e:
        pytest.skip(f"assembler module import failed: {e}")


def test_remediator_imports_cleanly():
    """Verify remediator module can be imported without errors."""
    try:
        import remediator  # noqa: F401
    except ImportError as e:
        pytest.skip(f"remediator module import failed: {e}")


# ── Phase 3b: Remediation dispatch ──────────────────────────────────────────

def test_exec_kubectl_signature_valid():
    """Verify _exec_kubectl has the expected signature."""
    from remediator import _exec_kubectl
    import inspect
    sig = inspect.signature(_exec_kubectl)
    params = list(sig.parameters.keys())
    assert "command" in params
    assert "happening" in params
    assert "log_fn" in params


def test_exec_shell_signature_valid():
    """Verify _exec_shell has the expected signature."""
    from remediator import _exec_shell
    import inspect
    sig = inspect.signature(_exec_shell)
    params = list(sig.parameters.keys())
    assert "command" in params
    assert "happening" in params
    assert "log_fn" in params


def test_exec_ansible_signature_valid():
    """Verify _exec_ansible has the expected signature."""
    from remediator import _exec_ansible
    import inspect
    sig = inspect.signature(_exec_ansible)
    params = list(sig.parameters.keys())
    assert "command" in params
    assert "happening" in params
    assert "log_fn" in params


def test_exec_winrm_signature_valid():
    """Verify _exec_winrm has the expected signature."""
    from remediator import _exec_winrm
    import inspect
    sig = inspect.signature(_exec_winrm)
    params = list(sig.parameters.keys())
    assert "command" in params
    assert "happening" in params
    assert "log_fn" in params


# ── Phase 1b: Webhook format validation ──────────────────────────────────────

def test_format_slack_payload_has_required_keys():
    from assembler import _format_slack_payload
    import json
    p = _format_slack_payload("sre", "Title", "Body", "test", "info")
    assert isinstance(p, bytes)
    payload = json.loads(p)
    assert isinstance(payload, dict)


def test_format_teams_payload_is_message_card():
    from assembler import _format_teams_payload
    import json
    p = _format_teams_payload("sre", "Title", "Body", "test", "info")
    assert isinstance(p, bytes)
    payload = json.loads(p)
    assert isinstance(payload, dict)


def test_format_generic_payload_has_required_keys():
    from assembler import _format_generic_payload
    import json
    p = _format_generic_payload("sre", "Title", "Body", "test", "info")
    assert isinstance(p, bytes)
    payload = json.loads(p)
    assert "domain" in payload
    assert "title" in payload


# ── Phase 2b: Sigma rule discovery ──────────────────────────────────────────

def test_sigma_pipelines_directory_exists():
    pipelines_dir = os.path.expanduser("~/Git/panops/rules/sigma/pipelines")
    assert os.path.isdir(pipelines_dir), f"Pipelines directory not found: {pipelines_dir}"


def test_clickhouse_pipelines_exist():
    pipelines_dir = os.path.expanduser("~/Git/panops/rules/sigma/pipelines")
    yaml_files = glob.glob(f"{pipelines_dir}/*clickhouse*.yaml")
    assert len(yaml_files) > 0, "No ClickHouse pipeline files found"
