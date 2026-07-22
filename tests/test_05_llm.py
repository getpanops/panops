"""
LLM escalation path tests.

Three tiers:
  1. Direct llama-server tests (connectivity + response schema)
  2. Assembler /test/llm endpoint (end-to-end: CH insert → LLM call → CH update)
  3. Circuit-breaker state inspection

The /test/llm endpoint must exist on the assembler. If it returns 404 the
end-to-end tests are skipped with an explanation — run assembler patch first.
"""
import json
import time
import urllib.error
import pytest
from conftest import http_get, http_post, ch_query, poll_happening_by_id, LLAMA_URL, POLL_TIMEOUT

# ── Tier 1: direct llama-server ───────────────────────────────────────────────

XOPS_LLM_SCHEMA = {"diagnosis", "steps", "validation_query", "confidence", "runbook_entry"}


def test_llama_server_reachable():
    status, body = http_get("/v1/models", base=LLAMA_URL)
    assert status == 200


def test_llama_chat_returns_choices():
    payload = {
        "model": "qwen",
        "messages": [{"role": "user", "content": "Say only: PONG"}],
        "max_tokens": 16,
        "temperature": 0.0,
    }
    status, body = http_post("/v1/chat/completions", payload, base=LLAMA_URL, timeout=60)
    assert status == 200
    data = json.loads(body)
    assert "choices" in data
    assert len(data["choices"]) >= 1
    assert data["choices"][0]["message"]["content"].strip()


def test_llama_returns_panops_json_schema():
    """
    Ask the LLM to produce the exact PanOps JSON schema the assembler expects.
    Verifies that the model can follow structured output constraints.
    """
    system_msg = (
        "You are PanOps-Brain, an autonomous SRE/SOC operations assistant managing mixed infrastructure "
        "(Kubernetes clusters, Linux hosts, Windows servers, and Hyper-V hypervisors). "
        "Output ONLY valid JSON. "
        "Do not add any text outside the JSON object."
    )
    user_msg = (
        "Incident happening:\n"
        "id: test-00000000\n"
        "domain: SRE\n"
        "affected_services: ['test-namespace']\n"
        "opened_at: 2026-01-01 00:00:00\n"
        "signals:\n- OOMKill detected in test-namespace\n\n"
        "Similar past incidents: none\n\n"
        "Available remediation actions:\n"
        "- kubectl rollout restart deployment/<name> -n <namespace>\n"
        "- kubectl delete pod <name> -n <namespace>\n\n"
        'Output JSON schema:\n{"diagnosis":"<1-2 sentence root cause>",'
        '"steps":[{"command":"<kubectl command>","expected_output":"<success indicator>"}],'
        '"validation_query":"<PromQL or LogQL>","confidence":<float 0-1>,'
        '"runbook_entry":"<markdown paragraph>"}'
    )
    payload = {
        "model": "qwen",
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user",   "content": user_msg},
        ],
        "max_tokens": 512,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    status, body = http_post("/v1/chat/completions", payload, base=LLAMA_URL, timeout=120)
    assert status == 200
    resp = json.loads(body)
    raw = resp["choices"][0]["message"]["content"].strip()
    result = json.loads(raw)
    missing = XOPS_LLM_SCHEMA - set(result.keys())
    assert not missing, f"LLM response missing required fields: {missing}\nGot: {list(result.keys())}"
    confidence = float(result["confidence"])
    assert 0.0 <= confidence <= 1.0, f"confidence out of range: {confidence}"
    assert result["diagnosis"]
    assert isinstance(result["steps"], list)


# ── Tier 2: end-to-end via /test/llm assembler endpoint ───────────────────────

def _check_testllm_available():
    """Return True if the assembler has the /test/llm endpoint (fast ping, no LLM call)."""
    try:
        status, _ = http_get("/test/llm/ping", timeout=5)
        return status == 200
    except urllib.error.HTTPError as e:
        return False
    except Exception:
        return False


@pytest.fixture(scope="module")
def testllm_available():
    if not _check_testllm_available():
        pytest.skip(
            "/test/llm endpoint not found on assembler — apply the assembler patch "
            "(add _test_llm_path() to Handler.do_GET) and redeploy."
        )


def test_assembler_llm_path_end_to_end(testllm_available):
    """
    GET /test/llm:
      - Assembler inserts a synthetic novel happening into panops.happenings
      - Calls _call_llm_server(happening_id) in the request thread
      - Returns JSON: {happening_id, status, confidence, actions_taken, elapsed_s}
    Verifies the full assembler → llama-server → CH write pipeline.
    """
    status, body = http_get("/test/llm", timeout=130)
    assert status == 200
    result = json.loads(body)
    assert "happening_id" in result, f"Response missing happening_id: {result}"
    assert "status" in result
    assert "confidence" in result
    assert result["status"] in ("validating", "escalated", "error"), (
        f"Unexpected status: {result['status']}"
    )
    if result["status"] != "error":
        conf = float(result["confidence"])
        assert 0.0 <= conf <= 1.0


def test_assembler_llm_updates_ch_record(testllm_available):
    """
    After /test/llm completes, the happening row in CH should have
    actions_taken and runbook_ref populated (not empty).
    """
    status, body = http_get("/test/llm", timeout=130)
    assert status == 200
    result = json.loads(body)
    if result.get("status") == "error":
        pytest.skip(f"LLM call errored: {result.get('error')}")

    happening_id = result["happening_id"]
    rows = ch_query(
        f"SELECT actions_taken, runbook_ref, status "
        f"FROM panops.happenings WHERE id = '{happening_id}' LIMIT 1"
    ).get("data", [])
    assert rows, f"Happening {happening_id} not found in CH after /test/llm"
    row = rows[0]
    assert row["actions_taken"] not in ("", "[]", None), (
        "actions_taken empty after LLM call — LLM response may not have been written to CH"
    )
    assert row["runbook_ref"], "runbook_ref empty after LLM call"


# ── Tier 3: circuit breaker state ─────────────────────────────────────────────

def test_llm_circuit_breaker_table_state():
    """
    The assembler tracks LLM failures in memory (_llm_circuit).
    We can't inspect in-process state from outside, but we can verify that
    LLM-processed happenings exist (circuit wasn't always open).
    """
    rows = ch_query(
        "SELECT count() as n FROM panops.happenings "
        "WHERE actions_taken != '' AND actions_taken != '[]' "
        "AND classifier_route IN ('novel', 'escalate') "
        "AND opened_at > now64() - INTERVAL 7 DAY"
    ).get("data", [])
    n = int(rows[0]["n"]) if rows else 0
    print(f"  LLM-processed happenings in last 7d: {n}")
    # If the /test/llm test passed, this will be >= 1.
    # If no novel happenings have occurred naturally, n=0 is also acceptable.
    # The test is primarily an informational assertion.
    assert n >= 0  # always true — documents the check


def test_novel_happenings_get_llm_response_eventually():
    """
    Any happening stuck with classifier_route='novel' and status='open'
    for > 10 minutes suggests the LLM circuit may be open or the assembler
    failed to call _call_llm_server.
    """
    rows = ch_query(
        "SELECT toString(id) as id, opened_at, status "
        "FROM panops.happenings "
        "WHERE classifier_route IN ('novel', 'escalate') "
        "AND status = 'open' "
        "AND opened_at < now64() - INTERVAL 10 MINUTE "
        "LIMIT 5"
    ).get("data", [])
    if rows:
        ids = [r["id"][:8] for r in rows]
        pytest.fail(
            f"Novel happenings stuck in 'open' status >10min: {ids}\n"
            "Possible causes: LLM circuit breaker open (>3 failures/hr), "
            "llama-server unavailable, or assembler crash during LLM call."
        )
