"""
Connectivity smoke tests — all must pass before integration tests run.
Run these first with: pytest tests/test_00_connectivity.py -v
"""
import json
import pytest
from conftest import http_get, http_post, ch_query, ASSEMBLER_URL, LLAMA_URL


def test_assembler_healthz():
    status, body = http_get("/healthz")
    assert status == 200
    assert body.strip() == "ok"


def test_assembler_decisions_endpoint():
    status, body = http_get("/decisions")
    assert status == 200
    data = json.loads(body)
    assert isinstance(data, list)


def test_clickhouse_reachable():
    rows = ch_query("SELECT 1 AS val").get("data", [])
    assert rows and int(rows[0]["val"]) == 1


def test_happenings_table_exists():
    rows = ch_query("SELECT count() as n FROM panops.happenings").get("data", [])
    assert rows  # table exists if query succeeds


def test_incident_embeddings_table_exists():
    rows = ch_query("SELECT count() as n FROM panops.incident_embeddings").get("data", [])
    assert rows


def test_consolidation_rewards_table_exists():
    rows = ch_query("SELECT count() as n FROM panops.consolidation_rewards").get("data", [])
    assert rows


def test_dream_state_table_exists():
    rows = ch_query("SELECT count() as n FROM panops.dream_state").get("data", [])
    assert rows


def test_component_heartbeats_table_exists():
    rows = ch_query("SELECT count() as n FROM panops.component_heartbeats").get("data", [])
    assert rows


def test_llama_server_models_endpoint():
    """llama-cpp-python[server] v0.3.9 exposes /v1/models (not /health)."""
    status, body = http_get("/v1/models", base=LLAMA_URL)
    assert status == 200
    data = json.loads(body)
    assert "data" in data


def test_llama_server_chat_completions_smoke():
    """Verify llama-server accepts a minimal chat request and returns valid JSON."""
    payload = {
        "model": "qwen",
        "messages": [{"role": "user", "content": "Reply with: OK"}],
        "max_tokens": 10,
        "temperature": 0.0,
    }
    status, body = http_post("/v1/chat/completions", payload, base=LLAMA_URL, timeout=60)
    assert status == 200
    data = json.loads(body)
    assert "choices" in data
    assert data["choices"][0]["message"]["content"]


def test_assembler_heartbeat_in_ch():
    """Assembler writes a heartbeat to CH every cycle — verify one exists within 5m."""
    from conftest import ch_query
    rows = ch_query(
        "SELECT recorded_at, status FROM panops.component_heartbeats "
        "WHERE component = 'assembler' "
        "AND recorded_at > now64() - INTERVAL 5 MINUTE "
        "ORDER BY recorded_at DESC LIMIT 1"
    ).get("data", [])
    assert rows, "No assembler heartbeat in CH in the last 5 minutes"
    assert rows[0]["status"] == "ok"
