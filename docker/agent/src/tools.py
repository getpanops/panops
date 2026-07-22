import json
import os

import httpx

CH_URL = os.getenv("CH_URL", "http://clickhouse:8123")
CH_PASSWORD = os.getenv("CH_PASSWORD", "")


def _ch(sql: str) -> list[dict]:
    auth = ("default", CH_PASSWORD) if CH_PASSWORD else None
    r = httpx.post(
        f"{CH_URL}/",
        params={"query": sql + " FORMAT JSONEachRow"},
        auth=auth,
        timeout=10,
    )
    r.raise_for_status()
    return [json.loads(line) for line in r.text.strip().splitlines() if line]


def query_happenings(happening_id: str = "", domain: str = "", limit: int = 10) -> str:
    """Fetch happening details from ClickHouse."""
    where_clauses = []
    if happening_id:
        where_clauses.append(f"id = '{happening_id}'")
    if domain:
        where_clauses.append(f"domain = '{domain}'")
    where = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    sql = f"""
        SELECT id, domain, affected_services, drain3_patterns, signals, status,
               runbook_ref, pending_synthesis, opened_at
        FROM panops.happenings
        {where}
        ORDER BY opened_at DESC
        LIMIT {limit}
    """
    rows = _ch(sql)
    return json.dumps(rows, default=str)


def get_similar_incidents(domain: str, limit: int = 5) -> str:
    """Find past incidents in the same domain that were resolved with a runbook."""
    rows = _ch(f"""
        SELECT id, domain, drain3_patterns, runbook_ref, opened_at
        FROM panops.happenings
        WHERE domain = '{domain}'
          AND runbook_ref IS NOT NULL
          AND runbook_ref != ''
        ORDER BY opened_at DESC
        LIMIT {limit}
    """)
    return json.dumps(rows, default=str)


def read_runbook(happening_id: str) -> str:
    """Read the runbook entry for a specific past incident."""
    rows = _ch(f"""
        SELECT runbook_ref FROM panops.happenings
        WHERE id = '{happening_id}' LIMIT 1
    """)
    if rows:
        return rows[0].get("runbook_ref", "No runbook found")
    return "Happening not found"


def get_node_metrics(namespace: str = "panops", limit: int = 5) -> str:
    """Get recent resource pressure signals from the signals column of happenings."""
    rows = _ch(f"""
        SELECT id, domain, signals, opened_at
        FROM panops.happenings
        WHERE JSONExtractString(signals, 'node') != ''
           OR JSONExtractString(signals, 'memory_pressure') != ''
        ORDER BY opened_at DESC
        LIMIT {limit}
    """)
    return json.dumps(rows, default=str)


def query_memory(scope: str = "global", scope_key: str = "", limit: int = 10) -> str:
    """Read from agent_memory for relevant past insights."""
    where_clauses = [f"scope = '{scope}'"]
    if scope_key:
        where_clauses.append(f"scope_key = '{scope_key}'")
    where = "WHERE " + " AND ".join(where_clauses)
    rows = _ch(f"""
        SELECT scope, scope_key, content, written_at
        FROM panops.agent_memory
        {where}
        ORDER BY written_at DESC
        LIMIT {limit}
    """)
    return json.dumps(rows, default=str)


# ── Schema exposed to the LLM ──────────────────────────────────────────────

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "query_happenings",
            "description": "Fetch happening/incident details from the panops database",
            "parameters": {
                "type": "object",
                "properties": {
                    "happening_id": {"type": "string", "description": "UUID of a specific happening"},
                    "domain":       {"type": "string", "description": "Filter by domain (e.g. 'kubernetes', 'security')"},
                    "limit":        {"type": "integer", "description": "Max rows to return", "default": 10},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_similar_incidents",
            "description": "Find past incidents in the same domain that have runbook entries",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to search"},
                    "limit":  {"type": "integer", "default": 5},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_runbook",
            "description": "Read the runbook entry for a specific past incident by ID",
            "parameters": {
                "type": "object",
                "properties": {
                    "happening_id": {"type": "string", "description": "UUID of the happening with a runbook"},
                },
                "required": ["happening_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_node_metrics",
            "description": "Get recent node-level resource pressure events",
            "parameters": {
                "type": "object",
                "properties": {
                    "namespace": {"type": "string", "default": "panops"},
                    "limit":     {"type": "integer", "default": 5},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_memory",
            "description": "Read persistent agent memory for past insights",
            "parameters": {
                "type": "object",
                "properties": {
                    "scope":     {"type": "string", "default": "global"},
                    "scope_key": {"type": "string", "description": "Optional key filter"},
                    "limit":     {"type": "integer", "default": 10},
                },
            },
        },
    },
]

_DISPATCH = {
    "query_happenings":    query_happenings,
    "get_similar_incidents": get_similar_incidents,
    "read_runbook":        read_runbook,
    "get_node_metrics":    get_node_metrics,
    "query_memory":        query_memory,
}


def dispatch(tool_name: str, args: dict) -> str:
    fn = _DISPATCH.get(tool_name)
    if fn is None:
        return f"unknown tool: {tool_name}"
    try:
        return fn(**args)
    except Exception as e:
        return f"tool error ({tool_name}): {e}"
