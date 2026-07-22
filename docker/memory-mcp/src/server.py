import json
import logging
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import structlog

log = structlog.get_logger()

CH_URL = os.getenv("CH_URL", "http://clickhouse:8123")
CH_PASSWORD = os.getenv("CH_PASSWORD", "")
PORT = int(os.getenv("PORT", "8082"))

TOOLS = {"memory_write", "memory_read", "memory_search"}


def _ch(sql: str) -> list[dict]:
    auth = ("default", CH_PASSWORD) if CH_PASSWORD else None
    r = httpx.post(f"{CH_URL}/", params={"query": sql + " FORMAT JSONEachRow"}, auth=auth, timeout=10)
    r.raise_for_status()
    return [json.loads(line) for line in r.text.strip().splitlines() if line]


def _ch_exec(sql: str):
    auth = ("default", CH_PASSWORD) if CH_PASSWORD else None
    r = httpx.post(f"{CH_URL}/", params={"query": sql}, auth=auth, timeout=10)
    r.raise_for_status()


def memory_write(scope: str, scope_key: str, content: str,
                 source_happening_id: str = "00000000-0000-0000-0000-000000000000") -> str:
    safe_content = content.replace("'", "\\'")[:2000]
    safe_key = scope_key.replace("'", "\\'")[:256]
    safe_scope = scope.replace("'", "\\'")[:64]
    _ch_exec(f"""
        INSERT INTO panops.agent_memory (scope, scope_key, content, source_happening_id)
        VALUES ('{safe_scope}', '{safe_key}', '{safe_content}', '{source_happening_id}')
    """)
    return json.dumps({"written": True, "scope": scope, "scope_key": scope_key})


def memory_read(scope: str, scope_key: str = "", limit: int = 10) -> str:
    where = f"WHERE scope = '{scope.replace(chr(39), chr(92)+chr(39))}'"
    if scope_key:
        where += f" AND scope_key = '{scope_key.replace(chr(39), chr(92)+chr(39))}'"
    rows = _ch(f"SELECT scope, scope_key, content, written_at FROM panops.agent_memory {where} ORDER BY written_at DESC LIMIT {int(limit)}")
    return json.dumps(rows, default=str)


def memory_search(query: str, limit: int = 5) -> str:
    safe_q = query.replace("'", "\\'")[:200]
    rows = _ch(f"SELECT scope, scope_key, content, written_at FROM panops.agent_memory WHERE content ILIKE '%{safe_q}%' ORDER BY written_at DESC LIMIT {int(limit)}")
    return json.dumps(rows, default=str)


_DISPATCH = {
    "memory_write": memory_write,
    "memory_read": memory_read,
    "memory_search": memory_search,
}


class MemoryHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        log.info("http", method=self.command, path=self.path, msg=format % args)

    def _json(self, status: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok", "tools": list(TOOLS)})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/tools/call":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            name = body.get("name", "")
            args = body.get("arguments", {})
            fn = _DISPATCH.get(name)
            if fn is None:
                self._json(400, {"error": f"unknown tool: {name}"})
                return
            try:
                result = fn(**args)
                self._json(200, {"content": [{"type": "text", "text": result}]})
            except Exception as e:
                log.error("tool error", tool=name, error=str(e))
                self._json(500, {"error": str(e)})
        else:
            self._json(404, {"error": "not found"})


if __name__ == "__main__":
    structlog.configure()
    log.info("starting", port=PORT, ch_url=CH_URL)
    server = HTTPServer(("0.0.0.0", PORT), MemoryHandler)
    server.serve_forever()
