import concurrent.futures
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import httpx
import structlog

log = structlog.get_logger()

LLAMA_URL = os.getenv("LLAMA_URL", "http://localhost:8080")
CH_URL = os.getenv("CH_URL", "http://clickhouse:8123")
MCP_MEMORY_URL = os.getenv("MCP_MEMORY_URL", "http://localhost:8082")
PORT = int(os.getenv("PORT", "8081"))

_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
_active: dict[str, concurrent.futures.Future] = {}


def check_llama() -> str:
    try:
        r = httpx.get(f"{LLAMA_URL}/v1/models", timeout=5)
        return "ready" if r.status_code == 200 else "degraded"
    except Exception:
        return "down"


def _run_investigation(happening: dict, flow_run_id: str) -> dict:
    from protocol import InvestigationProtocol
    proto = InvestigationProtocol(
        happening=happening,
        flow_run_id=flow_run_id,
        llama_url=LLAMA_URL,
        ch_url=CH_URL,
    )
    result = proto.run()
    return {
        "diagnosis": result.diagnosis,
        "confidence": result.confidence,
        "steps": result.steps,
    }


class AgentHandler(BaseHTTPRequestHandler):
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
            llama_status = check_llama()
            self._json(200, {"status": "ok", "llama": llama_status, "mcp": "disconnected"})
        elif self.path.startswith("/status"):
            hid = parse_qs(urlparse(self.path).query).get("happening_id", [""])[0]
            future = _active.get(hid)
            status = "unknown" if future is None else ("done" if future.done() else "running")
            self._json(200, {"status": status, "happening_id": hid})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/invoke":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            happening = body.get("happening", {})
            happening_id = str(happening.get("id", body.get("happening_id", "")))
            flow_run_id = body.get("flow_run_id", "")

            if not happening_id:
                self._json(400, {"error": "happening or happening_id required"})
                return

            # If already running for this happening, return current status
            existing = _active.get(happening_id)
            if existing and not existing.done():
                self._json(202, {"status": "running", "happening_id": happening_id})
                return

            future = _executor.submit(_run_investigation, happening, flow_run_id)
            _active[happening_id] = future

            def _on_done(f):
                try:
                    r = f.result(timeout=300)
                    log.info("investigation done", happening_id=happening_id, confidence=r.get("confidence"))
                except concurrent.futures.TimeoutError:
                    log.warning("investigation timeout", happening_id=happening_id)
                except Exception as e:
                    log.error("investigation error", happening_id=happening_id, error=str(e))
                _active.pop(happening_id, None)

            future.add_done_callback(_on_done)
            log.info("invoke", happening_id=happening_id, flow_run_id=flow_run_id)
            self._json(202, {"status": "accepted", "happening_id": happening_id})

        elif self.path == "/status":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            happening_id = body.get("happening_id", "")
            future = _active.get(happening_id)
            if future is None:
                self._json(200, {"status": "unknown", "happening_id": happening_id})
            elif future.done():
                self._json(200, {"status": "done", "happening_id": happening_id})
            else:
                self._json(200, {"status": "running", "happening_id": happening_id})

        else:
            self._json(404, {"error": "not found"})


if __name__ == "__main__":
    structlog.configure()
    log.info("starting", port=PORT, llama_url=LLAMA_URL)
    server = HTTPServer(("0.0.0.0", PORT), AgentHandler)
    server.serve_forever()
