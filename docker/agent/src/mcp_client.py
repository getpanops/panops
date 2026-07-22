import asyncio
import json
import logging
import os
from typing import Any, Optional

import httpx

log = logging.getLogger(__name__)

MCP_MEMORY_URL = os.getenv("MCP_MEMORY_URL", "http://localhost:8082")


class MCPClient:
    """Thin HTTP wrapper around the memory-mcp FastMCP server.

    The memory-mcp server exposes tools over HTTP at /tools/call.
    Falls back gracefully if the server is unreachable.
    """

    def __init__(self, base_url: str = MCP_MEMORY_URL, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._available: Optional[bool] = None

    def _call(self, tool_name: str, arguments: dict) -> Optional[Any]:
        """Synchronous tool call. Returns parsed result or None on failure."""
        try:
            r = httpx.post(
                f"{self.base_url}/tools/call",
                json={"name": tool_name, "arguments": arguments},
                timeout=self.timeout,
            )
            r.raise_for_status()
            data = r.json()
            # FastMCP returns {"content": [{"type": "text", "text": "..."}]}
            content = data.get("content", [])
            if content and content[0].get("type") == "text":
                raw = content[0]["text"]
                try:
                    return json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    return raw
            return data
        except httpx.ConnectError:
            if self._available is not False:
                log.debug("memory-mcp unavailable at %s", self.base_url)
            self._available = False
            return None
        except Exception as e:
            log.warning("mcp_call %s failed: %s", tool_name, e)
            return None

    def is_available(self) -> bool:
        try:
            r = httpx.get(f"{self.base_url}/health", timeout=2)
            self._available = r.status_code == 200
        except Exception:
            self._available = False
        return bool(self._available)

    def memory_write(self, scope: str, scope_key: str, content: str,
                     source_happening_id: str = "") -> bool:
        result = self._call("memory_write", {
            "scope": scope,
            "scope_key": scope_key,
            "content": content,
            "source_happening_id": source_happening_id,
        })
        return result is not None

    def memory_read(self, scope: str, scope_key: str = "", limit: int = 10) -> list[dict]:
        result = self._call("memory_read", {
            "scope": scope,
            "scope_key": scope_key,
            "limit": limit,
        })
        if isinstance(result, list):
            return result
        return []

    def memory_search(self, query: str, limit: int = 5) -> list[dict]:
        result = self._call("memory_search", {
            "query": query,
            "limit": limit,
        })
        if isinstance(result, list):
            return result
        return []
