import json, os, time, uuid, logging
from dataclasses import dataclass, field
from typing import Optional
import httpx

log = logging.getLogger(__name__)

LLAMA_URL = os.getenv("LLAMA_URL", "http://localhost:8080")
MAX_GATHER_STEPS = 5

VALID_PLANS = {
    "oom_investigation", "crashloop_investigation", "probe_investigation",
    "security_investigation", "novel_investigation"
}

# Tool list allowed per investigation plan (populated in task 3.3 — stub here)
PLAN_TOOLS: dict[str, list[str]] = {
    "oom_investigation":       ["query_happenings", "get_similar_incidents", "read_runbook", "query_memory"],
    "crashloop_investigation": ["query_happenings", "get_similar_incidents", "read_runbook"],
    "probe_investigation":     ["query_happenings", "read_runbook"],
    "security_investigation":  ["query_happenings", "get_similar_incidents", "query_memory"],
    "novel_investigation":     ["query_happenings", "get_similar_incidents", "get_node_metrics", "query_memory"],
}

@dataclass
class SynthesisResult:
    diagnosis: str = ""
    steps: list[str] = field(default_factory=list)
    confidence: float = 0.0
    runbook_entry: str = ""
    memory_note: Optional[str] = None

class InvestigationProtocol:
    def __init__(self, happening: dict, llama_url: str = LLAMA_URL,
                 ch_url: str = None, ch_password: str = None,
                 flow_run_id: str = ""):
        self.happening = happening
        self.happening_id = str(happening.get("id", ""))
        self.llama_url = llama_url
        self.flow_run_id = flow_run_id
        self.ch_url = ch_url or os.getenv("CH_URL", "http://clickhouse:8123")
        self.ch_password = ch_password or os.getenv("CH_PASSWORD", "")
        self.trace_step = 0

    def run(self) -> SynthesisResult:
        plan = self._triage()
        messages = self._gather(plan)
        result = self._synthesise(messages)
        self._validate(result)
        return result

    def _llm(self, messages: list, tools: list = None, json_mode: bool = False) -> dict:
        """Single call to llama-server. Returns the response message dict."""
        payload = {
            "model": "local",
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 1024,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        r = httpx.post(f"{self.llama_url}/v1/chat/completions", json=payload, timeout=120)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]

    def _write_trace(self, phase: str, tool_name: str = "", tool_input: str = "",
                     tool_output: str = "", model_output: str = ""):
        self.trace_step += 1
        try:
            self._ch_exec(f"""
                INSERT INTO panops.investigation_traces
                    (happening_id, flow_run_id, phase, step, tool_name, tool_input, tool_output, model_output)
                VALUES (
                    '{self.happening_id}', '{self.flow_run_id}', '{phase}',
                    {self.trace_step},
                    '{tool_name.replace("'", "\\'")}',
                    '{json.dumps(tool_input).replace("'", "\\'")}',
                    '{str(tool_output)[:2000].replace("'", "\\'")}',
                    '{str(model_output)[:2000].replace("'", "\\'")}')
            """)
        except Exception as e:
            log.warning("trace write failed: %s", e)

    def _ch_exec(self, sql: str):
        import requests as _requests
        auth = ("default", self.ch_password) if self.ch_password else None
        r = _requests.post(f"{self.ch_url}/", params={"query": sql}, auth=auth, timeout=10)
        r.raise_for_status()

    def _ch_query(self, sql: str) -> list[dict]:
        import requests as _requests
        auth = ("default", self.ch_password) if self.ch_password else None
        r = _requests.post(f"{self.ch_url}/", params={"query": sql + " FORMAT JSONEachRow"},
                           auth=auth, timeout=10)
        r.raise_for_status()
        return [json.loads(line) for line in r.text.strip().splitlines() if line]

    def _triage(self) -> str:
        """Phase 1: Classify incident type, select investigation plan."""
        h = self.happening
        prompt = f"""You are an SRE/SOC incident triage agent. Classify this incident and select an investigation plan.

Incident:
- Domain: {h.get('domain', 'UNKNOWN')}
- Affected services: {h.get('affected_services', [])}
- Drain3 patterns: {h.get('drain3_patterns', [])}
- Signals: {h.get('signals', {})}

Choose exactly one investigation_plan from: oom_investigation, crashloop_investigation, probe_investigation, security_investigation, novel_investigation

Respond with JSON only: {{"investigation_plan": "<plan>", "reasoning": "<one sentence>"}}"""

        msg = self._llm(
            [{"role": "user", "content": prompt}],
            json_mode=True
        )
        content = msg.get("content", "{}")
        try:
            result = json.loads(content)
            plan = result.get("investigation_plan", "novel_investigation")
            if plan not in VALID_PLANS:
                plan = "novel_investigation"
        except Exception:
            plan = "novel_investigation"

        self._write_trace("TRIAGE", model_output=f"plan={plan}")
        log.info("triage complete: plan=%s hid=%s", plan, self.happening_id)
        return plan

    def _gather(self, plan: str) -> list[dict]:
        """Phase 2: Bounded tool loop, max MAX_GATHER_STEPS calls."""
        from tools import TOOL_SCHEMAS, dispatch  # imported here; stubs until task 3.3

        allowed = PLAN_TOOLS.get(plan, [])
        tool_schemas = [s for s in TOOL_SCHEMAS if s["function"]["name"] in allowed]

        h = self.happening
        messages = [
            {"role": "system", "content": "You are an SRE/SOC investigation agent. Use tools to gather evidence about this incident. When you have enough information, stop calling tools."},
            {"role": "user", "content": f"Investigate this incident:\nDomain: {h.get('domain')}\nServices: {h.get('affected_services')}\nPatterns: {h.get('drain3_patterns')}\n\nPlan: {plan}"}
        ]

        for step in range(MAX_GATHER_STEPS):
            msg = self._llm(messages, tools=tool_schemas if tool_schemas else None)
            messages.append(msg)

            tool_calls = msg.get("tool_calls", [])
            if not tool_calls:
                self._write_trace("GATHER", model_output=f"step={step} no_more_tools")
                break

            for tc in tool_calls:
                name = tc["function"]["name"]
                args = json.loads(tc["function"].get("arguments", "{}"))
                try:
                    result = dispatch(name, args)
                except Exception as e:
                    result = f"error: {e}"
                self._write_trace("GATHER", tool_name=name, tool_input=str(args), tool_output=result)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": str(result)
                })

        return messages

    def _synthesise(self, messages: list) -> SynthesisResult:
        """Phase 3: Single structured synthesis call."""
        messages = messages + [{
            "role": "user",
            "content": """Based on the evidence gathered, provide a structured incident analysis.
Respond with JSON only:
{
  "diagnosis": "root cause in one clear sentence",
  "steps": ["remediation step 1", "step 2", "..."],
  "confidence": 0.85,
  "runbook_entry": "markdown runbook entry for future reference",
  "memory_note": "key insight worth remembering, or null"
}
confidence must be a float between 0 and 1."""
        }]

        msg = self._llm(messages, json_mode=True)
        content = msg.get("content", "{}")
        try:
            data = json.loads(content)
            result = SynthesisResult(
                diagnosis=data.get("diagnosis", ""),
                steps=data.get("steps", []),
                confidence=float(data.get("confidence", 0.0)),
                runbook_entry=data.get("runbook_entry", ""),
                memory_note=data.get("memory_note"),
            )
        except Exception as e:
            log.warning("synthesis parse failed: %s — %s", e, content[:200])
            result = SynthesisResult(confidence=0.0)

        self._write_trace("SYNTHESISE", model_output=f"confidence={result.confidence}")
        return result

    def _validate(self, result: SynthesisResult):
        """Phase 4: Deterministic routing by confidence. No model call."""
        hid = self.happening_id
        if result.confidence >= 0.70:
            # Write runbook and clear pending flag
            safe_runbook = result.runbook_entry.replace("'", "\\'")[:4000]
            self._ch_exec(f"""
                ALTER TABLE panops.happenings UPDATE
                    runbook_ref = '{safe_runbook}',
                    pending_synthesis = 0
                WHERE id = '{hid}'
            """)
            if result.memory_note:
                safe_note = result.memory_note.replace("'", "\\'")[:1000]
                self._ch_exec(f"""
                    INSERT INTO panops.agent_memory (scope, scope_key, content, source_happening_id)
                    VALUES ('incident', '{self.happening.get('domain','UNKNOWN')}',
                            '{safe_note}', '{hid}')
                """)
            log.info("validate: runbook written confidence=%.2f hid=%s", result.confidence, hid)
        elif result.confidence >= 0.50:
            self._ch_exec(f"""
                ALTER TABLE panops.happenings UPDATE
                    status = 'escalated',
                    pending_synthesis = 0
                WHERE id = '{hid}'
            """)
            log.info("validate: escalated confidence=%.2f hid=%s", result.confidence, hid)
        else:
            self._ch_exec(f"""
                ALTER TABLE panops.happenings UPDATE
                    status = 'escalated',
                    pending_synthesis = 1
                WHERE id = '{hid}'
            """)
            log.warning("validate: pending_synthesis set confidence=%.2f hid=%s", result.confidence, hid)
        self._write_trace("VALIDATE", model_output=f"confidence={result.confidence} routed")
