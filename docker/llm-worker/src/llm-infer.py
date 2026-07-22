#!/usr/bin/env python3
"""
PanOps Brain — LLM inference worker (Step 9)
Spawned as a Kubernetes Job for novel/escalate happenings.
Reads happening from CH, generates a diagnosis+plan via Qwen2.5-3B,
writes the result back to panops.happenings (runbook_ref + actions_taken).
"""
import json, os, sys, urllib.request, datetime

CH_URL      = os.environ["CH_URL"]
CH_USER     = os.environ.get("CH_USER", "default")
CH_PASSWORD = os.environ.get("CH_PASSWORD", "")
HAPPENING_ID = os.environ["HAPPENING_ID"]
MODEL_PATH  = os.environ.get("MODEL_PATH", "/models/Qwen2.5-3B-Instruct-Q4_K_M.gguf")
CONFIDENCE_THRESHOLD = float(os.environ.get("LLM_CONFIDENCE_THRESHOLD", "0.6"))

def ch_query(sql):
    data = (sql.strip() + " FORMAT JSON").encode()
    req = urllib.request.Request(CH_URL, data=data, method="POST")
    req.add_header("Content-Type", "text/plain")
    req.add_header("X-ClickHouse-User", CH_USER)
    req.add_header("X-ClickHouse-Key",  CH_PASSWORD)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def ch_exec(sql):
    data = sql.strip().encode()
    req = urllib.request.Request(CH_URL, data=data, method="POST")
    req.add_header("Content-Type", "text/plain")
    req.add_header("X-ClickHouse-User", CH_USER)
    req.add_header("X-ClickHouse-Key",  CH_PASSWORD)
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()

def log(msg):
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(f"{ts} [LLM] {msg}", flush=True)

def fetch_happening(hid):
    rows = ch_query(f"""
        SELECT *
        FROM panops.happenings
        WHERE id = '{hid}'
        LIMIT 1
    """).get("data", [])
    if not rows:
        raise RuntimeError(f"Happening {hid} not found")
    return rows[0]

def fetch_similar(happening, n=3):
    emb_rows = ch_query(f"""
        SELECT embedding
        FROM panops.incident_embeddings
        WHERE happening_id = '{happening["id"]}'
        LIMIT 1
    """).get("data", [])
    if not emb_rows:
        return []
    emb = emb_rows[0]["embedding"]
    similar = ch_query(f"""
        SELECT ie.happening_id, h.domain, h.outcome, h.actions_taken, h.runbook_ref,
               cosineDistance(ie.embedding, {emb}) AS dist
        FROM panops.incident_embeddings ie
        JOIN panops.happenings h ON h.id = ie.happening_id
        WHERE ie.happening_id != '{happening["id"]}'
          AND h.status = 'resolved'
        ORDER BY dist ASC
        LIMIT {n}
    """).get("data", [])
    return similar

def build_prompt(happening, similar):
    sig_summary = (
        f"Falco rules: {happening.get('falco_rules', '[]')}\n"
        f"Sigma rule IDs: {happening.get('sigma_rule_ids', '[]')}\n"
        f"YARA matches: {happening.get('yara_matches', '[]')}\n"
        f"Drain3 patterns: {happening.get('drain3_patterns', '[]')}\n"
        f"Metric anomalies: {happening.get('metric_anomalies', '[]')}"
    )
    similar_text = ""
    for s in similar:
        similar_text += (
            f"\n- Domain: {s.get('domain')}, Outcome: {s.get('outcome')}, "
            f"Actions: {s.get('actions_taken')}, Distance: {s.get('dist', 0):.3f}"
        )

    system_msg = (
        "You are a Kubernetes SRE assistant. "
        "Analyse the incident and output ONLY valid JSON matching the schema. "
        "Do not add any text outside the JSON object."
    )
    user_msg = f"""Incident happening:
id: {happening["id"]}
domain: {happening.get("domain")}
affected_services: {happening.get("affected_services")}
opened_at: {happening.get("opened_at")}
signals:
{sig_summary}

Similar past incidents:{similar_text if similar_text else " none"}

Available remediation actions:
- kubectl rollout restart deployment/<name> -n <namespace>
- kubectl delete pod <name> -n <namespace>
- kubectl patch deployment/<name> -n <namespace> -p '{{"spec":{{"template":{{"metadata":{{"annotations":{{"redeploy":"1"}}}}}}}}}}'
- kubectl scale deployment/<name> --replicas=<n> -n <namespace>

Output JSON schema:
{{
  "diagnosis": "<1-2 sentence root cause>",
  "steps": [{{"command": "<kubectl command>", "expected_output": "<what success looks like>"}}],
  "validation_query": "<PromQL or LogQL to confirm resolved>",
  "confidence": <float 0-1>,
  "runbook_entry": "<markdown paragraph suitable for a runbook>"
}}"""
    return system_msg, user_msg

def run_llm(system_msg, user_msg):
    log(f"Loading model from {MODEL_PATH}")
    from llama_cpp import Llama
    llm = Llama(
        model_path=MODEL_PATH,
        n_ctx=2048,
        n_threads=4,
        verbose=False,
    )
    log("Model loaded, running inference...")
    messages = [
        {"role": "system", "content": system_msg},
        {"role": "user",   "content": user_msg},
    ]
    resp = llm.create_chat_completion(
        messages=messages,
        max_tokens=512,
        temperature=0.1,
        response_format={"type": "json_object"},
    )
    raw = resp["choices"][0]["message"]["content"]
    log(f"Raw response: {raw[:200]}...")
    return json.loads(raw)

def write_result(hid, result, confidence):
    actions = json.dumps(result.get("steps", []))
    runbook = result.get("runbook_entry", "").replace("'", "''")
    diagnosis = result.get("diagnosis", "").replace("'", "''")
    status = "validating" if confidence >= CONFIDENCE_THRESHOLD else "escalated"
    ch_exec(f"""
        ALTER TABLE panops.happenings UPDATE
          actions_taken = '{actions}',
          runbook_ref   = 'auto-llm: {diagnosis[:200]}',
          status        = '{status}'
        WHERE id = '{hid}'
    """)
    log(f"Updated happening {hid}: status={status} confidence={confidence:.2f}")

def main():
    log(f"LLM inference starting for happening={HAPPENING_ID}")
    happening = fetch_happening(HAPPENING_ID)
    log(f"Fetched happening domain={happening.get('domain')} route={happening.get('classifier_route')}")
    similar = fetch_similar(happening)
    log(f"Found {len(similar)} similar resolved incidents")
    system_msg, user_msg = build_prompt(happening, similar)

    try:
        result = run_llm(system_msg, user_msg)
    except Exception as e:
        log(f"ERROR: LLM inference failed: {e}")
        ch_exec(f"""
            ALTER TABLE panops.happenings UPDATE
              status = 'escalated',
              runbook_ref = 'llm-failed: {str(e)[:100].replace("'", "")}'
            WHERE id = '{HAPPENING_ID}'
        """)
        sys.exit(1)

    confidence = float(result.get("confidence", 0.0))
    log(f"Inference complete. confidence={confidence:.2f}")
    log(f"Diagnosis: {result.get('diagnosis', '')}")
    log(f"Steps: {result.get('steps', [])}")

    print("=== LLM RUNBOOK ===", flush=True)
    print(result.get("runbook_entry", ""), flush=True)
    print("=== END RUNBOOK ===", flush=True)

    write_result(HAPPENING_ID, result, confidence)
    log("Done.")

if __name__ == "__main__":
    main()
