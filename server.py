#!/usr/bin/env python3
"""
Query Sanitizer MCP Middleware

Intercepts prompts before they reach external LLMs, redacts sensitive data
using a local model (Ollama / LM Studio), and restores placeholders in responses.

Tools:
  sanitize_query(text)          → sanitized text + san_id
  restore_response(text, san_id) → original values rehydrated
  view_ledger(last_n)           → recent sanitization history
"""

import json
import os
import random
import string
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

LOCAL_MODEL_URL = os.getenv("SANITIZER_MODEL_URL", "http://localhost:11434/v1/chat/completions")
LOCAL_MODEL_NAME = os.getenv("SANITIZER_MODEL_NAME", "llama3.2")

LEDGER_DIR = Path(os.getenv("SANITIZER_LEDGER_DIR", ".sanitizer-ledger"))
LEDGER_FILE = LEDGER_DIR / "ledger.jsonl"
CONFIG_FILE = LEDGER_DIR / "config.json"

# ---------------------------------------------------------------------------
# Sanitizer system prompt (embedded from skill rules)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a data loss prevention (DLP) engine. Analyze the user's text and redact ALL sensitive information.

Categories to detect and redact:
- CREDENTIAL: API keys, tokens, passwords, secrets → replace with [CREDENTIAL_REDACTED] and mark blocked:true
- INTERNAL_URL: intranet URLs, internal domains, staging endpoints → [INTERNAL_URL_N]
- PII_NAME: employee names, emails, phone numbers → [PII_NAME_N]
- PII_ID: SSNs, employee IDs, badge numbers → [PII_ID_N]
- ORG_NAME: company names, subsidiary names → [ORG_NAME_N]
- PROJECT_NAME: internal codenames, pre-launch product names → [PROJECT_NAME_N]
- INFRA: internal IPs, hostnames, cluster names, DB names → [INFRA_N]
- GEO_INTERNAL: office locations, building names → [GEO_INTERNAL_N]
- FINANCIAL: revenue figures, deal sizes, budget numbers → [FINANCIAL_N]
- LEGAL: contract terms, NDA entities, case numbers → [LEGAL_N]

Rules:
1. Same token → same placeholder throughout (consistency)
2. Emails generate both PII_NAME and ORG_NAME entries
3. When unsure, redact with low confidence (0.5–0.69) rather than miss it
4. Do NOT redact: generic tech terms (Kubernetes, PostgreSQL), public company names used generically, standard algorithms

Respond ONLY with valid JSON in this exact structure:
{
  "sanitized_text": "<text with placeholders>",
  "mappings": [
    {"placeholder": "[ORG_NAME_1]", "original": "<original>", "category": "ORG_NAME", "confidence": 0.95, "blocked": false},
    {"placeholder": "[CREDENTIAL_REDACTED]", "original": "[BLOCKED]", "category": "CREDENTIAL", "confidence": 0.99, "blocked": true}
  ]
}

If nothing sensitive is found, return:
{"sanitized_text": "<original text unchanged>", "mappings": []}
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _san_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = "".join(random.choices(string.hexdigits[:16], k=4)).lower()
    return f"san_{ts}_{suffix}"


def _call_local_model(text: str) -> dict:
    payload = json.dumps({
        "model": LOCAL_MODEL_NAME,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
        "temperature": 0.0,
        "response_format": {"type": "json_object"},
    }).encode()

    req = urllib.request.Request(
        LOCAL_MODEL_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = json.loads(resp.read())

    content = body["choices"][0]["message"]["content"]
    return json.loads(content)


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def _write_ledger(entry: dict):
    LEDGER_DIR.mkdir(exist_ok=True)
    with LEDGER_FILE.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _read_ledger(last_n: int = 0) -> list:
    if not LEDGER_FILE.exists():
        return []
    entries = [json.loads(l) for l in LEDGER_FILE.read_text().strip().splitlines() if l.strip()]
    return entries[-last_n:] if last_n else entries


def _build_ledger_entry(san_id: str, mappings: list) -> dict:
    stats = {"critical_blocked": 0, "high_redacted": 0, "medium_redacted": 0,
             "low_redacted": 0, "total_redacted": len(mappings)}
    high_cats = {"CREDENTIAL", "PII_NAME", "PII_ID", "ORG_NAME", "LEGAL"}
    medium_cats = {"PROJECT_NAME", "INFRA", "FINANCIAL"}
    for m in mappings:
        if m.get("blocked"):
            stats["critical_blocked"] += 1
        elif m["category"] in high_cats:
            stats["high_redacted"] += 1
        elif m["category"] in medium_cats:
            stats["medium_redacted"] += 1
        else:
            stats["low_redacted"] += 1
    return {
        "id": san_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "direction": "outbound",
        "token_count": len(mappings),
        "mappings": mappings,
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "query-sanitizer",
    instructions=(
        "DLP middleware: call sanitize_query before sending text to any external LLM. "
        "Call restore_response to rehydrate the LLM's answer with original values."
    ),
)


@mcp.tool()
def sanitize_query(text: str) -> str:
    """
    Sanitize a query before sending to an external LLM.
    Redacts org names, PII, credentials, internal infrastructure, and project codenames.
    Returns the safe text and a san_id needed to restore the response later.
    """
    try:
        result = _call_local_model(text)
    except Exception as e:
        return json.dumps({"error": f"Local model unavailable: {e}", "original_text": text})

    sanitized_text = result.get("sanitized_text", text)
    mappings = result.get("mappings", [])

    san_id = _san_id()
    entry = _build_ledger_entry(san_id, mappings)
    _write_ledger(entry)

    # Build report
    blocked = [m for m in mappings if m.get("blocked")]
    flagged = [m for m in mappings if not m.get("blocked") and m.get("confidence", 1.0) < 0.7]

    report_lines = [f"san_id: {san_id}"]

    if mappings:
        report_lines.append(f"redactions: {len(mappings)} ({entry['stats']['critical_blocked']} credentials blocked)")
        for m in mappings:
            conf = m.get("confidence", 1.0)
            flag = " [LOW CONFIDENCE — review]" if conf < 0.7 else ""
            masked = "██████" if not m.get("blocked") else "[BLOCKED]"
            report_lines.append(f"  {m['category']}: {masked} → {m['placeholder']} ({conf:.2f}){flag}")
    else:
        report_lines.append("no sensitive data detected")

    if blocked:
        report_lines.append(f"⚠  CREDENTIALS BLOCKED: {len(blocked)} credential(s) removed")

    report_lines.append("")
    report_lines.append("sanitized_text:")
    report_lines.append(sanitized_text)

    return "\n".join(report_lines)


@mcp.tool()
def restore_response(response_text: str, san_id: str) -> str:
    """
    Restore placeholders in an LLM response back to original values.
    Requires the san_id returned by sanitize_query.
    """
    entries = _read_ledger()
    entry = next((e for e in reversed(entries) if e["id"] == san_id), None)

    if not entry:
        return f"Error: san_id '{san_id}' not found in ledger."

    restored = response_text
    count = 0
    for m in entry["mappings"]:
        if not m.get("blocked") and m["placeholder"] in restored:
            restored = restored.replace(m["placeholder"], m["original"])
            count += 1

    unfound = [m["placeholder"] for m in entry["mappings"]
               if not m.get("blocked") and m["placeholder"] not in response_text]

    lines = [f"restored: {count}/{len([m for m in entry['mappings'] if not m.get('blocked')])} placeholders"]
    if unfound:
        lines.append(f"not found in response (left as-is): {', '.join(unfound)}")
    lines.append("")
    lines.append(restored)
    return "\n".join(lines)


@mcp.tool()
def view_ledger(last_n: int = 10) -> str:
    """Show recent sanitization history from the ledger."""
    entries = _read_ledger(last_n)
    if not entries:
        return "Ledger is empty."
    lines = [f"{'ID':<30} {'Timestamp':<26} {'Redacted':>8} {'Blocked':>8}"]
    lines.append("-" * 76)
    for e in entries:
        blocked = e.get("stats", {}).get("critical_blocked", 0)
        total = e.get("stats", {}).get("total_redacted", 0)
        flag = " ⚠" if blocked > 0 else ""
        lines.append(f"{e['id']:<30} {e['timestamp']:<26} {total:>8} {blocked:>8}{flag}")
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
