#!/usr/bin/env python3
"""
Query Sanitizer MCP Middleware — v0.2.0

Pipeline: regex pre-pass  →  LLM refinement  →  post-scan confidence check
Fail-safe: if local model unavailable, falls back to regex-only (never passes original text).

Tools:
  sanitize_query(text)            → redacted text + san_id
  restore_response(text, san_id)  → original values rehydrated
  scan_response(text)             → scan LLM output for data leakage
  view_ledger(last_n)             → recent sanitization history
"""

import json
import os
import re
import time
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
STORE_ORIGINALS = os.getenv("SANITIZER_LEDGER_STORE_ORIGINALS", "true").lower() == "true"
MODEL_RETRIES = int(os.getenv("SANITIZER_MODEL_RETRIES", "2"))

SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# Regex patterns — deterministic pre-pass layer
# Tuple: (category, compiled_pattern, is_blocked)
# Ordered: credentials first (highest priority), then PII, then infra/financial
# ---------------------------------------------------------------------------

_REGEX_PATTERNS: list[tuple[str, re.Pattern, bool]] = [
    # CREDENTIAL — blocked entirely (original never stored or restored)
    ("CREDENTIAL", re.compile(r"AKIA[0-9A-Z]{16}"), True),
    ("CREDENTIAL", re.compile(r"(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,}"), True),
    ("CREDENTIAL", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), True),
    ("CREDENTIAL", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), True),  # JWT
    ("CREDENTIAL", re.compile(
        r"(?i)(?:api[_\-]?key|secret[_\-]?key|client[_\-]?secret|auth[_\-]?token"
        r"|access[_\-]?token|private[_\-]?key)\s*[:=]\s*[\"']?[\w\-./+]{12,}[\"']?"
    ), True),
    ("CREDENTIAL", re.compile(r"://[^/\s]{1,64}:[^@\s]{4,}@"), True),  # password in URL
    # PII_NAME
    ("PII_NAME", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), False),
    ("PII_NAME", re.compile(r"(?<!\d)(\+\d{1,3}[-.\s])?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)"), False),
    # PII_ID
    ("PII_ID", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), False),  # SSN
    ("PII_ID", re.compile(r"\b(?:EMP|BADGE|EID)[-_]?\d{4,8}\b", re.IGNORECASE), False),
    # INFRA — RFC 1918 private ranges only
    ("INFRA", re.compile(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3})\b"
    ), False),
    # FINANCIAL
    ("FINANCIAL", re.compile(r"\$\s*\d[\d,]*(?:\.\d+)?(?:\s*[KMBkmb])?\b"), False),
]

# High-confidence patterns used only for post-scan miss detection
_POSTSCAN_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("CREDENTIAL", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("CREDENTIAL", re.compile(r"(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,}")),
    ("CREDENTIAL", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("PII_ID",     re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("PII_NAME",   re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
]

_PLACEHOLDER_RE = re.compile(r"^\[[A-Z_]+(?:_\d+)?(?:_REDACTED)?\]$")

# ---------------------------------------------------------------------------
# System prompt (base — org context appended dynamically from config)
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_BASE = """You are a data loss prevention (DLP) engine. Analyze the user's text and redact ALL sensitive information not already replaced by placeholders.

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
5. Do NOT re-redact existing placeholders like [PII_NAME_1] — leave them as-is

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
# In-memory session cache — preserves full originals for restore within session
# even when STORE_ORIGINALS=false
# ---------------------------------------------------------------------------

_SESSION_CACHE: dict[str, list] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _san_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = "".join(random.choices(string.hexdigits[:16], k=4)).lower()
    return f"san_{ts}_{suffix}"


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _build_system_prompt(config: dict) -> str:
    parts: list[str] = []
    if config.get("org_names"):
        parts.append(f"Organization names to ALWAYS redact as ORG_NAME: {', '.join(config['org_names'])}")
    if config.get("project_codenames"):
        parts.append(f"Project codenames to ALWAYS redact as PROJECT_NAME: {', '.join(config['project_codenames'])}")
    if config.get("known_employees"):
        parts.append(f"Known employee names to ALWAYS redact as PII_NAME: {', '.join(config['known_employees'])}")
    if config.get("always_allow"):
        parts.append(f"Terms to NEVER redact (always allow): {', '.join(config['always_allow'])}")
    if not parts:
        return _SYSTEM_PROMPT_BASE
    return _SYSTEM_PROMPT_BASE + "\n\nOrganization context (MUST apply):\n" + "\n".join(f"- {p}" for p in parts)


def _build_regex_patterns(config: dict) -> list[tuple[str, re.Pattern, bool]]:
    patterns: list[tuple[str, re.Pattern, bool]] = list(_REGEX_PATTERNS)
    for cp in config.get("custom_patterns", []):
        try:
            patterns.append((cp["category"], re.compile(cp["pattern"]), False))
        except (re.error, KeyError):
            pass
    for name in config.get("org_names", []):
        if name:
            patterns.append(("ORG_NAME", re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE), False))
    for name in config.get("project_codenames", []):
        if name:
            patterns.append(("PROJECT_NAME", re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE), False))
    for name in config.get("known_employees", []):
        if name:
            patterns.append(("PII_NAME", re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE), False))
    for domain in config.get("org_domains", []):
        if domain:
            patterns.append(("INTERNAL_URL", re.compile(
                r"https?://[^\s]*" + re.escape(domain) + r"[^\s]*", re.IGNORECASE
            ), False))
    return patterns


def _regex_prescan(text: str, config: dict) -> tuple[str, list]:
    """
    Deterministic regex pre-pass. Same token always maps to the same placeholder.
    Returns (redacted_text, mappings). Replaces in reverse-position order to preserve indices.
    """
    always_allow_lower = {v.lower() for v in config.get("always_allow", [])}
    patterns = _build_regex_patterns(config)

    seen: dict[str, str] = {}        # original_key → placeholder
    cat_counts: dict[str, int] = {}
    covered = bytearray(len(text))   # tracks which character positions are already matched
    raw: list[tuple[int, int, str, str, str, bool]] = []  # start, end, original, placeholder, category, blocked

    for category, pattern, blocked in patterns:
        for m in pattern.finditer(text):
            start, end = m.start(), m.end()
            if any(covered[start:end]):
                continue
            original = m.group(0)
            if original.lower() in always_allow_lower:
                continue
            covered[start:end] = b"\x01" * (end - start)
            key = original.lower() if not blocked else original
            if key not in seen:
                if blocked:
                    placeholder = "[CREDENTIAL_REDACTED]"
                else:
                    n = cat_counts.get(category, 0) + 1
                    cat_counts[category] = n
                    placeholder = f"[{category}_{n}]"
                seen[key] = placeholder
            raw.append((start, end, original, seen[key], category, blocked))

    chars = list(text)
    for start, end, _, placeholder, _, _ in sorted(raw, key=lambda x: -x[0]):
        chars[start:end] = list(placeholder)
    redacted = "".join(chars)

    seen_keys: set[str] = set()
    mappings: list[dict] = []
    for _, _, original, placeholder, category, blocked in sorted(raw, key=lambda x: x[0]):
        key = original.lower() if not blocked else original
        if key not in seen_keys:
            seen_keys.add(key)
            mappings.append({
                "placeholder": placeholder,
                "original": "[BLOCKED]" if blocked else original,
                "category": category,
                "confidence": 0.98,
                "blocked": blocked,
                "source": "regex",
            })
    return redacted, mappings


def _postscan_check(sanitized_text: str) -> list[dict]:
    """Run high-confidence patterns over sanitized text to flag potential LLM misses."""
    misses: list[dict] = []
    for category, pattern in _POSTSCAN_PATTERNS:
        for m in pattern.finditer(sanitized_text):
            val = m.group(0)
            if _PLACEHOLDER_RE.match(val):
                continue
            misses.append({"category": category, "hint": val[:6] + "…"})
    return misses


def _call_local_model(text: str, system_prompt: str) -> dict:
    payload = json.dumps({
        "model": LOCAL_MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": text},
        ],
        "temperature": 0.0,
        "enable_thinking": False,
    }).encode()

    last_err: Exception | None = None
    for attempt in range(MODEL_RETRIES + 1):
        if attempt:
            time.sleep(2 ** attempt)  # 2s then 4s backoff
        try:
            req = urllib.request.Request(
                LOCAL_MODEL_URL,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                body = json.loads(resp.read())
            content = body["choices"][0]["message"]["content"].strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            return json.loads(content.strip())
        except Exception as e:
            last_err = e
    raise RuntimeError(f"Local model unavailable after {MODEL_RETRIES + 1} attempt(s): {last_err}")


def _write_ledger(entry: dict) -> None:
    LEDGER_DIR.mkdir(exist_ok=True)
    with LEDGER_FILE.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _read_ledger(last_n: int = 0) -> list:
    if not LEDGER_FILE.exists():
        return []
    entries = [json.loads(ln) for ln in LEDGER_FILE.read_text().strip().splitlines() if ln.strip()]
    return entries[-last_n:] if last_n else entries


def _build_ledger_entry(san_id: str, mappings: list) -> dict:
    high_cats = {"CREDENTIAL", "PII_NAME", "PII_ID", "ORG_NAME", "LEGAL"}
    medium_cats = {"PROJECT_NAME", "INFRA", "FINANCIAL"}
    stats: dict[str, int] = {
        "critical_blocked": 0, "high_redacted": 0,
        "medium_redacted": 0, "low_redacted": 0, "total_redacted": len(mappings),
    }
    for m in mappings:
        if m.get("blocked"):
            stats["critical_blocked"] += 1
        elif m["category"] in high_cats:
            stats["high_redacted"] += 1
        elif m["category"] in medium_cats:
            stats["medium_redacted"] += 1
        else:
            stats["low_redacted"] += 1

    safe_mappings = []
    for m in mappings:
        sm = dict(m)
        if not STORE_ORIGINALS and not m.get("blocked"):
            sm["original"] = "[PRIVATE]"
        safe_mappings.append(sm)

    return {
        "schema_version": SCHEMA_VERSION,
        "id": san_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "direction": "outbound",
        "token_count": len(mappings),
        "mappings": safe_mappings,
        "stats": stats,
    }


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "query-sanitizer",
    instructions=(
        "DLP middleware: call sanitize_query before sending any text to an external LLM. "
        "Call restore_response to rehydrate the answer with original values. "
        "Call scan_response to check an LLM response for sensitive data it may have generated."
    ),
)


@mcp.tool()
def sanitize_query(text: str) -> str:
    """
    Sanitize a query before sending to an external LLM.

    Phase 1 — regex pre-pass: deterministically catches credentials, emails, SSNs,
               private IPs, phone numbers, and config-defined entities.
    Phase 2 — LLM refinement: catches contextual entities (org names, project codenames,
               employee names) that require semantic understanding.
    Phase 3 — post-scan check: runs regex over the sanitized output to flag any misses.

    Fail-safe: if the local model is unavailable, returns regex-only output with a
               clear warning. The original text is NEVER returned on failure.

    Returns the safe text plus a san_id needed to call restore_response later.
    """
    config = _load_config()

    # Phase 1 — always runs, deterministic, zero external calls
    pre_text, pre_mappings = _regex_prescan(text, config)
    pre_placeholders = {m["placeholder"] for m in pre_mappings}

    # Phase 2 — LLM refinement (best-effort; pre_text is the safe fallback)
    llm_failed = False
    llm_error = ""
    llm_mappings: list[dict] = []
    sanitized_text = pre_text

    try:
        result = _call_local_model(pre_text, _build_system_prompt(config))
        sanitized_text = result.get("sanitized_text", pre_text)
        llm_mappings = [m for m in result.get("mappings", []) if m["placeholder"] not in pre_placeholders]
    except RuntimeError as e:
        llm_failed = True
        llm_error = str(e)

    merged = pre_mappings + llm_mappings
    san_id = _san_id()
    entry = _build_ledger_entry(san_id, merged)
    _SESSION_CACHE[san_id] = merged  # full originals in memory regardless of STORE_ORIGINALS
    _write_ledger(entry)

    # Phase 3 — post-scan
    misses = _postscan_check(sanitized_text)
    blocked_count = entry["stats"]["critical_blocked"]

    lines = [f"san_id: {san_id}"]

    if llm_failed:
        lines.append(f"⚠  LLM UNAVAILABLE — regex-only fallback active. {llm_error}")

    if merged:
        lines.append(f"redactions: {len(merged)} ({blocked_count} credential(s) blocked)")
        for m in merged:
            conf = m.get("confidence", 1.0)
            src = " [regex]" if m.get("source") == "regex" else " [llm]"
            low_flag = " [LOW CONFIDENCE — review]" if conf < 0.7 else ""
            display = "[BLOCKED]" if m.get("blocked") else "██████"
            lines.append(f"  {m['category']}: {display} → {m['placeholder']} ({conf:.2f}){src}{low_flag}")
    else:
        lines.append("no sensitive data detected")

    if blocked_count:
        lines.append(f"⚠  CREDENTIALS BLOCKED: {blocked_count} credential(s) removed — will NOT be restored")

    if misses:
        lines.append(f"⚠  POST-SCAN WARNING: {len(misses)} potential miss(es) in sanitized output — review recommended")
        for miss in misses:
            lines.append(f"    {miss['category']}: {miss['hint']}")

    if not STORE_ORIGINALS:
        lines.append("ℹ  PRIVATE MODE: originals not stored in ledger (restore requires same server session)")

    lines += ["", "sanitized_text:", sanitized_text]
    return "\n".join(lines)


@mcp.tool()
def restore_response(response_text: str, san_id: str) -> str:
    """
    Restore placeholders in an LLM response back to original values.
    Requires the san_id returned by sanitize_query.
    Credentials (blocked items) are never restored.
    Returns a structured result distinguishing success, partial restore, and error.
    """
    mappings = _SESSION_CACHE.get(san_id)
    if mappings is None:
        entries = _read_ledger()
        entry = next((e for e in reversed(entries) if e["id"] == san_id), None)
        if not entry:
            return f"ERROR: san_id '{san_id}' not found in ledger or current session."
        mappings = entry["mappings"]

    if any(m.get("original") == "[PRIVATE]" for m in mappings if not m.get("blocked")):
        return (
            f"ERROR: san_id '{san_id}' was created in private mode (SANITIZER_LEDGER_STORE_ORIGINALS=false) — "
            "originals not stored in ledger. Restore is only available within the same server session."
        )

    restored = response_text
    count = 0
    for m in mappings:
        if not m.get("blocked") and m["placeholder"] in restored:
            restored = restored.replace(m["placeholder"], m["original"])
            count += 1

    restorable = [m for m in mappings if not m.get("blocked")]
    unfound = [m["placeholder"] for m in restorable if m["placeholder"] not in response_text]

    lines = [f"restored: {count}/{len(restorable)} placeholder(s)"]
    if unfound:
        lines.append(f"not found in response (left as-is): {', '.join(unfound)}")
    lines += ["", restored]
    return "\n".join(lines)


@mcp.tool()
def scan_response(response_text: str) -> str:
    """
    Scan an LLM response for sensitive data it may have generated, inferred, or echoed.
    Runs the same regex + LLM pipeline used for outbound sanitization.
    Use this after receiving any response from an external model.
    Returns a report and a cleaned version of the response.
    """
    config = _load_config()
    pre_text, pre_mappings = _regex_prescan(response_text, config)
    pre_ph = {m["placeholder"] for m in pre_mappings}

    llm_mappings: list[dict] = []
    sanitized = pre_text
    llm_failed = False
    try:
        result = _call_local_model(pre_text, _build_system_prompt(config))
        sanitized = result.get("sanitized_text", pre_text)
        llm_mappings = [m for m in result.get("mappings", []) if m["placeholder"] not in pre_ph]
    except RuntimeError:
        llm_failed = True

    all_mappings = pre_mappings + llm_mappings
    lines = ["=== Response Scan ==="]
    if llm_failed:
        lines.append("⚠  LLM unavailable — regex-only scan applied")
    if all_mappings:
        lines.append(f"WARNING: {len(all_mappings)} sensitive item(s) detected in LLM response")
        for m in all_mappings:
            src = " [regex]" if m.get("source") == "regex" else " [llm]"
            lines.append(f"  {m['category']} → {m['placeholder']} ({m.get('confidence', 0.98):.2f}){src}")
    else:
        lines.append("Clean — no sensitive data detected in response.")
    lines += ["", sanitized]
    return "\n".join(lines)


@mcp.tool()
def view_ledger(last_n: int = 10) -> str:
    """Show recent sanitization history from the ledger."""
    entries = _read_ledger(last_n)
    if not entries:
        return "Ledger is empty."
    lines = [f"{'ID':<30} {'Timestamp':<26} {'Redacted':>8} {'Blocked':>8} {'Ver':>4}"]
    lines.append("-" * 82)
    for e in entries:
        blocked = e.get("stats", {}).get("critical_blocked", 0)
        total = e.get("stats", {}).get("total_redacted", 0)
        ver = e.get("schema_version", "—")
        flag = " ⚠" if blocked > 0 else ""
        lines.append(f"{e['id']:<30} {e['timestamp']:<26} {total:>8} {blocked:>8} {str(ver):>4}{flag}")
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
