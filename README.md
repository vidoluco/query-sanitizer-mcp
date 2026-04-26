# query-sanitizer-mcp

A lightweight MCP middleware that sits between your prompts and external LLMs, automatically redacting sensitive data before anything leaves your machine.

```
[Your Prompt] → sanitize_query() → [Safe Prompt] → External LLM → [Response] → restore_response() → [You]
```

**v0.3.0** — Four-phase DLP pipeline: regex → GLiNER NER → LLM refinement → post-scan check.
Runs 100% open-source, 100% local. Tested on **M4 MacBook** and **Google Colab T4**.

---

## Why

Every time you paste internal context into Claude, ChatGPT, or any cloud LLM, you risk leaking:
- Employee names, emails, phone numbers
- Internal project codenames
- Infrastructure details (IPs, hostnames, DB names)
- API keys and credentials
- Company names, deal sizes, legal references

This MCP server intercepts that text, redacts sensitive tokens with typed placeholders
(`[ORG_NAME_1]`, `[PII_NAME_1]`, etc.), and restores them in the response —
so you see natural text, the cloud LLM never sees the real values.

---

## Tools

| Tool | Description |
|---|---|
| `sanitize_query(text)` | Three-phase redaction. Returns safe text + `san_id`. |
| `restore_response(text, san_id)` | Swap placeholders back to originals. |
| `scan_response(text)` | Scan an LLM's response for any data it may have generated or leaked. |
| `view_ledger(last_n)` | Show recent sanitization history. |

---

## Detection pipeline

### Phase 1 — Regex pre-pass (always runs, no model required)

Deterministic patterns for structured tokens. Runs even when the local model is offline.

| Pattern | Category | Blocked? |
|---|---|---|
| AWS access keys (`AKIA…`) | CREDENTIAL | Yes — blocked |
| GitHub tokens (`ghp_…`, `gho_…`) | CREDENTIAL | Yes |
| JWTs (`eyJ…`) | CREDENTIAL | Yes |
| Slack tokens (`xox[baprs]-…`) | CREDENTIAL | Yes |
| `api_key = "…"` style assignments | CREDENTIAL | Yes |
| Passwords in URLs (`://user:pass@`) | CREDENTIAL | Yes |
| Email addresses | PII_NAME | No — restored |
| Phone numbers | PII_NAME | No |
| SSNs (`NNN-NN-NNNN`) | PII_ID | No |
| Employee/badge IDs (`EMP-…`) | PII_ID | No |
| RFC 1918 private IPs | INFRA | No |
| Dollar amounts | FINANCIAL | No |
| Config-defined entities (org names, employees, codenames, domains) | varies | No |

### Phase 2 — LLM refinement (contextual, best-effort)

Catches entities that require semantic understanding: org names used in context,
project codenames, GEO_INTERNAL references, LEGAL terms, INTERNAL_URL patterns.
If the local model is unavailable, Phase 1 output is returned with a clear warning.

### Phase 3 — Post-scan confidence check

Runs high-confidence regex patterns over the sanitized text to flag potential
LLM misses (e.g. a JWT the model didn't catch). Shown as a warning in the report.

---

## Setup

### Option A — M4 MacBook (recommended)

**Stack:** Ollama 0.19+ (MLX backend, ~50 tok/s on M4) + GLiNER NER (MPS, ~80ms/call)

```bash
# 1. Install Ollama and pull the recommended model
brew install ollama
ollama pull qwen2.5:3b   # 2GB, fast + strong instruction following
ollama serve             # Ollama 0.19+ uses MLX automatically on Apple Silicon

# 2. Clone and install with NER layer
git clone https://github.com/vidoluco/query-sanitizer-mcp
cd query-sanitizer-mcp
python3 -m venv .venv
.venv/bin/pip install -e ".[nlp]"   # fastmcp + gliner (GLiNER NER layer)
```

**Add to Claude Code** (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "query-sanitizer": {
      "command": "/path/to/query-sanitizer-mcp/.venv/bin/python",
      "args": ["/path/to/query-sanitizer-mcp/server.py"],
      "env": {
        "SANITIZER_MODEL_NAME": "qwen2.5:3b",
        "SANITIZER_GLINER_MODEL": "urchade/gliner_medium-v2.1"
      }
    }
  }
}
```

**Alternative LLM models for M4 (all via Ollama):**

| Model | Size | Speed on M4 | Best for |
|---|---|---|---|
| `qwen2.5:3b` | 2 GB | ~50 tok/s | Default — fast, accurate |
| `phi4-mini` | 3 GB | ~40 tok/s | Strong reasoning |
| `llama3.2:3b` | 2 GB | ~45 tok/s | Broad general use |
| `qwen2.5:7b` | 5 GB | ~30 tok/s | Higher accuracy, more RAM |

---

### Option B — Google Colab T4

**Stack:** HuggingFace transformers (no Ollama needed) + GLiNER (CUDA)

```python
# Cell 1 — install
!pip install "query-sanitizer-mcp[colab]" -q
# fastmcp + gliner + transformers + torch + accelerate

# Cell 2 — configure
import os
os.environ["SANITIZER_BACKEND"]    = "hf"
os.environ["SANITIZER_HF_MODEL"]   = "Qwen/Qwen2.5-3B-Instruct"  # ~6GB, fits T4 16GB
os.environ["SANITIZER_GLINER_MODEL"] = "urchade/gliner_medium-v2.1"
os.environ["SANITIZER_LEDGER_DIR"] = "/content/sanitizer-ledger"

# Cell 3 — use directly (no MCP client needed in Colab)
import sys; sys.path.insert(0, ".")
from server import sanitize_query, restore_response, scan_response

result = sanitize_query("Send report to jane.doe@acme.com re: Project Phoenix")
print(result)
```

> First run downloads `Qwen2.5-3B-Instruct` (~6 GB) and `gliner_medium-v2.1` (~500 MB) to the Colab cache. Subsequent runs are instant.

---

### Minimum setup (regex-only, no models needed)

If you want zero-dependency operation (pure regex, no Ollama, no GLiNER):

```bash
pip install fastmcp
SANITIZER_MODEL_RETRIES=0 python server.py
```

Credentials, emails, SSNs, private IPs and financial amounts are caught by regex alone.
People, org names, and project codenames require GLiNER or the LLM layer.

---

## Configuration

Create `.sanitizer-ledger/config.json` (or run `python scripts/ledger.py init-config`):

```json
{
  "org_names": ["Acme Corp", "Acme"],
  "org_domains": ["acme-internal.net"],
  "project_codenames": ["Phoenix", "Titan"],
  "known_employees": ["Jane Smith", "Marcus Webb"],
  "internal_ip_ranges": ["10.0.0.0/8"],
  "custom_patterns": [
    {"pattern": "JIRA-\\d{4,}", "category": "PROJECT_NAME", "description": "Jira tickets"}
  ],
  "always_allow": ["Google Cloud", "Kubernetes", "BigQuery", "Terraform", "Docker"]
}
```

Config-defined entities (`org_names`, `known_employees`, etc.) are wired into **both**
the regex pre-pass (for deterministic matching) and the LLM system prompt (for contextual
variants). Changes take effect on the next `sanitize_query` call — no server restart needed.

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SANITIZER_MODEL_URL` | `http://localhost:11434/v1/chat/completions` | Local model endpoint |
| `SANITIZER_MODEL_NAME` | `llama3.2` | Model name |
| `SANITIZER_MODEL_RETRIES` | `2` | Retries on model failure (2s, 4s backoff) |
| `SANITIZER_LEDGER_DIR` | `.sanitizer-ledger/` | Ledger directory path |
| `SANITIZER_LEDGER_STORE_ORIGINALS` | `true` | Set to `false` to stop storing original values at rest (GDPR mode — restore only works within the same session) |

---

## Ledger CLI

```bash
python scripts/ledger.py list [N]                # recent N entries
python scripts/ledger.py lookup <san_id>         # full mapping for one entry
python scripts/ledger.py restore <san_id> <text> # restore from CLI
python scripts/ledger.py stats                   # aggregate stats by category and source
python scripts/ledger.py purge --older-than 30d  # enforce retention policy
python scripts/ledger.py init-config             # create starter config.json
```

---

## Redaction categories

| Category | Examples | Severity |
|---|---|---|
| `CREDENTIAL` | API keys, tokens, passwords | CRITICAL — blocked, never restored |
| `INTERNAL_URL` | Intranet URLs, staging endpoints | CRITICAL |
| `PII_NAME` | Names, emails, phone numbers | HIGH |
| `PII_ID` | SSNs, employee IDs, badge numbers | HIGH |
| `ORG_NAME` | Company / subsidiary names | HIGH |
| `LEGAL` | Contract terms, case numbers | HIGH |
| `PROJECT_NAME` | Internal codenames | MEDIUM |
| `INFRA` | IPs, hostnames, DB names | MEDIUM |
| `FINANCIAL` | Revenue, deal sizes, budgets | MEDIUM |
| `GEO_INTERNAL` | Office locations, building names | LOW |

---

## Security model

- **Credentials are never stored** — `[BLOCKED]` is written to the ledger instead of the original value
- **Fail-safe, not fail-open** — model unavailability triggers regex fallback, never plaintext passthrough
- **Local inference only** — no data sent to any external API for the sanitization step
- **Privacy mode** (`SANITIZER_LEDGER_STORE_ORIGINALS=false`) — originals not written to disk at all; restore works only within the same server session via in-memory cache

---

## Examples

See [`examples/`](examples/) for full session traces:

1. [`01_api_key_leak.md`](examples/01_api_key_leak.md) — AWS credential blocked by regex pre-pass
2. [`02_employee_pii.md`](examples/02_employee_pii.md) — HR prompt with names, emails, employee IDs + restore
3. [`03_internal_infra.md`](examples/03_internal_infra.md) — Infrastructure debugging with Ollama offline (regex fallback)

---

## Contributing

Open an issue or send a PR.

Ideas for what's next:
- [ ] Auto-suggest config entries from detected patterns
- [ ] Claude Code hook integration (pre-prompt auto-sanitize)
- [ ] Confidence threshold configuration
- [ ] Batch / bulk sanitization mode
- [ ] Code block scanning (inline secrets, import paths)
- [ ] Ledger encryption at rest
- [ ] Web UI for ledger review

---

## License

MIT
