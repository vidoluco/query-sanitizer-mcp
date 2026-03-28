# query-sanitizer-mcp

A lightweight MCP middleware that sits between your prompts and external LLMs, automatically redacting sensitive data using a **local model** (Ollama / LM Studio) before anything leaves your machine.

```
[Your Prompt] → sanitize_query() → [Safe Prompt] → External LLM → [Response] → restore_response() → [You]
```

## Why

Every time you paste internal context into Claude, ChatGPT, or any cloud LLM, you risk leaking:
- Employee names & emails
- Internal project codenames
- Infrastructure details (IPs, hostnames, DB names)
- API keys & credentials
- Company names, deal sizes, legal references

This MCP server intercepts that text, runs it through a **local DLP model**, replaces sensitive tokens with typed placeholders (`[ORG_NAME_1]`, `[PII_NAME_1]`, etc.), and restores them in the response — so you see natural text, the cloud LLM never sees the real values.

## Tools

| Tool | Description |
|------|-------------|
| `sanitize_query(text)` | Redact sensitive data. Returns safe text + `san_id` for later restore. |
| `restore_response(text, san_id)` | Swap placeholders back to originals using the ledger. |
| `view_ledger(last_n)` | Show recent sanitization history. |

## Setup

**Requirements:** Python 3.10+, Ollama or LM Studio running locally.

```bash
git clone https://github.com/vidoluco/query-sanitizer-mcp
cd query-sanitizer-mcp
python3.12 -m venv .venv
.venv/bin/pip install fastmcp
```

### Start your local model

```bash
# Ollama
ollama pull llama3.2
ollama serve

# LM Studio — just load a model and start the local server on port 1234
```

### Add to Claude Code

Merge into `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "query-sanitizer": {
      "command": "/path/to/query-sanitizer-mcp/.venv/bin/python",
      "args": ["/path/to/query-sanitizer-mcp/server.py"],
      "env": {
        "SANITIZER_MODEL_URL": "http://localhost:11434/v1/chat/completions",
        "SANITIZER_MODEL_NAME": "llama3.2"
      }
    }
  }
}
```

For **LM Studio**, change the env vars:
```json
"SANITIZER_MODEL_URL": "http://localhost:1234/v1/chat/completions",
"SANITIZER_MODEL_NAME": "your-loaded-model-name"
```

## Configuration

Create `.sanitizer-ledger/config.json` to boost detection accuracy for your org:

```json
{
  "org_names": ["Acme Corp", "Acme"],
  "org_domains": ["acme.com", "acme.internal"],
  "project_codenames": ["Phoenix", "Titan"],
  "known_employees": ["John Smith"],
  "internal_ip_ranges": ["10.0.0.0/8", "172.16.0.0/12"],
  "always_allow": ["Google Cloud", "Kubernetes", "BigQuery"]
}
```

Or run the included CLI:
```bash
python scripts/ledger.py init-config
```

## How it works

The local model receives a strict DLP system prompt and returns JSON with:
- `sanitized_text` — the safe version of your prompt
- `mappings` — a list of what was replaced and why

A ledger entry (`.sanitizer-ledger/ledger.jsonl`) is written per operation, enabling the restore step. Credentials are **blocked entirely** — never stored, never passed through.

## Redaction categories

| Category | Examples | Severity |
|----------|----------|----------|
| `CREDENTIAL` | API keys, tokens, passwords | CRITICAL — blocked |
| `INTERNAL_URL` | Intranet URLs, staging endpoints | CRITICAL |
| `PII_NAME` | Names, emails, phone numbers | HIGH |
| `ORG_NAME` | Company / subsidiary names | HIGH |
| `PROJECT_NAME` | Internal codenames | MEDIUM |
| `INFRA` | IPs, hostnames, DB names | MEDIUM |
| `FINANCIAL` | Revenue, deal sizes, budgets | MEDIUM |
| `LEGAL` | Contract terms, case numbers | HIGH |

## Contributing

This is an early proof of concept — feedback and contributions very welcome.

Ideas for where this could go:
- [ ] Auto-suggest ledger config entries from detected patterns
- [ ] Claude Code hook integration (pre-prompt hook that auto-sanitizes)
- [ ] Confidence threshold config
- [ ] Batch / bulk sanitization mode
- [ ] Support for code block scanning (inline secrets, import paths)
- [ ] Web UI for ledger review

Open an issue or send a PR.

## License

MIT
