# Example 3 — Internal Infrastructure + LLM Offline Fallback

## Scenario
A DevOps engineer asks for help debugging a network issue. The prompt contains
private IP addresses, an internal hostname, and a staging URL.
The local Ollama instance is **offline** — demonstrating fail-safe behavior.

---

## Config used
```json
{
  "org_domains": ["staging.acme-internal.net"],
  "internal_ip_ranges": ["10.0.0.0/8"]
}
```

---

## Step 1 — Call `sanitize_query` (Ollama offline)

**Input:**
```
Why can't the service at 10.42.7.15 reach the database at 10.42.7.90:5432?
The health endpoint https://api.staging.acme-internal.net/health returns 503.
The hostname is db-primary.prod.internal. Logs show connection refused on port 5432.
```

**Output:**
```
san_id: san_20260401_160845_9d3c
⚠  LLM UNAVAILABLE — regex-only fallback active. Local model unavailable after 3 attempt(s): ...
redactions: 4 (0 credential(s) blocked)
  INFRA: ██████ → [INFRA_1] (0.98) [regex]         ← 10.42.7.15
  INFRA: ██████ → [INFRA_2] (0.98) [regex]         ← 10.42.7.90
  INTERNAL_URL: ██████ → [INTERNAL_URL_1] (0.98) [regex]  ← https://api.staging.acme-internal.net/health
  ← NOTE: db-primary.prod.internal NOT caught (LLM offline, regex has no hostname pattern)

sanitized_text:
Why can't the service at [INFRA_1] reach the database at [INFRA_2]:5432?
The health endpoint [INTERNAL_URL_1] returns 503.
The hostname is db-primary.prod.internal. Logs show connection refused on port 5432.
```

> The internal hostname `db-primary.prod.internal` was NOT caught because:
> - It's a contextual entity (not a structured token)
> - The LLM was offline — Phase 2 did not run
> - Regex patterns don't cover arbitrary `.internal` hostnames without config
>
> Solution: Add it to `custom_patterns` in config or add INFRA hostname to `known_employees`-equivalent.

---

## Step 2 — Send to external LLM

The external LLM receives no private IPs. The hostname leak is flagged via post-scan:

```
⚠  POST-SCAN WARNING: 0 potential miss(es) detected in sanitized output
```

(Post-scan only checks structured token patterns — hostname miss requires a follow-up config update.)

---

## Step 3 — `scan_response` on LLM reply

After receiving the LLM's response, scan it:

```
=== Response Scan ===
⚠  LLM unavailable — regex-only scan applied
Clean — no sensitive data detected in response.

The 503 on [INTERNAL_URL_1] suggests the upstream service at [INFRA_2]:5432
may be overloaded or unreachable. Check firewall rules between [INFRA_1]
and [INFRA_2] subnets...
```

---

## Step 4 — Call `restore_response`

```
restored: 3/3 placeholder(s)

The 503 on https://api.staging.acme-internal.net/health suggests the upstream
service at 10.42.7.90:5432 may be overloaded or unreachable. Check firewall
rules between 10.42.7.15 and 10.42.7.90 subnets...
```

---

## Key takeaway

| What happened | Result |
|---|---|
| Ollama offline | Regex layer ran, private IPs and staging URL were caught |
| Original text returned | ❌ Never — fail-safe active |
| Structured tokens (IPs, URLs) | ✅ Caught by regex |
| Unstructured hostname | ⚠ Missed — config fix needed |
| Restore across session | ✅ Works via session cache |

**Config fix for hostnames:**
```json
{
  "custom_patterns": [
    {"pattern": "[a-z0-9\\-]+\\.prod\\.internal", "category": "INFRA", "description": "Internal prod hostnames"}
  ]
}
```
