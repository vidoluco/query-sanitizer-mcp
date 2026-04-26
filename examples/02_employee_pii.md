# Example 2 — Employee PII Redaction + Restore

## Scenario
An HR manager asks an LLM to draft a performance review summary. The prompt
contains employee names, emails, and an internal employee ID.

---

## Config used (`~/.sanitizer-ledger/config.json`)
```json
{
  "org_names": ["Acme Corp"],
  "known_employees": ["Sarah Chen", "Marcus Webb"],
  "always_allow": ["Google Cloud", "Kubernetes"]
}
```

---

## Step 1 — Call `sanitize_query`

**Input:**
```
Summarize the Q1 performance of Sarah Chen (sarah.chen@acme-internal.com,
EMP-004821) on the Platform team at Acme Corp. Her manager Marcus Webb
noted she delivered the Kubernetes migration 3 weeks early. Budget saved: $240,000.
```

**Output:**
```
san_id: san_20260401_153011_b2e1
redactions: 7 (0 credential(s) blocked)
  PII_NAME: ██████ → [PII_NAME_1] (0.98) [regex]      ← sarah.chen@acme-internal.com
  PII_ID:   ██████ → [PII_ID_1]   (0.98) [regex]      ← EMP-004821
  FINANCIAL: ██████ → [FINANCIAL_1] (0.98) [regex]    ← $240,000
  PII_NAME: ██████ → [PII_NAME_2] (0.98) [regex]      ← Sarah Chen (from config)
  PII_NAME: ██████ → [PII_NAME_3] (0.98) [regex]      ← Marcus Webb (from config)
  ORG_NAME: ██████ → [ORG_NAME_1] (0.98) [regex]      ← Acme Corp (from config)
  PROJECT_NAME: ██████ → [PROJECT_NAME_1] (0.91) [llm] ← Kubernetes migration (contextual)

sanitized_text:
Summarize the Q1 performance of [PII_NAME_2] ([PII_NAME_1],
[PII_ID_1]) on the Platform team at [ORG_NAME_1]. Her manager [PII_NAME_3]
noted she delivered the [PROJECT_NAME_1] 3 weeks early. Budget saved: [FINANCIAL_1].
```

---

## Step 2 — Send sanitized text to external LLM

```
[PII_NAME_2] delivered [PROJECT_NAME_1] ahead of schedule, demonstrating
strong technical execution. The [FINANCIAL_1] cost saving reflects
high-value impact for [ORG_NAME_1]. Recommended for recognition.
Manager [PII_NAME_3] should document this in the annual review system.
```

---

## Step 3 — Call `restore_response`

**Input:** response text + `san_20260401_153011_b2e1`

**Output:**
```
restored: 5/6 placeholder(s)
not found in response (left as-is): [PII_ID_1]

Sarah Chen delivered Kubernetes migration ahead of schedule, demonstrating
strong technical execution. The $240,000 cost saving reflects
high-value impact for Acme Corp. Recommended for recognition.
Manager Marcus Webb should document this in the annual review system.
```

---

## Key takeaway
- Config-driven entity detection (`known_employees`, `org_names`) runs through
  the regex layer — zero LLM calls needed for known terms.
- `always_allow: ["Kubernetes"]` ensures the generic tech term is preserved
  when the LLM is writing about it generically (the LLM labelled the specific
  project name "Kubernetes migration" as PROJECT_NAME, which is correct).
- `restore_response` reports `[PII_ID_1]` as not found — the LLM correctly
  never referenced the employee ID in its summary.
