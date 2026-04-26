# Example 1 — Credential Leak Prevention

## Scenario
A developer asks Claude to debug a Python script. The script contains a live AWS access key
hardcoded in the source. Without the sanitizer, the key would be sent to the external LLM.

---

## Step 1 — Call `sanitize_query`

**Input:**
```
Debug this Python script:

import boto3

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def list_buckets():
    s3 = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET
    )
    return s3.list_buckets()
```

**Output:**
```
san_id: san_20260401_142233_3a7f
redactions: 2 (2 credential(s) blocked)
  CREDENTIAL: [BLOCKED] → [CREDENTIAL_REDACTED] (0.98) [regex]
  CREDENTIAL: [BLOCKED] → [CREDENTIAL_REDACTED] (0.99) [llm]
⚠  CREDENTIALS BLOCKED: 2 credential(s) removed — will NOT be restored

sanitized_text:
Debug this Python script:

import boto3

AWS_ACCESS_KEY = "[CREDENTIAL_REDACTED]"
AWS_SECRET     = "[CREDENTIAL_REDACTED]"

def list_buckets():
    s3 = boto3.client(
        's3',
        aws_access_key_id=[CREDENTIAL_REDACTED],
        aws_secret_access_key=[CREDENTIAL_REDACTED]
    )
    return s3.list_buckets()
```

---

## Step 2 — Send sanitized text to external LLM

The LLM receives no real credentials. It returns:

```
The function looks correct. Make sure [CREDENTIAL_REDACTED] has
s3:ListBuckets permission in IAM. Also consider using environment
variables or AWS Secrets Manager instead of hardcoding credentials.
```

---

## Step 3 — Call `restore_response`

**Input:** response text + san_id `san_20260401_142233_3a7f`

**Output:**
```
restored: 0/0 placeholder(s)

The function looks correct. Make sure [CREDENTIAL_REDACTED] has
s3:ListBuckets permission in IAM. Also consider using environment
variables or AWS Secrets Manager instead of hardcoding credentials.
```

> Credentials are **never restored** — the LLM correctly referred to them
> only by placeholder. The advice is still useful without knowing the key value.

---

## Key takeaway
Regex pre-pass catches the AWS key pattern (`AKIA[0-9A-Z]{16}`) in Phase 1
with 100% reliability — no LLM inference needed for this category.
Even if Ollama is offline, credentials are blocked.
