"""
Unit and integration tests for server.py.
All tests mock the local model — no Ollama instance required.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Bootstrap: point ledger at a temp dir before importing server
# ---------------------------------------------------------------------------
_TMP = tempfile.mkdtemp()
os.environ["SANITIZER_LEDGER_DIR"] = _TMP
os.environ["SANITIZER_LEDGER_STORE_ORIGINALS"] = "true"
os.environ["SANITIZER_MODEL_RETRIES"] = "0"  # no retries in tests

sys.path.insert(0, str(Path(__file__).parent.parent))
import server  # noqa: E402  (must come after env setup)


def _mock_llm(sanitized_text: str, mappings: list):
    return {"sanitized_text": sanitized_text, "mappings": mappings}


class TestRegexPrescan(unittest.TestCase):

    def test_aws_access_key_blocked(self):
        text = "Key is AKIAIOSFODNN7EXAMPLE here"
        redacted, mappings = server._regex_prescan(text, {})
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertIn("[CREDENTIAL_REDACTED]", redacted)
        self.assertTrue(any(m["blocked"] for m in mappings))

    def test_github_token_blocked(self):
        text = "export GH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        redacted, mappings = server._regex_prescan(text, {})
        self.assertNotIn("ghp_", redacted)
        self.assertTrue(any(m["blocked"] for m in mappings))

    def test_jwt_blocked(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        text = f"Authorization: Bearer {jwt}"
        redacted, mappings = server._regex_prescan(text, {})
        self.assertNotIn(jwt, redacted)
        self.assertTrue(any(m["blocked"] for m in mappings))

    def test_email_redacted(self):
        text = "Send to john.doe@acme-internal.com for review"
        redacted, mappings = server._regex_prescan(text, {})
        self.assertNotIn("john.doe@acme-internal.com", redacted)
        self.assertTrue(any(m["category"] == "PII_NAME" for m in mappings))
        self.assertFalse(any(m["blocked"] for m in mappings))

    def test_ssn_redacted(self):
        text = "Employee SSN: 123-45-6789 on file"
        redacted, mappings = server._regex_prescan(text, {})
        self.assertNotIn("123-45-6789", redacted)
        self.assertTrue(any(m["category"] == "PII_ID" for m in mappings))

    def test_private_ip_redacted(self):
        for ip in ("10.0.0.1", "172.16.0.50", "192.168.1.100"):
            with self.subTest(ip=ip):
                redacted, mappings = server._regex_prescan(f"host {ip}", {})
                self.assertNotIn(ip, redacted)
                self.assertTrue(any(m["category"] == "INFRA" for m in mappings))

    def test_public_ip_not_redacted(self):
        text = "Connecting to 8.8.8.8"
        redacted, mappings = server._regex_prescan(text, {})
        self.assertIn("8.8.8.8", redacted)
        self.assertEqual(mappings, [])

    def test_financial_redacted(self):
        text = "Deal size $4.5M signed last quarter"
        redacted, mappings = server._regex_prescan(text, {})
        self.assertNotIn("$4.5M", redacted)
        self.assertTrue(any(m["category"] == "FINANCIAL" for m in mappings))

    def test_always_allow_respected(self):
        config = {"always_allow": ["john@public.com"]}
        text = "Contact john@public.com for details"
        redacted, mappings = server._regex_prescan(text, config)
        self.assertIn("john@public.com", redacted)
        self.assertEqual(mappings, [])

    def test_consistency_same_token_same_placeholder(self):
        text = "alice@corp.com submitted and alice@corp.com confirmed"
        redacted, mappings = server._regex_prescan(text, {})
        pii = [m for m in mappings if m["category"] == "PII_NAME"]
        self.assertEqual(len(pii), 1, "Duplicate token should appear once in mappings")
        self.assertEqual(redacted.count(pii[0]["placeholder"]), 2, "Both occurrences must be replaced")

    def test_clean_text_unchanged(self):
        text = "How does Kubernetes autoscaling work?"
        redacted, mappings = server._regex_prescan(text, {})
        self.assertEqual(redacted, text)
        self.assertEqual(mappings, [])

    def test_config_org_name(self):
        config = {"org_names": ["Acme Corp"], "always_allow": []}
        text = "I work at Acme Corp on a confidential project"
        redacted, mappings = server._regex_prescan(text, config)
        self.assertNotIn("Acme Corp", redacted)
        self.assertTrue(any(m["category"] == "ORG_NAME" for m in mappings))

    def test_config_custom_pattern(self):
        config = {"custom_patterns": [{"pattern": r"JIRA-\d{4,}", "category": "PROJECT_NAME"}]}
        text = "Fixed in JIRA-1234 and JIRA-5678"
        redacted, mappings = server._regex_prescan(text, config)
        self.assertNotIn("JIRA-1234", redacted)
        self.assertEqual(len([m for m in mappings if m["category"] == "PROJECT_NAME"]), 2)

    def test_config_known_employee(self):
        config = {"known_employees": ["Jane Smith"]}
        text = "Jane Smith approved the PR"
        redacted, mappings = server._regex_prescan(text, config)
        self.assertNotIn("Jane Smith", redacted)
        self.assertTrue(any(m["category"] == "PII_NAME" for m in mappings))

    def test_config_org_domain(self):
        config = {"org_domains": ["internal.acme.com"]}
        text = "Docs at https://wiki.internal.acme.com/page"
        redacted, mappings = server._regex_prescan(text, config)
        self.assertNotIn("internal.acme.com", redacted)
        self.assertTrue(any(m["category"] == "INTERNAL_URL" for m in mappings))

    def test_invalid_custom_pattern_silently_skipped(self):
        config = {"custom_patterns": [{"pattern": "[invalid(regex", "category": "X"}]}
        text = "Some text here"
        redacted, mappings = server._regex_prescan(text, config)
        self.assertEqual(redacted, text)  # no crash

    def test_credential_original_stored_as_blocked(self):
        text = "Key AKIAIOSFODNN7EXAMPLE used"
        _, mappings = server._regex_prescan(text, {})
        cred = next(m for m in mappings if m["blocked"])
        self.assertEqual(cred["original"], "[BLOCKED]")

    def test_source_field_is_regex(self):
        text = "IP 192.168.1.1 is down"
        _, mappings = server._regex_prescan(text, {})
        self.assertTrue(all(m["source"] == "regex" for m in mappings))


class TestPostscanCheck(unittest.TestCase):

    def test_detects_uncaught_aws_key(self):
        text = "Here is AKIAIOSFODNN7EXAMPLE remaining"
        misses = server._postscan_check(text)
        self.assertTrue(len(misses) > 0)
        self.assertTrue(any(m["category"] == "CREDENTIAL" for m in misses))

    def test_placeholder_not_flagged(self):
        text = "Token: [CREDENTIAL_REDACTED] email: [PII_NAME_1]"
        misses = server._postscan_check(text)
        self.assertEqual(misses, [])

    def test_clean_text_no_misses(self):
        text = "Tell me about Docker and Terraform"
        self.assertEqual(server._postscan_check(text), [])

    def test_detects_uncaught_email(self):
        text = "Forwarded to user@internal.corp for action"
        misses = server._postscan_check(text)
        self.assertTrue(any(m["category"] == "PII_NAME" for m in misses))


class TestBuildLedgerEntry(unittest.TestCase):

    def test_schema_version_present(self):
        entry = server._build_ledger_entry("san_test", [])
        self.assertIn("schema_version", entry)
        self.assertEqual(entry["schema_version"], server.SCHEMA_VERSION)

    def test_stats_all_categories(self):
        mappings = [
            {"category": "CREDENTIAL", "blocked": True,  "placeholder": "[CREDENTIAL_REDACTED]", "original": "[BLOCKED]",  "confidence": 0.99},
            {"category": "PII_NAME",   "blocked": False, "placeholder": "[PII_NAME_1]",          "original": "John",       "confidence": 0.95},
            {"category": "INFRA",      "blocked": False, "placeholder": "[INFRA_1]",              "original": "10.0.0.1",   "confidence": 0.98},
            {"category": "GEO_INTERNAL","blocked": False,"placeholder": "[GEO_INTERNAL_1]",       "original": "HQ Floor 3", "confidence": 0.80},
        ]
        entry = server._build_ledger_entry("san_test", mappings)
        s = entry["stats"]
        self.assertEqual(s["critical_blocked"], 1)
        self.assertEqual(s["high_redacted"], 1)
        self.assertEqual(s["medium_redacted"], 1)
        self.assertEqual(s["low_redacted"], 1)
        self.assertEqual(s["total_redacted"], 4)

    def test_private_mode_masks_originals(self):
        orig = server.STORE_ORIGINALS
        try:
            server.STORE_ORIGINALS = False
            mappings = [{"category": "PII_NAME", "blocked": False, "placeholder": "[PII_NAME_1]", "original": "Alice", "confidence": 0.95}]
            entry = server._build_ledger_entry("san_test", mappings)
            self.assertEqual(entry["mappings"][0]["original"], "[PRIVATE]")
        finally:
            server.STORE_ORIGINALS = orig

    def test_private_mode_keeps_blocked_as_blocked(self):
        orig = server.STORE_ORIGINALS
        try:
            server.STORE_ORIGINALS = False
            mappings = [{"category": "CREDENTIAL", "blocked": True, "placeholder": "[CREDENTIAL_REDACTED]", "original": "[BLOCKED]", "confidence": 0.99}]
            entry = server._build_ledger_entry("san_test", mappings)
            self.assertEqual(entry["mappings"][0]["original"], "[BLOCKED]")
        finally:
            server.STORE_ORIGINALS = orig


class TestSanitizeQuery(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.mkdtemp()
        server.LEDGER_DIR = Path(self._td)
        server.LEDGER_FILE = Path(self._td) / "ledger.jsonl"
        server._SESSION_CACHE.clear()

    def test_llm_success_report_format(self):
        mock = _mock_llm("My org is [ORG_NAME_1]", [
            {"placeholder": "[ORG_NAME_1]", "original": "Acme", "category": "ORG_NAME", "confidence": 0.92, "blocked": False}
        ])
        with patch("server._call_local_model", return_value=mock):
            result = server.sanitize_query("My org is Acme")
        self.assertIn("san_id:", result)
        self.assertIn("[ORG_NAME_1]", result)
        self.assertIn("sanitized_text:", result)

    def test_llm_failure_fallback_regex_catches_credential(self):
        with patch("server._call_local_model", side_effect=RuntimeError("Ollama down")):
            result = server.sanitize_query("Key: AKIAIOSFODNN7EXAMPLE in config")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result)
        self.assertIn("LLM UNAVAILABLE", result)
        self.assertIn("[CREDENTIAL_REDACTED]", result)

    def test_llm_failure_original_text_not_in_output(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        with patch("server._call_local_model", side_effect=RuntimeError("down")):
            result = server.sanitize_query(f"secret={secret}")
        self.assertNotIn(secret, result)

    def test_clean_text_no_redactions_message(self):
        mock = _mock_llm("Tell me about Python", [])
        with patch("server._call_local_model", return_value=mock):
            result = server.sanitize_query("Tell me about Python")
        self.assertIn("no sensitive data detected", result)

    def test_session_cache_populated(self):
        mock = _mock_llm("Hello [ORG_NAME_1]", [
            {"placeholder": "[ORG_NAME_1]", "original": "Acme", "category": "ORG_NAME", "confidence": 0.9, "blocked": False}
        ])
        with patch("server._call_local_model", return_value=mock):
            result = server.sanitize_query("Hello Acme")
        san_id = result.split("\n")[0].replace("san_id: ", "").strip()
        self.assertIn(san_id, server._SESSION_CACHE)

    def test_ledger_written(self):
        mock = _mock_llm("text", [])
        with patch("server._call_local_model", return_value=mock):
            server.sanitize_query("text")
        entries = server._read_ledger()
        self.assertEqual(len(entries), 1)
        self.assertIn("schema_version", entries[0])

    def test_postscan_warning_shown(self):
        # LLM returns sanitized text that still has an email — post-scan should flag it
        mock = _mock_llm("Email still here user@corp.com", [])
        with patch("server._call_local_model", return_value=mock):
            result = server.sanitize_query("Email still here user@corp.com")
        self.assertIn("POST-SCAN WARNING", result)

    def test_credentials_blocked_message(self):
        mock = _mock_llm("[CREDENTIAL_REDACTED] was used", [
            {"placeholder": "[CREDENTIAL_REDACTED]", "original": "[BLOCKED]", "category": "CREDENTIAL", "confidence": 0.99, "blocked": True}
        ])
        with patch("server._call_local_model", return_value=mock):
            result = server.sanitize_query("AKIAIOSFODNN7EXAMPLE was used")
        self.assertIn("CREDENTIALS BLOCKED", result)


class TestRestoreResponse(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.mkdtemp()
        server.LEDGER_DIR = Path(self._td)
        server.LEDGER_FILE = Path(self._td) / "ledger.jsonl"
        server._SESSION_CACHE.clear()

    def _seed(self, san_id: str, mappings: list) -> None:
        entry = server._build_ledger_entry(san_id, mappings)
        server._write_ledger(entry)
        server._SESSION_CACHE[san_id] = mappings

    def test_restore_from_session_cache(self):
        mappings = [{"placeholder": "[PII_NAME_1]", "original": "Alice", "category": "PII_NAME", "confidence": 0.95, "blocked": False}]
        self._seed("san_test_001", mappings)
        result = server.restore_response("Hello [PII_NAME_1]", "san_test_001")
        self.assertIn("Alice", result)

    def test_restore_from_ledger_fallback(self):
        mappings = [{"placeholder": "[PII_NAME_1]", "original": "Bob", "category": "PII_NAME", "confidence": 0.95, "blocked": False}]
        entry = server._build_ledger_entry("san_test_002", mappings)
        server._write_ledger(entry)
        # Session cache is empty (simulates server restart)
        result = server.restore_response("Hello [PII_NAME_1]", "san_test_002")
        self.assertIn("Bob", result)

    def test_missing_san_id_returns_error(self):
        result = server.restore_response("Hello [PII_NAME_1]", "san_does_not_exist")
        self.assertIn("ERROR", result)
        self.assertIn("not found", result.lower())

    def test_blocked_credentials_never_restored(self):
        mappings = [
            {"placeholder": "[CREDENTIAL_REDACTED]", "original": "[BLOCKED]", "category": "CREDENTIAL", "confidence": 0.99, "blocked": True},
            {"placeholder": "[PII_NAME_1]", "original": "Carol", "category": "PII_NAME", "confidence": 0.95, "blocked": False},
        ]
        self._seed("san_test_003", mappings)
        result = server.restore_response("[CREDENTIAL_REDACTED] used by [PII_NAME_1]", "san_test_003")
        self.assertIn("Carol", result)
        self.assertIn("[CREDENTIAL_REDACTED]", result)  # still present, not restored

    def test_partial_restore_count_reported(self):
        mappings = [
            {"placeholder": "[PII_NAME_1]", "original": "Dave", "category": "PII_NAME", "confidence": 0.9, "blocked": False},
            {"placeholder": "[ORG_NAME_1]", "original": "Acme", "category": "ORG_NAME", "confidence": 0.9, "blocked": False},
        ]
        self._seed("san_test_004", mappings)
        # Only one placeholder present in response
        result = server.restore_response("Hello [PII_NAME_1]", "san_test_004")
        self.assertIn("1/2", result)
        self.assertIn("[ORG_NAME_1]", result)  # listed as not found

    def test_private_mode_error_message(self):
        mappings = [{"placeholder": "[PII_NAME_1]", "original": "[PRIVATE]", "category": "PII_NAME", "confidence": 0.9, "blocked": False}]
        entry = server._build_ledger_entry("san_test_005", mappings)
        server._write_ledger(entry)
        # No session cache entry (simulates cross-session restore with private mode)
        result = server.restore_response("Hello [PII_NAME_1]", "san_test_005")
        self.assertIn("ERROR", result)
        self.assertIn("private mode", result.lower())


class TestScanResponse(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.mkdtemp()
        server.LEDGER_DIR = Path(self._td)
        server.LEDGER_FILE = Path(self._td) / "ledger.jsonl"

    def test_clean_response(self):
        mock = _mock_llm("Kubernetes scales pods based on CPU usage", [])
        with patch("server._call_local_model", return_value=mock):
            result = server.scan_response("Kubernetes scales pods based on CPU usage")
        self.assertIn("Clean", result)

    def test_detects_leaked_credential(self):
        with patch("server._call_local_model", side_effect=RuntimeError("down")):
            result = server.scan_response("Your key is AKIAIOSFODNN7EXAMPLE")
        self.assertIn("WARNING", result)
        self.assertIn("[CREDENTIAL_REDACTED]", result)

    def test_llm_failure_noted_in_output(self):
        with patch("server._call_local_model", side_effect=RuntimeError("down")):
            result = server.scan_response("Normal text here")
        self.assertIn("LLM unavailable", result)


class TestViewLedger(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.mkdtemp()
        server.LEDGER_DIR = Path(self._td)
        server.LEDGER_FILE = Path(self._td) / "ledger.jsonl"

    def test_empty_ledger(self):
        result = server.view_ledger()
        self.assertIn("empty", result.lower())

    def test_shows_entries_with_schema_version(self):
        entry = server._build_ledger_entry("san_test_view", [])
        server._write_ledger(entry)
        result = server.view_ledger()
        self.assertIn("san_test_view", result)
        self.assertIn("Ver", result)


class TestGlinerScan(unittest.TestCase):
    """GLiNER tests use a mock model — no download required."""

    def setUp(self):
        self._td = tempfile.mkdtemp()
        server.LEDGER_DIR = Path(self._td)
        server.LEDGER_FILE = Path(self._td) / "ledger.jsonl"

    def _mock_gliner_entities(self, entities):
        """Return a mock GLiNER instance whose predict_entities returns `entities`."""
        mock_model = unittest.mock.MagicMock()
        mock_model.predict_entities.return_value = entities
        return mock_model

    def test_gliner_unavailable_returns_unchanged(self):
        orig = server.GLINER_AVAILABLE
        try:
            server.GLINER_AVAILABLE = False
            text = "Alice Smith works at Acme Corp"
            result, mappings = server._gliner_scan(text, {}, {})
            self.assertEqual(result, text)
            self.assertEqual(mappings, [])
        finally:
            server.GLINER_AVAILABLE = orig

    def test_gliner_catches_person(self):
        entities = [{"start": 0, "end": 11, "text": "Alice Smith", "label": "person", "score": 0.92}]
        with patch("server._get_gliner", return_value=self._mock_gliner_entities(entities)):
            server.GLINER_AVAILABLE = True
            text = "Alice Smith approved the change"
            redacted, mappings = server._gliner_scan(text, {}, {})
        server.GLINER_AVAILABLE = False
        self.assertNotIn("Alice Smith", redacted)
        self.assertEqual(mappings[0]["category"], "PII_NAME")
        self.assertEqual(mappings[0]["source"], "gliner")

    def test_gliner_always_allow_respected(self):
        entities = [{"start": 0, "end": 10, "text": "Kubernetes", "label": "organization", "score": 0.85}]
        config = {"always_allow": ["Kubernetes"]}
        with patch("server._get_gliner", return_value=self._mock_gliner_entities(entities)):
            server.GLINER_AVAILABLE = True
            text = "Kubernetes runs our cluster"
            redacted, mappings = server._gliner_scan(text, config, {})
        server.GLINER_AVAILABLE = False
        self.assertIn("Kubernetes", redacted)
        self.assertEqual(mappings, [])

    def test_gliner_placeholder_not_reclassified(self):
        # [PII_NAME_1] from Phase 1 should not be re-detected by GLiNER
        entities = [{"start": 0, "end": 11, "text": "[PII_NAME_1]", "label": "person", "score": 0.88}]
        with patch("server._get_gliner", return_value=self._mock_gliner_entities(entities)):
            server.GLINER_AVAILABLE = True
            text = "[PII_NAME_1] approved the change"
            redacted, mappings = server._gliner_scan(text, {}, {"PII_NAME": 1})
        server.GLINER_AVAILABLE = False
        self.assertEqual(redacted, text)  # placeholder left intact
        self.assertEqual(mappings, [])

    def test_gliner_counter_offset_avoids_collision(self):
        # Regex already used PII_NAME_1; GLiNER should start at PII_NAME_2
        entities = [{"start": 0, "end": 10, "text": "Bob Wilson", "label": "person", "score": 0.90}]
        with patch("server._get_gliner", return_value=self._mock_gliner_entities(entities)):
            server.GLINER_AVAILABLE = True
            _, mappings = server._gliner_scan("Bob Wilson did something", {}, {"PII_NAME": 1})
        server.GLINER_AVAILABLE = False
        self.assertEqual(mappings[0]["placeholder"], "[PII_NAME_2]")

    def test_gliner_exception_returns_unchanged(self):
        mock_model = unittest.mock.MagicMock()
        mock_model.predict_entities.side_effect = RuntimeError("model error")
        with patch("server._get_gliner", return_value=mock_model):
            server.GLINER_AVAILABLE = True
            text = "Some text here"
            redacted, mappings = server._gliner_scan(text, {}, {})
        server.GLINER_AVAILABLE = False
        self.assertEqual(redacted, text)
        self.assertEqual(mappings, [])

    def test_gliner_integrated_into_sanitize_query(self):
        entities = [{"start": 0, "end": 9, "text": "Jane Doe", "label": "person", "score": 0.91}]
        mock_llm = _mock_llm("Hello [PII_NAME_1]", [])
        mock_gliner = self._mock_gliner_entities(entities)
        with patch("server._call_local_model", return_value=mock_llm), \
             patch("server._get_gliner", return_value=mock_gliner), \
             patch.object(server, "GLINER_AVAILABLE", True):
            result = server.sanitize_query("Jane Doe approved")
        self.assertIn("[PII_NAME", result)
        self.assertNotIn("Jane Doe", result.split("sanitized_text:")[-1])


class TestHFBackend(unittest.TestCase):

    def test_call_hf_model_no_pipeline_raises(self):
        orig = server._hf_pipeline
        try:
            server._hf_pipeline = None
            server._HF_PIPE = None
            with self.assertRaises(RuntimeError):
                server._call_hf_model("text", "prompt")
        finally:
            server._hf_pipeline = orig

    def test_sanitizer_backend_env(self):
        # Default backend should be "ollama" in test env
        self.assertEqual(server.SANITIZER_BACKEND, "ollama")


import unittest.mock  # needed for MagicMock in GLiNER tests


if __name__ == "__main__":
    unittest.main(verbosity=2)
