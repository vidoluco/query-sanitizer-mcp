"""
Unit tests for scripts/ledger.py CLI tool.
"""

import json
import os
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import ledger  # noqa: E402


class LedgerTestBase(unittest.TestCase):
    """Sets up a fresh temp ledger directory for each test."""

    def setUp(self):
        self._td = tempfile.mkdtemp()
        ledger.LEDGER_DIR = Path(self._td)
        ledger.LEDGER_FILE = ledger.LEDGER_DIR / "ledger.jsonl"
        ledger.CONFIG_FILE = ledger.LEDGER_DIR / "config.json"

    def _write_entry(self, san_id: str, mappings: list, blocked: int = 0) -> None:
        entry = {
            "schema_version": 1,
            "id": san_id,
            "timestamp": "2026-04-01T10:00:00Z",
            "direction": "outbound",
            "token_count": len(mappings),
            "mappings": mappings,
            "stats": {
                "critical_blocked": blocked,
                "high_redacted": len(mappings) - blocked,
                "medium_redacted": 0,
                "low_redacted": 0,
                "total_redacted": len(mappings),
            },
        }
        ledger.LEDGER_DIR.mkdir(exist_ok=True)
        with ledger.LEDGER_FILE.open("a") as f:
            f.write(json.dumps(entry) + "\n")


class TestReadLedger(LedgerTestBase):

    def test_empty_file_returns_empty_list(self):
        self.assertEqual(ledger.read_ledger(), [])

    def test_missing_file_returns_empty_list(self):
        self.assertEqual(ledger.read_ledger(), [])

    def test_reads_entries(self):
        self._write_entry("san_001", [])
        self._write_entry("san_002", [])
        entries = ledger.read_ledger()
        self.assertEqual(len(entries), 2)

    def test_skips_malformed_lines(self):
        ledger.LEDGER_DIR.mkdir(exist_ok=True)
        with ledger.LEDGER_FILE.open("w") as f:
            f.write('{"id": "san_ok"}\n')
            f.write("not-valid-json\n")
            f.write('{"id": "san_ok2"}\n')
        entries = ledger.read_ledger()
        self.assertEqual(len(entries), 2)


class TestCmdList(LedgerTestBase):

    def test_empty_ledger_message(self):
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            ledger.cmd_list([])
        self.assertIn("empty", mock_out.getvalue().lower())

    def test_lists_entries(self):
        self._write_entry("san_abc", [])
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            ledger.cmd_list([])
        self.assertIn("san_abc", mock_out.getvalue())

    def test_limit_respected(self):
        for i in range(5):
            self._write_entry(f"san_{i:03}", [])
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            ledger.cmd_list(["2"])
        output = mock_out.getvalue()
        self.assertIn("san_004", output)
        self.assertNotIn("san_000", output)

    def test_blocked_flag_shown(self):
        self._write_entry("san_blocked", [
            {"placeholder": "[CREDENTIAL_REDACTED]", "original": "[BLOCKED]", "category": "CREDENTIAL", "blocked": True, "confidence": 0.99}
        ], blocked=1)
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            ledger.cmd_list([])
        self.assertIn("⚠", mock_out.getvalue())


class TestCmdStats(LedgerTestBase):

    def test_empty_ledger(self):
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            ledger.cmd_stats([])
        self.assertIn("empty", mock_out.getvalue().lower())

    def test_aggregates_correctly(self):
        self._write_entry("san_a", [
            {"category": "PII_NAME", "blocked": False, "placeholder": "[PII_NAME_1]", "original": "Alice", "confidence": 0.95},
        ])
        self._write_entry("san_b", [
            {"category": "PII_NAME", "blocked": False, "placeholder": "[PII_NAME_1]", "original": "Bob", "confidence": 0.95},
            {"category": "INFRA",    "blocked": False, "placeholder": "[INFRA_1]",    "original": "10.0.0.1", "confidence": 0.98},
        ])
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            ledger.cmd_stats([])
        output = mock_out.getvalue()
        self.assertIn("Total sanitizations", output)
        self.assertIn("PII_NAME", output)
        self.assertIn("INFRA", output)

    def test_source_breakdown_shown(self):
        self._write_entry("san_src", [
            {"category": "PII_NAME", "blocked": False, "placeholder": "[PII_NAME_1]", "original": "X", "confidence": 0.9, "source": "regex"},
        ])
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            ledger.cmd_stats([])
        self.assertIn("regex", mock_out.getvalue())


class TestCmdPurge(LedgerTestBase):

    def _write_old_entry(self, san_id: str) -> None:
        entry = {
            "schema_version": 1,
            "id": san_id,
            "timestamp": "2020-01-01T00:00:00Z",
            "direction": "outbound",
            "token_count": 0,
            "mappings": [],
            "stats": {"critical_blocked": 0, "high_redacted": 0, "medium_redacted": 0, "low_redacted": 0, "total_redacted": 0},
        }
        ledger.LEDGER_DIR.mkdir(exist_ok=True)
        with ledger.LEDGER_FILE.open("a") as f:
            f.write(json.dumps(entry) + "\n")

    def test_purges_old_entries(self):
        self._write_old_entry("san_old")
        self._write_entry("san_new", [])
        with patch("sys.stdout", new_callable=StringIO):
            ledger.cmd_purge(["--older-than", "30d"])
        remaining = ledger.read_ledger()
        ids = [e["id"] for e in remaining]
        self.assertNotIn("san_old", ids)
        self.assertIn("san_new", ids)

    def test_purge_missing_args_exits(self):
        with self.assertRaises(SystemExit):
            ledger.cmd_purge([])


class TestCmdInitConfig(LedgerTestBase):

    def test_creates_config(self):
        with patch("sys.stdout", new_callable=StringIO):
            ledger.cmd_init_config([])
        self.assertTrue(ledger.CONFIG_FILE.exists())
        config = json.loads(ledger.CONFIG_FILE.read_text())
        self.assertIn("org_names", config)
        self.assertIn("always_allow", config)

    def test_does_not_overwrite_existing(self):
        ledger.LEDGER_DIR.mkdir(exist_ok=True)
        ledger.CONFIG_FILE.write_text('{"custom": true}')
        with patch("sys.stdout", new_callable=StringIO):
            ledger.cmd_init_config([])
        config = json.loads(ledger.CONFIG_FILE.read_text())
        self.assertTrue(config.get("custom"))


class TestCmdLookup(LedgerTestBase):

    def test_lookup_found(self):
        self._write_entry("san_lookup_01", [
            {"category": "PII_NAME", "blocked": False, "placeholder": "[PII_NAME_1]", "original": "Eve", "confidence": 0.9}
        ])
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            ledger.cmd_lookup(["san_lookup_01"])
        self.assertIn("san_lookup_01", mock_out.getvalue())

    def test_lookup_not_found_exits(self):
        with self.assertRaises(SystemExit):
            ledger.cmd_lookup(["san_nonexistent"])

    def test_lookup_masks_private_originals(self):
        self._write_entry("san_priv", [
            {"category": "PII_NAME", "blocked": False, "placeholder": "[PII_NAME_1]", "original": "[PRIVATE]", "confidence": 0.9}
        ])
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            ledger.cmd_lookup(["san_priv"])
        self.assertIn("[PRIVATE — not stored]", mock_out.getvalue())


class TestCmdRestore(LedgerTestBase):

    def test_restore_replaces_placeholder(self):
        self._write_entry("san_r01", [
            {"category": "PII_NAME", "blocked": False, "placeholder": "[PII_NAME_1]", "original": "Frank", "confidence": 0.9}
        ])
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            ledger.cmd_restore(["san_r01", "Hello [PII_NAME_1]"])
        self.assertIn("Frank", mock_out.getvalue())

    def test_restore_skips_blocked(self):
        self._write_entry("san_r02", [
            {"category": "CREDENTIAL", "blocked": True, "placeholder": "[CREDENTIAL_REDACTED]", "original": "[BLOCKED]", "confidence": 0.99}
        ])
        with patch("sys.stdout", new_callable=StringIO) as mock_out:
            ledger.cmd_restore(["san_r02", "Token: [CREDENTIAL_REDACTED]"])
        self.assertIn("[CREDENTIAL_REDACTED]", mock_out.getvalue())

    def test_restore_missing_san_id_exits(self):
        with self.assertRaises(SystemExit):
            ledger.cmd_restore(["san_nonexistent", "text"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
