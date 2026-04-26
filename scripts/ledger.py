#!/usr/bin/env python3
"""
Sanitizer Ledger CLI — manage redaction entries.

Usage:
  python ledger.py list [N]                Show recent N entries (default 10)
  python ledger.py lookup <san_id>         Get mappings for a specific sanitization
  python ledger.py restore <san_id> <text> Restore placeholders in text using ledger entry
  python ledger.py stats                   Show aggregate stats
  python ledger.py purge --older-than Nd   Remove entries older than N days
  python ledger.py init-config             Create a starter config.json
"""

import json
import sys
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

LEDGER_DIR = Path(os.getenv("SANITIZER_LEDGER_DIR", ".sanitizer-ledger"))
LEDGER_FILE = LEDGER_DIR / "ledger.jsonl"
CONFIG_FILE = LEDGER_DIR / "config.json"


def ensure_dir() -> None:
    LEDGER_DIR.mkdir(exist_ok=True)


def read_ledger() -> list:
    if not LEDGER_FILE.exists():
        return []
    entries = []
    for line in LEDGER_FILE.read_text().strip().split("\n"):
        if line.strip():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def cmd_list(args: list) -> None:
    entries = read_ledger()
    n = int(args[0]) if args else 10
    if not entries:
        print("Ledger is empty.")
        return
    print(f"{'ID':<30} {'Timestamp':<26} {'Redacted':>8} {'Blocked':>8} {'Ver':>4}")
    print("-" * 82)
    for entry in entries[-n:]:
        blocked = entry.get("stats", {}).get("critical_blocked", 0)
        total = entry.get("stats", {}).get("total_redacted", 0)
        ver = entry.get("schema_version", "—")
        flag = " ⚠  CREDENTIALS BLOCKED" if blocked > 0 else ""
        print(f"{entry['id']:<30} {entry['timestamp']:<26} {total:>8} {blocked:>8} {str(ver):>4}{flag}")


def cmd_lookup(args: list) -> None:
    if not args:
        print("Usage: ledger.py lookup <san_id>")
        sys.exit(1)
    san_id = args[0]
    for entry in read_ledger():
        if entry["id"] == san_id:
            # Mask private originals in output
            display = dict(entry)
            display["mappings"] = [
                {**m, "original": "[PRIVATE — not stored]"} if m.get("original") == "[PRIVATE]" else m
                for m in entry.get("mappings", [])
            ]
            print(json.dumps(display, indent=2, ensure_ascii=False))
            return
    print(f"Not found: {san_id}")
    sys.exit(1)


def cmd_restore(args: list) -> None:
    if len(args) < 2:
        print("Usage: ledger.py restore <san_id> <text>")
        sys.exit(1)
    san_id, text = args[0], " ".join(args[1:])
    for entry in read_ledger():
        if entry["id"] == san_id:
            private_count = sum(
                1 for m in entry.get("mappings", [])
                if m.get("original") == "[PRIVATE]" and not m.get("blocked")
            )
            if private_count:
                print(
                    f"Warning: {private_count} mapping(s) were stored in private mode — "
                    "those placeholders cannot be restored from ledger.",
                    file=sys.stderr,
                )
            for m in entry.get("mappings", []):
                if not m.get("blocked") and m.get("original") not in ("[PRIVATE]", "[BLOCKED]"):
                    text = text.replace(m["placeholder"], m["original"])
            print(text)
            return
    print(f"Not found: {san_id}")
    sys.exit(1)


def cmd_stats(args: list) -> None:
    entries = read_ledger()
    if not entries:
        print("Ledger is empty.")
        return
    total_ops = len(entries)
    total_redacted = sum(e.get("stats", {}).get("total_redacted", 0) for e in entries)
    total_blocked = sum(e.get("stats", {}).get("critical_blocked", 0) for e in entries)
    private_ops = sum(
        1 for e in entries
        if any(m.get("original") == "[PRIVATE]" for m in e.get("mappings", []))
    )
    cats: dict[str, int] = {}
    for e in entries:
        for m in e.get("mappings", []):
            cats[m["category"]] = cats.get(m["category"], 0) + 1
    sources: dict[str, int] = {}
    for e in entries:
        for m in e.get("mappings", []):
            src = m.get("source", "llm")
            sources[src] = sources.get(src, 0) + 1

    print(f"Total sanitizations : {total_ops}")
    print(f"Total tokens redacted: {total_redacted}")
    print(f"Credentials blocked : {total_blocked}")
    if private_ops:
        print(f"Private-mode ops    : {private_ops} (originals not stored)")
    if sources:
        print(f"\nBy detection source:")
        for src, count in sorted(sources.items(), key=lambda x: -x[1]):
            print(f"  {src}: {count}")
    if cats:
        print(f"\nBy category:")
        for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
            print(f"  {cat}: {count}")


def cmd_purge(args: list) -> None:
    if not args or args[0] != "--older-than" or len(args) < 2:
        print("Usage: ledger.py purge --older-than 30d")
        sys.exit(1)
    days = int(args[1].rstrip("d"))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    entries = read_ledger()
    kept = []
    for e in entries:
        ts_str = e["timestamp"].rstrip("Z")
        try:
            ts = datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc)
        except ValueError:
            kept.append(e)
            continue
        if ts >= cutoff:
            kept.append(e)
    purged = len(entries) - len(kept)
    LEDGER_FILE.write_text(
        ("\n".join(json.dumps(e) for e in kept) + "\n") if kept else ""
    )
    print(f"Purged {purged} entries older than {days}d. {len(kept)} remaining.")


def cmd_init_config(args: list) -> None:
    ensure_dir()
    if CONFIG_FILE.exists():
        print(f"Config already exists: {CONFIG_FILE}")
        return
    starter = {
        "org_names": [],
        "org_domains": [],
        "project_codenames": [],
        "known_employees": [],
        "internal_ip_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "custom_patterns": [
            {"pattern": "JIRA-\\d{4,}", "category": "PROJECT_NAME", "description": "Jira ticket IDs"}
        ],
        "always_allow": ["Google Cloud", "Kubernetes", "BigQuery", "Terraform", "Docker"],
    }
    CONFIG_FILE.write_text(json.dumps(starter, indent=2))
    print(f"Created starter config: {CONFIG_FILE}")
    print("Edit this file to add your org-specific entities for better detection.")


COMMANDS = {
    "list": cmd_list,
    "lookup": cmd_lookup,
    "restore": cmd_restore,
    "stats": cmd_stats,
    "purge": cmd_purge,
    "init-config": cmd_init_config,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(1)
    COMMANDS[sys.argv[1]](sys.argv[2:])
