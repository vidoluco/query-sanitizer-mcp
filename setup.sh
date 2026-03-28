#!/usr/bin/env bash
# Setup script for query-sanitizer MCP middleware
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

# Find Python 3.10+
PYTHON=""
for candidate in python3.12 python3.11 python3.10 \
    /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11; do
  if command -v "$candidate" &>/dev/null; then
    VER=$("$candidate" -c "import sys; print(sys.version_info[:2])")
    if [[ "$VER" > "(3, 9)" ]]; then
      PYTHON="$candidate"
      break
    fi
  fi
done

if [[ -z "$PYTHON" ]]; then
  echo "❌  Python 3.10+ required. Install via: brew install python@3.12"
  exit 1
fi

echo "✓ Using $PYTHON ($($PYTHON --version))"

# Create venv and install
"$PYTHON" -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install fastmcp

echo "✓ fastmcp installed in $VENV"
echo ""
echo "Add to Claude Code (~/.claude/settings.json or claude_desktop_config.json):"
echo ""
cat <<JSON
{
  "mcpServers": {
    "query-sanitizer": {
      "command": "$VENV/bin/python",
      "args": ["$SCRIPT_DIR/server.py"],
      "env": {
        "SANITIZER_MODEL_URL": "http://localhost:11434/v1/chat/completions",
        "SANITIZER_MODEL_NAME": "llama3.2"
      }
    }
  }
}
JSON
