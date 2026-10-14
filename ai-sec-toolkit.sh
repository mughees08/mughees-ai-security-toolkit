#!/usr/bin/env bash
# AI Security Toolkit launcher
# Developer: Muhammad Mughees Abbasi
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "python3 not found. Install Python 3.10+ and try again."
  exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/main.py" "$@"
