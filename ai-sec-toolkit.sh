#!/usr/bin/env bash
# AI Security Toolkit launcher (Linux: Kali, Ubuntu, Parrot, BlackArch, Debian, Arch, Fedora; Termux; macOS)
# Developer: Muhammad Mughees Abbasi
set -euo pipefail
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  case "$SOURCE" in /*) ;; *) SOURCE="$DIR/$SOURCE" ;; esac
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[x] python3 not found. Install Python 3.10+ (Termux: pkg install python) and retry."
  exit 1
fi
if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "[x] Python 3.10+ required (found $("$PYTHON_BIN" -V 2>&1))."
  exit 1
fi
exec "$PYTHON_BIN" "$SCRIPT_DIR/main.py" "$@"
