#!/usr/bin/env bash
# AI Security Toolkit installer: Termux, Kali, Ubuntu/Debian, Parrot, BlackArch/Arch, Fedora, Alpine, macOS
# Pure Python standard library: nothing to pip-install.
# Developer: Muhammad Mughees Abbasi
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

have_py() { command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)'; }
SUDO=""; [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

detect() {
  if [ -n "${TERMUX_VERSION:-}" ] || [ -d /data/data/com.termux ]; then echo termux; return; fi
  [ "$(uname -s)" = "Darwin" ] && { echo macos; return; }
  local id="" like=""
  if [ -r /etc/os-release ]; then . /etc/os-release; id="${ID:-}"; like="${ID_LIKE:-}"; fi
  case "$id $like" in
    *kali*|*parrot*|*ubuntu*|*debian*|*mint*|*pop*) echo debian ;;
    *blackarch*|*arch*|*manjaro*) echo arch ;;
    *fedora*|*rhel*|*centos*) echo fedora ;;
    *alpine*) echo alpine ;;
    *) echo unknown ;;
  esac
}

OS="$(detect)"
echo "[*] Platform: $OS"

if ! have_py; then
  echo "[*] Python 3.10+ not found, installing..."
  case "$OS" in
    termux) pkg install -y python ;;
    debian) $SUDO apt-get update -y && $SUDO apt-get install -y python3 ;;
    arch)   $SUDO pacman -Sy --noconfirm python ;;
    fedora) $SUDO dnf install -y python3 ;;
    alpine) $SUDO apk add --no-cache python3 ;;
    macos)  command -v brew >/dev/null && brew install python || { echo "[x] Install Python 3.10+ from python.org"; exit 1; } ;;
    *)      echo "[x] Unknown distro. Install Python 3.10+ manually."; exit 1 ;;
  esac
fi
have_py || { echo "[x] Python 3.10+ still unavailable (found: $(python3 -V 2>&1 || echo none))."; exit 1; }

chmod +x "$DIR/ai-sec-toolkit.sh"
BIN="$HOME/.local/bin"; [ "$OS" = termux ] && BIN="${PREFIX:-/usr}/bin"
mkdir -p "$BIN"
ln -sf "$DIR/ai-sec-toolkit.sh" "$BIN/aisec"
echo "[+] Installed. Run:  aisec        (or  $DIR/ai-sec-toolkit.sh)"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "[!] Add to PATH:  export PATH=\"$BIN:\$PATH\"" ;; esac
python3 "$DIR/main.py" --version
