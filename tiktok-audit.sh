#!/bin/bash
# TikTok privacy audit, read-only. macOS / Linux launcher.
#
# Usage: ./tiktok-audit.sh [seconds]     (default 40)
set -e
cd "$(dirname "$0")"

DURATION="${1:-40}"

fail() {
  echo
  echo "  audit halted: $1"
  shift
  for h in "$@"; do echo "  $h"; done
  echo
  exit 1
}

# prefer a project venv, then the original macOS venv, then PATH
if [ -x ".venv/bin/python" ]; then BIN=".venv/bin/"
elif [ -x "$HOME/.local/frida-venv/bin/python" ]; then BIN="$HOME/.local/frida-venv/bin/"
else BIN=""; fi

if ! "${BIN}frida-ps" -U >/dev/null 2>&1; then
  fail "Frida cannot reach the phone." \
    "check, in order:" \
    "  1. phone plugged in over USB, unlocked, and this Mac trusted" \
    "  2. phone still jailbroken. it is semi-tethered, so a reboot drops it." \
    "     re-apply with:  sudo palera1n -l"
fi

# recompile the hooks only if the build dep is present
if [ -d node_modules/frida-objc-bridge ]; then
  "${BIN}frida-compile" observe.js -o observe.compiled.js
elif [ ! -f observe.compiled.js ]; then
  fail "no observe.compiled.js and no node_modules to build it from." \
    "run 'bun install' (or 'npm install') first."
fi

exec "${BIN}python" run_observe.py "$DURATION"
