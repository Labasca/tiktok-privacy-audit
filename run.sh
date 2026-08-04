#!/bin/bash
# Read-only TikTok privacy audit runner.
# Usage: ./run.sh [seconds]   (default 40)
set -e
cd "$(dirname "$0")"

# prefer this repo's original macOS venv if it exists, else fall back to PATH tools
if [ -x "$HOME/.local/frida-venv/bin/python" ]; then BIN="$HOME/.local/frida-venv/bin/"; else BIN=""; fi
DURATION="${1:-40}"

echo "[*] checking the phone is reachable over Frida..."
if ! "${BIN}frida-ps" -U >/dev/null 2>&1; then
  echo "[!] Frida can't reach the phone."
  echo "    The jailbreak is semi-tethered - if the phone rebooted, re-run:  sudo palera1n -l"
  echo "    Then plug the phone in and try again."
  exit 1
fi

# recompile only if the build dep is present, else use the committed bundle
if [ -d node_modules/frida-objc-bridge ]; then
  echo "[*] recompiling observe.js -> observe.compiled.js"
  "${BIN}frida-compile" observe.js -o observe.compiled.js
else
  echo "[*] node_modules missing - using committed observe.compiled.js (run 'bun install' to edit hooks)"
fi

echo "[*] running audit for ${DURATION}s (read-only). Scroll TikTok to trigger more."
"${BIN}python" run_observe.py "$DURATION" | tee session.log

echo
echo "[*] quick summary:"
grep -oE 'IDENTIFIER|LOCATION|KEYCHAIN|FINGERPRINT|NETWORK|REQUEST' session.log 2>/dev/null | sort | uniq -c | sort -rn
echo "[*] full log saved to: $(pwd)/session.log"
