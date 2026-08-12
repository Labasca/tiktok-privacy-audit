#!/bin/bash
# TikTok privacy audit, read-only. macOS / Linux launcher.
#
# Usage: ./tiktok-audit.sh [seconds] [--full] [--attach] [--deep] [--touch]
#                                    [--quiet] [--stream] [--run NAME]
#
# --run NAME writes this run's artifacts to runs/NAME/ instead of overwriting
# the ones in the project root. Use it whenever more than one run is going to be
# compared, which is every run of a stamping test: compare_runs.py names each
# column after the directory, so the name given here is the name in the matrix.
#
# --full adds the net / tls / sys probe groups. They are not switched on at load:
# they attach one group at a time, for well under a second, starting at 11s, which
# is past the 10.00s scene-create allowance iOS gives the app. Give --full a window
# of 25s or more so a full probe pass fits.
set -e
cd "$(dirname "$0")"

DURATION=40
want_run=0
for arg in "$@"; do
  # --run takes a value, so the next loop pass has to be treated as that value
  # rather than as a flag of its own.
  if [ "$want_run" = "1" ]; then
    export TIKTOK_AUDIT_RUN="$arg"
    want_run=0
    continue
  fi
  case "$arg" in
    --run)    want_run=1 ;;
    --run=*)  export TIKTOK_AUDIT_RUN="${arg#--run=}" ;;
    --full)   export TIKTOK_AUDIT_FULL=1 ;;
    --attach) export TIKTOK_AUDIT_ATTACH=1 ;;
    --deep)   export TIKTOK_AUDIT_DEEP=1 ;;
    --touch)  export TIKTOK_AUDIT_TOUCH=1 ;;
    --quiet)  export TIKTOK_AUDIT_QUIET=1 ;;
    --stream) export TIKTOK_AUDIT_VERBOSE=1 ;;
    ''|*[!0-9]*) echo "  ignoring unrecognised argument: $arg" ;;
    *) DURATION="$arg" ;;
  esac
done

needed=11
[ -n "${TIKTOK_AUDIT_FULL:-}" ]  && needed=$((needed + 6))
[ -n "${TIKTOK_AUDIT_DEEP:-}" ]  && needed=$((needed + 2))
[ -n "${TIKTOK_AUDIT_TOUCH:-}" ] && needed=$((needed + 2))
if [ "$needed" -gt 11 ] && [ "$DURATION" -lt "$needed" ]; then
  echo
  echo "  window is ${DURATION}s but the probe schedule needs about ${needed}s."
  echo "  The later groups will not be armed. Try: ./tiktok-audit.sh $needed ..."
fi

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
