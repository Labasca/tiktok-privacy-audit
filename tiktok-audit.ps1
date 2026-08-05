# TikTok privacy audit, read-only. Windows launcher + supervisor.
#
# Usage:  .\tiktok-audit.ps1 [seconds] [-Full]        (default 40)
#
# Runs the audit as a SEPARATE child process and supervises it from a loop that
# never touches USB, so even if the phone-side Frida wedges the USB link, this
# supervisor stays alive and force-kills the child. It kills on: a hard deadline,
# a stale heartbeat (the child stopped reporting), or Ctrl-C. Between this, the
# child's own self-kill watchdog, and kill-audit.ps1, a hung run cannot linger.
#
# Default is the known-safe hook set (loads reliably, captures ~90%). -Full adds
# the raw syscall + TLS payload hooks: more data, but they can wedge the USB link
# or crash the app on launch, so use -Full with a short window (15) at first and
# keep kill-audit.ps1 handy.
#
# Requires: the project venv (.venv) with the pinned Frida client, and Apple's
# usbmux layer (iTunes or the Apple Devices app) so Frida can see the iPhone.
param([int]$Duration = 40, [switch]$Full, [switch]$Touch, [switch]$Stream)

Set-Location -Path $PSScriptRoot

# The hooks and the report both emit UTF-8. Without this the console falls back
# to the ANSI code page and mangles box drawing and punctuation.
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

function Fail($msg, $hints) {
    Write-Host ""
    Write-Host "  audit halted: $msg" -ForegroundColor Red
    foreach ($h in $hints) { Write-Host "  $h" -ForegroundColor DarkGray }
    Write-Host ""
    exit 1
}

# prefer the project venv over whatever `python` is on PATH, since on Windows
# that is usually the Microsoft Store stub rather than a real interpreter.
$py = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$fridaPs = Join-Path $PSScriptRoot ".venv\Scripts\frida-ps.exe"
$fridaCompile = Join-Path $PSScriptRoot ".venv\Scripts\frida-compile.exe"

if (-not (Test-Path $py)) {
    Fail "no .venv in this folder." @(
        "create it once with:",
        "  uv venv --python 3.12 .venv",
        "  uv pip install --native-tls -r requirements.txt --python .venv\Scripts\python.exe"
    )
}

& $fridaPs -U > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    Fail "Frida cannot reach the phone." @(
        "check, in order:",
        "  1. phone plugged in over USB, unlocked, and this PC trusted",
        "  2. Apple Mobile Device Service running (comes with iTunes / Apple Devices)",
        "  3. phone still jailbroken. it is semi-tethered, so a reboot drops it.",
        "     on Windows re-apply with the palen1x USB, palera1n does not run here."
    )
}

# recompile the hooks only if the build dep is present, otherwise use the
# committed bundle as-is
if (Test-Path "node_modules/frida-objc-bridge") {
    & $fridaCompile observe.js -o observe.compiled.js
    if ($LASTEXITCODE -ne 0) { Fail "frida-compile failed on observe.js." @() }
} elseif (-not (Test-Path "observe.compiled.js")) {
    Fail "no observe.compiled.js and no node_modules to build it from." @(
        "run 'bun install' (or 'npm install') first."
    )
}

# full data unless -Safe. The child reads this env var.
$env:TIKTOK_AUDIT_FULL = if ($Full) { "1" } else { "" }
# touch provenance is its own opt-in, separate from -Full. When on, warn clearly:
# it hooks the per-frame input path, so keep the window short and kill-audit ready.
$env:TIKTOK_AUDIT_TOUCH = if ($Touch) { "1" } else { "" }
# -Stream brings back the live per-event stream during the run. Off by default:
# the boxed report at the end is the product. The full stream is always in session.log.
$env:TIKTOK_AUDIT_VERBOSE = if ($Stream) { "1" } else { "" }
if ($Touch) {
    Write-Host ""
    Write-Host "  -Touch: input-path hooks are ON (finger-vs-synthetic, scroll)." -ForegroundColor Yellow
    Write-Host "  They sample only tens of calls then detach. Keep the window short" -ForegroundColor DarkGray
    Write-Host "  and kill-audit.ps1 ready in another terminal, just in case." -ForegroundColor DarkGray
}

# clear any stale heartbeat so a leftover file cannot look "fresh"
$hb = Join-Path $PSScriptRoot "audit.heartbeat"
Remove-Item $hb -Force -ErrorAction SilentlyContinue

# hard limits for the supervisor. The child self-terminates at $Duration; these
# are the outer backstops if it does not.
$DeadlineSec = $Duration + 20     # absolute wall-clock kill
$StaleSec = 6                     # kill if the heartbeat file stops updating

$proc = Start-Process -FilePath $py -ArgumentList "run_observe.py $Duration" `
    -NoNewWindow -PassThru
# below-normal priority so a busy run cannot starve this supervisor or the desktop
try { $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch {}

$reason = ""
try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while (-not $proc.HasExited) {
        Start-Sleep -Milliseconds 300     # this loop never touches USB
        if ($sw.Elapsed.TotalSeconds -gt $DeadlineSec) { $reason = "deadline"; break }
        if (Test-Path $hb) {
            $age = ((Get-Date) - (Get-Item $hb).LastWriteTime).TotalSeconds
            if ($age -gt $StaleSec) { $reason = "heartbeat stale ${StaleSec}s+, the link wedged"; break }
        }
    }
}
finally {
    if ($proc -and -not $proc.HasExited) {
        Write-Host ""
        Write-Host "  supervisor: killing the audit ($reason)." -ForegroundColor Red
        # /T kills the whole tree so no frida child survives
        & taskkill.exe /F /T /PID $proc.Id 2>$null | Out-Null
    }
    Remove-Item $hb -Force -ErrorAction SilentlyContinue
    $env:TIKTOK_AUDIT_FULL = ""
    $env:TIKTOK_AUDIT_TOUCH = ""
    $env:TIKTOK_AUDIT_VERBOSE = ""
}
exit 0
