# kill-audit.ps1  -  the manual emergency stop.
#
# Open a NEW terminal and run this if a run ever hangs. It force-kills the audit
# process and any Frida helper it spawned. It does NOT touch USB, so it stays
# responsive even when the audit terminal is frozen.
#
#   .\kill-audit.ps1
#
# If the machine is so wedged that even this will not run, unplug the phone: that
# drops the USB session and the link recovers within a few seconds.

$killed = 0

# 1. the audit itself: any python running run_observe.py
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine -match 'run_observe\.py' } |
    ForEach-Object {
        Write-Host "  killing audit  pid $($_.ProcessId)" -ForegroundColor Yellow
        & taskkill.exe /F /T /PID $_.ProcessId 2>$null | Out-Null
        $killed++
    }

# 2. any lingering Frida CLI helpers from this project's venv
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine -match 'tiktok-privacy-audit.*frida' } |
    ForEach-Object {
        Write-Host "  killing frida  pid $($_.ProcessId)" -ForegroundColor Yellow
        & taskkill.exe /F /T /PID $_.ProcessId 2>$null | Out-Null
        $killed++
    }

Remove-Item (Join-Path $PSScriptRoot "audit.heartbeat") -Force -ErrorAction SilentlyContinue

if ($killed -eq 0) {
    Write-Host "  nothing running to kill." -ForegroundColor DarkGray
} else {
    Write-Host "  killed $killed process(es). If USB still looks stuck, unplug the phone." -ForegroundColor Green
}
