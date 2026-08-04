# Read-only TikTok privacy audit runner (Windows / PowerShell).
# Usage:  .\run.ps1 [seconds]      (default 40)
# Requires: python with frida-tools installed (see requirements.txt),
#           and Apple's usbmux layer (iTunes or the Apple Devices app) so
#           `frida -U` can see the iPhone over USB.
param([int]$Duration = 40)

Set-Location -Path $PSScriptRoot

Write-Host "[*] checking the phone is reachable over Frida..."
frida-ps -U > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Frida can't reach the phone."
    Write-Host "    - Is iTunes / the Apple Devices app installed? (provides the USB driver)"
    Write-Host "    - Is the phone still jailbroken? It's semi-tethered: after a reboot you must"
    Write-Host "      re-jailbreak. On Windows that means the palen1x USB (palera1n does not run on Windows)."
    exit 1
}

# recompile only if node_modules (the frida-objc-bridge dep) is present;
# otherwise fall back to the committed observe.compiled.js
if (Test-Path "node_modules/frida-objc-bridge") {
    Write-Host "[*] recompiling observe.js -> observe.compiled.js"
    frida-compile observe.js -o observe.compiled.js
} else {
    Write-Host "[*] node_modules missing - using committed observe.compiled.js (run 'npm install' to enable editing hooks)"
}

Write-Host "[*] running audit for $Duration s (read-only). Scroll TikTok to trigger more."
python run_observe.py $Duration | Tee-Object -FilePath session.log

Write-Host "`n[*] quick summary:"
Select-String -Path session.log -Pattern 'IDENTIFIER|LOCATION|KEYCHAIN|FINGERPRINT|NETWORK|REQUEST' `
    | ForEach-Object { ($_.Matches.Value) } | Group-Object | Sort-Object Count -Descending `
    | ForEach-Object { "{0,5} {1}" -f $_.Count, $_.Name }
Write-Host "[*] full log saved to: $(Join-Path $PSScriptRoot 'session.log')"
