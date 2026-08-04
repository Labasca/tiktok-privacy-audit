# TikTok Privacy Audit (read-only)

Instruments TikTok on a **jailbroken iPhone you own** with Frida, to observe what
data the app **reads** from the device. This is an observation tool. It logs what
TikTok touches, it does **not** modify, spoof, or fake anything (no fake GPS, no
fake device IDs, no VPN-status tampering).

## What's in here

| File | Purpose |
|------|---------|
| `observe.js` | The read-only hooks you edit (identifiers, fingerprint sysctls, keychain, interface scans, requests). |
| `observe.compiled.js` | Generated bundle Frida actually runs (contains the ObjC bridge). Regenerate after editing `observe.js`. |
| `run_observe.py` | Cross-platform driver: spawns TikTok, loads the script, streams logs for N seconds. |
| `run.sh` / `run.ps1` | Convenience wrappers (macOS/Linux and Windows). |
| `requirements.txt` | Pinned Frida client versions (must match the phone). |
| `package.json` / `bun.lock` | The one build dependency, `frida-objc-bridge` (only needed to recompile hooks). |

## Prerequisites (both platforms)

- An iPhone **you own**, jailbroken with palera1n (checkm8/A11 devices are semi-tethered).
- On the phone (via Sileo): **Frida** (from `https://build.frida.re`) and **OpenSSH**.
- The phone must be **jailbroken and powered on** for `frida-server` to be running.

> **Version match matters.** The phone's `frida-server` is **17.16.4**. The client
> here is pinned to match in `requirements.txt`. If the two differ on major/minor,
> `frida -U` refuses to connect. If you upgrade Frida on the phone, bump both.

## Run it on macOS / Linux

```bash
pip install -r requirements.txt      # first time
./run.sh 40                          # observe for 40s
```

## Run it on Windows

1. **Install Python**, then:
   ```powershell
   pip install -r requirements.txt
   ```
2. **Install Apple's USB layer.** Frida reaches the phone over USB through Apple's
   `usbmux`. On Windows that ships with **iTunes** (the Apple website installer, not
   necessarily the Microsoft Store one) or the **Apple Devices** app. Without it,
   `frida -U` will not see the phone. This is the #1 Windows gotcha.
3. Plug in the phone and run:
   ```powershell
   .\run.ps1 40
   ```
   or directly: `python run_observe.py 40`

### Editing the hooks on Windows

`run.ps1` will use the committed `observe.compiled.js` as-is. To edit `observe.js`
and recompile, restore the one build dependency first (needs Node.js or Bun):

```powershell
npm install            # or: bun install
frida-compile observe.js -o observe.compiled.js
```

`frida-compile` itself comes from `frida-tools` (installed via pip), so you do not
need Node to *run* the compiler, only to *install* the `frida-objc-bridge` package.

## Re-jailbreaking (semi-tethered reality)

The jailbreak lives on the phone and drops on every reboot. To restore it:

- **macOS / Linux:** `sudo palera1n -l` (re-download palera1n from the official
  GitHub releases first).
- **Windows:** palera1n does **not** run on Windows. Use the **palen1x** bootable
  USB instead. Set this up *before* you rely on the phone rebooting.

Nothing about the jailbreak is tied to a specific computer. Any machine can connect
to the jailbroken phone and any machine (Mac/Linux with palera1n, or Windows with
palen1x) can re-apply the jailbreak.

## Scope

Single device, your own, observation only. See the hook header in `observe.js`.
