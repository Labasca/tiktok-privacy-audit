# TikTok Privacy Audit (read-only)

Instruments TikTok on a **jailbroken iPhone you own** with Frida, to observe what
data the app **reads** from the device. This is an observation tool. It logs what
TikTok touches, it does **not** modify, spoof, or fake anything (no fake GPS, no
fake device IDs, no VPN-status tampering).

## What's in here

| File | Purpose |
|------|---------|
| `tiktok-audit.ps1` / `tiktok-audit.sh` | **The command.** Preflights the phone, rebuilds the hooks, runs the audit. |
| `observe.js` | The read-only hooks (identifiers, fingerprint sysctls, keychain, interface scans, requests). They emit structured events, no formatting. |
| `observe.compiled.js` | Generated bundle Frida actually runs (contains the ObjC bridge). Regenerate after editing `observe.js`. |
| `run_observe.py` | The driver and the report: spawns TikTok, deduplicates the event stream, explains it, writes the artifacts. |
| `requirements.txt` | Pinned Frida client versions (must match the phone). |
| `package.json` / `bun.lock` | The one build dependency, `frida-objc-bridge` (only needed to recompile hooks). |

Written on each run, both gitignored:

| Artifact | Contents |
|----------|----------|
| `session.log` | Everything printed to the terminal, minus the colour codes. |
| `audit.json` | Every distinct thing read, with counts, first/last timestamps and the values returned. Keeps the per-item detail that the terminal report rolls up. |

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
./tiktok-audit.sh 40                 # observe for 40s
```

## Run it on Windows

1. **Create the venv and install the Frida client** (one time):
   ```powershell
   uv venv --python 3.12 .venv
   uv pip install --native-tls -r requirements.txt --python .venv\Scripts\python.exe
   ```
   Use a venv rather than a global `pip install`: a bare `python` on Windows usually
   resolves to the Microsoft Store stub, not a real interpreter. `tiktok-audit.ps1`
   looks for `.venv` and uses it directly. The `--native-tls` flag makes `uv` trust the
   Windows certificate store, needed if a proxy or antivirus intercepts TLS (otherwise
   you get `invalid peer certificate: UnknownIssuer`).
2. **Install Apple's USB layer.** Frida reaches the phone over USB through Apple's
   `usbmux`. On Windows that ships with **iTunes** (the Apple website installer, not
   necessarily the Microsoft Store one) or the **Apple Devices** app. Without it,
   `frida -U` will not see the phone. This is the #1 Windows gotcha. Check it with:
   ```powershell
   Get-Service "Apple Mobile Device Service"      # should be Running
   ```
3. Plug in the phone (unlocked, "Trust This Computer" accepted) and confirm Frida
   sees it:
   ```powershell
   .\.venv\Scripts\frida-ps.exe -U
   ```
   A process list means `frida-server` is up. An error means the phone is not
   jailbroken right now, or `usbmux` is missing.
4. Run the audit:
   ```powershell
   .\tiktok-audit.ps1 40
   ```

## Reading the output

Two phases. **Live**, one line per *new* thing TikTok touches, repeats counted rather
than printed. A 40 second window produces roughly 500 raw calls and about 40 lines.

```
  !   0.2s  IDENTITY    identifierForVendor   0AFC2304-563F-4BF2-BCBA-D72C5D34C2E7
  !   0.5s  NETWORK     getifaddrs            network interface enumeration
  !   0.8s  KEYCHAIN    com.appsFlyer.sdk     generic password
```

Then the **digest**. Sections are named for what they mean to you, not for the API they
came from: *Who you are*, *Where you sit on the network*, *Survives deleting the app*,
*Checks on the phone, not on you*, *Who else was told*, *What phone this is*.

Each section opens with a short intro saying what the group is and what it means **for
this run** (the VPN verdict, the list of SDKs found, whether the jailbreak was visible),
then lists every mechanism as one row:

```
  ! Vendor device ID      identifierForVendor   0AFC2304-563F-4BF2-BCBA-D72C5D34C2E7   1x
    Hardware model        hw.machine            iPhone10,3                            57x
    Memory fitted         hw.memsize            2.8 GB                                 5x
```

Plain-English name, the raw key so you can search for it, the value your phone actually
returned, and how often it was asked. A `!` marks something worth attention rather than
routine. Sections where the owner is the finding (keychain, endpoints) drop the value
column and name the company instead.

It closes with **Not shown**, the honest limits. Keep that in view: it is what stops the
sections above from reading as a complete picture.

To change what a mechanism is called or how it is explained, edit `HUMAN`,
`KEYCHAIN_OWNERS` and the `intro_*` functions in `run_observe.py`. Adding a hook to
`observe.js` without adding a `HUMAN` entry still works, it just falls back to the raw
key.

### Network exposure

The first section answers "what can TikTok tell about my connection". `getifaddrs`
returns the full interface list, so instead of counting the calls the audit decodes what
they returned and classifies every address:

```
  ! read the full interface list 58x. it returned:
  ! utun4        VPN tunnel, live       10.8.0.2               private
    en0          Wi-Fi                  192.168.0.149          private
  ! pdp_ip0      cellular               2a02:8109:aabb::1      PUBLIC
  ! proxy config explicit check         9x, the app asked the OS outright
```

- **VPN detection is address-based, not name-based.** iOS keeps `utun0..2` up for system
  services such as Handoff and AirPlay, and those only ever hold a link-local address.
  A tunnel is only reported as a live VPN when it carries a routable address, so idle
  system tunnels do not produce a false positive.
- **PUBLIC** marks a globally routable address readable straight off the device. If a VPN
  is up *and* another interface still exposes one, the report calls that out: it usually
  means the tunnel covers IPv4 while IPv6 goes around it.
- Carrier NAT (`100.64.0.0/10`), private, link-local and loopback are distinguished, since
  they carry very different weight.
- Interfaces holding only link-local addresses collapse to one summary line.

What this **cannot** see is the public IP recorded server-side. That is observed by
TikTok's servers, not readable from the phone. What the interface list does tell you is
which path carries your default route, which is what determines that address.

### What it can see about the network

Addresses are watched through five separate channels, because `getifaddrs` alone only
shows what the phone *has*, not what it *uses*:

| Hook | Answers |
|------|---------|
| `getifaddrs` | Every interface and address the phone holds, including any VPN |
| `getsockname` | The source address traffic **actually left from**, measured rather than inferred |
| `connect` / `connectx` | Every destination socket, including traffic that bypasses NSURLSession |
| `getaddrinfo` | Which names it resolved and to what, used to put hostnames back on raw addresses |
| `nw_path_uses_interface_type` | The modern VPN and connection-type check, which an app can use without ever calling `getifaddrs` |
| `ioctl(SIOCGIFCONF/SIOCGIFADDR)` | The older, quieter way of listing interfaces |

**VPN detection is address-based, not name-based.** iOS keeps `utun0..4` up for system
services such as Handoff and AirPlay, and those hold only link-local addresses. A tunnel
counts as a live VPN only when it carries a routable address, so idle system tunnels do
not produce a false positive.

`198.18.0.0/15` is flagged as a **benchmark range**. It is reserved for testing and never
routed, which is exactly why on-device proxy clients self-assign it. Seeing it means the
tunnel endpoint is local. It says nothing about where traffic finally exits.

Absence still proves nothing: "no location calls" means none happened while observed.
Exercise the app during the window.

## Running it, and the crash

```powershell
.\tiktok-audit.ps1 40          # everything on, supervised
.\tiktok-audit.ps1 40 -Safe    # minimal known-safe hook set, if you ever want it
```

**All hooks are on by default** for maximum coverage. The freeze risk is real: the network
and payload hooks sit on the app's hot path, and under active scrolling they can peg the
phone's frida-server and hang the USB link, which freezes the terminals. Host memory stays
low the whole time, so watching host RAM does not catch it.

The safety is not fewer hooks, it is **four independent ways a hung run dies**, none of
which touch USB:

1. **Phone-side self-detach.** Every hot hook (`hotHook`) grabs a small sample then removes
   itself, and a 9s time-box detaches all of them regardless. Instrumentation winds down on
   its own after the first seconds.
2. **Host self-kill watchdog.** A daemon thread in the driver hard-exits (`os._exit`) if the
   phone goes silent for 6s. That fires even while the main thread is stuck in a native
   Frida call, because the phone flushes a heartbeat every 400ms and real silence means the
   link wedged.
3. **External supervisor.** `tiktok-audit.ps1` runs the audit as a separate low-priority
   child and watches it from a loop that never touches USB, so it stays responsive and
   force-kills the child on a deadline, a stale heartbeat, or Ctrl-C.
4. **Manual kill.** If a run ever hangs, open a new terminal and run `.\kill-audit.ps1`. It
   force-kills the audit without touching USB. If even that will not run, unplug the phone:
   that drops the USB session and the link recovers in seconds.

**Honest limit:** if the USB stall is severe enough to freeze Windows entirely, no host-side
script can run. That is why layers 1 and 2 (phone-side and the self-kill) exist, and why the
manual last resort is to unplug the phone.

Inside `observe.js` the switches are `SYSCALL_ENABLED` and `TLS_ENABLED`, single digits the
driver flips in place (a length change would corrupt the compiled bundle's byte-offset
header). `-Safe` leaves them at 0. Any hot C function is looked up through
`dangerousExport()`, which returns null when the gate is off so the hook never attaches.

## Safety rules for adding hooks

**Read this before touching `observe.js`.** An earlier version hooked `open`, `stat` and
`-[UIScreen scale]` and called `send()` on every call. Those fire tens of thousands of
times a second, the driver allocates for every message, the queue grows faster than it
drains, and **the host machine runs out of memory and locks up.** The launcher recompiles
`observe.js` on every run, so an untested hook reaches the phone the moment you run it.

The deeper lesson from the repeated freezes: a `budget()` stops the *work* in a handler but
Frida still *traps every call*, and on a hot function that trapping alone hangs the phone.
The real fixes are (a) don't hook hot syscalls by default, and (b) for the ones you do,
route them through `hotHook()`, which detaches the listener after a small sample so the
function goes back to running natively with zero Frida involvement.

Three rules, all enforced in the code:

1. **Never call `send()` from a hook.** Everything goes through `emit()`, which counts in
   memory. A timer ships only what changed, a few times a second, so the message rate is a
   constant no matter how hot the hooked function is.
2. **Budget any hook on a hot function.** `budget(n, label)` returns a counter that stops
   the expensive work (string reads, ObjC wrappers) after `n` calls. Aggregation protects
   the host, the budget protects the app. When a budget runs out the report says the count
   is a floor rather than printing it as exact.
3. **Order your guards cheap to expensive.** Integer compare, then length check, then
   regex. The filesystem hooks skip anything over 70 characters before touching a pattern.

Ceilings, all fail-safe: 3000 distinct events and 4M observed calls in the script, 4000
records in the driver. Past those it stops recording and the report says it truncated.

Deliberately not hooked: `-[UIScreen scale]` (every layout pass), `open` and `fopen` (a
jailbreak check uses `stat` or `access`), `getattrlist` (general file metadata).

To sanity check a change before trusting it, run it in a job and watch memory:

```powershell
$job = Start-Job { Set-Location C:\Users\Domas\tiktok-privacy-audit; .\tiktok-audit.ps1 15 }
while ($job.State -eq 'Running') { Start-Sleep 1
  (Get-Process python -EA SilentlyContinue | Measure-Object WorkingSet64 -Max).Maximum/1MB }
```

A healthy run sits around 50 MB and stays flat. Climbing steadily means a hook is
flooding, and you should stop it before it takes the machine with it.

## Finding what is not covered yet

`discover.js` answers "what are we missing" with evidence rather than guesswork:

```powershell
.\.venv\Scripts\python.exe run_discover.py 30
```

It enumerates every C function the binary imports (the ceiling on what it can call), casts
a wide net over privacy-relevant Objective-C classes and reports which ones actually fire,
and records which module each call came from so you can tell TikTok asking from the OS
doing it by itself. Findings land in `discovery.json`, and anything worth keeping gets
promoted into `observe.js` as a real hook.

### Editing the hooks

`tiktok-audit.ps1` uses the committed `observe.compiled.js` as-is. To edit `observe.js`
and recompile, restore the one build dependency first (needs Node.js or Bun):

```powershell
bun install            # or: npm install
```

`frida-compile` itself comes from `frida-tools` (installed into `.venv`), so you do
not need Node to *run* the compiler, only to *install* the `frida-objc-bridge`
package. Once `node_modules` exists, the launcher recompiles on every run.

Keep the split: `observe.js` emits structured `{cat, key, value}` events and nothing
else, `run_observe.py` owns all naming, grouping and presentation. To teach the audit
what a new key means, edit the tables at the top of `run_observe.py`, not the hooks.

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
