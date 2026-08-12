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
| `dump_tags.py` | Reads a media file directly with exiftool into the same shape `tags.json` uses. The denominator for a coverage check. |
| `compare_runs.py` | Diffs the tag inventory across several runs, or a file dump against a run. This is what a stamping test is read out of. |
| `requirements.txt` | Pinned Frida client versions (must match the phone). |
| `package.json` / `bun.lock` | The one build dependency, `frida-objc-bridge` (only needed to recompile hooks). |

Written on each run, both gitignored:

| Artifact | Contents |
|----------|----------|
| `session.log` | Everything printed to the terminal, minus the colour codes. |
| `audit.json` | Every distinct thing read, with counts, first/last timestamps and the values returned. Keeps the per-item detail that the terminal report rolls up. |
| `tags.json` | Flat, sorted tag-to-value map for the post path only. Shaped to be diffed against another run rather than read once. |
| `bodies/` | Captured request bodies, whole, one file each. **Carries session auth headers and account state.** Never commit it. |

Pass `-Run NAME` (or `--run NAME`) and all four go to `runs/NAME/` instead of the
project root. Use it for every run that will be compared against another,
because the default fixed filenames mean the second post erases the first.

## Measuring the post path

The rest of this tool records that TikTok asked a question. The post path also
records **what the answer was**, field by field, because a metadata question is
comparative: what a native capture carries that a generated file does not, and
which of it survives the re-encode.

Three things bracket a post:

| Container | What it is |
|-----------|------------|
| `INPUT` | The file TikTok opened, dumped in full by the rig |
| `OUTPUT` / `UPLOADED` | What its encoder wrote and what left the phone |
| `image` / `video` / `library` | What it read live, as it read it |

A file is parsed on the flush timer, never on an app thread, and only once its
size has stopped changing between ticks, so a growing export is not read
half-written. While the rig parses a file it sets an internal flag that makes
every hook ignore its own reads, otherwise the tool's curiosity is logged as the
app's behaviour and every count is inflated.

### A stamping test, end to end

One post per run. The tally is cumulative, so two posts in one run produce a
blended count that cannot be attributed to either file.

```bash
# 1. the denominator: every tag actually in the file, before it is posted
./dump_tags.py testfiles/01-native.mov

# 2. the run. Post exactly one video during the window.
./tiktok-audit.sh 90 --run 01-native

# 3. coverage: what was in the file vs what the rig saw cross
./compare_runs.py testfiles/01-native.tags.json runs/01-native/tags.json     --normalize --diff-only

# 4. once several arms exist, the comparison the work actually asks
./compare_runs.py runs/*/tags.json --diff-only --csv matrix.csv
```

A tag `dump_tags.py` finds that the rig never names is either a tag TikTok did
not touch or a hook that does not exist. Those two look identical until the
coverage check is run, which is the whole reason to run it before trusting an
absence.

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

## Running it

```powershell
.\tiktok-audit.ps1 40                    # always-on hooks, supervised
.\tiktok-audit.ps1 40 -Full              # adds the net / tls / sys probes
.\tiktok-audit.ps1 25 -Full -Attach      # probe an app you already have open
.\tiktok-audit.ps1 40 -Full -Deep        # adds stat / access / statfs
.\tiktok-audit.ps1 40 -Quiet             # progress bar only, no live stream
```

The live stream runs by default, so the first seconds show each identifier as it is
read rather than an empty progress bar. `-Quiet` mutes it and leaves only the bar and
the report. `session.log` holds the full stream either way.

`-Full` needs about 17s of window for one probe pass, so give it 25 or more. The launcher
warns if the window is too short instead of silently skipping groups.

### What was actually killing it

For a long time the theory was that the hot hooks wedged the USB link and froze the host.
That is not what happens. iOS crash reports name it exactly:

```
scene-create watchdog transgression: application<com.zhiliaoapp.musically>
exhausted real (wall clock) time allowance of 10.00 seconds
Elapsed total CPU time (seconds): 4.570, 7% CPU
```

**SpringBoard was killing TikTok**, because instrumentation made it miss the 10.00 second
wall-clock deadline it gets to bring a scene up. Across twelve terminations the app never
exceeded 26% CPU. It was not busy, it was *blocked*: every intercepted call is a native to
JS transition onto one serialized script thread, so the app's threads queue behind each
other. That cost is invisible in CPU time and fatal in wall-clock time, which is the only
thing iOS measures. Everything downstream (the phone going quiet, the host watchdog firing,
a truncated report) followed from the app dying.

So the rule is now about **when**, not only how much:

- Hooks that fire at app-logic rate (ObjC selectors, keychain, `sysctlbyname`, `getenv`)
  attach at load and cover the launch. They were never implicated.
- Hooks that fire at packet or syscall rate are *registered* at load and attached later, in
  named **probe groups**, one group at a time, for well under a second, starting at 11s.
  11s is not arbitrary: it is past the 10.00s scene-create allowance, so a probe can never
  contribute to that kill.
- Both cutoffs, sample count and wall clock, are checked **inline on the trap itself**. The
  old time-box ran on the flush timer, which is starved by exactly the call storm it existed
  to stop.

The probe schedule repeats for as long as the window allows, because a single sub-second
sample of `connect()` only sees anything if the app happens to be opening a socket in that
exact sub-second.

### Four independent ways a hung run still dies

None of them touch USB, and all four are unchanged. They were never the problem, they were
just diagnosing the wrong cause.

1. **Phone-side self-detach.** Every probe dies on its sample count or its wall-clock
   deadline, both checked inline, plus the driver disarming it, plus a flush-timer sweep.
2. **Host self-kill watchdog.** A daemon thread in the driver hard-exits (`os._exit`) if the
   phone goes silent for 6s. That fires even while the main thread is stuck in a native
   Frida call, because the phone flushes a heartbeat every 400ms.
3. **External supervisor.** `tiktok-audit.ps1` runs the audit as a separate low-priority
   child and watches it from a loop that never touches USB, so it stays responsive and
   force-kills the child on a deadline, a stale heartbeat, or Ctrl-C.
4. **Manual kill.** If a run ever hangs, open a new terminal and run `.\kill-audit.ps1`. If
   even that will not run, unplug the phone: that drops the USB session and it recovers in
   seconds.

**Honest limit:** if a USB stall is ever severe enough to freeze Windows entirely, no
host-side script can run. That is why layers 1 and 2 exist.

### The driver now knows when the app dies

The driver registers `session.on('detached')`. Without it a terminated process and an idle
one are indistinguishable, so a run that iOS killed at 12.9s was reported as a clean 40
second audit, with 27 seconds of dead air presented as observation. The summary panel now
prints the window the app was **alive** for, not the one that was requested, and says so in
red when they differ.

It also records how many calls each probe group actually saw. A group that armed correctly
and saw zero is a fact about the run (the app was idle), not a fact about TikTok, and the
report says which one it is.

### Choosing between spawn and attach

Raw-socket and TLS work clusters in the first ten seconds after launch, which is under the
watchdog floor and cannot be sampled safely. So:

- **Default (spawn)** captures the whole launch sequence through the always-on hooks, which
  is where the identifier reads are, but the probes usually arrive after the network burst.
- **`-Attach`** instruments an app you already have open and are using. Nothing is spawned,
  so there is no scene-create watchdog to violate at all, and the probes land while the app
  is genuinely busy. It cannot see the launch.

Either way, scroll the feed while the probes run. The footer shows which group is live.

### The post path

Posting is the one flow that hands TikTok a file off your phone, and the file is the
finding, not the upload. A video shot on an iPhone carries its capture time, the camera
model and, unless you turned that off, the coordinates. Reading those out of a file the
app already holds needs no permission, produces no prompt, and never touches
`CLLocationManager`, so "no location calls" was never the same as "no location".

These hooks are always on, because a post happens once and a timed probe would miss it:

| Question | Hook |
|----------|------|
| Which picker opened | `PHPickerViewController -initWithConfiguration:` (out of process, no permission, no library access) vs `UIImagePickerController -setSourceType:` (in process, needs both) |
| Was the camera actually on | `AVCaptureSession -startRunning` and `-addInput:`, which names the device. The permission section only ever tells you it *asked* |
| Was the mic armed | `AVAudioSession -setCategory:` filtered to the Record categories |
| Was file metadata opened | `CGImageSourceCopyProperties(AtIndex)` for images, `AVAsset -commonMetadata` / `-metadata` for video. Key names only, and a GPS block or a `location` metadata item is called out by name |
| What the library knew | `PHAsset -location`, `-creationDate`, `-localIdentifier` |
| What got encoded | `AVAssetWriter`, `AVAssetExportSession`, `VTCompressionSessionCreate` |
| The upload | `NSURLSession -uploadTaskWithRequest:...`, which is the only place the payload size is visible before the bytes reach the socket |

A geotag found this way is promoted to the summary panel at the top and rewrites the
location caveat at the bottom, so the report cannot report an empty location section and
a coordinate read in the same breath. If nothing fires, the closing notes say so
explicitly rather than leaving the silence to be read as proof.

The panel itself is split three ways, *what it switched on*, *what it read out of the
files themselves*, *what left the phone*, and then closes with **what did NOT happen**.
That last block is the point. In this section an absence is a finding and a missing row
looks like no finding, so every step of a post that produced nothing is named along with
what its silence means: no picker but a live capture session means the media came from
the in-app camera, no upload task means the file went out through TikTok's own uploader
where only the `tls` probe could ever see it. Metadata reads with no location block are
reported with the field names that *did* come back, because orientation and pixel
geometry are what an image decoder wants, while a GPS or full EXIF block is what a
harvester wants, and the two are indistinguishable without that list.

Counting is deliberately unbudgeted while the dictionary walks are capped. A count that
stops at its budget prints as an exact number and gets read as one, which is how a run
came back reporting exactly 60 metadata reads when the budget was 60.

Three of these could in principle run hotter than app-logic rate, because a media grid or
a video feed touches them per item: the image metadata reads, the asset metadata reads and
the `PHAsset` property reads. All three are budgeted. If a run is ever killed after this,
measure those three first.

One trap worth knowing about if you extend this block: `ObjC.classes.X['- init']` happily
resolves an *inherited* method, so asking `UIImagePickerController` for `- init` hands back
`NSObject`'s and hooking it traps every object the app ever allocates. `mediaHook()` refuses
any selector that is not in the class's own `$ownMethods` for exactly that reason.

Because that guard is strict, every miss is **named**, with why: `class not present on this
build`, `not implemented by this class`, `selector did not resolve`, or the exception. A
hook that failed and a mechanism the app never used produce identical silence, so the
report will not draw a conclusion from an absence whose hook never attached. It says the
gap is the rig's instead, and lists the misses in the closing notes.

### Reading a request off the wire

The `tls` probe captures request lines before encryption. It reads **16 bytes** to decide
whether a buffer is HTTP at all, which is the cheap guard that runs on every outbound
buffer, then **400 bytes** only for the ones that already look like a request. That second
window is what reaches the `Host:` header on the line after the request line, and the host
is folded in right after the method so it survives the clipping the report does on long
paths:

```
POST lab-va.tiktokv.com/upload/v1/lab-speech-video-caption-no/oQAobegf9qib...
  speech to text: your audio, uploaded to be transcribed
```

The second line comes from `PLAINTEXT_PATHS` in `run_observe.py`, a small table of paths
worth recognising by name. It exists so two runs can be compared (captions on versus off,
say) without re-reading a raw path every time. Add to it as you learn what a path is.

CR and LF are preserved as line breaks rather than mapped to `.` with the other
unprintables. Mapping them is what used to produce `HTTP/1.1..Host: lf` and put the
endpoint permanently out of reach.

## Safety rules for adding hooks

**Read this before touching `observe.js`.** An earlier version hooked `open`, `stat` and
`-[UIScreen scale]` and called `send()` on every call. Those fire tens of thousands of
times a second, the driver allocates for every message, the queue grows faster than it
drains, and **the host machine runs out of memory and locks up.** The launcher recompiles
`observe.js` on every run, so an untested hook reaches the phone the moment you run it.

The deeper lesson from the repeated freezes: a `budget()` stops the *work* in a handler but
Frida still *traps every call*, and the trapping alone is what costs. The fixes are (a)
never attach a packet-rate hook at load, register it in a probe group instead, and (b) make
every cutoff inline, because anything on a timer is starved when it matters most.

Four rules, all enforced in the code:

1. **Never call `send()` from a hook.** Everything goes through `emit()`, which counts in
   memory. A timer ships only what changed, a few times a second, so the message rate is a
   constant no matter how hot the hooked function is.
2. **Budget any hook on a hot function.** `budget(n, label)` returns a counter that stops
   the expensive work (string reads, ObjC wrappers) after `n` calls. Aggregation protects
   the host, the budget protects the app. When a budget runs out the report says the count
   is a floor rather than printing it as exact.
3. **Order your guards cheap to expensive.** Integer compare, then length check, then
   regex. The filesystem hooks skip anything over 70 characters before touching a pattern.
4. **Anything at packet or syscall rate goes in a probe group.** `probe(group, target,
   limit, label, handlers)` registers without attaching; `hotHook(...)` is the same thing
   pinned to the always-on `base` group. If you are unsure which a function is, measure it
   before you decide: attach a bare counter for one second and look at the number. On this
   phone `ioctl` came back at 2802 calls in a two second window, and `SSL_read` at 1504.

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
