#!/usr/bin/env python3
"""
TikTok privacy audit, read-only observation driver.

Spawns TikTok, loads observe.compiled.js, and turns the raw hook stream into
something a human can act on. The hooks are the sensor. This file is the
report: it deduplicates, names things in plain English, flags what actually
matters, and writes the artifacts.

Cross-platform (macOS / Windows / Linux). Needs the `frida` python package
matching the phone's frida-server, and on Windows Apple's usbmux layer from
iTunes or the Apple Devices app.

Usage:  python run_observe.py [seconds]
"""
import sys, os, re, time, json, shutil, threading, ipaddress, frida
from collections import Counter

import mobilegestalt_keys

# run from the script's own directory so observe.compiled.js resolves anywhere
os.chdir(os.path.dirname(os.path.abspath(__file__)))

BUNDLE = "com.zhiliaoapp.musically"
DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 40
# A named run keeps its artifacts in runs/<name>/ instead of overwriting the
# ones in the project root. A comparison needs several runs side by side, and
# the default fixed filenames mean the second post erases the evidence from the
# first. compare_runs.py takes each run's column name from its directory, so the
# name given here is the name that appears in the matrix.
RUN_NAME = os.environ.get("TIKTOK_AUDIT_RUN", "").strip()
if RUN_NAME:
    # Two passes, and both are load-bearing. The first keeps the name to
    # characters a filesystem is happy with. The second stops the result from
    # being a traversal: a name of ".." would otherwise resolve to the project
    # root and quietly overwrite the very artifacts a named run exists to keep
    # apart. Leading dots go, and a name that was nothing but dots and
    # separators falls back rather than resolving anywhere surprising.
    _safe = re.sub(r"[^A-Za-z0-9._-]+", "-", RUN_NAME).lstrip(".-")
    if not _safe.strip("._-"):
        _safe = "run"
    _OUT = os.path.join("runs", _safe)
    os.makedirs(_OUT, exist_ok=True)
    _out = lambda n: os.path.join(_OUT, n)
else:
    # unnamed runs keep the bare filenames they always had, so nothing that
    # already reads audit.json in the project root has to learn a new path.
    _out = lambda n: n

LOG_PATH = _out("session.log")
JSON_PATH = _out("audit.json")
# The two artifacts a stamping test is actually read out of. tags.json is flat
# and sorted so two runs diff cleanly, and bodies/ holds the request payloads
# whole, which is where the metadata TikTok kept becomes visible again.
TAGS_PATH = _out("tags.json")
BODY_DIR = _out("bodies")
# Last line of defence. The script already caps what it records and batches what
# it sends, but a bug on either side must never be able to grow this process
# without bound. Exceeding it truncates the report rather than the machine.
MAX_ITEMS = 10000

def _flag(name):
    return os.environ.get(name, "") not in ("", "0", "false", "no")


# The hot hooks (raw syscalls, TLS payload) are opt-in via TIKTOK_AUDIT_FULL.
# What changed: they are no longer switched on at load. They are registered on
# the phone and ATTACHED LATER, one group at a time, for a fraction of a second
# each, long after the app has finished launching.
#
# The reason is in the iOS crash reports. TikTok was not wedging the USB link,
# it was being killed by SpringBoard's launch watchdog for missing the 10.00
# second wall-clock allowance to bring a scene up, while using 5-26% CPU. The
# app was blocked on Frida's single script thread, not busy. Any hook that is
# live during a watchdog window costs wall-clock time the app does not have.
_FULL = _flag("TIKTOK_AUDIT_FULL")
# Touch provenance (finger vs synthetic, scroll velocity, live motion) sits on the
# per-frame input path. It is its OWN opt-in, separate from -Full, so it can be
# captured without also enabling the raw syscall hooks. Enabled with -Touch.
TOUCH_ON = _flag("TIKTOK_AUDIT_TOUCH")
# stat / lstat / access / statfs are the highest-volume, lowest-value hooks in
# the set, so -Full no longer includes them. -Deep adds them back.
DEEP_ON = _flag("TIKTOK_AUDIT_DEEP")
# Attach to an already-running TikTok instead of spawning it. This removes the
# scene-create watchdog from the picture entirely, at the cost of the launch
# sequence, which is where most of the identifier reads happen.
ATTACH_ON = _flag("TIKTOK_AUDIT_ATTACH")
# One SSL_write hook for the publish body. Not -Full: that carousel is what
# killed TikTok on Post. Armed once and left up. Use with -Attach on compose.
PUBLISH_ON = _flag("TIKTOK_AUDIT_PUBLISH")
# The whole window spent on the network group, nothing else armed. -Full samples
# it twice for under a second each, which proves a mechanism is in use and can
# never enumerate what it touched. This is the mode for the address list.
NET_ON = _flag("TIKTOK_AUDIT_NET")
# The capability sweep: call, from inside TikTok's own process, the things it
# could have asked for and did not. Answers "what can they get", where the rest
# of the run answers "what did they take". Off unless asked for.
REACH_ON = _flag("TIKTOK_AUDIT_REACH")
# The one sweep probe that puts a packet on the wire, so it is its own switch.
WAN_ON = _flag("TIKTOK_AUDIT_WAN")
# After the launch watchdog and after the first probe pass, so a sweep can never
# be blamed for a scene-deadline kill.
REACH_AT_S = 13.0
# The direct-socket probe blocks the script thread for up to two seconds, so it
# gets its own tick, well clear of the rest of the sweep.
REACH_WAN_AT_S = 17.0

# 11s, and the number is not arbitrary: scene-create's allowance is 10.00 seconds
# measured from launch. Arming strictly after it means a probe can never
# contribute to a scene-create kill, whatever else is going on. The scene-update
# watchdog is also 10s but runs per update cycle, and what protects against that
# one is each group being live for well under a second.
#
# The other side of the constraint, measured on this phone with an uninstrumented
# launch: TikTok's network activity is heavily bursty and almost all of it lands
# between 5s and 17s (one 2s bucket held 1504 SSL_read and 2802 ioctl calls; past
# 17s idle buckets are flat zero unless someone is scrolling). So the first pass
# has to start the moment the watchdog floor lifts, and the passes have to be
# tight, or an 800ms sample lands in dead air and reports nothing.
PROBE_SETTLE_S = 11.0   # after resume, before the first group is armed
PROBE_GAP_S = 0.8       # idle between groups, so the app's run loop catches up
PROBE_ROUND_GAP_S = 1.5     # idle between complete passes over the plan
PROBE_MAX_ROUNDS = 12

PROBE_PLAN = []
if PUBLISH_ON:
    _pub_settle = 2.0 if ATTACH_ON else PROBE_SETTLE_S
    _pub_ms = max(8000, int((DURATION - _pub_settle - 1.0) * 1000))
    PROBE_PLAN += [("publish", _pub_ms)]
elif NET_ON:
    # Sampling answers "does it do this at all". It cannot answer "every address
    # it touched", because two sub-second passes over connect() see two random
    # slices and miss everything between them. This mode gives up the tls and
    # sys carousel and spends the whole window on the network group instead.
    _net_settle = 2.0 if ATTACH_ON else PROBE_SETTLE_S
    _net_ms = max(8000, int((DURATION - _net_settle - 1.0) * 1000))
    PROBE_PLAN += [("net", _net_ms)]
elif _FULL:
    PROBE_PLAN += [("net", 800), ("tls", 600), ("sys", 800)]
if not (PUBLISH_ON or NET_ON):
    if DEEP_ON:
        PROBE_PLAN += [("fs", 700)]
    if TOUCH_ON:
        PROBE_PLAN += [("touch", 700)]


def probe_min_duration(plan, settle=PROBE_SETTLE_S, gap=PROBE_GAP_S):
    """Shortest window that fits one complete pass."""
    t = settle
    for _group, win in plan:
        t += win / 1000.0 + 0.35 + gap
    return t


def probe_schedule(plan, duration, settle=PROBE_SETTLE_S, gap=PROBE_GAP_S,
                   round_gap=PROBE_ROUND_GAP_S, max_rounds=PROBE_MAX_ROUNDS):
    """Offsets from resume: when to arm each group and when to tear it down.

    The plan repeats for as long as the window allows. A single pass is a lottery:
    a sub-second sample of connect() only sees anything if the app happens to be
    opening a socket in that exact sub-second, and by moving off the launch path
    we deliberately gave up the busiest moment in the process's life. Repeating
    cheaply buys back the coverage, because each pass re-attaches from scratch
    with a fresh sample count and a fresh deadline.

    The teardown is slack past the phone-side deadline on purpose. The inline
    cutoffs are what actually end a sample; this is only tidy-up, and it must
    never be the thing the safety depends on, because it travels over USB.
    """
    # Two modes arm a single group for one long window instead of sampling: the
    # publish catch and the deep network sweep. A carousel is the wrong shape for
    # both, because what they are waiting for happens when it happens.
    if plan and (PUBLISH_ON or NET_ON) and plan[0][0] in ("publish", "net"):
        t = 2.0 if ATTACH_ON else settle
        group, win = plan[0]
        down = min(duration - 0.4, t + win / 1000.0 + 0.35)
        if down <= t:
            return []
        return [(t, down, group, win)]
    out, t, rounds = [], settle, 0
    if not plan:
        return out
    while rounds < max_rounds:
        for group, win in plan:
            down = t + win / 1000.0 + 0.35
            if down > duration - 0.4:
                return out
            out.append((t, down, group, win))
            t = down + gap
        t += round_gap
        rounds += 1
    return out
# The live per-event stream is back on by default. Muting it left the first ten
# seconds looking like a hung loading bar, when in fact that window is where the
# identifier reads land and is the most interesting part of the run. -Quiet mutes
# it again. Either way the full stream is always written to session.log.
LIVE = not _flag("TIKTOK_AUDIT_QUIET")
# Separate and still off by default: the per-group probe arm/disarm log, which is
# diagnostic detail about the rig rather than about TikTok. -Stream turns it on.
VERBOSE = _flag("TIKTOK_AUDIT_VERBOSE")

# If the phone-side script goes silent this long, the instrumentation has wedged
# the USB link. The watchdog thread hard-exits so the stall cannot drag on. The
# phone flushes every 400ms even when idle, so real silence means trouble.
STUCK_S = 6.0

# Fit the terminal, but stay inside a range where the columns still line up.
# A 36 character UUID needs roughly 90 before it fits on one line.
W = max(76, min(shutil.get_terminal_size((96, 24)).columns - 2, 100))

LIVE_KEY_COL = 26  # live stream key column


# --------------------------------------------------------------------------
# terminal
# --------------------------------------------------------------------------

def _enable_ansi():
    """Turn on VT processing so ANSI colours work in conhost as well."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        k.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return True
    except Exception:
        return False


def _enable_utf8():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        return True
    except Exception:
        return False


TTY = sys.stdout.isatty()
UNI = _enable_utf8()
COLOR = TTY and _enable_ansi() and not os.environ.get("NO_COLOR")

if UNI:
    RULE, THICK, BAR_ON, BAR_OFF, ELL, MARK = "─", "═", "█", "░", "…", "▸"
else:
    RULE, THICK, BAR_ON, BAR_OFF, ELL, MARK = "-", "=", "#", ".", "...", ">"


def c(code, text):
    return "\x1b[%sm%s\x1b[0m" % (code, text) if COLOR else text


DIM, BOLD = "2", "1"
CAT_COLOR = {
    "IDENTITY":    "1;33",
    "LOCATION":    "1;31",
    "KEYCHAIN":    "1;35",
    "ANTI-TAMPER": "1;31",
    "NETWORK":     "1;34",
    "REQUEST":     "1;32",
    "HARDWARE":    "36",
    "MEDIA":       "1;36",
    "PROVENANCE":  "1;35",
}


def clip(s, n):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - len(ELL)] + ELL


class Console:
    """Prints to the terminal in colour and mirrors plain text to the log."""

    def __init__(self, path):
        self.lock = threading.Lock()
        # utf-8-sig, not utf-8: PowerShell 5.1's Get-Content defaults to the ANSI
        # code page and mangles a BOM-less file. The BOM makes it read correctly
        # in Get-Content, Notepad and editors alike.
        self.log = open(path, "w", encoding="utf-8-sig")
        self.footer = ""

    def _clear_footer(self):
        if self.footer and TTY:
            sys.stdout.write("\r\x1b[2K")

    def _draw_footer(self):
        if self.footer and TTY:
            sys.stdout.write("\r\x1b[2K" + self.footer)

    def line(self, coloured="", plain=None):
        with self.lock:
            self._clear_footer()
            sys.stdout.write(coloured + "\n")
            self._draw_footer()
            sys.stdout.flush()
            self.log.write((coloured if plain is None else plain) + "\n")

    def log_only(self, plain):
        """Write to the transcript but not the terminal, for the live stream when
        it is muted by default."""
        with self.lock:
            self.log.write(plain + "\n")

    def set_footer(self, text):
        if not TTY:
            return
        with self.lock:
            self.footer = text
            self._draw_footer()
            sys.stdout.flush()

    def drop_footer(self):
        with self.lock:
            self._clear_footer()
            self.footer = ""
            sys.stdout.flush()

    def close(self):
        self.log.close()


# --------------------------------------------------------------------------
# what the things TikTok reads actually mean
# --------------------------------------------------------------------------

FLAG, WATCH, INFO = "flag", "watch", "info"

SYSCTL = {
    "hw.machine":            ("hardware model code", WATCH),
    "hw.model":              ("logic board identifier", WATCH),
    "hw.product":            ("product identifier", WATCH),
    "hw.target":             ("internal target name", WATCH),
    "hw.memsize":            ("installed RAM", WATCH),
    "hw.ncpu":               ("CPU core count", WATCH),
    "hw.logicalcpu":         ("logical CPU count", WATCH),
    "hw.logicalcpu_max":     ("max logical CPUs", WATCH),
    "hw.physicalcpu":        ("physical CPU count", WATCH),
    "hw.physicalcpu_max":    ("max physical CPUs", WATCH),
    "hw.cputype":            ("CPU type", WATCH),
    "hw.cpusubtype":         ("CPU subtype", WATCH),
    "hw.cpufrequency":       ("CPU frequency", WATCH),
    "hw.l1dcachesize":       ("L1 cache size", WATCH),
    "hw.l2cachesize":        ("L2 cache size", WATCH),
    "hw.l3cachesize":        ("L3 cache size", WATCH),
    "hw.pagesize":           ("memory page size", INFO),
    "hw.byteorder":          ("byte order", INFO),
    "kern.osversion":        ("OS build number", WATCH),
    "kern.osproductversion": ("iOS version", INFO),
    "kern.ostype":           ("OS type", INFO),
    "kern.osrelease":        ("kernel release", WATCH),
    "kern.version":          ("full kernel version string", WATCH),
    "kern.hostname":         ("device hostname", FLAG),
    "kern.maxvnodes":        ("kernel vnode limit", INFO),
    "kern.maxproc":          ("kernel process limit", INFO),
    "kern.boottime":         ("time the phone last booted", FLAG),
    "kern.bootsessionuuid":  ("per-boot identifier", FLAG),
    "kern.secure_kernel":    ("kernel lockdown state", FLAG),
    "kern.hv_vmm_present":   ("hypervisor present", FLAG),
    "kern.bootargs":         ("kernel boot arguments", FLAG),
    "uname":                 ("kernel release and architecture", WATCH),
}

ANTI_TAMPER = {
    "kern.secure_kernel", "kern.hv_vmm_present", "kern.bootargs",
    "security.mac.amfi.allow_any_signature",
}

IDENT = {
    "identifierForVendor": ("vendor device ID (IDFV)", FLAG),
    "name":                ("device name", FLAG),
    "systemVersion":       ("iOS version", INFO),
    "model":               ("device class", INFO),
    "localizedModel":      ("device class, localised", INFO),
}

# host suffix -> (owner, what it is, tier)
HOSTS = [
    ("appsflyersdk.com",     "AppsFlyer",   "third-party attribution SDK", FLAG),
    ("appsflyer.com",        "AppsFlyer",   "third-party attribution SDK", FLAG),
    ("adjust.com",           "Adjust",      "third-party attribution SDK", FLAG),
    ("branch.io",            "Branch",      "third-party attribution SDK", FLAG),
    ("snapkit.com",          "Snap",        "Snap Kit SDK", FLAG),
    ("facebook.com",         "Meta",        "Facebook SDK", FLAG),
    ("facebook.net",         "Meta",        "Facebook SDK", FLAG),
    ("doubleclick.net",      "Google",      "ad exchange", FLAG),
    ("googleadservices.com", "Google",      "ad services", FLAG),
    ("google-analytics.com", "Google",      "analytics", FLAG),
    ("app-measurement.com",  "Google",      "Firebase analytics", FLAG),
    ("crashlytics.com",      "Google",      "crash reporting", WATCH),
    ("sentry.io",            "Sentry",      "crash reporting", WATCH),
    ("pangle.io",            "ByteDance",   "in-house ad network", WATCH),
    ("pangleglobal.com",     "ByteDance",   "in-house ad network", WATCH),
    ("tiktokv.com",          "TikTok",      "first-party API", INFO),
    ("tiktokv.eu",           "TikTok",      "first-party API, EU region", INFO),
    ("tiktokv.us",           "TikTok",      "first-party API", INFO),
    ("tiktokcdn-eu.com",     "TikTok",      "first-party CDN, EU region", INFO),
    ("tiktokcdn.com",        "TikTok",      "first-party CDN", INFO),
    ("tiktokcdn-us.com",     "TikTok",      "first-party CDN", INFO),
    ("tiktokrow-cdn.com",    "TikTok",      "first-party CDN", INFO),
    ("tiktokw.us",           "TikTok",      "first-party API", INFO),
    ("byteoversea.com",      "ByteDance",   "first-party API", INFO),
    ("ibytedtos.com",        "ByteDance",   "first-party CDN", INFO),
    ("ibyteimg.com",         "ByteDance",   "first-party CDN", INFO),
    ("byteimg.com",          "ByteDance",   "first-party CDN", INFO),
    ("bytedance.com",        "ByteDance",   "first-party", INFO),
    ("bytedanceapi.com",     "ByteDance",   "first-party API", INFO),
    ("snssdk.com",           "ByteDance",   "first-party API", INFO),
    ("isnssdk.com",          "ByteDance",   "first-party API", INFO),
    ("amemv.com",            "ByteDance",   "first-party API", INFO),
    ("musical.ly",           "TikTok",      "legacy first-party", INFO),
    # Not Apple, despite the name. WHOIS registrant is Google LLC, the addresses
    # sit in AS15169, and it speaks the same POST /a protobuf as the
    # app-measurement.com entry above: it is GA4 for Firebase's current
    # collection endpoint. The -att variant is the path used when App Tracking
    # Transparency was granted, which is why seeing one and not the other says
    # something about the ATT answer.
    ("app-analytics-services.com",     "Google", "Firebase analytics", FLAG),
    ("app-analytics-services-att.com", "Google", "Firebase analytics, ATT path", FLAG),
    ("firebaseinstallations.googleapis.com", "Google", "Firebase installation ID", FLAG),
    ("googleapis.com",       "Google",      "platform service", WATCH),
    # ByteDance's own resolver and steering layer. A connection here is the app
    # deciding where to connect next, outside the system resolver entirely.
    ("bdurl.net",            "ByteDance",   "HTTPDNS, its own resolver", FLAG),
    ("ttdns2.com",           "ByteDance",   "resolver wrapper domain", FLAG),
    ("ttlivecdn.com",        "ByteDance",   "live streaming CDN", INFO),
    ("pstatp.com",           "ByteDance",   "legacy first-party CDN", INFO),
    ("ipstatp.com",          "ByteDance",   "legacy first-party CDN", INFO),
    ("apple.com",            "Apple",       "platform service", INFO),
    ("icloud.com",           "Apple",       "platform service", INFO),
]


# ---------------------------------------------------------------------------
# network exposure: what the interface scans actually revealed
# ---------------------------------------------------------------------------

# longest prefix wins, so en0 is matched before en
IFACE_ROLES = [
    ("pdp_ip", "cellular"),
    ("bridge", "hotspot bridge"),
    ("ipsec",  "IPsec tunnel"),
    ("utun",   "tunnel"),
    ("awdl",   "AirDrop / AWDL"),
    ("anpi",   "internal"),
    ("ap1",    "personal hotspot"),
    ("llw",    "low latency WLAN"),
    ("ppp",    "PPP tunnel"),
    ("tap",    "tunnel"),
    ("tun",    "tunnel"),
    ("XHC",    "USB"),
    ("en0",    "Wi-Fi"),
    ("en",     "Wi-Fi / Ethernet"),
    ("lo",     "loopback"),
]

TUNNEL_ROLES = {"tunnel", "IPsec tunnel", "PPP tunnel"}
CGNAT = ipaddress.ip_network("100.64.0.0/10")
# 198.18.0.0/15 is reserved for benchmarking and is never used for real
# addressing, which is exactly why on-device proxy clients (Shadowrocket,
# Surge, Clash and friends) self-assign it to their tunnel. Seeing it says the
# tunnel endpoint is local. It says nothing about where traffic finally exits.
BENCH = ipaddress.ip_network("198.18.0.0/15")
ULA = ipaddress.ip_network("fc00::/7")


def iface_role(name):
    for prefix, role in sorted(IFACE_ROLES, key=lambda x: -len(x[0])):
        if name.startswith(prefix):
            return role
    return "interface"


def addr_kind(addr):
    """Classify an address. Returns (label, tier, routable)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "unparsed", INFO, False
    if ip.is_loopback:
        return "loopback", INFO, False
    if ip.is_link_local:
        return "link-local", INFO, False
    if ip.version == 4 and ip in CGNAT:
        return "carrier NAT", WATCH, True
    if ip.version == 4 and ip in BENCH:
        return "benchmark range", INFO, True
    if ip.version == 6 and ip in ULA:
        return "unique local", INFO, True
    if ip.is_private:
        return "private", INFO, True
    return "PUBLIC", FLAG, True


def is_ip_literal(s):
    """getaddrinfo is often handed an address string rather than a name. That is
    parsing, not a lookup, and it must not be presented as one."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# connecting straight to one of these is a DNS query going out in the clear
RESOLVERS = {
    "8.8.8.8": "Google public DNS", "8.8.4.4": "Google public DNS",
    "1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS", "208.67.222.222": "OpenDNS",
}


def norm_addr(addr):
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        return addr


def is_app_tunnel(addrs):
    """A tunnel addressed out of the benchmark range was set up by an app on
    this phone rather than handed out by a remote VPN server."""
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.version == 4 and ip in BENCH:
            return True
    return False


def mask_to_prefix(mask):
    """255.255.255.0 -> /24. Nobody reads a netmask in dotted quad on sight."""
    if not mask:
        return None
    m = str(mask).replace("netmask ", "").strip()
    try:
        ip = ipaddress.ip_address(m.split("%")[0])
    except ValueError:
        return m
    bits = bin(int(ip)).count("1")
    return "/%d" % bits


def mac_from_eui64(addr):
    """A link-local address is usually dismissed as identifying nothing. That is
    true of the ones iOS generates opaquely per network, and false of the ones
    built the old way: those wrap the interface's own MAC around a fixed ff:fe,
    and a MAC does not change when you join a different network. Returns the
    MAC if the address was derived from one, else None."""
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return None
    if ip.version != 6:
        return None
    b = ip.packed[8:]
    if b[3] != 0xFF or b[4] != 0xFE:
        return None                      # opaque (RFC 7217) or random, no MAC
    raw = bytes([b[0] ^ 0x02, b[1], b[2], b[5], b[6], b[7]])
    return ":".join("%02x" % x for x in raw)


def masked_mac(mac):
    """iOS hands every app 02:00:00:00:00:00 instead of the real hardware
    address. Seeing that is the OS refusing, not the app failing to ask."""
    return mac in ("02:00:00:00:00:00", "00:00:00:00:00:00")


def net_picture(items):
    """Everything the interface scans revealed, sorted into the questions a
    person actually asks: am I on a VPN, which addresses can it see, is my real
    one leaking."""
    ifaces = [r for r in items if r.get("src") == "INTERFACE"]
    pic = {"tunnels": [], "lan": [], "carrier": [], "public": [], "hotspot": [],
           "scans": 0, "proxy": 0, "n_ifaces": len(ifaces),
           "egress": [], "nwpath": [], "ifenum": 0,
           "resolvers": [], "gateways": [], "neighbours": [], "route_reads": 0,
           "iflist_reads": 0,
           "hw": [], "derived": [], "masks": {}, "peers": [],
           "wifi": {}, "proxy_answers": [], "public_echo": [],
           "reach": {}, "blocked": {}, "wan": [], "hw_sweep": {},
           "sweep_addr": {}, "nbr": {}, "paths": []}
    for r in items:
        if r["key"] == "getifaddrs":
            pic["scans"] = r["count"]
        elif r.get("src") == "PROXY":
            # the question and the answer arrive as the same KIND; only the
            # question is a count, the answers are facts
            if r["key"] in ("proxy config", "VPN status"):
                pic["proxy"] += r["count"]
            else:
                for v in r["values"]:
                    pic["proxy_answers"].append((r["key"], v))
        elif r.get("src") == "EGRESS":
            # a socket bound to loopback never left the phone
            if addr_kind(r["key"])[2]:
                pic["egress"].append(norm_addr(r["key"]))
        elif r.get("src") == "NWPATH":
            answer = r["values"].most_common(1)[0][0] if r["values"] else "?"
            pic["nwpath"].append((r["key"], answer, r["count"]))
        elif r.get("src") == "IFENUM":
            pic["ifenum"] += r["count"]
        elif r.get("src") == "RESOLVER":
            if r["key"] == "DNS server":
                for v in r["values"]:
                    pic["resolvers"].append(norm_addr(v))
        elif r.get("src") == "ROUTE":
            # one KIND, three questions: the router, the route table, and a
            # third route to the interface list that neither getifaddrs nor
            # ioctl covers
            if r["key"] == "default gateway":
                for v in r["values"]:
                    pic["gateways"].append(norm_addr(v))
            elif "interface list" in r["key"]:
                pic["iflist_reads"] += r["count"]
            else:
                pic["route_reads"] += r["count"]
        elif r.get("src") == "NEIGHBOUR":
            for v in r["values"]:
                pic["neighbours"].append((norm_addr(r["key"]), v))
        elif r.get("src") == "IFACE_HW":
            for v in r["values"]:
                pic["hw"].append((r["key"], v))
        elif r.get("src") == "IFACE_MASK":
            for v in r["values"]:
                pic["masks"][r["key"]] = v
        elif r.get("src") == "PUBLIC_IP":
            pic["public_echo"].append(norm_addr(r["key"]))
        elif r.get("src") == "INTERFACE_ID":
            for v in r["values"]:
                pic["wifi"].setdefault(r["key"], []).append(v)
        # the capability sweep: what it could have had, and what iOS refused
        elif r.get("src") == "REACH":
            for v in r["values"]:
                pic["reach"].setdefault(r["key"], []).append(v)
        elif r.get("src") == "REACH_NO":
            for v in r["values"]:
                pic["blocked"][r["key"]] = v
        elif r.get("src") == "REACH_PATH":
            for v in r["values"]:
                pic["paths"].append((r["key"], v))
        elif r.get("src") == "REACH_WAN":
            for v in r["values"]:
                pic["wan"].append((norm_addr(r["key"]), v))
        elif r.get("src") == "REACH_IFACE":
            for v in r["values"]:
                pic["hw_sweep"][r["key"]] = v
        elif r.get("src") == "REACH_IFADDR":
            for v in r["values"]:
                pic["sweep_addr"].setdefault(r["key"], v)
        elif r.get("src") == "REACH_NEIGHBOUR":
            pic["nbr"][norm_addr(r["key"])] = (r["values"].most_common(1)[0][0]
                                               if r["values"] else "")
    for r in ifaces:
        addrs = sorted(r["values"])
        role = iface_role(r["key"])
        routable = [a for a in addrs if addr_kind(a)[2]]
        # done before the tunnel branch below returns, because a tunnel's
        # link-local carries a MAC as readily as any other interface's
        for a in addrs:
            mac = mac_from_eui64(a)
            if mac:
                pic["derived"].append((r["key"], norm_addr(a), mac))
        if role in TUNNEL_ROLES and routable:
            pic["tunnels"].append((r["key"], [norm_addr(a) for a in routable],
                                   is_app_tunnel(routable)))
            continue
        for a in addrs:
            kind = addr_kind(a)[0]
            if kind == "PUBLIC":
                pic["public"].append((r["key"], norm_addr(a)))
            elif kind == "carrier NAT":
                pic["carrier"].append((r["key"], norm_addr(a)))
            elif kind in ("private", "unique local"):
                pic["lan"].append((r["key"], norm_addr(a)))
            if role in ("hotspot bridge", "personal hotspot") and kind != "link-local":
                pic["hotspot"].append(r["key"])
    return pic


def net_summary_rows(pic):
    """The at-a-glance answer sheet, as (question, answer, note) triples."""
    out = []
    if pic["tunnels"]:
        name, addrs, app_based = pic["tunnels"][0]
        out.append(("On a VPN", "yes, and it can tell",
                    "%s, %s" % (name, "set up by an app on this phone"
                                if app_based else "system tunnel")))
        out.append(("VPN address it sees", addrs[0],
                    ("plus " + ", ".join(addrs[1:])) if len(addrs) > 1 else ""))
        if app_based:
            out.append(("", "", "benchmark range, so the tunnel endpoint is local. "
                                "Where traffic exits is not visible from here."))
    else:
        out.append(("On a VPN", "no tunnel carrying traffic",
                    "it saw your connection directly"))

    if pic["lan"]:
        nm, a = pic["lan"][0]
        out.append(("Your address it sees", a,
                    "%s, your own network%s" % (nm, ", unchanged by the VPN"
                                                if pic["tunnels"] else "")))
    if pic["carrier"]:
        nm, a = pic["carrier"][0]
        out.append(("Mobile address it sees", a, "%s, carrier NAT, shared with others" % nm))

    if pic["public"]:
        nm, a = pic["public"][0]
        out.append(("Your real public address", a,
                    "readable straight off %s, no server needed" % nm))
    elif pic["public_echo"]:
        # Nothing on the device holds it, so the app was told. This is the one
        # answer here that comes from the far end rather than from the phone.
        out.append(("Your real public address", sorted(set(pic["public_echo"]))[0],
                    "not on any interface: its own resolver echoed it back, "
                    "so the app holds it anyway"))
    else:
        out.append(("Your real public address", "not exposed",
                    "nothing globally routable on the device"
                    + (", no leak past the tunnel" if pic["tunnels"] else "")))

    # The router. Not derivable from any address the phone holds, and the one
    # fact here that is the same for every device behind it.
    if pic["gateways"]:
        gws = sorted(set(pic["gateways"]))
        out.append(("The router it found", gws[0],
                    "read out of the routing table, which needs no permission"
                    + (", plus " + ", ".join(gws[1:]) if len(gws) > 1 else "")))
    elif pic["route_reads"]:
        out.append(("Routing table read", "%d times" % pic["route_reads"],
                    "no default route in what it asked for"))

    if pic["resolvers"]:
        rs = sorted(set(pic["resolvers"]))
        out.append(("DNS servers it read", rs[0],
                    "these name your ISP even when a VPN carries the traffic"
                    + (", plus " + ", ".join(rs[1:]) if len(rs) > 1 else "")))

    if pic["neighbours"]:
        out.append(("Other devices on the LAN", "%d seen" % len(set(pic["neighbours"])),
                    "read from the neighbour cache, no local network prompt"))

    # A MAC survives changing networks, which is the whole difference between it
    # and every address above.
    real = [d for d in pic["derived"] if not masked_mac(d[2])]
    if real:
        by_mac = {}
        for name, _addr, mac in real:
            by_mac.setdefault(mac, set()).add(name)
        for mac in sorted(by_mac):
            out.append(("MAC address leaked", mac,
                        "recoverable from the link-local address on %s"
                        % ", ".join(sorted(by_mac[mac]))))

    if pic["wifi"]:
        name = pic["wifi"].get("Wi-Fi network name")
        bssid = pic["wifi"].get("Wi-Fi router address")
        if name:
            out.append(("Wi-Fi network name", name[0], "the SSID you are joined to"))
        if bssid:
            out.append(("Wi-Fi router address", bssid[0],
                        "the BSSID, which public databases map to a street"))
        answer = pic["wifi"].get("Wi-Fi network identity answer")
        if answer and not (name or bssid):
            out.append(("Asked for the Wi-Fi name", "refused", answer[0]))

    if pic["proxy_answers"]:
        for k, v in pic["proxy_answers"][:4]:
            out.append((clip(k, 24), clip(v, 26), "what iOS answered"))

    if pic["hotspot"]:
        out.append(("Sharing this connection", "yes",
                    "%s is up, so tethering is visible" % pic["hotspot"][0]))

    # measured rather than inferred: the address the kernel actually picked
    if pic["egress"]:
        tunnel_addrs = {a for _n, addrs, _b in pic["tunnels"] for a in addrs}
        through = [a for a in pic["egress"] if a in tunnel_addrs]
        out.append(("Traffic left from", ", ".join(pic["egress"][:2]),
                    "measured, not inferred"
                    + (". this is the tunnel address, so the VPN is carrying it"
                       if through else
                       ". not the tunnel address" if pic["tunnels"] else "")))

    out.append(("Interface list read", "%d times" % pic["scans"],
                "each read shows the tunnel" if pic["tunnels"]
                else "each read shows every address at once"))
    if pic["ifenum"]:
        out.append(("Listed them a second way", "%d times" % pic["ifenum"],
                    "via ioctl, which is a quieter route to the same thing"))
    if pic["iflist_reads"]:
        out.append(("Listed them a %s way" % ("third" if pic["ifenum"] else "second"),
                    "%d times" % pic["iflist_reads"],
                    "via sysctl over the route socket, which needs no interface name"))
    if pic["proxy"]:
        out.append(("Proxy config asked", "%d times" % pic["proxy"],
                    "a deliberate question to iOS, not a side effect"))
    for name, answer, count in pic["nwpath"]:
        out.append(("Asked if path uses", clip(name, 26),
                    "answer was %s, %d time%s" % (answer, count,
                                                  "" if count == 1 else "s")))
    return out


def iface_verdict(name, addrs):
    """An interface is only a live VPN if it carries a routable address.

    iOS keeps utun0..2 up for system services such as Handoff and AirPlay, and
    those only ever hold a link-local address. Calling every utun a VPN would be
    a false positive, so the address is what decides it."""
    role = iface_role(name)
    routable = [a for a in addrs if addr_kind(a)[2]]
    if role in TUNNEL_ROLES:
        if routable:
            return ("VPN tunnel, app-based" if is_app_tunnel(routable)
                    else "VPN tunnel, live"), FLAG
        return "system tunnel, idle", INFO
    if any(addr_kind(a)[0] == "PUBLIC" for a in addrs):
        return role, FLAG
    return role, WATCH if routable else INFO


# substrings that give away an embedded SDK, seen in keychain service names
SDK_MARKERS = {
    "appsflyer":  "AppsFlyer (attribution)",
    "firebase":   "Firebase (Google)",
    "linecorp":   "LINE",
    "linesdk":    "LINE",
    "snapchat":   "Snap",
    "snapkit":    "Snap",
    "facebook":   "Meta",
    "twitter":    "Twitter/X",
    "kakao":      "Kakao",
    "adjust":     "Adjust (attribution)",
    "branch":     "Branch (attribution)",
}


# What a first-party endpoint is FOR, inferred from ByteDance's naming, which is
# consistent across regions. Inference, not documentation, and labelled as such.
ENDPOINT_ROLE = [
    ("attribution", "install attribution"),
    ("-ssp",        "ad supply-side platform"),
    ("pangle",      "ad network"),
    ("rtlog",       "real-time telemetry"),
    ("mssdk",       "device security SDK"),
    ("webcast",     "live streaming"),
    ("frontier",    "push channel"),
    ("search",      "search"),
    ("libra",       "experiment assignment"),
    ("gecko",       "resource delivery"),
    ("bsync",       "background sync"),
    ("aggr",        "event aggregation"),
    ("oec",         "e-commerce"),
    ("tnc",         "network configuration"),
    ("vcs",         "config service"),
    ("cp-rp",       "content platform"),
    ("log",         "telemetry"),
    ("sign",        "signed media"),
    ("api",         "main API"),
]


def endpoint_role(host):
    h = host.lower()
    for marker, role in ENDPOINT_ROLE:
        if marker in h:
            return role
    return None


# URL scheme -> human app name. iOS apps register a scheme, often cryptic, so this
# turns the raw scheme TikTok probes into the app a person recognises. Exact
# matches first, then substring rules for families, then a cleaned fallback.
SCHEME_APP = {
    "spotify": "Spotify", "deezer": "Deezer", "youtubemusic": "YouTube Music",
    "amznmp3": "Amazon Music", "anghami": "Anghami", "soundcloud": "SoundCloud",
    "tidal": "TIDAL", "pandora": "Pandora", "boomplay": "Boomplay", "joox": "JOOX",
    "resso": "Resso", "audiomack": "Audiomack", "gaana": "Gaana",
    "jiosaavn": "JioSaavn", "wynk": "Wynk Music", "napster": "Napster",
    "instagram": "Instagram", "whatsapp": "WhatsApp", "snapchat": "Snapchat",
    "pinterest": "Pinterest", "tumblr": "Tumblr", "reddit": "Reddit",
    "discord": "Discord", "telegram": "Telegram", "tg": "Telegram",
    "line": "LINE", "wechat": "WeChat", "weixin": "WeChat", "threads": "Threads",
    "youtube": "YouTube", "gmail": "Gmail", "linkedin": "LinkedIn",
    "twitch": "Twitch", "netflix": "Netflix", "spotifyartists": "Spotify Artists",
    "capcut": "CapCut", "capcutus": "CapCut", "lemon8": "Lemon8",
    "shopee": "Shopee", "lazada": "Lazada", "paypal": "PayPal", "venmo": "Venmo",
    "uber": "Uber", "grab": "Grab", "gojek": "Gojek", "shazam": "Shazam",
}

# scheme families matched by prefix/substring
SCHEME_FAMILY = [
    ("fbapi", "Facebook"), ("fbauth", "Facebook"), ("fb-messenger", "Messenger"),
    ("fbmessenger", "Messenger"), ("facebook", "Facebook"), ("fb", "Facebook"),
    ("twitterauth", "Twitter / X"), ("twitter", "Twitter / X"),
    ("lineauth", "LINE"), ("line", "LINE"),
    ("doordash", "DoorDash"), ("mercadopago", "Mercado Pago"),
    ("ascendmoney", "Ascend Money"),
    ("kakao", "KakaoTalk"), ("comgoogle", "Google app"), ("googlephotos", "Google Photos"),
    ("googledrive", "Google Drive"), ("google", "Google app"),
    ("applemusic", "Apple Music"), ("music", "Apple Music"),
    ("vk", "VK"), ("aweme", "Douyin (TikTok CN)"), ("musically", "TikTok"),
    ("tiktok", "TikTok"), ("helo", "Helo"),
]


# schemes that are protocols, not apps: drop them from the app list entirely
NON_APP_SCHEMES = {"http", "https", "itms", "itms-apps", "mailto", "tel", "sms",
                   "file", "ftp"}

# brand token (from a reverse-DNS scheme) -> proper display name
BRAND_NAME = {
    "soundcloud": "SoundCloud", "venmo": "Venmo", "anghami": "Anghami",
    "amazon": "Amazon", "upscrolled": "Upscrolled", "google": "Google app",
    "microsoft": "Microsoft", "linkedin": "LinkedIn", "paypal": "PayPal",
}


def scheme_to_app(scheme):
    s = scheme.lower().rstrip(":/").strip()
    if not s or s in NON_APP_SCHEMES:
        return None
    if s in SCHEME_APP:
        return SCHEME_APP[s]
    if s.startswith("snssdk"):
        digits = "".join(ch for ch in s[6:] if ch.isdigit())
        return "ByteDance app (id %s)" % digits if digits else "ByteDance app"
    if s.startswith("fb") and s[2:].isdigit():
        return "Facebook"
    for marker, name in SCHEME_FAMILY:
        if s.startswith(marker):
            return name
    # reverse-DNS scheme (com.brand.something, ShareMedia-com.brand...): the brand
    # is the token after the tld prefix
    core = s
    if "-" in core and "com." in core:            # e.g. ShareMedia-com.foo.bar
        core = core.split("com.", 1)[1]
        core = "com." + core
    parts = core.split(".")
    if len(parts) >= 2 and parts[0] in ("com", "net", "org", "io", "co", "app"):
        brand = parts[1]
        return BRAND_NAME.get(brand, brand.title())
    # last resort: strip auth/api/sdk noise and title-case what remains
    for junk in ("opensdk", "auth2", "auth", "api", "sdk", "share", "open"):
        if core.endswith(junk) and len(core) > len(junk) + 2:
            core = core[: -len(junk)]
    return core.replace("-", " ").replace(".", " ").strip().title() or scheme


def classify_host(host):
    h = host.lower()
    # Two labels are checked before the suffix table, because what they do
    # matters more than whose domain they sit on. Both are server-configurable,
    # so match the label rather than listing hosts that change without an app
    # update: dig.* is ByteDance's own HTTP resolver, and tnc* is Network
    # Control, the endpoint that pushes the domain and address map the app then
    # steers its next connections by.
    if h.startswith("dig.") or h.startswith("dig-"):
        return "ByteDance", "HTTPDNS, its own resolver", FLAG
    if h.startswith("tnc") and any(m in h for m in ("tiktok", "snssdk", "byted")):
        return "TikTok", "network control, pushes its routing config", FLAG
    for suffix, owner, what, tier in HOSTS:
        if h == suffix or h.endswith("." + suffix):
            return owner, what, tier
    # regional domains multiply faster than any suffix list keeps up with
    if any(m in h for m in ("tiktok", "bytedance", "byted", "byteimg", "musical.ly")):
        return "TikTok", "first-party", INFO
    return "unrecognised", "unclassified endpoint", WATCH


# MobileGestalt properties that are an identity, not a capability. A codec or
# screen-geometry read is the app sizing its encoder. These are the device itself,
# so they get FLAG rather than the WATCH every other gestalt read receives.
# RegionCode and RegionInfo are in here for a reason that is not obvious: they are
# the sales region burned in at manufacture, so unlike locale, language, timezone
# or a proxy exit country, they do not move. A fleet bought in one region and
# presented as another disagrees here permanently.
GESTALT_IDENTITY = {
    "UniqueDeviceID", "UniqueDeviceIDData", "UniqueChipID", "InverseDeviceID",
    "SerialNumber", "MLBSerialNumber", "SysCfg",
    "InternationalMobileEquipmentIdentity", "InternationalMobileEquipmentIdentity2",
    "MobileEquipmentIdentifier", "BasebandSerialNumber", "BasebandChipId",
    "WifiAddress", "WifiAddressData", "BluetoothAddress", "BluetoothAddressData",
    "EthernetMacAddress", "EthernetMacAddressData",
    "DieId", "BoardId", "ChipID",
    "RegionCode", "RegionInfo",
    "DeviceName", "UserAssignedDeviceName",
    "apple-internal-install",
}


def gestalt_name(key):
    """Resolve an obfuscated MobileGestalt key to its property name.

    MGCopyAnswer is usually handed base64(md5("MGCopyAnswer" + name))[:22] rather
    than the name, so the raw stream is full of 22-character tokens that say
    nothing. Resolving host-side rather than in observe.js is deliberate: the
    hooks run on a single script thread against a 10 second launch watchdog, and
    a table lookup per read is cost the phone should never pay.

    Returns the key unchanged when it is already plaintext, and marks a token we
    cannot name so an unresolved key is never mistaken for a real property.
    """
    hit = mobilegestalt_keys.resolve(key)
    if hit:
        return hit
    if re.fullmatch(r"[A-Za-z0-9+/]{22}", key):
        return "unnamed key " + key
    return key


def describe(cat, key):
    """Return (label, tier) for a raw event key."""
    if cat == "FINGERPRINT":
        if key in SYSCTL:
            return SYSCTL[key]
        if key.startswith("hw.optional."):
            return ("CPU instruction set probe", WATCH)
        if key.startswith("hw."):
            return ("hardware attribute", WATCH)
        if key.startswith("kern."):
            return ("kernel attribute", WATCH)
        if key.startswith("net."):
            return ("network stack attribute", WATCH)
        return ("system attribute", WATCH)
    if cat == "IDENTIFIER":
        return IDENT.get(key, ("device attribute", WATCH))
    if cat == "KEYCHAIN":
        return ("keychain lookup", FLAG)
    if cat == "NETWORK":
        return ("network interface enumeration", FLAG)
    if cat == "INTERFACE":
        return (iface_role(key), WATCH)
    if cat == "PROXY":
        return ("explicit VPN / proxy check", FLAG)
    if cat == "EGRESS":
        return ("source address traffic left from", FLAG)
    if cat == "NWPATH":
        return ("connection type check", FLAG)
    if cat == "IFENUM":
        return ("second way of listing interfaces", FLAG)
    if cat == "IFACE_MASK":
        return ("subnet size", INFO)
    if cat == "IFACE_HW":
        return ("hardware address", FLAG)
    if cat == "IFACE_PEER":
        return ("far end of the tunnel", FLAG)
    if cat == "RESOLVER":
        return ("DNS resolver", FLAG)
    if cat == "ROUTE":
        if key == "default gateway":
            return ("the router on this network", FLAG)
        if "interface list" in key:
            return ("third way of listing interfaces", FLAG)
        return ("routing table read", FLAG)
    if cat == "NEIGHBOUR":
        return ("another device on this network", FLAG)
    if cat == "DNS":
        owner, what, tier = classify_host(key)
        return ("%s, %s" % (owner, what), tier)
    if cat == "DNS_FAIL":
        return ("name lookup that failed", WATCH)
    if cat == "DNS_NUMERIC":
        return ("address it already had", FLAG)
    if cat == "SOCKTYPE":
        return ("datagram socket", WATCH)
    if cat == "REACH":
        return ("available to it, unasked", FLAG)
    if cat == "REACH_NO":
        return ("iOS refused this app", INFO)
    if cat == "REACH_IFACE":
        return ("interface, name and hardware address", FLAG)
    if cat == "REACH_IFADDR":
        return ("address on that interface", WATCH)
    if cat == "REACH_NEIGHBOUR":
        return ("another device on this network", FLAG)
    if cat == "REACH_PATH":
        return ("does this path work at all", INFO)
    if cat == "REACH_WAN":
        return ("your public address", FLAG)
    if cat == "PUBLIC_IP":
        return ("your public address, handed to the app", FLAG)
    if cat == "HTTPDNS":
        return ("resolved by ByteDance's own resolver", FLAG)
    if cat == "DNS_CNAME":
        return ("canonical name behind it", INFO)
    if cat == "DNS_REVERSE":
        return ("reverse lookup", INFO)
    if cat == "SNI":
        owner, what, tier = classify_host(key)
        return ("%s, %s" % (owner, what), tier)
    if cat == "NW_ENDPOINT":
        return ("Network.framework endpoint", WATCH)
    if cat == "UDP_PEER":
        return ("datagram peer", WATCH)
    if cat == "PEER":
        return ("connected peer", WATCH)
    if cat == "CONNECT_FAIL":
        return ("socket that never connected", INFO)
    if cat == "CONNECT":
        return ("socket opened", WATCH)
    if cat == "LOCALE":
        return (key, FLAG if key in ("installed keyboards", "preferred languages")
                else WATCH)
    if cat == "SETTINGS":
        return ("system setting read", WATCH)
    if cat == "CARRIER":
        return (key, FLAG)
    if cat == "SCHEME":
        return ("checked whether this app is installed", FLAG)
    if cat == "QUERYABLE":
        return (scheme_to_app(key) or "", INFO)
    if cat == "PASTEBOARD":
        return ("read the clipboard", FLAG)
    if cat == "DISPLAY":
        return (key, WATCH)
    if cat == "TAMPER":
        return ("tamper check", FLAG)
    if cat == "PERMS":
        return (key, WATCH)
    if cat == "SENSOR":
        return (key, FLAG)
    if cat == "INTERFACE_ID":
        return (key, FLAG)
    if cat == "LOCATION":
        return ("location access", FLAG)
    if cat == "REQUEST":
        owner, what, tier = classify_host(key)
        return ("%s, %s" % (owner, what), tier)
    # behavioral & anti-automation layer
    if cat == "A11Y":
        hot = key in ("AssistiveTouch", "VoiceOver", "Switch Control", "Guided Access")
        return (key, FLAG if hot else WATCH)
    if cat == "GESTALT":
        # key arrives already resolved from apply(), so this only has to decide
        # whether the property is an identity or a capability.
        if key.startswith("unnamed key "):
            raw = key[len("unnamed key "):]
            if raw in mobilegestalt_keys.UNRECOVERED_ON_THIS_BUILD:
                # confirmed a real property in this phone's own libMobileGestalt,
                # just one nobody has recovered the name of. Worth a mark: TikTok
                # reaching for a key this obscure is not incidental.
                return ("MobileGestalt: real key on this build, name not "
                        "publicly recovered", FLAG)
            return ("MobileGestalt: unrecognised token, not a key in this "
                    "build's dylib", WATCH)
        return ("MobileGestalt: " + key,
                FLAG if key in GESTALT_IDENTITY else WATCH)
    if cat == "CAPTURE":
        return (key, FLAG)
    if cat == "PERIPHERAL":
        return (key, FLAG)
    if cat == "CONTEXT":
        return (key, WATCH)
    if cat == "TOUCH":
        return (key, WATCH)
    if cat == "SCROLL":
        return (key, WATCH)
    if cat == "HAPTIC":
        return (key, WATCH)
    if cat == "INSTRUMENT":
        return (key, FLAG)
    if cat == "SENSOR_VALUE":
        return (key, WATCH)
    if cat == "MEDIA":
        # opening a picker or an encoder is what a post does. Turning the camera
        # on, or putting bytes on the wire, is the part worth a mark.
        return (key, WATCH if key in MEDIA_ROUTINE else FLAG)
    if cat == "MEDIA_TAG":
        # a tag is evidence, not a verdict. Only the fields that place a person
        # or name a device carry a mark, so a 60 row dump still reads.
        return (key, FLAG if TAG_IS_IDENTIFYING(key) else WATCH)
    if cat == "MEDIA_FILE":
        return (key, WATCH)
    if cat == "MEDIA_META":
        # opening a metadata container is routine, an image decoder does it
        # constantly. Pulling a coordinate, a capture time or a camera out of
        # one is the finding, so only those carry the mark.
        return (key, WATCH if key in MEDIA_META_ROUTINE else FLAG)
    return (key, INFO)


# Tags that either place the person or name the device. Everything else in a
# provenance dump is exposure settings and pixel geometry, which is noise until
# you are comparing two files field by field.
TAG_IDENTIFYING = (
    "GPS", "Latitude", "Longitude", "Altitude", "location", "ISO6709",
    "Make", "Model", "LensMake", "LensModel", "Software", "HostComputer",
    "SerialNumber", "ImageUniqueID", "ContentIdentifier", "content.identifier",
    "camera.identifier", "DateTimeOriginal", "CreationDate", "creationdate",
    "OffsetTime", "mediaSubtypes", "sourceType", "originalFilename",
)


def TAG_IS_IDENTIFYING(key):
    return any(t in key for t in TAG_IDENTIFYING)


# the mechanical steps of a post, as opposed to the reads that ride along with it
MEDIA_ROUTINE = ("system photo picker", "video encode started", "video export started",
                 "hardware video encoder", "audio session set to record",
                 "microphone permission")


# opening the container and reading pixel geometry is what a decoder does on
# every image it draws. Only what identifies you or where you were is marked.
MEDIA_META_ROUTINE = ("image metadata block", "video metadata block",
                      "other metadata fields", "other video metadata fields",
                      "video metadata came back empty")


def is_geotag(key):
    """A coordinate read out of a file rather than asked of the OS."""
    return "geotag" in key or "GPS" in key


# families of near-identical keys that are only meaningful in aggregate. The
# CPU capability probes come in a burst of 15+ and would otherwise drown the
# things that actually matter. Individual members stay in audit.json.
GROUPS = {"hw.optional.": "CPU feature probes"}


def group_for(key):
    for prefix in GROUPS:
        if key.startswith(prefix):
            return prefix
    return None


def display_cat(cat, key):
    if cat == "FINGERPRINT":
        return "ANTI-TAMPER" if key in ANTI_TAMPER else "HARDWARE"
    return {"IDENTIFIER": "IDENTITY",
            "INTERFACE": "EXPOSURE",
            "PROXY": "EXPOSURE",
            "NETWORK": "EXPOSURE",
            "EGRESS": "EXPOSURE",
            "NWPATH": "EXPOSURE",
            "IFENUM": "EXPOSURE",
            "IFACE_MASK": "EXPOSURE",
            "IFACE_HW": "EXPOSURE",
            "IFACE_PEER": "EXPOSURE",
            "RESOLVER": "EXPOSURE",
            "ROUTE": "EXPOSURE",
            "NEIGHBOUR": "EXPOSURE",
            "REQUEST": "DEST",
            "CONNECT": "DEST",
            "CONNECT_FAIL": "DEST",
            "PEER": "DEST",
            "UDP_PEER": "DEST",
            "NW_ENDPOINT": "DEST",
            "SNI": "DEST",
            "DNS": "DEST",
            "DNS_FAIL": "DEST",
            "DNS_NUMERIC": "DEST",
            "SOCKTYPE": "DEST",
            "HTTPDNS": "DEST",
            "PUBLIC_IP": "EXPOSURE",
            "REACH": "EXPOSURE",
            "REACH_NO": "EXPOSURE",
            "REACH_NEIGHBOUR": "EXPOSURE",
            "REACH_IFACE": "EXPOSURE",
            "REACH_IFADDR": "EXPOSURE",
            "REACH_WAN": "EXPOSURE",
            "REACH_PATH": "EXPOSURE",
            "DNS_CNAME": "DEST",
            "DNS_REVERSE": "DEST",
            "LOCALE": "LOCALE",
            "SETTINGS": "LOCALE",
            "CARRIER": "CARRIER",
            "SCHEME": "SCHEME",
            "QUERYABLE": "QUERYABLE",
            "PASTEBOARD": "CLIPBOARD",
            "DISPLAY": "HARDWARE",
            "PERMS": "PERMS",
            "SENSOR": "SENSOR",
            "INTERFACE_ID": "EXPOSURE",
            "HEADER": "DEST",
            "BODY": "DEST",
            "PLAINTEXT": "DEST",
            "RESPONSE": "DEST",
            "TAMPER": "ANTI-TAMPER",
            "INSTRUMENT": "ANTI-TAMPER",
            "A11Y": "ACCESSIBILITY",
            "GESTALT": "GESTALT",
            "CAPTURE": "ENVIRONMENT",
            "PERIPHERAL": "ENVIRONMENT",
            "CONTEXT": "SENSOR",
            "SENSOR_VALUE": "SENSOR",
            "TOUCH": "INTERACTION",
            "SCROLL": "INTERACTION",
            "HAPTIC": "INTERACTION",
            "MEDIA": "MEDIA",
            "MEDIA_META": "MEDIA",
            # the tag inventory is a different KIND of fact from the rest of the
            # report. Everything else records that the app asked a question.
            # These record what the answer was, field by field, which is what a
            # stamping test has to diff between runs.
            "MEDIA_TAG": "PROVENANCE",
            "MEDIA_FILE": "PROVENANCE"}.get(cat, cat)


# the raw integer is meaningless, what it tells the app is not
PROBE_RESULT = {
    ("kern.secure_kernel", "0"): "0, kernel not locked down (the jailbreak is visible)",
    ("kern.secure_kernel", "1"): "1, kernel locked down",
    ("kern.hv_vmm_present", "0"): "0, no hypervisor",
    ("kern.hv_vmm_present", "1"): "1, running under a hypervisor",
}


# iOS 16 deprecated CTCarrier. It now returns these placeholders instead of real
# SIM data, so a value in this set means the app learned nothing from the call.
CARRIER_SENTINELS = {"65535", "65534", "--", "---", "", "0", "unknown"}


def is_carrier_sentinel(value):
    return value is None or str(value).strip() in CARRIER_SENTINELS


def pretty_value(cat, key, value):
    if value is None:
        return ""
    value = str(value)
    if cat == "CARRIER" and is_carrier_sentinel(value):
        return "%s, no data (iOS 16+ retired this API)" % value
    if (key, value) in PROBE_RESULT:
        return PROBE_RESULT[(key, value)]
    if key == "hw.memsize":
        try:
            return "%.1f GB" % (int(value) / 1024 ** 3)
        except Exception:
            return value
    if cat == "EXPOSURE":
        return norm_addr(value)
    if key.endswith("cachesize"):
        try:
            return "%.0f KB" % (int(value) / 1024)
        except Exception:
            return value
    return value


# --------------------------------------------------------------------------
# recorder
# --------------------------------------------------------------------------

class Recorder:
    def __init__(self, console):
        self.console = console
        self.items = {}          # (src, key) -> record
        self.t0 = time.time()
        self.lock = threading.Lock()
        self.groups_seen = set()
        self.truncated = False
        self.dropped = 0
        self.marks = []          # operator boundaries between posts in one run
        self.blob_n = 0
        self.blob_index = []     # [(filename, description, bytes)]
        self.caps = {}           # hook label -> the limit it stopped at

    def write_blob(self, name, b64):
        """Write one captured request body to disk. Names are derived from the
        host and path, numbered, so two calls to the same endpoint do not
        overwrite each other and the order is recoverable from the listing."""
        import base64 as _b64
        os.makedirs(BODY_DIR, exist_ok=True)
        self.blob_n += 1
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:80].strip("_") or "body"
        fn = "%03d-%s.bin" % (self.blob_n, safe)
        try:
            raw = _b64.b64decode(b64)
        except Exception:
            return
        with open(os.path.join(BODY_DIR, fn), "wb") as f:
            f.write(raw)
        self.blob_index.append((fn, name, len(raw)))

    @property
    def total(self):
        """Derived, never accumulated: the script sends absolute counts."""
        return sum(r["count"] for r in self.items.values())

    def apply(self, cat, key, value, count, first_s):
        """Counts arrive as absolute totals from the script, not increments, so
        a dropped or duplicated batch cannot skew the numbers."""
        # Resolve here, before anything keys off it, so the plain name reaches the
        # live stream, the report, the dedup key and audit.json alike. The mapping
        # is one-to-one, so two hashes can never collapse into one row.
        if cat == "GESTALT":
            key = gestalt_name(key)
        dcat = display_cat(cat, key)
        label, tier = describe(cat, key)
        if cat == "INTERFACE" and value:
            # a public address or a tunnel actually carrying traffic is the
            # part worth flagging, and that is decided by the address
            kind, atier, routable = addr_kind(value)
            if atier == FLAG or (routable and iface_role(key) in TUNNEL_ROLES):
                tier = FLAG
        if cat == "CARRIER" and is_carrier_sentinel(value):
            # iOS 16+ deprecated CTCarrier: it hands back 65535 / "--" placeholders,
            # not real data. TikTok learned nothing, so this is not exposure.
            tier = INFO
        now = first_s
        with self.lock:
            # key on the RAW category, not the display one. Several raw
            # categories now share a display section, and a socket to
            # 198.18.0.10 must not merge with a name lookup for the same string.
            k = (cat, key)
            rec = self.items.get(k)
            if rec is None:
                # a hard ceiling here is the last line of defence against a
                # runaway hook eating the host's memory
                if len(self.items) >= MAX_ITEMS:
                    self.truncated = True
                    return
                rec = self.items[k] = {
                    "cat": dcat, "src": cat, "key": key, "label": label,
                    "tier": tier, "count": 0, "first": now, "last": now,
                    "vcounts": {}, "values": Counter(), "announced": False,
                }
            elif tier == FLAG:
                rec["tier"] = FLAG   # a later address can escalate the row
            rec["vcounts"][value or ""] = count
            rec["count"] = sum(rec["vcounts"].values())
            rec["first"] = min(rec["first"], now)
            rec["last"] = max(rec["last"], now)
            rec["values"] = Counter({v: n for v, n in rec["vcounts"].items() if v})
            # sysctl is called twice per read: once with a null buffer just to
            # size the result, then again for the data. Announcing on the first
            # call would print every hardware attribute with no value, so hold
            # the line until a value lands or it is clear none is coming.
            ready = bool(value) or cat != "FINGERPRINT" or rec["count"] >= 2
            # a link-local or loopback address identifies nothing, so it stays
            # out of the live stream and is summarised in the report instead
            if cat == "INTERFACE" and not (value and addr_kind(value)[2]):
                ready = False
            announce = ready and not rec["announced"]
            label_as = None
            if announce:
                rec["announced"] = True
                g = group_for(key)
                if g:
                    # one line for the whole family, not one per member
                    if g in self.groups_seen:
                        announce = False
                    else:
                        self.groups_seen.add(g)
                        label_as = (g + "*", GROUPS[g])
        if announce:
            self._announce(rec, now, value, label_as)

    @staticmethod
    def _muted(rec):
        # interfaces that only ever held link-local addresses stay out of the
        # stream permanently, the report summarises them in one line
        return (rec["src"] == "INTERFACE"
                and not any(addr_kind(a)[2] for a in rec["values"]))

    def flush(self):
        """Announce anything that never met the value threshold."""
        with self.lock:
            pending = [r for r in self.items.values()
                       if not r["announced"] and not self._muted(r)]
            for r in pending:
                r["announced"] = True
        for r in pending:
            top = r["values"].most_common(1)
            self._announce(r, r["first"], top[0][0] if top else None)

    def _announce(self, rec, now, value, label_as=None):
        colour = CAT_COLOR.get(rec["cat"], "")
        if label_as:
            key_text, detail = label_as
        else:
            key_text = rec["key"]
            detail = pretty_value(rec["cat"], rec["key"], value) or rec["label"]
        mark = "!" if rec["tier"] == FLAG else " "
        key = clip(key_text, LIVE_KEY_COL)
        detail = clip(detail, W - (LIVE_KEY_COL + 25))
        plain = "  %s %5.1fs  %-11s %-*s %s" % (
            mark, now, rec["cat"], LIVE_KEY_COL, key, detail)
        pretty = "  %s %s  %s %s %s" % (
            c("1;31", mark) if mark == "!" else " ",
            c(DIM, "%5.1fs" % now),
            c(colour, "%-11s" % rec["cat"]),
            "%-*s" % (LIVE_KEY_COL, key),
            c(DIM, detail),
        )
        if LIVE:
            self.console.line(pretty, plain)
        else:
            self.console.log_only(plain)


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

# Plain-English name for each mechanism. The raw key stays on the row next to
# it, so the reader gets the human meaning and the thing to search for.
HUMAN = {
    "identifierForVendor":       "Vendor device ID",
    "name":                      "Device name",
    "systemVersion":             "iOS version",
    "model":                     "Device class",
    "localizedModel":            "Device class",
    "hw.machine":                "Hardware model",
    "hw.model":                  "Logic board",
    "hw.product":                "Product code",
    "hw.target":                 "Internal target name",
    "hw.memsize":                "Memory fitted",
    "hw.ncpu":                   "Processor cores",
    "hw.logicalcpu":             "Logical cores",
    "hw.logicalcpu_max":         "Logical cores, max",
    "hw.physicalcpu":            "Physical cores",
    "hw.physicalcpu_max":        "Physical cores, max",
    "hw.cputype":                "Processor family",
    "hw.cpusubtype":             "Processor revision",
    "hw.cpufrequency":           "Processor speed",
    "hw.l1dcachesize":           "L1 cache",
    "hw.l2cachesize":            "L2 cache",
    "hw.l3cachesize":            "L3 cache",
    "hw.cachelinesize":          "Cache line size",
    "hw.pagesize":               "Memory page size",
    "hw.byteorder":              "Byte order",
    "hw.optional.*":             "Chip capability probes",
    "kern.osversion":            "OS build",
    "kern.osproductversion":     "iOS version",
    "kern.ostype":               "OS name",
    "kern.osrelease":            "Kernel release",
    "kern.version":              "Kernel version string",
    "kern.hostname":             "Device hostname",
    "kern.maxvnodes":            "Kernel file limit",
    "kern.maxproc":              "Kernel process limit",
    "kern.boottime":             "Last restart time",
    "kern.bootsessionuuid":      "Boot session ID",
    "kern.secure_kernel":        "Kernel lockdown",
    "kern.hv_vmm_present":       "Virtual machine check",
    "kern.bootargs":             "Boot arguments",
    "uname":                     "Kernel and architecture",
    "free disk space":           "Free disk space",
    "physicalMemory":            "Memory fitted",
    "processorCount":            "Processor cores",
    "activeProcessorCount":      "Active cores",
    "systemUptime":              "Time since last restart",
    "thermalState":              "How hot the phone is",
    "isLowPowerModeEnabled":     "Low power mode on or off",
    "screen resolution":         "Screen resolution",
    "screen brightness":         "Screen brightness",
    "battery level":             "Battery percentage",
    "battery state":             "Charging or not",
    "current locale":            "Region and formatting",
    "preferred languages":       "Languages, in your order",
    "installed keyboards":       "Keyboards you have added",
    "timezone":                  "Timezone",
    "offset from GMT":           "Offset from GMT",
    "calendar":                  "Calendar system",
    "carrier":                   "Mobile carrier",
    "carrier name":              "Mobile carrier",
    "country code":              "SIM country",
    "mobile country code":       "SIM country code",
    "mobile network code":       "SIM network code",
    "radio technology":          "Mobile data generation",
    "advertisingIdentifier":     "Advertising ID (IDFA)",
    "tracking permission":       "Tracking permission state",
}


def human(key):
    if key in HUMAN:
        return HUMAN[key]
    if key.startswith("hw.optional."):
        return "Chip capability probe"
    if key.startswith("hw."):
        return "Hardware attribute"
    if key.startswith("kern."):
        return "Kernel attribute"
    if key.startswith("security."):
        return "Security attribute"
    return key


# who a keychain entry belongs to. Specific matches first, the generic TikTok
# catch-all last, or every ByteDance entry would swallow the SDK names.
KEYCHAIN_OWNERS = [
    ("appsflyer",           "AppsFlyer, ad attribution"),
    ("firebase",            "Firebase, Google"),
    ("linecorp",            "LINE, login provider"),
    ("linesdk",             "LINE, login provider"),
    ("facebook",            "Meta"),
    ("snapchat",            "Snap"),
    ("snapkit",             "Snap"),
    ("kakao",               "Kakao"),
    ("twitter",             "Twitter/X"),
    ("bundleseedid",        "Apple team identifier"),
    ("keychainsharelogin",  "TikTok, cross-app login"),
    ("ktiktokkeychain",     "TikTok, main store"),
    ("account.historylogin", "TikTok, previous accounts"),
    ("account.",            "TikTok, account state"),
    ("cloud",               "TikTok, account identity"),
    ("zhiliaoapp",          "TikTok, app bundle"),
    ("tiktok",              "TikTok"),
]


def keychain_owner(key, kind):
    k = key.lower()
    for marker, owner in KEYCHAIN_OWNERS:
        if marker in k:
            return owner
    return kind or "unlabelled entry"


# --------------------------------------------------------------------------
# section intros: what this group is, and what it means for THIS run
# --------------------------------------------------------------------------

def intro_identity(rows, items):
    out = ["The values that name this exact phone rather than merely describe it."]
    idfv = next((r for r in rows if r["key"] == "identifierForVendor"), None)
    if idfv:
        out.append("The vendor ID is the anchor everything else attaches to. Every app "
                   "from the same publisher reads the same value, and it survives app "
                   "updates, signing out and making a new account. It resets only if you "
                   "delete every app that publisher makes.")
    return out


def intro_keychain(rows, items):
    calls = sum(r["count"] for r in rows)
    out = ["The one place on iOS an app can leave something and still find it after you "
           "delete the app and install it again. %d lookups across %d named entries."
           % (calls, len(rows))]
    found = sorted({name for r in rows for marker, name in SDK_MARKERS.items()
                    if marker in r["key"].lower()})
    if found:
        out.append("The entry names double as an inventory of the advertising and "
                   "analytics code compiled into the app: %s." % ", ".join(found))
    return out


def intro_network(rows, items):
    pic = net_picture(items)
    out = ["The interface list is the richest thing an app can learn about your connection "
           "without asking for anything. One read returns every address the phone holds, "
           "so your local network and any VPN arrive together."]
    if pic["tunnels"]:
        out.append("A tunnel was up the whole time and every scan showed it. TikTok can "
                   "tell you use a VPN. What it does not learn here is which provider, or "
                   "where your traffic finally exits.")
    if pic["public"]:
        out.append("A globally routable address is readable straight off the device, which "
                   "is your real public address without its servers observing anything."
                   + (" A VPN is up and this is going around it, which is what an IPv6 leak "
                      "looks like." if pic["tunnels"] else ""))
    if pic["lan"]:
        out.append("A LAN address does not identify you by itself, but it fingerprints the "
                   "network you are on, which tells home from office from a friend's Wi-Fi "
                   "as you move between them.")
    return out


def intro_antitamper(rows, items):
    out = ["Not data collection. These are TikTok inspecting the phone it is running on, "
           "which is ordinary for any app handling accounts and payments."]
    sk = next((r for r in rows if r["key"] == "kern.secure_kernel"), None)
    if sk and sk["values"] and sk["values"].most_common(1)[0][0] == "1":
        out.append("Worth noting on a jailbroken phone: the kernel reported itself locked "
                   "down, so this check did not reveal the jailbreak.")
    return out


def intro_hardware(rows, items):
    calls = sum(r["count"] for r in rows)
    out = ["No single line here identifies you. The combination does: it stays identical "
           "across reinstalls, needs no permission, and is enough to recognise a device "
           "that has otherwise been wiped. %d attributes, read %d times."
           % (len(rows), calls)]
    if any(r["key"] == "kern.bootsessionuuid" for r in rows):
        out.append("The boot session ID is the exception. Your phone generates it fresh on "
                   "each restart and any app can read it, so two apps that both read it can "
                   "confirm they are on the same handset until you reboot.")
    return out


def intro_request(rows, items):
    socks = [r for r in rows if r.get("src") == "CONNECT"]
    urls = [r for r in rows if r.get("src") == "REQUEST"]
    out = ["Every server the app opened a connection to. Sockets are watched underneath "
           "Apple's networking as well as through it, so this now covers TikTok's own "
           "traffic and not only the embedded SDKs."]
    third = [r for r in urls if r["tier"] == FLAG]
    if third:
        out.append("Anything marked here is code from another company running inside "
                   "TikTok and reporting to its own servers, rather than TikTok passing "
                   "your data along.")
    if socks:
        out.append("Raw addresses are matched back to the names the app resolved. Several "
                   "names often share one address, so the name shown is one that resolved "
                   "there rather than certainly the one used. An address with no name was "
                   "looked up before the capture started or answered from cache.")
    if any(endpoint_role(r["key"]) for r in rows if r.get("src") == "DNS"):
        out.append("What each endpoint is for is inferred from ByteDance's naming, which "
                   "is consistent across regions. Useful for seeing the shape of what runs "
                   "at launch, but it is a reading of the names, not documentation.")
    return out


def intro_location(rows, items):
    return ["Calls into the location APIs. Any entry here means the app asked where the "
            "phone is during the window."]


def intro_locale(rows, items):
    out = ["Where you are, what you speak and how you write it. None of this asks "
           "permission, and together it narrows you down hard: a timezone plus a "
           "language order plus a keyboard list is a small crowd."]
    kb = next((r for r in rows if r["key"] == "installed keyboards"), None)
    if kb and kb["values"]:
        out.append("The keyboard list is the sharpest of them. It names the languages you "
                   "actually type in, which is a stronger claim about you than the phone's "
                   "display language.")
    return out


def intro_carrier(rows, items):
    # if every carrier value we saw is a sentinel, the app got nothing usable
    vals = [v for r in rows for v in r["values"]]
    all_dead = vals and all(is_carrier_sentinel(v) for v in vals)
    if all_dead:
        return ["The app asked your SIM for its carrier, country and network codes. On this "
                "phone it got nothing: iOS 16 retired the CTCarrier API and now hands back "
                "placeholders (65535, \"--\"), so these reads are an attempt that returns a "
                "dead value, not real data about your network. A pre-iOS-16 device would "
                "have leaked the real codes here."]
    return ["Your mobile network. When these return real values, the country and network "
            "codes place you geographically even with location refused and a VPN running, "
            "because they come from the SIM rather than the connection. On iOS 16 and later "
            "the API is deprecated and often returns a 65535 placeholder instead."]


def intro_scheme(rows, items):
    return ["An app can ask whether another app is installed by testing whether it can "
            "open its URL scheme. No permission, no prompt. A list of these is a profile "
            "of what else you use, which is why Apple limited it.",
            "These are the ones it actually probed during this run. The full set it is "
            "built to look for is in the next section."]


def intro_queryable(rows, items):
    return ["The complete, authoritative list. iOS makes an app declare every scheme it "
            "will ever check, and refuses the check for anything undeclared, so this is "
            "exactly the set of apps TikTok is built to look for, whether or not it probed "
            "them this run. Names are mapped from the raw schemes."]


def intro_clipboard(rows, items):
    return ["Reading the pasteboard hands the app whatever you last copied, which is "
            "regularly a password, an address or a message. This records only that the "
            "read happened, never the contents."]


def intro_perms(rows, items):
    out = ["Asking what you have ALLOWED is not itself gated behind a prompt. An app can "
           "sweep every permission silently, and the set of answers describes your privacy "
           "posture without ever asking you anything."]
    denied = [r for r in rows
              if r["values"] and "denied" in r["values"].most_common(1)[0][0]]
    if denied:
        out.append("A refusal is information too. Knowing which permissions you turned "
                   "down is itself a way to tell you apart from someone who left the "
                   "defaults alone.")
    return out


def intro_sensor(rows, items):
    return ["The accelerometer and gyroscope need no permission at all. Their output "
            "carries the chip's factory calibration, which differs between physically "
            "identical handsets, so a raw stream is close to reading a serial number.",
            "Only the start calls and the accessors are recorded here, not the samples "
            "themselves. Sensors deliver up to a hundred readings a second, and watching "
            "every one would cost more than it tells you."]


def intro_interaction(rows, items):
    return ["This is how you touch the glass, not what your device is. For every touch, "
            "iOS records its source and whether it arrived with the tiny sub-frame samples "
            "that only real hardware produces. So a line reading 'a real finger' means a "
            "genuine finger on the screen. A mouse or trackpad pointer, a stylus, or a "
            "finger with no sub-samples would show up instead, and would suggest something "
            "other than a hand is driving the feed.",
            "The flick-speed line is the app measuring how fast and hard you swipe. The "
            "haptic lines are its own buzzes on taps, likes and errors."]


def intro_accessibility(rows, items):
    return ["None of these need a permission prompt. AssistiveTouch and VoiceOver being "
            "on are the strongest signals, they are how accessibility-driven automation "
            "reaches an app. The rest are low-entropy settings that still help tell one "
            "person's device from another."]


def intro_environment(rows, items):
    return ["Signals about the physical world around the phone: whether the screen is "
            "being recorded or mirrored to another display, and whether an external "
            "mouse, keyboard, game controller, or Bluetooth device is attached. A mouse "
            "or keyboard driving a phone feed is a classic automation-rig tell."]


def intro_gestalt(rows, items):
    return ["MobileGestalt is the private system database of hardware facts. The keys "
            "listed here are what the app asked it for: model, region, and, when present, "
            "unique hardware identifiers and the production-status and Developer Mode "
            "probes. This records the questions, never the answers."]


def intro_media(rows, items):
    keys = {r["key"] for r in rows}
    out = ["Posting is the one thing you do that hands over a file. What matters is "
           "not the upload, it is what was already inside the file. A video shot on "
           "an iPhone carries the time it was taken, the camera that took it and, "
           "unless you turned that off, the coordinates. Reading those out of a file "
           "the app is already holding needs no permission and produces no prompt."]
    geo = [k for k in keys if "GPS" in k or "geotag" in k]
    if geo:
        out.append("This run it DID read location out of the file itself. That is a "
                   "position fix obtained without CLLocationManager, so it would not "
                   "appear anywhere else in this report.")
    elif any(r["cat"] == "MEDIA" and r["src"] == "MEDIA_META" for r in rows):
        out.append("It opened the metadata container but no location block came back, "
                   "which means either the file carried no coordinates or it read only "
                   "the parts listed here.")
    if "system photo picker" in keys and "in-app camera or picker" not in keys:
        out.append("The picker it used runs outside the app, so it got the one file you "
                   "chose and no access to the rest of your library. That is also why "
                   "the permission section shows no photo-library grant.")
    if "capture session" in keys:
        out.append("The camera or microphone was not merely asked about, it was opened.")
    return out


def intro_provenance(rows, items):
    out = ["Every metadata field seen on the post path this run, with its value. "
           "The rest of this report records that TikTok asked a question. This "
           "records what the answer was, which is the only form the data can take "
           "if you intend to diff one posted file against another."]
    have = {tag_bucket(r["key"]) for r in rows if r.get("src") == "MEDIA_TAG"}
    if "INPUT" in have and ("UPLOADED" in have or "OUTPUT" in have):
        out.append("Both ends were captured. The fields present under INPUT and "
                   "absent under OUTPUT or UPLOADED are the ones the re-encode "
                   "dropped, which is the list worth stamping against.")
    if "written into the export" in have:
        out.append("TikTok wrote metadata into its own export. Those fields are "
                   "the ones it chose to carry forward, and they are listed "
                   "separately below.")
    return out


SECTION_SPECS = [
    ("IDENTITY",    "WHO YOU ARE",                      intro_identity,   "kv"),
    ("PERMS",       "WHAT IT CHECKED YOU HAD ALLOWED",  intro_perms,      "kv"),
    ("MEDIA",       "WHAT YOUR POST HANDED OVER",       intro_media,      "media"),
    ("PROVENANCE",  "EVERY TAG ON THE POST PATH",       intro_provenance, "tags"),
    ("INTERACTION", "HOW YOU TOUCH THE SCREEN",         intro_interaction, "kv"),
    ("ACCESSIBILITY", "ASSISTIVE AND ACCESSIBILITY STATE", intro_accessibility, "kv"),
    ("ENVIRONMENT", "WHAT IS AROUND YOUR PHONE",        intro_environment, "kv"),
    ("GESTALT",     "WHAT IT ASKED THE OS ABOUT THIS DEVICE", intro_gestalt, "kv"),
    ("SENSOR",      "MOTION SENSORS",                   intro_sensor,     "kv"),
    ("LOCALE",      "WHERE YOU ARE AND WHAT YOU SPEAK", intro_locale,     "kv"),
    ("CARRIER",     "YOUR MOBILE NETWORK",              intro_carrier,    "kv"),
    ("CLIPBOARD",   "YOUR CLIPBOARD",                   intro_clipboard,  "pair"),
    ("SCHEME",      "WHAT ELSE YOU HAVE INSTALLED",     intro_scheme,     "pair"),
    ("QUERYABLE",   "EVERY APP IT IS BUILT TO LOOK FOR", intro_queryable, "applist"),
    ("EXPOSURE",    "WHERE YOU SIT ON THE NETWORK",     intro_network,    "net"),
    ("KEYCHAIN",    "SURVIVES DELETING THE APP",        intro_keychain,   "pair"),
    ("LOCATION",    "WHERE THE PHONE IS",               intro_location,   "kv"),
    ("ANTI-TAMPER", "CHECKS ON THE PHONE, NOT ON YOU",  intro_antitamper, "kv"),
    ("DEST",        "WHO IT TALKED TO",                 intro_request,    "dest"),
    ("HARDWARE",    "WHAT PHONE THIS IS",               intro_hardware,   "kv"),
]


def collapse_groups(rows):
    """Fold key families into one aggregate row. Detail survives in audit.json."""
    out, families = [], {}
    for r in rows:
        g = group_for(r["key"])
        if g is None:
            out.append(r)
        else:
            families.setdefault(g, []).append(r)
    for g, members in families.items():
        supported = sum(1 for m in members
                        if m["values"] and m["values"].most_common(1)[0][0] == "1")
        summary = "%d probed, %d supported" % (len(members), supported)
        out.append({
            "cat": members[0]["cat"], "key": g + "*", "label": GROUPS[g],
            "tier": WATCH, "count": sum(m["count"] for m in members),
            "values": Counter({summary: 1}),
        })
    return out


def render_reach(p, rows, all_items):
    """What the app could have had for the asking. Every call here was made from
    inside TikTok's own process, so the sandbox and entitlements that decided
    each answer were the app's. A refusal is therefore a real result: iOS held
    the line against THIS app, not merely in principle."""
    got = [r for r in rows if r.get("src") in ("REACH", "REACH_WAN")]
    ifaces = [r for r in rows if r.get("src") == "REACH_IFACE"]
    ifaddrs = [r for r in rows if r.get("src") == "REACH_IFADDR"]
    denied = [r for r in rows if r.get("src") == "REACH_NO"]
    nbrs = [r for r in rows if r.get("src") == "REACH_NEIGHBOUR"]

    # anything it also asked for on its own is not news; say so rather than
    # listing it twice
    observed = set()
    for r in all_items:
        if r.get("src") in ("RESOLVER", "ROUTE", "PROXY", "INTERFACE_ID", "GESTALT"):
            observed.add(r["key"])

    name_w = max(26, int(W * 0.40))
    val_w = max(18, W - name_w - 10)

    if got:
        p("    " + c(DIM, "it never asked for these in this window, and would have got them:"))
        for r in sorted(got, key=lambda r: (0 if r["tier"] == FLAG else 1, r["key"])):
            val = r["values"].most_common(1)[0][0] if r["values"] else "available"
            also = "  (and did ask)" if r["key"] in observed else ""
            p("  %s %-*s %s%s" % (c("1;31", "!"), name_w, clip(r["key"], name_w),
                                  clip(val, val_w), c(DIM, also)))
        p("")

    if ifaces or ifaddrs:
        p("    " + c(DIM, "every interface and address, via the sysctl route it "
                          "calls most:"))
        for r in sorted(ifaces, key=lambda r: r["key"]):
            v = r["values"].most_common(1)[0][0] if r["values"] else ""
            masked = "masked" in v
            p("  %s %-*s %s" % (" " if masked else c("1;31", "!"),
                                name_w, clip(r["key"], name_w),
                                c(DIM, v) if masked else c("1;31", v)))
        for r in sorted(ifaddrs, key=lambda r: r["key"]):
            v = r["values"].most_common(1)[0][0] if r["values"] else ""
            p("    %-*s %s" % (name_w, clip(r["key"], name_w), c(DIM, v)))
        p("")

    if nbrs:
        p("    " + c(DIM, "every other device it could see on this network:"))
        for r in sorted(nbrs, key=lambda r: r["key"])[:24]:
            mac = r["values"].most_common(1)[0][0] if r["values"] else ""
            p("  %s %-*s %s" % (c("1;31", "!"), name_w, clip(r["key"], name_w), c(DIM, mac)))
        if len(nbrs) > 24:
            p("    " + c(DIM, "and %d more" % (len(nbrs) - 24)))
        p("")

    if denied:
        p("    " + c(DIM, "asked for on its behalf and refused by iOS:"))
        for r in sorted(denied, key=lambda r: r["key"]):
            why = r["values"].most_common(1)[0][0] if r["values"] else "refused"
            p("    %-*s %s" % (name_w, clip(r["key"], name_w), c(DIM, clip(why, val_w))))
        p("")
        for ln in wrap("Those are the protections that actually hold. They were tested with "
                       "this app's own entitlements, so they say what TikTok cannot have "
                       "rather than what iOS restricts in general.", W - 6):
            p("    " + c(DIM, ln))


# Rows whose answer is a fact about you rather than a count. The old test read
# the answer string, which cannot see that a router address matters.
HOT_QUESTIONS = ("The router it found", "DNS servers it read",
                 "MAC address leaked", "Wi-Fi router address",
                 "Wi-Fi network name", "Other devices on the LAN")


def render_exposure(p, rows, all_items):
    """One section for the whole network picture.

    The answer sheet comes first and always lists the same fields, whether the
    app read them in this window or merely could have. A 45-second sample is a
    lower bound on behaviour and says nothing about capability, so the two are
    shown side by side with the provenance of each spelled out:

        read      the app asked for it during this run
        open      it did not ask, and the same call from its process returned
                  this anyway
        blocked   the same call from its process was refused by iOS

    Everything below the sheet appears exactly once. The old layout printed the
    same address in three places, which made a long report look like a lot of
    findings rather than a few facts."""
    pic = net_picture(all_items)

    q_w = max(26, int(W * 0.34))
    v_w = max(20, int(W * 0.34))
    note_w = max(30, W - 12)

    def sheet(label, value, how, note=""):
        if value is None:
            return
        colour = {"LEAK": "1;31", "blocked": DIM, "open": "1;33"}.get(how)
        hot = how in ("LEAK", "open")
        p("  %s %-*s %s  %s" % (
            c("1;31", "!") if how == "LEAK" else " ",
            q_w, clip(label, q_w),
            (c("1;31", "%-*s" % (v_w, clip(value, v_w))) if hot
             else "%-*s" % (v_w, clip(value, v_w))),
            c(colour or DIM, how)))
        if note:
            for ln in wrap(note, note_w):
                p("    " + c(DIM, ln))

    def first(d, *names):
        for n in names:
            if d.get(n):
                v = d[n]
                return v[0] if isinstance(v, list) else v
        return None

    # ---- what the phone holds, merged from both routes, deduped ------------
    ifrows = {}
    for r in [x for x in rows if x.get("src") == "INTERFACE"]:
        ifrows.setdefault(r["key"], set()).update(r["values"])
    for key in pic["sweep_addr"]:
        parts = key.split("  ")
        if len(parts) == 2:
            ifrows.setdefault(parts[0], set()).add(parts[1])
    own = {norm_addr(a) for addrs in ifrows.values() for a in addrs}

    macs = {(i, a): m for i, a, m in pic["derived"]}
    leaked = sorted({m for _i, _a, m in pic["derived"] if not masked_mac(m)})

    lan = [a for a in own if addr_kind(a)[0] in ("private", "unique local")]
    public_on_device = [a for a in own if addr_kind(a)[0] == "PUBLIC"]
    v6_global = [a for a in own if ":" in a and addr_kind(a)[2]
                 and not a.lower().startswith("fe80")]

    p("  " + c(DIM, "THE ANSWER SHEET".ljust(q_w) + "  value"))
    p("")

    # 1. the address the far end records
    if pic["wan"]:
        # Several probes, deliberately: the app's own networking, and one that
        # ignores its proxy settings. Agreement is reassuring; disagreement is
        # the finding, because it means some of the phone's traffic leaves by a
        # path the proxy is not on.
        thru = [a for a, l in pic["wan"] if "ignoring" not in l and ":" not in a]
        direct = [a for a, l in pic["wan"] if "ignoring" in l]
        best = (thru or direct or [pic["wan"][0][0]])[0]
        sheet("Public address a server sees", best, "open",
              "fetched from inside the app's own process: this is the number "
              "TikTok's servers record")
        if thru and direct and direct[0] not in thru:
            sheet("Address when the proxy is bypassed", direct[0], "LEAK",
                  "traffic that ignores the app's proxy settings leaves by a "
                  "different exit, so the tunnel does not cover everything")
        elif direct and not thru:
            sheet("Address, proxy settings bypassed", direct[0], "open",
                  "the app's own networking gave no answer this run, so this is "
                  "a direct socket and may not be the exit its traffic uses")
    elif public_on_device:
        sheet("Public address a server sees", public_on_device[0], "LEAK",
              "readable straight off an interface, no server needed")
    elif pic["public_echo"]:
        sheet("Public address a server sees", sorted(set(pic["public_echo"]))[0],
              "LEAK", "its own resolver echoed it back")
    else:
        # Say why, not just that it is missing. A local proxy explains it, and
        # the distinction matters: the app being unable to locate itself is a
        # different fact from the rig failing to ask.
        local_proxy = any("127.0.0.1" in str(v) for vs in pic["reach"].values()
                          for v in (vs if isinstance(vs, list) else [vs])) or                       any("127.0.0.1" in v for _k, v in pic["proxy_answers"])
        tried = len([k for k in pic["blocked"]
                     if "server sees" in k or "provider" in k or "socket" in k
                     or "session" in k or "family" in k or "numeric" in k])
        if local_proxy:
            sheet("Public address a server sees", "no probe could reach out", "read",
                  "%d attempts failed, over several transports and destinations. "
                  "A proxy is running on this phone at 127.0.0.1 and every "
                  "connection terminates there, so nothing originating in the app "
                  "gets far enough to be told its own address. The app cannot "
                  "locate itself either." % max(tried, 1))
        else:
            sheet("Public address a server sees", "not determined this run", "read",
                  "nothing globally routable on the device, and nothing told it")

    for name, outcome in sorted(pic["paths"]):
        sheet("Control: " + name, clip(outcome, 34),
              "read" if "completed" in outcome else "blocked")

    # 2. the rest of the position
    sheet("Address on this network", (sorted(lan) or ["none"])[0], "read")
    sheet("Default gateway", first(pic["reach"], "default gateway")
          or (sorted(set(pic["gateways"]))[0] if pic["gateways"] else "not read"),
          "open" if pic["reach"].get("default gateway") and not pic["gateways"]
          else "read")
    sheet("DNS resolver", (sorted(set(pic["resolvers"]))[0] if pic["resolvers"]
                           else first(pic["reach"], "DNS servers") or "not read"),
          "read" if pic["resolvers"] else "open")
    sheet("IPv6 on this network",
          v6_global[0] if v6_global else
          ("yes, " + [a for a, _l in pic["wan"] if ":" in a][0]
           if any(":" in a for a, _l in pic["wan"]) else "none"),
          "LEAK" if v6_global else "read",
          "no global v6, so nothing can slip around a v4-only proxy"
          if not v6_global else "a globally routable v6 is a per-device address")

    if pic["tunnels"]:
        name, addrs, app_based = pic["tunnels"][0]
        sheet("On a VPN", "yes, " + name, "LEAK",
              "app-based tunnel" if app_based else "system tunnel carrying traffic")
    else:
        sheet("On a VPN", "no tunnel carrying traffic", "read",
              "any redirection is upstream of the phone, which the app cannot see")
    sheet("System proxy",
          first(pic["reach"], "proxy settings")
          or (pic["proxy_answers"][0][1] if pic["proxy_answers"] else "not read"),
          "read")

    # 3. identity that a proxy cannot move
    ssid = pic["wifi"].get("Wi-Fi network name")
    if ssid:
        sheet("Wi-Fi network name", ssid[0], "LEAK")
    elif "Wi-Fi SSID and BSSID" in pic["blocked"]:
        sheet("Wi-Fi name and router MAC", "refused by iOS", "blocked",
              pic["blocked"]["Wi-Fi SSID and BSSID"])
    if leaked:
        sheet("Hardware MAC, via link-local", "  ".join(leaked[:2]), "LEAK",
              "the official API returns 02:00:00:00:00:00, and the link-local "
              "address on the same call hands the MAC over anyway")
    if pic["hw_sweep"] or pic["hw"]:
        sheet("Hardware MAC, official API", "02:00:00:00:00:00", "blocked",
              "iOS substitutes this for every app, on every interface")
    region = first(pic["reach"], "gestalt RegionInfo", "gestalt RegionCode")
    if region:
        sheet("Sales region, burned in", region, "open",
              "set at manufacture. No proxy, VPN or setting changes it")

    # 4. the story check: does the device agree with the exit address
    tz = kb = None
    for r in all_items:
        if r["key"] == "timezone" and r["values"]:
            tz = r["values"].most_common(1)[0][0]
        if r["key"] == "installed keyboards" and r["values"]:
            kb = r["values"].most_common(1)[0][0]
    if tz or region:
        bits = []
        if region:
            bits.append("hardware %s" % region)
        if tz:
            bits.append("timezone %s" % tz)
        if kb:
            bits.append("keyboards %s" % clip(kb, 40))
        if pic["wan"]:
            bits.append("exit %s" % pic["wan"][0][0])
        p("")
        p("    " + c(DIM, "story check, all read every launch:"))
        for b in bits:
            p("      " + c(DIM, clip(b, W - 14)))

    # ---- the detail, once ---------------------------------------------------
    p("")
    p("    " + c(DIM, "every interface and address, deduplicated:"))
    # interior is W-6; the fixed columns eat 35, so split what is left
    addr_w = max(24, W - 68)
    tail_w = max(18, (W - 6) - 35 - addr_w - 1)

    def addr_order(a):
        kind, _t, routable = addr_kind(a)
        return (0 if kind == "PUBLIC" else 1 if routable else 2, a)

    for name in sorted(ifrows, key=lambda n: (0 if any(
            macs.get((n, norm_addr(a))) and not masked_mac(macs[(n, norm_addr(a))])
            for a in ifrows[n]) else 1, n)):
        addrs = sorted(ifrows[name], key=addr_order)
        role = iface_role(name)
        flagged = any(macs.get((name, norm_addr(a)))
                      and not masked_mac(macs[(name, norm_addr(a))]) for a in addrs)
        for i, a in enumerate(addrs):
            kind = addr_kind(a)[0]
            na = norm_addr(a)
            mask = pic["sweep_addr"].get("%s  %s" % (name, a)) or \
                   pic["masks"].get("%s %s" % (name, a))
            tail = kind
            pref = mask_to_prefix(mask)
            if pref:
                tail += " " + pref
            p("  %s %-11s %-18s %-*s %s" % (
                c("1;31", "!") if (flagged and i == 0) else " ",
                name if i == 0 else "", (role if i == 0 else "")[:18],
                addr_w, clip(na, addr_w), c(DIM, clip(tail, tail_w))))
            mac = macs.get((name, na))
            if mac and not masked_mac(mac):
                p("  " + " " * 33 + c("1;31", "contains the MAC " + mac))

    quiet = sorted(n for n in pic["hw_sweep"] if n not in ifrows)
    if quiet:
        for ln in wrap("%d further interfaces exist with no address: %s"
                       % (len(quiet), ", ".join(quiet)), W - 10):
            p("    " + c(DIM, ln))

    # ---- who else is on the wire, self and multicast removed ---------------
    others = []
    for ip, note in pic["nbr"].items():
        if ip in own or addr_kind(ip)[0] in ("loopback", "link-local"):
            continue
        try:
            if ipaddress.ip_address(ip.split("%")[0]).is_multicast:
                continue
        except ValueError:
            pass
        others.append((ip, note))
    if others:
        p("")
        p("    " + c(DIM, "other devices it can see on this network:"))
        for ip, note in sorted(others)[:20]:
            p("  %s %-*s %s" % (c("1;31", "!"), addr_w + 12, clip(ip, addr_w + 12),
                                c(DIM, clip(note, max(16, (W - 6) - addr_w - 16)))))

    # ---- what iOS refused, compact -----------------------------------------
    if pic["blocked"]:
        p("")
        p("    " + c(DIM, "asked for on the app's behalf and refused by iOS:"))
        names = sorted(k.replace("gestalt ", "") for k in pic["blocked"])
        for ln in wrap(", ".join(names), W - 12):
            p("      " + c(DIM, ln))
        for ln in wrap("Tested with this app's own entitlements, so these say "
                       "what TikTok cannot have rather than what iOS restricts "
                       "in general.", W - 10):
            p("    " + c(DIM, ln))

    # ---- how often it asked, moved to the bottom ---------------------------
    counts = []
    if pic["scans"]:
        counts.append("getifaddrs %dx" % pic["scans"])
    if pic["iflist_reads"]:
        counts.append("sysctl interface list %dx" % pic["iflist_reads"])
    if pic["ifenum"]:
        counts.append("ioctl %dx" % pic["ifenum"])
    if pic["route_reads"]:
        counts.append("route table %dx" % pic["route_reads"])
    if pic["proxy"]:
        counts.append("proxy config %dx" % pic["proxy"])
    for name, answer, count in pic["nwpath"]:
        counts.append("path %s %dx" % (clip(name, 14), count))
    if counts:
        p("")
        for ln in wrap("It asked, in this window: " + ", ".join(counts) + ".",
                       W - 10):
            p("    " + c(DIM, ln))


LBL_W = 23   # plain-English name
RAW_W = 21   # the underlying key, for searching


def rows_kv(p, rows, cat):
    """name in human words | the raw key | the value we got | how often."""
    val_w = max(18, W - (LBL_W + RAW_W + 13))
    for r in rows:
        mark = c("1;31", "!") if r["tier"] == FLAG else " "
        top = r["values"].most_common(1)
        val = pretty_value(cat, r["key"], top[0][0]) if top else ""
        if not val:
            val = r["label"]
        raw = r["key"] if human(r["key"]) != r["key"] else ""
        p("  %s %-*s %s %s %s" % (
            mark, LBL_W, clip(human(r["key"]), LBL_W),
            c(DIM, "%-*s" % (RAW_W, clip(raw, RAW_W))),
            "%-*s" % (val_w, clip(val, val_w)) if len(val) <= val_w else "",
            c(DIM, "%4dx" % r["count"])))
        if len(val) > val_w:
            p("      " + val)


# A raw request line off the wire says nothing on its own. These are the paths
# worth recognising by name, so a run can be compared against another one
# (captions on versus off, say) without re-reading the path every time.
PLAINTEXT_PATHS = [
    ("lab-speech-video-caption", "speech to text: your audio, uploaded to be transcribed"),
    ("/upload/v1/", "an upload, not a fetch"),
    ("aweme", "publish / aweme API"),
    ("CANARY", "injected canary string on the wire"),
    ("speedtest", "upload bandwidth measurement, a property of your connection"),
    ("ies.fe.effect", "editor effect assets"),
    ("/video/tos/", "video object storage, the region is in the path"),
]


def plaintext_meaning(line):
    for needle, meaning in PLAINTEXT_PATHS:
        if needle in line:
            return meaning
    return ""


# The containers a tag can come from, in the order a post touches them. The
# first three are what TikTok read live. The next three are the file dumps that
# bracket the post, and the difference between INPUT and UPLOADED is the whole
# question of what survives an upload.
TAG_CONTAINERS = [
    ("INPUT",   "the file TikTok opened"),
    ("OUTPUT",  "what its encoder wrote"),
    ("UPLOADED", "the artifact that left the phone"),
    ("image",   "read live out of an image"),
    ("video",   "read live out of a video"),
    ("XMP",     "XMP tags in the file"),
    ("track",   "codec"),
    ("library", "what the Photos database said"),
    ("resource", "the asset's backing file"),
    ("file",    "filesystem attributes"),
    ("written into the export", "TikTok wrote this into its own re-encode"),
]


def tag_bucket(key):
    for prefix, _ in TAG_CONTAINERS:
        if key == prefix or key.startswith(prefix + " "):
            return prefix
    return "other"


def render_provenance(p, rows, items):
    """Every media tag observed this run, grouped by where it came from. This is
    the section a stamping test is read out of, so it prints values and never
    collapses two fields into one row: the point is to diff it against the next
    run, not to summarise it."""
    files = [r for r in rows if r.get("src") == "MEDIA_FILE"]
    tags = [r for r in rows if r.get("src") == "MEDIA_TAG"]

    if files:
        p("")
        p("  " + c(BOLD, "files opened end to end"))
        for r in sorted(files, key=lambda r: r["first"]):
            for v, _n in r["values"].most_common(4):
                p("    %-12s %s" % (r["key"], c(DIM, v)))

    if not tags:
        p("")
        for ln in wrap("No media tags were seen. Either nothing was posted this run "
                       "or the post path never opened a file with provenance in it. "
                       "A run intended as a stamping test that prints this line "
                       "produced no data, whatever else it recorded.", W - 6):
            p("  " + c(DIM, ln))
        return

    # QuickTime keys are long ('mdta/com.apple.quicktime.content.identifier'),
    # so this section gives the name more room than the others. The untruncated
    # pair always survives in tags.json, which is what a diff reads anyway.
    name_w = max(34, int(W * 0.54))
    val_w = max(14, W - name_w - 14)
    buckets = {}
    for r in tags:
        buckets.setdefault(tag_bucket(r["key"]), []).append(r)

    order = [b[0] for b in TAG_CONTAINERS] + ["other"]
    titles = dict(TAG_CONTAINERS)
    for b in order:
        rs = buckets.get(b)
        if not rs:
            continue
        p("")
        p("  " + c(BOLD, b) + c(DIM, "  " + titles.get(b, "")))
        for r in sorted(rs, key=lambda r: r["key"]):
            # strip the container off the front, it is already the heading
            short = r["key"][len(b):].strip() if r["key"].startswith(b) else r["key"]
            mark = c("1;31", "!") if r["tier"] == FLAG else " "
            vals = r["values"].most_common(3)
            val = ", ".join(v for v, _ in vals) if vals else c(DIM, "(no value)")
            p("  %s %-*s %s %s" % (mark, name_w, clip(short or b, name_w),
                                   clip(val, val_w),
                                   c(DIM, "%dx" % r["count"])))

    # the one comparison the section exists to make. Section intros are not
    # rendered by the panel loop, so the guidance that decides whether this run
    # is usable has to live here or it is never seen.
    have = {b for b in buckets}
    p("")
    if "INPUT" in have and (have & {"UPLOADED", "OUTPUT"}):
        for ln in wrap("Both ends were captured. Fields listed under INPUT and "
                       "absent under OUTPUT or UPLOADED are the ones the "
                       "re-encode dropped, and that difference is the list worth "
                       "stamping against. Diff this run against another with "
                       "compare_runs.py.", W - 6):
            p("  " + c(DIM, ln))
    else:
        for ln in wrap("Only one end was captured, so nothing here says what "
                       "survives a post. Run compare_runs.py against a second "
                       "run to get a comparison.", W - 6):
            p("  " + c(DIM, ln))
    if "INPUT" in have and "UPLOADED" not in have and "OUTPUT" not in have:
        p("")
        for ln in wrap("The input file was dumped but no encoder output or upload "
                       "file was. TikTok either had not finished the post when the "
                       "run ended or it uploaded through a path that never named a "
                       "file. Extend the run past the export before reading this as "
                       "nothing having been uploaded.", W - 6):
            p("  " + c(DIM, ln))


def render_media(p, rows, items):
    """The post path, split by what it did: switched something on, read something
    out of a file, put something on the wire. The steps that produced NOTHING are
    then named with what that means and what to do about it, because in this
    section an absence is a finding and a missing row looks like no finding."""
    name_w = max(26, int(W * 0.42))
    val_w = max(16, W - name_w - 12)

    def line(r):
        mark = c("1;31", "!") if r["tier"] == FLAG else " "
        top = r["values"].most_common(1)
        val = top[0][0] if top else r["label"]
        # several distinct field names under one row, so say how many
        extra = ""
        if len(r["values"]) > 1:
            extra = " (+%d more)" % (len(r["values"]) - 1)
        p("  %s %-*s %s %s" % (mark, name_w, clip(human(r["key"]), name_w),
                               "%-*s" % (val_w, clip(val + extra, val_w)),
                               c(DIM, "%4dx" % r["count"])))

    def block(title, rs):
        if not rs:
            return
        p("  " + c(DIM, title))
        for r in sorted(rs, key=lambda r: (0 if r["tier"] == FLAG else 1, -r["count"])):
            line(r)
        p("")

    # Which post-path hooks never attached. A hook that failed and a mechanism
    # the app never used produce identical silence, so every conclusion drawn
    # from an absence below has to know the difference.
    unattached = set()
    for r in items:
        if r["cat"] == "RIG" and r["key"] == "post-path hook NOT attached":
            for v in r["values"]:
                unattached.add(v.split(" ", 1)[0])

    def blind(*classes):
        return sorted(c for c in classes if c in unattached)

    keys = {r["key"] for r in rows}
    reads = [r for r in rows if r.get("src") == "MEDIA_META"]
    ups = [r for r in rows if r["key"].startswith("upload to ")]
    upkeys = {r["key"] for r in ups}
    steps = [r for r in rows if r.get("src") == "MEDIA" and r["key"] not in upkeys]

    block("what it switched on:", steps)
    block("what it read out of the files themselves:", reads)
    block("what left the phone:", ups)

    # --- the absences, which is the actionable half --------------------------
    geo = [r for r in reads if is_geotag(r["key"])]
    img = sum(r["count"] for r in reads if r["key"] == "image metadata block")
    vid = sum(r["count"] for r in reads if r["key"] == "video metadata block")
    notes = []

    if reads and not geo:
        # image field names only. The video side reports "format-specific field"
        # placeholders, which would read as nonsense in a list of EXIF keys.
        fields = set()
        for r in reads:
            if r["key"] == "other metadata fields":
                fields |= set(r["values"])
        detail = (", ".join(sorted(fields)[:6]) + (", ..." if len(fields) > 6 else "")
                  if fields else "")
        notes.append(
            "%d metadata reads and NO location block in any of them. Either these files "
            "carry no coordinates or these were decode-time reads, which look the same "
            "from here. The tell is which fields came back%s: orientation, pixel geometry "
            "and camera model are what a decoder wants, a GPS or a full EXIF block is what "
            "a harvester wants."
            % (img + vid, (" (" + detail + ")") if detail else ""))
    if not (keys & {"system photo picker", "in-app camera or picker"}):
        deaf = blind("PHPickerViewController", "UIImagePickerController")
        if deaf:
            notes.append(
                "No picker row, but %s never attached this run, so this is a gap in the "
                "rig and NOT a finding about the app. Fix the hook before reading anything "
                "into the silence." % " and ".join(deaf))
        elif "capture session" in keys:
            notes.append(
                "No picker of either kind opened, but a capture session did, so the media "
                "came from the in-app camera rather than from your library.")
        else:
            notes.append(
                "No picker of either kind opened, so nothing was chosen through a system "
                "UI in this window. If you did pick something, TikTok used its own gallery "
                "and reached the library directly, which is worth a separate look.")
    if not (keys & {"video encode started", "video export started",
                    "hardware video encoder"}):
        deaf = blind("AVAssetWriter", "AVAssetExportSession")
        if deaf:
            notes.append(
                "No encoder row, but %s never attached, so the silence is the rig's, not "
                "the app's." % " and ".join(deaf))
        else:
            notes.append(
                "No encoder started. AVAssetWriter, AVAssetExportSession and VideoToolbox "
                "all stayed quiet, so the encode either happened outside this window or "
                "runs through a bundled encoder that never calls the system one.")
    if not ups:
        if blind("NSURLSession"):
            notes.append(
                "No upload row, but the NSURLSession upload hooks never attached, so this "
                "says nothing about how the file left.")
        else:
            notes.append(
                "No upload task was created, so nothing left through Apple's networking. "
                "TikTok publishes through its own uploader, and the only hook that can see "
                "those bytes is the tls probe, which samples for 600ms at a time. Run with "
                "-Full and publish while a probe window is live, or treat the upload "
                "itself as out of reach.")
    if unattached:
        notes.append(
            "%d post-path %s did not attach at all: %s. Everything above is blind to those."
            % (len(unattached), "hook" if len(unattached) == 1 else "hooks",
               ", ".join(sorted(unattached))))
    if notes:
        p("  " + c(DIM, "what did NOT happen, and what that means:"))
        for n in notes:
            for i, ln in enumerate(wrap(n, W - 8)):
                p("    " + ("  " if i else c(DIM, MARK + " ")) + c(DIM, ln))


def render_applist(p, rows):
    """The full declared query list, as clean app names in aligned columns.
    Deduped (several schemes can map to one app) and sorted."""
    names = sorted({r["label"] for r in rows if r["label"]}, key=lambda s: s.lower())
    if not names:
        return
    p("  " + c(DIM, "%d apps, %d declared schemes:" % (len(names), len(rows))))
    p("")
    # pack into aligned columns to keep a long list compact
    colw = max((len(n) for n in names), default=10) + 3
    cols = max(1, (W - 4) // colw)
    for i in range(0, len(names), cols):
        row = names[i:i + cols]
        p("  " + "".join(("%-*s" % (colw, n)) for n in row).rstrip())


def rows_pair(p, rows, cat):
    """entry or host | who it belongs to | how often. No value column, because
    for these the identity of the owner IS the finding."""
    name_w = max(24, int(W * 0.42))
    note_w = max(18, W - name_w - 13)
    for r in rows:
        mark = c("1;31", "!") if r["tier"] == FLAG else " "
        if cat == "KEYCHAIN":
            top = r["values"].most_common(1)
            note = keychain_owner(r["key"], top[0][0] if top else "")
        else:
            note = r["label"]
        p("  %s %-*s %s %s" % (
            mark, name_w, clip(r["key"], name_w),
            c(DIM, "%-*s" % (note_w, clip(note, note_w))),
            c(DIM, "%4dx" % r["count"])))
        if cat == "REQUEST":
            for sample, _n in r["values"].most_common(2):
                p("      " + c(DIM, clip(sample, W - 8)))


def render_destinations(p, rows, all_items):
    """Three ways of seeing the same thing: full URLs where Apple's networking
    was used, raw sockets where it was not, and the name lookups that let us put
    a hostname back on those raw addresses."""
    urls = [r for r in rows if r.get("src") == "REQUEST"]
    # a TCP connect, a UDP datagram and a peer read are three ways of learning
    # the same fact, and leaving the last two out made the app look TCP-only
    socks = [r for r in rows if r.get("src") in ("CONNECT", "PEER", "UDP_PEER")]
    headers = [r for r in rows if r.get("src") == "HEADER"]
    bodies = [r for r in rows if r.get("src") == "BODY"]
    # an address handed to getaddrinfo resolves to itself, which is not a name
    dns = [r for r in rows if r.get("src") == "DNS" and not is_ip_literal(r["key"])]
    # the same call with a literal address is not a lookup, it is the app
    # confirming an address it already had from somewhere this rig cannot see
    literal = [r for r in rows if r.get("src") == "DNS" and is_ip_literal(r["key"])]
    # measured rather than inferred: the caller set AI_NUMERICHOST, so it was
    # testing a string it already held, not asking for a name to be resolved
    numeric = [r for r in rows if r.get("src") == "DNS_NUMERIC"]
    udp = {norm_addr(r["key"]) for r in rows if r.get("src") == "SOCKTYPE"}
    httpdns = [r for r in rows if r.get("src") == "HTTPDNS"]
    sni = [r for r in rows if r.get("src") == "SNI"]
    nwep = [r for r in rows if r.get("src") == "NW_ENDPOINT"]
    failed = [r for r in rows if r.get("src") in ("CONNECT_FAIL", "DNS_FAIL")]
    cnames = [r for r in rows if r.get("src") == "DNS_CNAME"]

    # address -> the name it was resolved from
    ip2host = {}
    for r in dns:
        for addr in r["values"]:
            ip2host.setdefault(norm_addr(addr), r["key"])
    for r in [x for x in rows if x.get("src") == "DNS_REVERSE"]:
        for name in r["values"]:
            ip2host.setdefault(norm_addr(r["key"]), name)
    for r in httpdns:
        for addr in r["values"]:
            ip2host.setdefault(norm_addr(addr), r["key"])

    name_w = max(24, int(W * 0.40))
    note_w = max(18, W - name_w - 13)

    def line(tier, name, note, count):
        p("  %s %-*s %s %s" % (
            c("1;31", "!") if tier == FLAG else " ",
            name_w, clip(name, name_w),
            c(DIM, "%-*s" % (note_w, clip(note, note_w))),
            c(DIM, "%4dx" % count)))

    if urls:
        p("    " + c(DIM, "through Apple's networking, so the full URL is visible:"))
        for r in sorted(urls, key=lambda r: (0 if r["tier"] == FLAG else 1, -r["count"])):
            line(r["tier"], r["key"], r["label"], r["count"])
            for sample, _n in r["values"].most_common(1):
                p("      " + c(DIM, clip(sample, W - 8)))
        p("")

    if socks:
        p("    " + c(DIM, "raw sockets, including the traffic that never touches it:"))
        annotated, masked = [], 0
        for r in socks:
            addr = norm_addr(r["key"])
            host = ip2host.get(addr)
            kind = addr_kind(addr)[0]
            if host:
                owner, what, tier = classify_host(host)
                note, tier = "%s, %s" % (host, owner), tier
            elif addr in RESOLVERS:
                note, tier = "%s, queried directly" % RESOLVERS[addr], FLAG
            elif kind == "benchmark range":
                # a local proxy in fake-IP mode answers with a stand-in address
                # and keeps the real destination to itself
                note, tier = "stand-in address from the on-device proxy", WATCH
                masked += r["count"]
            elif kind == "loopback":
                note, tier = "a listener on the phone itself, the proxy", WATCH
                masked += r["count"]
            else:
                note, tier = "not resolved during this window", WATCH
            # UDP is where QUIC and STUN live, and neither shows up in connect()
            via = {"UDP_PEER": "UDP", "PEER": "connected socket"}.get(r.get("src"))
            if addr in udp:
                via = "QUIC"
            if via:
                note = "%s, %s" % (via, note)
            annotated.append((tier, addr, note, r["count"]))
        for tier, addr, note, count in sorted(
                annotated, key=lambda x: (0 if x[0] == FLAG else 1, -x[3])):
            line(tier, addr, note, count)
        if masked:
            p("")
            for ln in wrap("%d of those connections went to the VPN client running on this "
                           "phone rather than straight out. It substitutes its own addresses "
                           "and forwards the traffic itself, so the real destination behind "
                           "them is not visible from inside the app." % masked, W - 6):
                p("    " + c(DIM, ln))
        p("")

    if dns:
        p("    " + c(DIM, "names it looked up, and what each one appears to be for:"))
        for r in sorted(dns, key=lambda r: (0 if r["tier"] == FLAG else 1, -r["count"])):
            owner, what, _t = classify_host(r["key"])
            role = endpoint_role(r["key"])
            note = "%s, %s" % (owner, role) if role else "%s, %s" % (owner, what)
            line(r["tier"], r["key"], note, r["count"])
        for r in sorted(cnames, key=lambda r: -r["count"])[:8]:
            for canon, _n in r["values"].most_common(1):
                p("      " + c(DIM, clip("%s is really %s" % (r["key"], canon), W - 8)))
        p("")

    if literal:
        p("    " + c(DIM, "addresses it asked the resolver to confirm, "
                          "having got them somewhere else:"))
        for r in sorted(literal, key=lambda r: -r["count"])[:20]:
            addr = norm_addr(r["key"])
            line(WATCH, addr, "no name was ever looked up for this", r["count"])
        proof = (" The hint flags on those calls say AI_NUMERICHOST, so this is "
                 "measured, not inferred: the app was checking a string it already "
                 "held rather than asking for a lookup." if numeric else "")
        for ln in wrap("A literal address handed to getaddrinfo is not a lookup. The app "
                       "already knew the address, which means it came from a channel this "
                       "rig does not watch: a server-pushed list or a resolver of its own "
                       "reached over HTTPS." + proof, W - 6):
            p("    " + c(DIM, ln))
        p("")

    if httpdns:
        p("    " + c(DIM, "names resolved by ByteDance's own resolver, not by the phone's:"))
        for r in sorted(httpdns, key=lambda r: -r["count"]):
            line(r["tier"], r["key"], ", ".join(sorted(r["values"]))[:60], r["count"])
        for ln in wrap("These never went near the system resolver, so nothing in the phone's "
                       "DNS settings applies to them and nothing on the device chose the "
                       "address. The same reply is what carries the client's own public "
                       "address back to the app.", W - 6):
            p("    " + c(DIM, ln))
        p("")

    if sni:
        p("    " + c(DIM, "hostnames read off the TLS handshake, before any encryption:"))
        for r in sorted(sni, key=lambda r: (0 if r["tier"] == FLAG else 1, -r["count"])):
            owner, what, _t = classify_host(r["key"])
            line(r["tier"], r["key"], "%s, %s" % (owner, what), r["count"])
        p("")

    if nwep:
        p("    " + c(DIM, "endpoints opened through Network.framework, which "
                          "bypasses all of the above:"))
        for r in sorted(nwep, key=lambda r: -r["count"])[:20]:
            kind = r["values"].most_common(1)[0][0] if r["values"] else "endpoint"
            line(r["tier"], r["key"], kind, r["count"])
        p("")

    if failed:
        p("    " + c(DIM, "asked for and did not get:"))
        for r in sorted(failed, key=lambda r: -r["count"])[:16]:
            why = r["values"].most_common(1)[0][0] if r["values"] else "failed"
            line(INFO, r["key"], why, r["count"])
        p("")

    # The residual. Every address the phone connected to that no resolver this
    # rig watches ever produced. It is not an inference about a mechanism: it is
    # the arithmetic of two sets the run already collected, and it is the
    # cleanest measure of how much resolution happens somewhere else.
    resolved = set()
    for r in dns:
        for a in r["values"]:
            resolved.add(norm_addr(a))
    for r in httpdns:                       # resolved, just not by the phone
        for a in r["values"]:
            resolved.add(norm_addr(a))
    reached = set()
    for r in socks:
        a = norm_addr(r["key"])
        if addr_kind(a)[2] and not a.startswith("127."):
            reached.add(a)
    # An endpoint Network.framework opened by address counts as reached too, and
    # it is the path least likely to have gone through the system resolver.
    for r in nwep:
        if "address" not in r["values"]:
            continue
        try:
            ipaddress.ip_address(r["key"].split("%")[0])
        except ValueError:
            continue
        a = norm_addr(r["key"])
        if addr_kind(a)[2] and not a.startswith("127."):
            reached.add(a)
    own = {norm_addr(a) for r in all_items if r.get("src") == "INTERFACE"
           for a in r["values"]}
    reached -= own                      # the phone's own address is not a peer
    failed_addrs = {norm_addr(r["key"]) for r in rows if r.get("src") == "CONNECT_FAIL"}
    residual = sorted(reached - resolved - failed_addrs)
    if reached:
        p("    " + c(DIM, "resolution, reconciled:"))
        line(FLAG if residual else INFO,
             "%d of %d addresses reached" % (len(residual), len(reached)),
             "were never produced by any resolver this run watched", len(reached))
        if residual:
            for ln in wrap("Those are: " + ", ".join(residual[:12])
                           + (", and %d more" % (len(residual) - 12) if len(residual) > 12
                              else "") + ". Something told the app where to connect, and "
                           "it was not the system resolver, so it is not visible from "
                           "inside the app's own syscalls.", W - 6):
                p("    " + c(DIM, ln))
        p("")

    # ByteDance's signing headers are the interesting ones, so surface them
    SIGNING = {"x-argus": "ByteDance request signature",
               "x-gorgon": "ByteDance request signature",
               "x-khronos": "ByteDance request timestamp",
               "x-ladon": "ByteDance request signature",
               "x-ss-stub": "ByteDance body checksum",
               "x-tt-token": "TikTok session token",
               "cookie": "stored cookies riding along",
               "x-tt-trace-id": "request trace identifier"}
    if headers:
        p("")
        p("    " + c(DIM, "request headers seen, names only:"))
        known = sorted((r for r in headers if r["key"].lower() in SIGNING),
                       key=lambda r: -r["count"])
        for r in known:
            line(FLAG, r["key"], SIGNING[r["key"].lower()], r["count"])
        other = sorted((r["key"] for r in headers if r["key"].lower() not in SIGNING))
        if other:
            for ln in wrap("other headers: " + ", ".join(other), W - 6):
                p("      " + c(DIM, ln))

    if bodies:
        p("")
        p("    " + c(DIM, "request bodies, size and a short preview only:"))
        for r in sorted(bodies, key=lambda r: -r["count"]):
            for sample, _n in r["values"].most_common(1):
                p("      " + c(DIM, clip("%s  %s" % (r["key"], sample), W - 8)))

    plain = [r for r in rows if r.get("src") == "PLAINTEXT"]
    if plain:
        p("")
        p("  " + c("1;31", "!") + " " + c(DIM,
          "request lines captured BEFORE encryption, straight off TikTok's own TLS:"))
        for r in sorted(plain, key=lambda r: -r["count"]):
            p("      " + clip(r["key"], W - 8) + c(DIM, "  %dx" % r["count"]))
            what = plaintext_meaning(r["key"])
            if what:
                p("        " + c(DIM, what))

    resp = [r for r in rows if r.get("src") == "RESPONSE"]
    if resp:
        p("")
        p("  " + c("1;31", "!") + " " + c(DIM,
          "responses captured AFTER decryption, what the servers sent back:"))
        # JSON payloads first, they carry more than a bare status line
        for r in sorted(resp, key=lambda r: (0 if r["key"].startswith("JSON") else 1,
                                             -r["count"])):
            p("      " + clip(r["key"], W - 8) + c(DIM, "  %dx" % r["count"]))


# ---- panel rendering (the boxed "Panels" layout) ------------------------------
_ANSI_RE = re.compile("\x1b\\[[0-9;]*m")
_BOX = ("╭", "╮", "╰", "╯", "─", "│") if UNI else ("+", "+", "+", "+", "-", "|")


def vislen(s):
    """Visible width, ignoring ANSI colour codes."""
    return len(_ANSI_RE.sub("", s))


def pad_vis(s, n):
    """Right-pad s to visible width n. If it overflows, clip ANSI-aware (dropping
    colour on the clipped tail is a safe, rare fallback)."""
    v = vislen(s)
    if v < n:
        return s + " " * (n - v)
    if v == n:
        return s
    return _ANSI_RE.sub("", s)[: max(0, n - 1)] + ELL


def panel_top(p, title, tail, color):
    tl, tr, bl, br, h, v = _BOX
    outer = W - 2
    left = tl + h + " " + title + " "
    right = ((tail + " " + h) if tail else h) + tr
    fill = max(1, outer - len(left) - len(right) - (1 if tail else 0))
    body = left + h * fill + ((" " + right) if tail else right)
    p("  " + c(color, body))


def panel_row(p, content, color):
    _, _, _, _, _, v = _BOX
    interior = (W - 2) - 4
    p("  " + c(color, v) + " " + pad_vis(content, interior) + " " + c(color, v))


def panel_bottom(p, color):
    tl, tr, bl, br, h, v = _BOX
    p("  " + c(color, bl + h * ((W - 2) - 2) + br))


def _capture(mode, rows, cat, items):
    """Run a section's existing renderer into a buffer at a narrowed width, so its
    lines fit inside the box. Returns the content lines with their outer margin
    stripped."""
    global W
    saved = W
    W = max(44, saved - 6)     # leave room for the box walls
    buf = []
    cap = lambda coloured="", plain=None: buf.append(coloured)
    try:
        if mode == "media":
            render_media(cap, rows, items)
        elif mode == "tags":
            render_provenance(cap, rows, items)
        elif mode == "net":
            render_exposure(cap, rows, items)
        elif mode == "dest":
            render_destinations(cap, rows, items)
        elif mode == "applist":
            render_applist(cap, rows)
        elif mode == "pair":
            rows_pair(cap, rows, cat)
        else:
            rows_kv(cap, rows, cat)
    except Exception as e:
        buf.append(c(DIM, "(render error: %s)" % e))
    finally:
        W = saved
    return [ln[2:] if ln.startswith("  ") else ln for ln in buf]


def report(rec, console, meta):
    p = console.line
    items = list(rec.items.values())
    burst = max((r["first"] for r in items), default=0.0)

    # --- summary panel -------------------------------------------------------
    p("")
    if items:
        panel_top(p, "TIKTOK AUDIT", "%d things" % len(items), BOLD)
        # The window that matters is the one the app was ALIVE for, not the one
        # that was asked for. Printing the requested duration next to a process
        # that died a third of the way through is how a 13 second capture got
        # read as a 40 second audit.
        obs = meta.get("observed_s")
        full = obs is None or obs >= meta["duration_s"] - 1.0
        if full:
            panel_row(p, c(DIM, "%d reads in total, last new at %.1fs of a %ds window"
                           % (rec.total, burst, meta["duration_s"])), BOLD)
        else:
            panel_row(p, c("1;31", "%d reads over %.1fs, not the %ds asked for"
                           % (rec.total, obs, meta["duration_s"]))
                      + c(DIM, "   last new at %.1fs" % burst), BOLD)
            panel_row(p, c(DIM, "the app %s, so the rest of the window is not observation"
                           % ("was killed" if meta.get("died_reason") == "process-terminated"
                              else "stopped reporting")), BOLD)
        if meta.get("attached"):
            panel_row(p, c(DIM, "attached to a running app, so the launch sequence is "
                                "outside this capture"), BOLD)
        pic = net_picture(items)
        bits = []
        if pic["tunnels"]:
            bits.append(c("1;31", "VPN up and visible to the app (%s)" % pic["tunnels"][0][0]))
        elif pic["scans"]:
            bits.append("no VPN, connection seen directly")
        if pic["public"]:
            bits.append(c("1;31", "real public address exposed"))
        elif pic["scans"]:
            bits.append("no public address exposed")
        if bits:
            panel_row(p, c(DIM, "network   ") + "   ".join(bits), BOLD)
        # The post line only appears when a post actually happened. A coordinate
        # read out of the file is the one finding that belongs at the very top,
        # because it is a location fix that never touches CLLocationManager and
        # so contradicts the location section sitting empty further down.
        media = [r for r in items if r["cat"] == "MEDIA"]
        if media:
            mbits = []
            if any(is_geotag(r["key"]) for r in media):
                mbits.append(c("1;31", "location read out of the file itself"))
            elif any(r.get("src") == "MEDIA_META" for r in media):
                mbits.append("file metadata read, no location in it")
            if any(r["key"] == "capture session" for r in media):
                mbits.append(c("1;31", "camera or mic opened"))
            ups = [r for r in media if r["key"].startswith("upload to ")]
            if ups:
                mbits.append("%d upload %s"
                             % (len(ups), "target" if len(ups) == 1 else "targets"))
            if mbits:
                panel_row(p, c(DIM, "post      ") + "   ".join(mbits), BOLD)
        panel_bottom(p, BOLD)
    else:
        panel_top(p, "TIKTOK AUDIT", "nothing", BOLD)
        panel_row(p, c(DIM, "nothing captured. check the app launched and you touched the phone."), BOLD)
        panel_bottom(p, BOLD)

    # --- one boxed panel per section ----------------------------------------
    for cat, title, intro, mode in SECTION_SPECS:
        rows = sorted(collapse_groups([r for r in items if r["cat"] == cat]),
                      key=lambda r: (0 if r["tier"] == FLAG else 1, -r["count"], r["key"]))
        if not rows:
            continue
        color = CAT_COLOR.get(cat, "36")          # cyan default so every panel has a hue
        if cat == "EXPOSURE":
            tail = "%d interfaces" % sum(1 for r in rows if r.get("src") == "INTERFACE")
        else:
            tail = "%d" % len(rows)
        p("")
        panel_top(p, title.strip(), tail, color)
        for ln in _capture(mode, rows, cat, items):
            panel_row(p, ln, color)
        panel_bottom(p, color)

    # --- honest limits, kept light and unboxed to close the report ----------
    extra = []
    if meta.get("died_reason") == "process-terminated":
        extra.append(
            "Anything after %.1fs. iOS killed the app there, so the remaining %.0fs of "
            "the window recorded nothing and no absence below should be read as proof."
            % (meta.get("observed_s") or 0.0,
               max(0.0, meta["duration_s"] - (meta.get("observed_s") or 0.0))))
    if meta.get("attached"):
        extra.append(
            "The launch sequence. This run attached to an app that was already open, "
            "which is what keeps iOS from killing it, but the first seconds of a cold "
            "start are where most identifier reads happen.")
    if meta.get("probes"):
        calls = meta.get("probe_calls") or {}
        idle = [g for g in meta["probes"] if calls.get(g, 0) == 0]
        extra.append(
            "Most of what the %s %s could have seen. Each attaches for well under a "
            "second at a time, %d %s in this run, because keeping them on is what made "
            "iOS kill the app. They prove a mechanism is used, never how often."
            % (", ".join(meta["probes"]),
               "probe" if len(meta["probes"]) == 1 else "probes",
               meta.get("probe_passes") or 0,
               "pass" if (meta.get("probe_passes") or 0) == 1 else "passes"))
        if idle:
            extra.append(
                "Anything the %s %s would have caught. %s armed correctly and saw ZERO "
                "calls, which means the app was idle in those windows, not that it never "
                "does these things. Raw-socket and TLS work clusters in the first ten "
                "seconds, which is under the launch watchdog and cannot be sampled "
                "safely. Scroll the feed while the probes run, or use -Attach on an app "
                "you are already using."
                % (", ".join(idle), "probe" if len(idle) == 1 else "probes",
                   "It" if len(idle) == 1 else "They"))
    p("")
    p("  " + c(DIM, "not shown"))
    for line in extra + caveats(items, rec):
        for i, ln in enumerate(wrap(line, W - 6)):
            p("  " + ("  " if i else c(DIM, MARK + " ")) + c(DIM, ln))
    p("")


def wrap(text, width):
    words, out, cur = text.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            out.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    if cur:
        out.append(cur)
    return out


def caveats(items, rec=None):
    """The honest limits. Without these the sections above read as a total,
    which they are not."""
    out = []
    if rec is not None and rec.caps:
        # Two very different things end a probe, and only one of them means the
        # number shown is a floor. A SAMPLE cap ("400") means the calls kept
        # coming and we stopped counting. A WINDOW cap ("800ms") means the probe
        # simply ran out of its slot, which says nothing about the true rate and
        # is already covered by the probe caveat. Listing both put fifty lines of
        # "the real one is higher" under hooks that saw nothing at all.
        floors = {k: v for k, v in rec.caps.items() if not str(v).endswith("ms")}
        windowed = [k for k, v in rec.caps.items() if str(v).endswith("ms")]
        for label, limit in sorted(floors.items()):
            out.append("Exact counts for %s. It stopped counting at %s to keep the app "
                       "responsive, so that number is a floor and the real one is higher."
                       % (label, limit))
        if windowed:
            out.append("Rates for %d other %s. They ran for a fixed slice of time rather "
                       "than to a call limit, so their counts are what happened in that "
                       "slice and imply nothing about the rest of the run."
                       % (len(windowed), "hook" if len(windowed) == 1 else "hooks"))
    missed = sorted(v for r in items if r["cat"] == "RIG"
                    and r["key"] == "post-path hook NOT attached" for v in r["values"])
    if missed:
        out.append("Anything these post-path hooks would have caught, because they never "
                   "attached: " + ", ".join(missed) + ". A hook that failed and a mechanism "
                   "the app never used look identical from here, and only one of them is a "
                   "finding.")
    if rec is not None and rec.truncated:
        out.append("Some kinds of event beyond the safety ceiling. The capture stops "
                   "recording new ones rather than growing without bound.")
    if not items:
        out.append("Nothing was captured at all. Check the app actually launched and that "
                   "you interacted with the phone during the window.")
        return out

    out.append("What was inside any of it. Destinations are captured at the socket, so "
               "TikTok's own traffic is included now, but the contents stay encrypted and "
               "this makes no attempt to open them.")
    if any(r.get("src") == "PUBLIC_IP" for r in items):
        out.append("Nothing, on this one. The public address usually cannot be read from the "
                   "phone, but this run caught the app being told it by the resolver it "
                   "asked, so it is in the report above rather than missing from it.")
    else:
        out.append("The public IP its servers recorded. That is observed at their end, not "
                   "readable from the phone. The measured source address above tells you "
                   "which connection carried the traffic that produced it. An app can still "
                   "learn it by being told: a resolver that echoes the client address back "
                   "would put it in the app's hands, and this run saw no such reply.")
    if any(r.get("src") == "CONNECT" and addr_kind(r["key"])[0]
           in ("benchmark range", "loopback") for r in items):
        out.append("The real destination behind the VPN client. With a proxy running on "
                   "the phone the app connects to a stand-in address and the client "
                   "forwards it, so the far end is not visible from inside the app.")
    if not any(r["cat"] == "LOCATION" for r in items):
        if any(r["cat"] == "MEDIA" and is_geotag(r["key"]) for r in items):
            # saying "no location" here while the post section reports a
            # coordinate read out of the file would be the report contradicting
            # itself, and the file route is the one that needs no permission
            out.append("Location asked of the OS. The app made no CLLocationManager calls, "
                       "but it DID read a position out of a media file, which is listed "
                       "above and needs no permission. Absence here is not absence of "
                       "location.")
        else:
            out.append("Location. The app made no location calls this run, which is not "
                       "proof it never asks, only that it did not while being watched.")
    if not any(r["cat"] == "MEDIA" for r in items):
        out.append("Anything about a post. The picker, capture-session, encoder, file "
                   "metadata and upload hooks are live in every run and not one of them "
                   "fired, so nothing was recorded, picked or uploaded while being "
                   "watched. Post something during the window to exercise that path.")
    out.append("Which of the values above rode along in which request. Reads and "
               "connections are both captured, but nothing ties a specific identifier to "
               "a specific outbound packet.")
    out.append("Anything past the safety caps. The script stops recording new kinds of "
               "event once it hits its ceiling, so a runaway hook truncates this report "
               "instead of exhausting the machine running it.")
    out.append("Anything the app never got round to. Watching, messaging or paying each "
               "open behaviour that never ran here.")
    out.append("Full transcript in %s, machine-readable in %s." % (LOG_PATH, JSON_PATH))
    return out


def dump_json(rec, meta):
    data = {
        "target": BUNDLE,
        "meta": meta,
        "total_calls": rec.total,
        "distinct": len(rec.items),
        "events": [
            {
                "category": r["cat"], "key": r["key"], "label": r["label"],
                "tier": r["tier"], "count": r["count"],
                "first_seen_s": round(r["first"], 3), "last_seen_s": round(r["last"], 3),
                "values": dict(r["values"]),
            }
            for r in sorted(rec.items.values(), key=lambda r: (r["cat"], -r["count"]))
        ],
    }
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    write_tags(rec, meta)


def write_tags(rec, meta):
    """The diffable sidecar. audit.json is the whole run and is shaped for a
    human to read once. This is one flat sorted mapping of tag to value, which
    is the only shape that survives being compared against five other runs
    without the comparison drowning in structure."""
    tags, files = {}, {}
    for r in rec.items.values():
        if r["src"] == "MEDIA_TAG":
            vals = sorted(r["values"])
            tags[r["key"]] = {
                "value": vals[0] if len(vals) == 1 else (vals or None),
                "reads": r["count"],
                "first_seen_s": round(r["first"], 3),
            }
        elif r["src"] == "MEDIA_FILE":
            files[r["key"]] = sorted(r["values"])
    data = {
        "run": meta,
        "marks": [{"label": k, "at": v} for k, v in rec.marks],
        "files": files,
        "bodies": [{"file": f, "from": n, "bytes": b} for f, n, b in rec.blob_index],
        "tag_count": len(tags),
        "tags": {k: tags[k] for k in sorted(tags)},
    }
    with open(TAGS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def make_message_handler(rec, console, errors, last_beat, armed, probe_log, probe_calls):
    """Build the frida message callback.

    This is a factory rather than a closure inside main() for one reason: main()
    opens a USB device on its second line, so anything nested in it can only be
    exercised with a phone attached. Every decision about what a row MEANS lives
    in here, which makes it the part most worth testing on a laptop. selftest.py
    replays a recorded batch through this exact function."""

    def on_message(msg, data):
        t = msg.get("type")
        if t == "send":
            last_beat[0] = time.time()
            armed[0] = True
            pl = msg.get("payload") or {}
            # Request bodies ride beside the batch rather than through the tally,
            # because the tally is a counter keyed by string and a body is
            # neither short nor repeated. Written out whole so the publish call
            # can be read after the fact.
            for blob in pl.get("blobs") or []:
                try:
                    rec.write_blob(blob.get("n") or "body", blob.get("b") or "")
                except Exception as e:
                    errors.append("blob: %s" % e)
            if "b" not in pl:
                return
            if pl.get("capped"):
                rec.truncated = True
                rec.dropped = max(rec.dropped, int(pl.get("dropped") or 0))
            for row in pl.get("b") or []:
                try:
                    cat, key, value, count, first_ms = row
                except (ValueError, TypeError):
                    continue
                if cat == "READY":
                    continue
                if cat == "ERROR":
                    errors.append("%s: %s" % (key, value))
                    continue
                if cat == "CAPPED":
                    # the hook stopped counting, so the number it reported is a
                    # floor. Saying so beats printing it as if it were exact.
                    rec.caps[key] = value
                    continue
                if cat == "PROBE":
                    # scheduling diagnostics, not a finding about the phone.
                    # "group|label saw N calls" also tells us whether a probe
                    # window landed on a busy app or on dead air.
                    probe_log.append("%s %s" % (key, value))
                    if "|" in key and "saw " in (value or ""):
                        grp = key.split("|", 1)[0]
                        try:
                            probe_calls[grp] = probe_calls.get(grp, 0) + int(
                                value.split("saw ", 1)[1].split()[0])
                        except (ValueError, IndexError):
                            pass
                    continue
                if cat == "NOTE":
                    continue
                if cat == "MARK":
                    # a boundary the operator dropped between two posts in one
                    # run. Not a finding, but it is what lets the counts either
                    # side of it be told apart.
                    rec.marks.append((key, value))
                    console.line(c(BOLD, "  -- mark: %s (%s)" % (key, value)))
                    continue
                rec.apply(cat, key or "?", value or None, count, first_ms / 1000.0)
        elif t == "error":
            errors.append(msg.get("stack", msg.get("description", "?")))
        elif t == "log":
            console.line(c(DIM, "  " + str(msg.get("payload", ""))))

    return on_message


def main():
    console = Console(LOG_PATH)
    rec = Recorder(console)
    errors = []
    last_beat = [time.time()]   # wall time of the last message from the phone
    armed = [False]             # watchdog waits for the first message before judging
    probe_log = []              # which groups actually attached, for the footer
    probe_calls = {}            # group -> calls its hooks actually saw
    on_message = make_message_handler(rec, console, errors, last_beat, armed,
                                      probe_log, probe_calls)

    dev = frida.get_usb_device(timeout=8)
    with open("observe.compiled.js", "r", encoding="utf-8") as f:
        src = f.read()
    # No source rewriting any more. Which hooks run is decided at RUNTIME, by the
    # driver calling arm() over rpc, so the compiled bundle ships byte for byte as
    # frida-compile produced it and the old length-preserving digit-flip hack (and
    # the "malformed package" class of failure it invited) is gone.
    #
    # Spawn + load, with a couple of retries. "connection is closed" here usually
    # means frida-server on the phone is recovering (often right after a previous
    # rough run) or the app died on launch; a fresh spawn commonly succeeds.
    pid = session = script = None
    last_err = None
    spawned = not ATTACH_ON
    for attempt in range(3):
        try:
            if ATTACH_ON:
                # attach to the running app: no scene-create watchdog to violate,
                # because the scene is already up before we touch anything.
                # Match on the bundle identifier, not the process name: get_process
                # matches names ("TikTok") and would miss com.zhiliaoapp.musically.
                app = next((a for a in dev.enumerate_applications()
                            if a.identifier == BUNDLE), None)
                if app is None or not app.pid:
                    raise frida.ProcessNotFoundError(BUNDLE)
                pid = app.pid
                session = dev.attach(pid)
            else:
                pid = dev.spawn([BUNDLE])
                session = dev.attach(pid)
            script = session.create_script(src)
            script.on("message", on_message)
            script.load()
            last_err = None
            break
        except frida.ProcessNotFoundError as e:
            sys.stderr.write(
                "\n[attach failed] TikTok is not running.\n"
                "  -Attach instruments an app that is already open. Launch TikTok\n"
                "  on the phone, wait for the feed, then run this again.\n")
            raise SystemExit(1)
        except (frida.TransportError, frida.InvalidOperationError,
                frida.ProcessNotRespondingError) as e:
            last_err = e
            try:
                if pid and spawned:
                    dev.kill(pid)
            except Exception:
                pass
            time.sleep(1.5)
    if last_err is not None:
        sys.stderr.write(
            "\n[load failed] %s\n"
            "  This is a phone-side problem, not the host. Try, in order:\n"
            "   1. force-quit TikTok on the phone, then run again\n"
            "   2. restart frida-server on the phone (or reboot + re-jailbreak)\n"
            "   3. confirm the link is alive:  .\\.venv\\Scripts\\frida-ps.exe -U\n"
            % last_err)
        raise SystemExit(1)

    ident = None
    try:
        ident = script.exports_sync
    except Exception:
        pass

    # ----- know when the app dies -----
    # Without this a terminated process and an idle one look identical to the
    # driver, so it keeps counting down a window in which nothing is left alive
    # to observe, and then prints the result as if it were a full observation.
    # That is how a run that was killed by iOS at 12.9s got reported as a clean
    # 40 second audit. frida fires 'detached' with a reason; the reason that
    # matters is process-terminated.
    died = {"reason": None, "t": None}

    def on_detached(*a):
        if died["reason"] is None:
            died["reason"] = str(a[0]) if a else "unknown"
            died["t"] = time.time()

    try:
        session.on("detached", on_detached)
    except Exception:
        pass

    # ----- self-kill watchdog: an independent liveness guard -----
    # Runs as a daemon thread. Every 0.5s it stamps a heartbeat file (which the
    # external supervisor also watches) and checks how long the phone has been
    # silent. If that exceeds STUCK_S the USB link has wedged, so it hard-exits
    # the whole process with os._exit, which is a raw syscall that fires even
    # while the main thread is stuck inside a native Frida call. This is the
    # layer that guarantees a hung run dies on its own instead of freezing on.
    hb_path = os.path.join(os.getcwd(), "audit.heartbeat")
    stop_watch = threading.Event()

    def _watchdog():
        while not stop_watch.wait(0.5):
            now = time.time()
            silence = now - last_beat[0]
            try:
                with open(hb_path, "w") as hf:
                    hf.write("%.3f %.3f" % (now, silence))
            except Exception:
                pass
            if armed[0] and silence > STUCK_S:
                sys.stderr.write(
                    "\n[watchdog] phone silent %.1fs, the link wedged. Hard-exiting "
                    "to free the machine.\n" % silence)
                sys.stderr.flush()
                os._exit(2)

    threading.Thread(target=_watchdog, daemon=True).start()

    console.line("")
    console.line("  " + c(BOLD, "TIKTOK PRIVACY AUDIT"))
    console.line("  " + c(DIM, "read-only. nothing on the device is modified, spoofed or blocked."))
    console.line("")
    console.line("  " + c(DIM, "%-9s" % "target") + BUNDLE + c(DIM, "  pid %d" % pid))
    console.line("  " + c(DIM, "%-9s" % "device") + str(dev.name))
    console.line("  " + c(DIM, "%-9s" % "window") + "%ds" % DURATION)
    if PUBLISH_ON:
        mode = c("1;33", "PUBLISH") + c(DIM, "  (one SSL_write hook, left up for the window)")
    elif PROBE_PLAN:
        mode = c("1;31", "FULL") + c(DIM, "  (%s, armed one at a time after launch)"
                                     % ", ".join(g for g, _ in PROBE_PLAN))
    else:
        mode = c("1;32", "safe") + c(DIM, "  (always-on hooks only)")
    console.line("  " + c(DIM, "%-9s" % "mode") + mode)
    if ATTACH_ON:
        console.line("  " + c(DIM, "%-9s" % "") + c(DIM, "attached to the running app, launch not observed"))
    console.line("")
    if LIVE:
        console.line("  " + c(DIM, RULE * (W - 2)))
        console.line("  " + c(DIM, "one line per NEW thing TikTok touches. repeats are counted, not printed."))
        console.line("  " + c(DIM, "scroll the feed on the phone to exercise more of the app."))
        console.line("  " + c(DIM, RULE * (W - 2)))
    else:
        console.line("  " + c(DIM, "watching for %ds. scroll the feed on the phone. the report prints below." % DURATION))
    console.line("")

    if not ATTACH_ON:
        dev.resume(pid)
    rec.t0 = time.time()
    last_beat[0] = time.time()
    # Stamp the phone-side clock the moment the app is actually running. The base
    # probes hold no deadline until this lands, because a spawn-paused process
    # burns no wall-clock time and must not burn its sample either.
    try:
        script.exports_sync.start()
    except Exception:
        pass

    sched = probe_schedule(PROBE_PLAN, DURATION)
    if PROBE_PLAN and not sched:
        console.line("  " + c("1;33", "note: ") + c(DIM,
            "the window is %ds, too short to arm a single probe pass (needs about "
            "%.0fs). Running with the always-on hooks only."
            % (DURATION, probe_min_duration(PROBE_PLAN))))
        console.line("")
    elif sched:
        rounds = len(sched) // max(1, len(PROBE_PLAN))
        console.line("  " + c(DIM, "%-9s" % "probes") + c(DIM,
            "%d %s from %.0fs. scroll the feed while they run, that is when the "
            "network hooks can see anything."
            % (rounds, "pass" if rounds == 1 else "passes", PROBE_SETTLE_S)))
        console.line("")
    next_arm, pending = 0, None
    swept, swept_wan = [False], [False]

    # The phone-side script flushes every 400ms, empty batch or not, so a silence
    # longer than this means it has wedged. Rather than let a hung frida-server
    # drag the host down, we abort and free everything. This is the host-side half
    # of the safety story, the self-detaching hooks being the phone-side half.
    WATCHDOG_S = 5.0
    aborted = False

    try:
        while True:
            elapsed = time.time() - rec.t0
            if died["reason"]:
                break
            if elapsed >= DURATION:
                break
            if time.time() - last_beat[0] > WATCHDOG_S:
                aborted = True
                break

            # --- probe schedule -------------------------------------------
            # Arming is a host-side decision so the sequencing cannot be starved
            # by the phone's script thread. The phone still enforces its own
            # inline cutoffs, so a group that never hears the disarm still dies.
            if pending is None and next_arm < len(sched) and elapsed >= sched[next_arm][0]:
                pending = sched[next_arm]
                try:
                    script.exports_sync.arm(pending[2], pending[3])
                except Exception:
                    pass
            elif pending is not None and elapsed >= pending[1]:
                try:
                    script.exports_sync.disarm(pending[2])
                except Exception:
                    pass
                pending = None
                next_arm += 1

            # --- capability sweep, once ------------------------------------
            # Runs on the phone's script thread, not an app thread, and holds
            # the self-read flag throughout so none of it lands in the counts
            # above as something TikTok did.
            if REACH_ON and not swept[0] and elapsed >= REACH_AT_S:
                swept[0] = True
                try:
                    script.exports_sync.reach(WAN_ON)
                except Exception as e:
                    errors.append(("REACH", "capability sweep failed: %s" % e))

            if (REACH_ON and WAN_ON and not swept_wan[0]
                    and elapsed >= REACH_WAN_AT_S):
                swept_wan[0] = True
                try:
                    script.exports_sync.reachwan()
                except Exception as e:
                    errors.append(("REACH", "direct address probe failed: %s" % e))

            filled = int(24 * elapsed / DURATION)
            bar = BAR_ON * filled + BAR_OFF * (24 - filled)
            probing = c("1;33", "  probing %s" % pending[2]) if pending else ""
            console.set_footer("  %s  %s  %s%s" % (
                c("1;32", bar),
                c(DIM, "%2ds / %ds" % (int(elapsed), DURATION)),
                c(DIM, "%d calls, %d distinct" % (rec.total, len(rec.items))),
                probing,
            ))
            time.sleep(0.2)
    except KeyboardInterrupt:
        console.line("")
        console.line("  " + c(DIM, "stopped early, reporting on what was captured."))

    if died["reason"]:
        observed = max(0.0, died["t"] - rec.t0)
    elif aborted:
        observed = max(0.0, last_beat[0] - rec.t0)
    else:
        observed = time.time() - rec.t0

    if died["reason"]:
        console.drop_footer()
        console.line("")
        if died["reason"] == "process-terminated":
            console.line("  " + c("1;31", "the app died ") + c(DIM,
                "%.1fs into a %ds window. iOS kills TikTok when instrumentation makes "
                "it miss a scene deadline. Everything below is what was seen before "
                "that, and nothing after." % (observed, DURATION)))
        else:
            console.line("  " + c("1;31", "session ended early ") + c(DIM,
                "at %.1fs of %ds (%s)." % (observed, DURATION, died["reason"])))

    if aborted:
        console.drop_footer()
        console.line("")
        console.line("  " + c("1;31", "watchdog: ") + c(DIM,
            "the phone went silent for %ds, so the session was cut short to protect "
            "this machine. Reporting on what was captured before that." % int(WATCHDOG_S)))
        try:
            session.detach()
        except Exception:
            pass

    console.drop_footer()
    # tear every probe down before we let go, then ask for one last batch so the
    # final 400ms is not lost. Both are skipped when the session is already gone.
    if not aborted and not died["reason"]:
        try:
            script.exports_sync.disarmall()
        except Exception:
            pass
        try:
            script.exports_sync.flush()
            time.sleep(0.3)
        except Exception:
            pass
    rec.flush()
    stop_watch.set()   # normal exit: stop the self-kill watchdog
    try:
        os.remove(hb_path)
    except Exception:
        pass
    try:
        session.detach()
    except Exception:
        pass

    meta = {"window": "%ds window" % DURATION, "duration_s": DURATION,
            "device": str(dev.name), "pid": pid,
            "observed_s": round(observed, 1),
            "died_reason": died["reason"],
            "attached": bool(ATTACH_ON),
            "probes": [g for g, _ in PROBE_PLAN],
            "probe_calls": dict(probe_calls),
            "probe_passes": (len(probe_log and [x for x in probe_log if "armed" in x])
                             // max(1, len(PROBE_PLAN))),
            "probe_log": list(probe_log)}
    if probe_log and VERBOSE:
        console.line("")
        for ln in probe_log:
            console.line("  " + c(DIM, "probe  " + ln))
    report(rec, console, meta)
    if errors:
        console.line("  " + c(DIM, "hook errors: " + "; ".join(errors[:3])))
        console.line("")
    dump_json(rec, meta)
    console.close()


if __name__ == "__main__":
    main()
