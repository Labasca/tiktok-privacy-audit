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

# run from the script's own directory so observe.compiled.js resolves anywhere
os.chdir(os.path.dirname(os.path.abspath(__file__)))

BUNDLE = "com.zhiliaoapp.musically"
DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 40
LOG_PATH = "session.log"
JSON_PATH = "audit.json"
# Last line of defence. The script already caps what it records and batches what
# it sends, but a bug on either side must never be able to grow this process
# without bound. Exceeding it truncates the report rather than the machine.
MAX_ITEMS = 4000

def _flag(name):
    return os.environ.get(name, "") not in ("", "0", "false", "no")


# Default is the known-safe hook set, which loads reliably. The hot hooks (raw
# syscalls, TLS payload) are opt-in via TIKTOK_AUDIT_FULL, because turning them
# all on at launch can crash the app before the script even finishes loading,
# and because they are the ones that can wedge the USB link. Use the -Full switch
# on the launcher, which runs the kill layers alongside them.
_FULL = _flag("TIKTOK_AUDIT_FULL")
SYSCALL_ON = _FULL
TLS_ON = _FULL
# Touch provenance (finger vs synthetic, scroll velocity, live motion) sits on the
# per-frame input path. It is its OWN opt-in, separate from -Full, so it can be
# captured without also enabling the raw syscall hooks. Enabled with -Touch.
TOUCH_ON = _flag("TIKTOK_AUDIT_TOUCH")
# The live per-event stream is noise on a repeat run. It is off by default now, the
# boxed report at the end is the product. -Verbose brings the stream back. Either
# way the full stream is always written to session.log.
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
    ("app-analytics-services.com", "Apple", "App Store analytics", WATCH),
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


def net_picture(items):
    """Everything the interface scans revealed, sorted into the questions a
    person actually asks: am I on a VPN, which addresses can it see, is my real
    one leaking."""
    ifaces = [r for r in items if r.get("src") == "INTERFACE"]
    pic = {"tunnels": [], "lan": [], "carrier": [], "public": [], "hotspot": [],
           "scans": 0, "proxy": 0, "n_ifaces": len(ifaces),
           "egress": [], "nwpath": [], "ifenum": 0}
    for r in items:
        if r["key"] == "getifaddrs":
            pic["scans"] = r["count"]
        elif r.get("src") == "PROXY":
            pic["proxy"] += r["count"]
        elif r.get("src") == "EGRESS":
            # a socket bound to loopback never left the phone
            if addr_kind(r["key"])[2]:
                pic["egress"].append(norm_addr(r["key"]))
        elif r.get("src") == "NWPATH":
            answer = r["values"].most_common(1)[0][0] if r["values"] else "?"
            pic["nwpath"].append((r["key"], answer, r["count"]))
        elif r.get("src") == "IFENUM":
            pic["ifenum"] += r["count"]
    for r in ifaces:
        addrs = sorted(r["values"])
        role = iface_role(r["key"])
        routable = [a for a in addrs if addr_kind(a)[2]]
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
    else:
        out.append(("Your real public address", "not exposed",
                    "nothing globally routable on the device"
                    + (", no leak past the tunnel" if pic["tunnels"] else "")))

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
    for suffix, owner, what, tier in HOSTS:
        if h == suffix or h.endswith("." + suffix):
            return owner, what, tier
    # regional domains multiply faster than any suffix list keeps up with
    if any(m in h for m in ("tiktok", "bytedance", "byted", "byteimg", "musical.ly")):
        return "TikTok", "first-party", INFO
    return "unrecognised", "unclassified endpoint", WATCH


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
    if cat == "DNS":
        owner, what, tier = classify_host(key)
        return ("%s, %s" % (owner, what), tier)
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
        return ("MobileGestalt: " + key, WATCH)
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
    return (key, INFO)


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
            "REQUEST": "DEST",
            "CONNECT": "DEST",
            "DNS": "DEST",
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
            "HAPTIC": "INTERACTION"}.get(cat, cat)


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
        self.caps = {}           # hook label -> the limit it stopped at

    @property
    def total(self):
        """Derived, never accumulated: the script sends absolute counts."""
        return sum(r["count"] for r in self.items.values())

    def apply(self, cat, key, value, count, first_s):
        """Counts arrive as absolute totals from the script, not increments, so
        a dropped or duplicated batch cannot skew the numbers."""
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
        if VERBOSE:
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


SECTION_SPECS = [
    ("IDENTITY",    "WHO YOU ARE",                      intro_identity,   "kv"),
    ("PERMS",       "WHAT IT CHECKED YOU HAD ALLOWED",  intro_perms,      "kv"),
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


def render_exposure(p, rows, all_items):
    """What the scans revealed. Interfaces holding only a link-local address
    carry no identifying information, so they collapse to a single line."""
    ifaces = [r for r in rows if r.get("src") == "INTERFACE"]
    addr_w = max(20, W - 58)

    # the answer sheet first, the raw interface list underneath it
    pic = net_picture(all_items)
    q_w, a_w = 24, 26
    note_w = max(24, W - q_w - a_w - 6)
    pad = " " * (q_w + a_w + 4)
    for question, answer, note in net_summary_rows(pic):
        hot = answer.startswith("yes") or "readable straight off" in note
        lines = wrap(note, note_w) or [""]
        if not question and not answer:
            for ln in lines:
                p(pad + c(DIM, ln))
            continue
        p("  %-*s %s %s" % (
            q_w, question,
            (c("1;31", "%-*s" % (a_w, answer)) if hot else "%-*s" % (a_w, answer)),
            c(DIM, lines[0])))
        for ln in lines[1:]:
            p(pad + c(DIM, ln))

    p("")
    p("    " + c(DIM, "every interface those %d scans handed over:" % pic["scans"]))

    live, quiet = [], []
    for r in ifaces:
        routable = sorted([a for a in r["values"] if addr_kind(a)[2]],
                          key=lambda a: (addr_kind(a)[0] != "PUBLIC", a))
        (live if routable else quiet).append((r, routable))

    def sort_key(item):
        r, addrs = item
        return (0 if iface_verdict(r["key"], addrs)[1] == FLAG else 1, r["key"])

    for r, addrs in sorted(live, key=sort_key):
        verdict, tier = iface_verdict(r["key"], addrs)
        mark = c("1;31", "!") if tier == FLAG else " "
        for i, a in enumerate(addrs):
            kind, ktier, _ = addr_kind(a)
            p("  %s %-12s %-22s %-*s %s" % (
                mark if i == 0 else " ",
                r["key"] if i == 0 else "",
                (verdict if i == 0 else "")[:22],
                addr_w, clip(norm_addr(a), addr_w),
                c("1;31", kind) if ktier == FLAG else c(DIM, kind)))

    if quiet:
        names = ", ".join(sorted(r["key"] for r, _ in quiet))
        p("")
        for ln in wrap("%d further interfaces were visible but held only link-local or "
                       "loopback addresses, which identify nothing: %s"
                       % (len(quiet), names), W - 6):
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
    socks = [r for r in rows if r.get("src") == "CONNECT"]
    headers = [r for r in rows if r.get("src") == "HEADER"]
    bodies = [r for r in rows if r.get("src") == "BODY"]
    # an address handed to getaddrinfo resolves to itself, which is not a name
    dns = [r for r in rows if r.get("src") == "DNS" and not is_ip_literal(r["key"])]

    # address -> the name it was resolved from
    ip2host = {}
    for r in dns:
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
        if mode == "net":
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
        panel_row(p, c(DIM, "%d reads in total, last new at %.1fs of a %ds window"
                       % (rec.total, burst, meta["duration_s"])), BOLD)
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
    p("")
    p("  " + c(DIM, "not shown"))
    for line in caveats(items, rec):
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
        for label, limit in sorted(rec.caps.items()):
            out.append("Exact counts for %s. It stopped counting at %s to keep the app "
                       "responsive, so that number is a floor and the real one is higher."
                       % (label, limit))
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
    out.append("The public IP its servers recorded. That is observed at their end, not "
               "readable from the phone. The measured source address above tells you which "
               "connection carried the traffic that produced it.")
    if any(r.get("src") == "CONNECT" and addr_kind(r["key"])[0]
           in ("benchmark range", "loopback") for r in items):
        out.append("The real destination behind the VPN client. With a proxy running on "
                   "the phone the app connects to a stand-in address and the client "
                   "forwards it, so the far end is not visible from inside the app.")
    if not any(r["cat"] == "LOCATION" for r in items):
        out.append("Location. The app made no location calls this run, which is not proof "
                   "it never asks, only that it did not while being watched.")
    out.append("Which of the values above rode along in which request. Reads and "
               "connections are both captured, but nothing ties a specific identifier to "
               "a specific outbound packet.")
    out.append("Anything past the safety caps. The script stops recording new kinds of "
               "event once it hits its ceiling, so a runaway hook truncates this report "
               "instead of exhausting the machine running it.")
    out.append("Anything the app never got round to. This is a launch sequence. Watching, "
               "posting, messaging or paying each open behaviour that never ran here.")
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


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    console = Console(LOG_PATH)
    rec = Recorder(console)
    errors = []
    last_beat = [time.time()]   # wall time of the last message from the phone
    armed = [False]             # watchdog waits for the first message before judging

    def on_message(msg, data):
        t = msg.get("type")
        if t == "send":
            last_beat[0] = time.time()
            armed[0] = True
            pl = msg.get("payload") or {}
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
                if cat == "NOTE":
                    continue
                rec.apply(cat, key or "?", value or None, count, first_ms / 1000.0)
        elif t == "error":
            errors.append(msg.get("stack", msg.get("description", "?")))
        elif t == "log":
            console.line(c(DIM, "  " + str(msg.get("payload", ""))))

    dev = frida.get_usb_device(timeout=8)
    with open("observe.compiled.js", "r", encoding="utf-8") as f:
        src = f.read()
    # Payload capture (SSLRead/SSLWrite) is OFF unless explicitly asked for, because
    # those hooks are what has taken the machine down. Turn on with TIKTOK_AUDIT_TLS=1.
    # The flip is a SINGLE character so the compiled bundle's baked-in byte offsets
    # do not move. Changing the length would corrupt the package (malformed package).
    def flip(src, before, after):
        # single-character, length-preserving edit: the compiled bundle bakes byte
        # offsets into its header, so any length change corrupts it ("malformed
        # package"). That is why the flags are digits, not true/false.
        if before not in src:
            raise SystemExit("anchor '%s' not found, recompile observe.js first" % before)
        assert len(before) == len(after)
        return src.replace(before, after, 1)

    if SYSCALL_ON:
        src = flip(src, "var SYSCALL_ENABLED = 0;", "var SYSCALL_ENABLED = 1;")
    if TLS_ON:
        src = flip(src, "var TLS_ENABLED = 0;", "var TLS_ENABLED = 1;")
    if TOUCH_ON:
        src = flip(src, "var TOUCH_ENABLED = 0;", "var TOUCH_ENABLED = 1;")
    # Spawn + load, with a couple of retries. "connection is closed" here usually
    # means frida-server on the phone is recovering (often right after a previous
    # rough run) or the app died on launch; a fresh spawn commonly succeeds.
    pid = session = script = None
    last_err = None
    for attempt in range(3):
        try:
            pid = dev.spawn([BUNDLE])
            session = dev.attach(pid)
            script = session.create_script(src)
            script.on("message", on_message)
            script.load()
            last_err = None
            break
        except (frida.TransportError, frida.InvalidOperationError,
                frida.ProcessNotRespondingError) as e:
            last_err = e
            try:
                if pid:
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
    if TLS_ON and SYSCALL_ON:
        mode = c("1;31", "FULL, all hooks") + c(DIM, "  (hot hooks on, self-kills if it wedges)")
    elif SYSCALL_ON:
        mode = c("1;31", "FULL, no payload") + c(DIM, "  (hot hooks on)")
    else:
        mode = c("1;32", "safe") + c(DIM, "  (known-good hooks, ~90% coverage)")
    console.line("  " + c(DIM, "%-9s" % "mode") + mode)
    console.line("")
    if VERBOSE:
        console.line("  " + c(DIM, RULE * (W - 2)))
        console.line("  " + c(DIM, "one line per NEW thing TikTok touches. repeats are counted, not printed."))
        console.line("  " + c(DIM, "scroll the feed on the phone to exercise more of the app."))
        console.line("  " + c(DIM, RULE * (W - 2)))
    else:
        console.line("  " + c(DIM, "watching for %ds. scroll the feed on the phone. the report prints below." % DURATION))
    console.line("")

    dev.resume(pid)
    rec.t0 = time.time()
    last_beat[0] = time.time()

    # The phone-side script flushes every 400ms, empty batch or not, so a silence
    # longer than this means it has wedged. Rather than let a hung frida-server
    # drag the host down, we abort and free everything. This is the host-side half
    # of the safety story, the self-detaching hooks being the phone-side half.
    WATCHDOG_S = 5.0
    aborted = False

    try:
        while True:
            elapsed = time.time() - rec.t0
            if elapsed >= DURATION:
                break
            if time.time() - last_beat[0] > WATCHDOG_S:
                aborted = True
                break
            filled = int(24 * elapsed / DURATION)
            bar = BAR_ON * filled + BAR_OFF * (24 - filled)
            console.set_footer("  %s  %s  %s" % (
                c("1;32", bar),
                c(DIM, "%2ds / %ds" % (int(elapsed), DURATION)),
                c(DIM, "%d calls, %d distinct" % (rec.total, len(rec.items))),
            ))
            time.sleep(0.2)
    except KeyboardInterrupt:
        console.line("")
        console.line("  " + c(DIM, "stopped early, reporting on what was captured."))

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
    # ask the script for one last batch, so the final 400ms is not lost. Skipped
    # after a watchdog abort, where the session is already gone.
    if not aborted:
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
            "device": str(dev.name), "pid": pid}
    report(rec, console, meta)
    if errors:
        console.line("  " + c(DIM, "hook errors: " + "; ".join(errors[:3])))
        console.line("")
    dump_json(rec, meta)
    console.close()


if __name__ == "__main__":
    main()
