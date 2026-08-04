#!/usr/bin/env python3
"""
Coverage discovery, read-only.

Answers "what are we missing" with evidence instead of a list written from
memory. Loads discover.compiled.js, which watches a wide net of privacy-relevant
APIs, then reports what actually fired and which of it observe.js does not yet
capture.

Usage:  python run_discover.py [seconds]
"""
import sys, os, time, json, shutil, threading, frida
from collections import defaultdict

os.chdir(os.path.dirname(os.path.abspath(__file__)))

BUNDLE = "com.zhiliaoapp.musically"
DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 30
OUT = "discovery.json"
W = max(76, min(shutil.get_terminal_size((96, 24)).columns - 2, 100))


def _ansi():
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        m = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(m)):
            return False
        k.SetConsoleMode(h, m.value | 0x0004)
        return True
    except Exception:
        return False


try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
COLOR = sys.stdout.isatty() and _ansi()


def c(code, s):
    return "\x1b[%sm%s\x1b[0m" % (code, s) if COLOR else s


DIM, BOLD, HOT, NEW = "2", "1", "1;31", "1;32"

# what observe.js already captures, so discovery can report only the gap
HOOKED_C = {
    "SecItemCopyMatching", "sysctlbyname", "uname", "getifaddrs",
    "CFNetworkCopySystemProxySettings", "connect", "connectx", "getsockname",
    "getaddrinfo", "nw_path_uses_interface_type", "ioctl",
}
HOOKED_OBJC = {
    "CLLocationManager", "NSURLSession", "NEVPNManager",
    "UIDevice - identifierForVendor", "UIDevice - systemVersion",
    "UIDevice - model", "UIDevice - name", "UIDevice - localizedModel",
}

# C imports worth a second look if the binary links them
INTERESTING = (
    "sysctl", "uname", "gethostname", "statfs", "getattrlist", "getfsstat",
    "IORegistry", "IOService", "IOPlatform",
    "SecItem", "SecKey", "SecCertificate", "SecTrust",
    "getifaddrs", "getaddrinfo", "connect", "getsockname", "getpeername",
    "res_", "dns_", "nw_path", "SCNetwork", "SCDynamicStore", "CFNetwork",
    "proc_", "task_info", "dyld", "dlopen", "dlsym", "ptrace", "sysconf",
    "CFLocale", "CFTimeZone", "CFCalendar", "localtime", "tzset", "strftime",
    "CFPreferences", "CFUserNotification", "MGCopyAnswer", "notify_",
    "AudioSession", "AVCapture", "CTTelephony", "CoreTelephony",
    "mach_absolute_time", "gettimeofday", "clock_gettime",
    "getpwuid", "getuid", "geteuid", "getppid", "kill", "fork",
)

# a plain-English name for each thing worth explaining
MEANING = {
    "NSLocale": "region, language and formatting preferences",
    "NSTimeZone": "which timezone the phone is set to",
    "NSCalendar": "calendar system and first day of week",
    "UITextInputMode": "which keyboards are installed, so which languages you type",
    "ASIdentifierManager": "the advertising identifier (IDFA)",
    "ATTrackingManager": "whether you granted tracking permission",
    "CTTelephonyNetworkInfo": "mobile carrier and radio technology",
    "CTCarrier": "carrier name and country code",
    "UIPasteboard": "the clipboard, whatever you last copied",
    "DCDevice": "Apple device attestation token",
    "CMMotionManager": "accelerometer and gyroscope",
    "CMPedometer": "step count and walking data",
    "CMAltimeter": "barometric altitude",
    "UIScreen": "screen size, scale and brightness",
    "UIDevice": "device name, model and battery",
    "NSProcessInfo": "memory, CPU count, uptime and thermal state",
    "NSFileManager": "free disk space and file existence",
    "UIApplication": "which other apps are installed, via URL schemes",
    "AVAudioSession": "audio route, so whether headphones are connected",
    "UIFont": "installed font list",
    "NSBundle": "the app's own identity and configuration",
    "AVCaptureDevice": "camera permission state",
    "PHPhotoLibrary": "photo library permission state",
    "CNContactStore": "contacts permission state",
    "EKEventStore": "calendar permission state",
    "CBCentralManager": "Bluetooth state",
    "NSHTTPCookieStorage": "stored cookies",
    "WKWebView": "the web view user agent",
    "LAContext": "whether Face ID or Touch ID is available",
    "UNUserNotificationCenter": "notification permission state",
}

DEFAULT_MEANING = {
    "applelanguages": "the ordered list of languages you have set",
    "applelocale": "your region and formatting locale",
    "applekeyboards": "every keyboard you have installed",
    "applekeyboardsexpanded": "keyboard configuration detail",
    "appleicucalendar": "calendar preference",
    "appleitunesstorei": "store account region hints",
    "nslanguages": "language preferences",
    "appletimezone": "the timezone you are set to",
}


def rule(ch="─"):
    return ch * (W - 2)


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


def section(title, tail=""):
    print("")
    head = "  " + title
    print(c(BOLD, head) + " " * max(1, W - len(head) - len(tail)) + c(DIM, tail))
    print("  " + c(DIM, rule()))


def main():
    found = defaultdict(list)
    imports = []
    lock = threading.Lock()

    def on_message(msg, data):
        if msg.get("type") != "send":
            if msg.get("type") == "error":
                print(c(HOT, "  script error: ")
                      + msg.get("stack", msg.get("description", "?"))[:400])
            return
        pl = msg.get("payload") or {}
        cat, key, val = pl.get("cat"), pl.get("key"), pl.get("value")
        with lock:
            if cat == "IMPORTS":
                imports.extend(val or [])
            elif cat:
                found[cat].append((key, val))

    dev = frida.get_usb_device(timeout=8)
    with open("discover.compiled.js", "r", encoding="utf-8") as f:
        src = f.read()
    pid = dev.spawn([BUNDLE])
    session = dev.attach(pid)
    script = session.create_script(src)
    script.on("message", on_message)
    script.load()

    print("")
    print("  " + c(BOLD, "COVERAGE DISCOVERY"))
    print("  " + c(DIM, "what the app COULD touch, and what it actually did. read-only."))
    print("  " + c(DIM, "target %s, pid %d, %ds window" % (BUNDLE, pid, DURATION)))
    print("")
    print("  " + c(DIM, "exercise the app while this runs. anything you do not do here"))
    print("  " + c(DIM, "will not show up as a gap."))

    dev.resume(pid)
    t0 = time.time()
    try:
        while time.time() - t0 < DURATION:
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    try:
        session.detach()
    except Exception:
        pass

    # ---------------------------------------------------------------- report
    # allocWithZone: and friends are called by everything and mean nothing here
    NOISE = {"initialize", "alloc", "allocWithZone:", "init", "dealloc",
             "copyWithZone:", ".cxx_construct", ".cxx_destruct", "_cfTypeID",
             "class", "respondsToSelector:", "load", "new", "hash", "isEqual:",
             "description", "debugDescription"}

    def is_noise(sel):
        return sel.lstrip("+- ").strip() in NOISE or sel.lstrip("+- ").startswith("_")

    called = defaultdict(list)
    callers = defaultdict(set)
    for key, caller in found.get("CALLED", []):
        cls, sel = key.split(" ", 1)
        if is_noise(sel):
            continue
        called[cls].append(sel)
        if caller:
            callers[cls].add(caller)
    called = {k: v for k, v in called.items() if v}

    section("OBJECTIVE-C IT ACTUALLY CALLED", "%d classes" % len(called))
    print("  " + c(DIM, "a + marks something observe.js does not capture yet. the caller"))
    print("  " + c(DIM, "tells you whether TikTok asked, or the OS did it by itself."))
    print("")
    for cls in sorted(called, key=lambda k: -len(called[k])):
        sels = sorted(set(called[cls]))
        covered = cls in HOOKED_OBJC or any(
            ("%s %s" % (cls, s)) in HOOKED_OBJC for s in sels)
        mark = " " if covered else c(NEW, "+")
        src = ", ".join(sorted(callers[cls]))[:34] or "?"
        print("  %s %-24s %-36s %s" % (mark, cls,
                                       c(DIM, MEANING.get(cls, "")[:36]),
                                       c(DIM, "from " + src)))
        for s in sels[:10]:
            print("      " + c(DIM, s[:W - 8]))
        if len(sels) > 10:
            print("      " + c(DIM, "and %d more" % (len(sels) - 10)))

    keys = sorted({k for k, _ in found.get("DEFAULTS", [])})
    if keys:
        section("SETTINGS IT READ", "%d keys" % len(keys))
        print("  " + c(DIM, "NSUserDefaults is where language, locale and keyboard"))
        print("  " + c(DIM, "preferences live. the key being asked for is the finding."))
        print("")
        for k in keys[:40]:
            note = ""
            for marker, m in DEFAULT_MEANING.items():
                if marker in k.lower().replace(" ", ""):
                    note = m
                    break
            mark = c(NEW, "+") if note else " "
            print("  %s %-40s %s" % (mark, k[:40], c(DIM, note)))
        if len(keys) > 40:
            print("  " + c(DIM, "and %d more" % (len(keys) - 40)))

    tls = found.get("TLSSYM", [])
    section("TLS ENTRY POINTS", "%d modules" % len(tls))
    print("  " + c(DIM, "request bodies for TikTok's own traffic can only be read at the"))
    print("  " + c(DIM, "TLS layer. these are the modules exporting a hookable symbol."))
    print("")
    if tls:
        for mod, syms in tls:
            print("  " + c(NEW, "+") + " %-30s %s" % (mod[:30], c(DIM, str(syms)[:W - 40])))
    else:
        print("  " + c(DIM, "none exported. BoringSSL is statically linked and stripped, so"))
        print("  " + c(DIM, "a payload hook needs a pattern scan, not a symbol lookup."))

    schemes = sorted({k for k, _ in found.get("SCHEME", [])})
    if schemes:
        section("OTHER APPS IT LOOKED FOR", "%d schemes" % len(schemes))
        print("  " + c(DIM, "canOpenURL: tells an app whether another app is installed."))
        print("  " + c(DIM, "a list of these is a profile of what else you use."))
        print("")
        for s in schemes[:40]:
            print("  " + c(NEW, "+") + " " + s[:W - 6])
        if len(schemes) > 40:
            print("  " + c(DIM, "and %d more" % (len(schemes) - 40)))

    probes = sorted({k for k, _ in found.get("PROBE", [])})
    if probes:
        section("FILESYSTEM PROBES", "%d paths" % len(probes))
        print("  " + c(DIM, "paths that only exist on a jailbroken phone. this is"))
        print("  " + c(DIM, "tamper detection, not data collection."))
        print("")
        for pth in probes[:30]:
            print("  " + c(NEW, "+") + " " + pth[:W - 6])
        if len(probes) > 30:
            print("  " + c(DIM, "and %d more" % (len(probes) - 30)))

    cfuncs = sorted({(k, v) for k, v in found.get("CFUNC", [])})
    if cfuncs:
        section("C FUNCTIONS IT CALLED", "%d" % len(cfuncs))
        for name, what in cfuncs:
            mark = c(DIM, " ") if name in HOOKED_C else c(NEW, "+")
            print("  %s %-24s %s" % (mark, name, c(DIM, what or "")))

    if imports:
        hits = sorted({i for i in imports
                       if any(m.lower() in i.lower() for m in INTERESTING)})
        missing = [i for i in hits if i not in HOOKED_C]
        section("LINKED BUT NOT WATCHED", "%d of %d imports" % (len(missing), len(imports)))
        print("  " + c(DIM, "the binary imports these, so it can call them. being here is"))
        print("  " + c(DIM, "not proof it did, only that the capability is compiled in."))
        print("")
        for i in missing[:60]:
            print("    " + i[:W - 6])
        if len(missing) > 60:
            print("  " + c(DIM, "and %d more" % (len(missing) - 60)))

    notes = found.get("NOTE", [])
    if notes:
        section("HOOK DIAGNOSTICS", "%d" % len(notes))
        print("  " + c(DIM, "so an empty section above can be read as 'did not happen'"))
        print("  " + c(DIM, "rather than 'the hook quietly failed'."))
        print("")
        for k, v in notes:
            print("    %-42s %s" % (k[:42], c(DIM, str(v)[:W - 50])))

    absent = sorted({k for k, _ in found.get("ABSENT", [])})
    if absent:
        section("NOT PRESENT IN THIS APP", "%d classes" % len(absent))
        print("  " + c(DIM, "watched for but never loaded, so nothing to capture:"))
        print("  " + ", ".join(absent)[:W * 3])

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"called": {k: sorted(set(v)) for k, v in called.items()},
                   "defaults": keys,
                   "schemes": schemes,
                   "probes": probes,
                   "cfuncs": [list(x) for x in cfuncs],
                   "imports": sorted(set(imports))}, f, indent=2)
    print("")
    print("  " + c(DIM, "full lists written to %s" % OUT))
    print("")


if __name__ == "__main__":
    main()
