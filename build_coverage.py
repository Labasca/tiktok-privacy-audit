#!/usr/bin/env python3
"""
Build the coverage matrix: every known iOS privacy-read surface (from three
sources of truth) checked against what observe.js actually hooks today.

Sources of truth
  A. Apple Required-Reason API list  -> the canonical fingerprinting-API checklist
  B. Off-the-shelf toolkit surfaces  -> objection / frida-ios-hook / research catalog
  C. TikTok's own PrivacyInfo.xcprivacy (coverage/tiktok_declared.json)

Output: coverage/coverage.json  + printed summary. Feeds the HTML report.
Status per row: hooked | full-only (gated behind -Full) | missing
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OBS = os.path.join(HERE, "observe.js")
OUT = os.path.join(HERE, "coverage")

src = open(OBS, "r", encoding="utf-8").read()

# tokens that only attach when the -Full syscall/TLS gate is on
GATED = {
    "statfs", "statfs64", "stat", "lstat", "access", "connect", "connectx",
    "getsockname", "getaddrinfo", "nw_path", "SSLRead", "SSLWrite", "csops",
}

# Each row: (theme, surface, [symbols], sources, detect_tokens)
# sources: A=Apple required-reason, T=toolkit, D=TikTok-declared manifest
ROWS = [
    # ---- Identity ----
    ("Identity", "Vendor ID (IDFV)", "identifierForVendor", "T,D", ["identifierForVendor"]),
    ("Identity", "Advertising ID (IDFA)", "ASIdentifierManager advertisingIdentifier", "T,D", ["advertisingIdentifier"]),
    ("Identity", "ATT tracking status", "ATTrackingManager trackingAuthorizationStatus", "T,D", ["ATTrackingManager", "trackingAuthorizationStatus"]),
    ("Identity", "Device name / model", "UIDevice name/model/localizedModel", "T", ["'- model'", "'- localizedModel'"]),
    ("Identity", "OS version", "UIDevice systemVersion / NSProcessInfo", "T", ["'- systemVersion'", "operatingSystemVersion"]),
    ("Identity", "Hardware model string", "sysctlbyname(hw.machine/hw.model)", "T", ["sysctlbyname"]),
    ("Identity", "Kernel/build (uname)", "uname()", "T", ["uname"]),
    ("Identity", "Physical memory / CPU count", "NSProcessInfo physicalMemory/processorCount", "T", ["physicalMemory", "processorCount"]),

    # ---- Required-reason: boot time ----
    ("Boot time*", "System uptime", "NSProcessInfo systemUptime", "A,T,D", ["systemUptime"]),
    ("Boot time*", "Boot time via sysctl", "sysctlbyname(kern.boottime)", "A,T,D", ["sysctlbyname"]),
    ("Boot time*", "mach_absolute_time", "mach_absolute_time()", "A,D", ["mach_absolute_time"]),

    # ---- Required-reason: disk space ----
    ("Disk space*", "statfs family", "statfs / statfs64", "A,D", ["statfs"]),
    ("Disk space*", "statvfs family", "statvfs / fstatfs / fstatvfs", "A,D", ["statvfs", "fstatfs"]),
    ("Disk space*", "Free space via ObjC", "NSFileManager attributesOfFileSystemForPath (NSFileSystemFreeSize)", "A,D", ["attributesOfFileSystemForPath"]),
    ("Disk space*", "Volume capacity URL keys", "NSURL volumeAvailableCapacity* / volumeTotalCapacity", "A,D", ["VolumeAvailableCapacity", "volumeAvailableCapacity"]),

    # ---- Required-reason: file timestamps ----
    ("File timestamps*", "stat / lstat", "stat / lstat", "A,D", ["stat", "lstat"]),
    ("File timestamps*", "getattrlist family", "getattrlist / getattrlistbulk / fgetattrlist / getattrlistat", "A,D", ["getattrlist"]),
    ("File timestamps*", "File dates via ObjC", "NSFileManager attributesOfItemAtPath (creation/modification date)", "A,D", ["attributesOfItemAtPath"]),
    ("File timestamps*", "File dates via NSURL", "NSURL contentModificationDateKey / creationDateKey", "A,D", ["ModificationDateKey", "CreationDateKey"]),

    # ---- Required-reason: keyboards + user defaults ----
    ("Keyboards*", "Active keyboards", "UITextInputMode activeInputModes", "A,T,D", ["activeInputModes"]),
    ("User defaults*", "User defaults read", "NSUserDefaults objectForKey/dictionaryRepresentation", "A,T,D", ["NSUserDefaults"]),

    # ---- Locale / region ----
    ("Locale/Region", "Current locale", "NSLocale currentLocale", "T", ["currentLocale"]),
    ("Locale/Region", "Preferred languages", "NSLocale preferredLanguages", "T", ["preferredLanguages"]),
    ("Locale/Region", "Time zone", "NSTimeZone defaultTimeZone", "T", ["defaultTimeZone"]),
    ("Locale/Region", "Calendar", "NSCalendar currentCalendar", "T", ["Calendar"]),

    # ---- Carrier / network ----
    ("Carrier/Network", "Carrier name/MCC/MNC/ISO", "CTCarrier", "T,D", ["CTCarrier"]),
    ("Carrier/Network", "WiFi SSID/BSSID", "CNCopyCurrentNetworkInfo", "T", ["CNCopyCurrentNetworkInfo"]),
    ("Carrier/Network", "Local IPs / interfaces", "getifaddrs", "T", ["getifaddrs"]),
    ("Carrier/Network", "Outbound connections", "connect / getaddrinfo / nw_path", "T", ["connect", "getaddrinfo"]),
    ("Carrier/Network", "HTTP cookies", "NSHTTPCookieStorage cookies", "T", ["NSHTTPCookieStorage"]),
    ("Carrier/Network", "TLS payload", "SSLRead / SSLWrite", "T", ["SSLRead", "SSLWrite"]),

    # ---- Clipboard ----
    ("Clipboard", "Pasteboard contents", "UIPasteboard generalPasteboard", "T,D", ["generalPasteboard", "UIPasteboard"]),

    # ---- Keychain / credentials ----
    ("Keychain/Creds", "Keychain query", "SecItemCopyMatching", "T", ["SecItemCopyMatching"]),
    ("Keychain/Creds", "URL credential store", "NSURLCredentialStorage allCredentials", "T", ["NSURLCredentialStorage"]),
    ("Keychain/Creds", "Crypto material", "CCCrypt / CCCryptorUpdate", "T", ["CCCrypt"]),

    # ---- Installed apps ----
    ("Installed apps", "Enumerate installed apps", "LSApplicationWorkspace allApplications", "T", ["LSApplicationWorkspace"]),
    ("Installed apps", "Can-open URL probing", "canOpenURL:", "T,D", ["canOpenURL"]),
    ("Installed apps", "Declared query schemes", "Info.plist LSApplicationQueriesSchemes", "D", ["LSApplicationQueriesSchemes"]),

    # ---- Sensors ----
    ("Sensors", "Motion/accelerometer/gyro", "CMMotionManager", "T", ["CMMotionManager"]),
    ("Sensors", "Pedometer / steps", "CMPedometer", "T", ["CMPedometer"]),
    ("Sensors", "Battery level/state", "UIDevice batteryLevel/State", "T", ["batteryLevel"]),
    ("Sensors", "Screen geometry", "UIScreen nativeBounds/scale", "T", ["nativeBounds"]),

    # ---- Location ----
    ("Location", "GPS location", "CLLocationManager location/startUpdating", "T,D", ["CLLocationManager"]),

    # ---- Permissions / contacts ----
    ("Permissions", "Permission status probes", "authorizationStatus (photos/contacts/mic/...)", "T,D", ["authorizationStatus"]),
    ("Permissions", "Contacts read", "CNContactStore enumerateContacts", "T,D", ["enumerateContacts"]),

    # ---- Anti-tamper ----
    ("Anti-tamper", "Debugger/code-sign check", "csops", "-", ["csops"]),
    ("Anti-tamper", "Jailbreak path probes", "stat/lstat/access on JB paths", "-", ["JBPATH", "jailbreak"]),
]


# surfaces observe.js intentionally does NOT hook, with the reason. These read as
# "missing" but the gap is a deliberate safety choice, not an oversight.
EXCLUDED = {
    "getattrlist family": "excluded by design: fires constantly on the hot path, "
                          "needs a self-detaching hotHook before it is safe to add",
}


def status_for(surface, detect):
    if surface in EXCLUDED:
        return "missing"
    hooked = any(tok in src for tok in detect)
    if not hooked:
        return "missing"
    # gated if the only matching tokens are gated ones
    matched = [tok for tok in detect if tok in src]
    plain = [t.strip("'").strip() for t in matched]
    if all(p in GATED for p in plain) and any(p in GATED for p in plain):
        return "full-only"
    return "hooked"


def main():
    os.makedirs(OUT, exist_ok=True)
    declared = {}
    dpath = os.path.join(OUT, "tiktok_declared.json")
    if os.path.exists(dpath):
        declared = json.load(open(dpath, encoding="utf-8"))

    rows = []
    counts = {"hooked": 0, "full-only": 0, "missing": 0}
    for theme, surface, symbol, sources, detect in ROWS:
        st = status_for(surface, detect)
        counts[st] += 1
        rows.append({"theme": theme, "surface": surface, "symbol": symbol,
                     "sources": sources.split(","), "status": st,
                     "note": EXCLUDED.get(surface, "")})

    result = {"counts": counts, "rows": rows,
              "tiktok_declared_summary": {
                  "manifests": declared.get("manifest_count"),
                  "required_reason_categories": list(declared.get("required_reason_apis", {}).keys()),
                  "tracking_domains": declared.get("tracking_domains", []),
                  "collected_data_types": list(declared.get("collected_data_types", {}).keys()),
                  "declared_query_schemes": len(declared.get("declared_app_query_schemes", [])),
              }}
    json.dump(result, open(os.path.join(OUT, "coverage.json"), "w", encoding="utf-8"), indent=2)

    # print
    print(f"  coverage: {counts['hooked']} hooked, {counts['full-only']} full-only, {counts['missing']} MISSING\n")
    icon = {"hooked": "[x]", "full-only": "[~]", "missing": "[ ]"}
    last = None
    for r in rows:
        if r["theme"] != last:
            print(f"\n  {r['theme']}   (* = Apple required-reason category TikTok declares)")
            last = r["theme"]
        print(f"    {icon[r['status']]:4} {r['surface']:34} {r['symbol']}")
    print("\n  MISSING (worth adding):")
    for r in rows:
        if r["status"] == "missing":
            print(f"    - {r['surface']:34} {r['symbol']}   [{','.join(r['sources'])}]")
    print(f"\n  wrote coverage/coverage.json")


if __name__ == "__main__":
    main()
