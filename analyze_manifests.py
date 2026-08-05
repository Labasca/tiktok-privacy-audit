#!/usr/bin/env python3
"""
Aggregate every PrivacyInfo.xcprivacy we pulled into TikTok's DECLARED privacy
surface, and dump the root Info.plist's declared app-probe list. This is the
"source of truth" side: what Apple forces TikTok (and each embedded SDK) to admit.

Reads manifests/*.  Writes coverage/tiktok_declared.json  + prints a summary.
"""
import json
import os
import plistlib
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
MAN = os.path.join(HERE, "manifests")
OUT = os.path.join(HERE, "coverage")

# Apple reason-code -> short human meaning (from the required-reason spec)
REASONS = {
    "DDA9.1": "show file timestamps to the user",
    "C617.1": "read metadata of files in the app's own containers",
    "3B52.1": "read metadata of user-granted files (document picker)",
    "0A2A.1": "3rd-party SDK wrapper around file-timestamp APIs",
    "35F9.1": "measure elapsed time between in-app events",
    "8FFB.1": "absolute timestamps for in-app UIKit/audio events",
    "3D61.1": "boot time in a user-submitted bug report",
    "85F4.1": "display disk space to the user",
    "E174.1": "check for sufficient/low disk space before file IO",
    "7D9E.1": "disk space in a user-submitted bug report",
    "B728.1": "health-research low-disk detection",
    "3EC4.1": "custom-keyboard app enumerating active keyboards",
    "54BD.1": "customize UI based on active keyboards",
    "CA92.1": "read/write the app's own user defaults",
    "1C8F.1": "read/write user defaults shared in the App Group",
    "C56D.1": "3rd-party SDK wrapper around user-defaults APIs",
    "AC6B.1": "read/write MDM managed-app config",
}
CAT_SHORT = {
    "NSPrivacyAccessedAPICategoryFileTimestamp": "File timestamps",
    "NSPrivacyAccessedAPICategorySystemBootTime": "System boot time",
    "NSPrivacyAccessedAPICategoryDiskSpace": "Disk space",
    "NSPrivacyAccessedAPICategoryActiveKeyboards": "Active keyboards",
    "NSPrivacyAccessedAPICategoryUserDefaults": "User defaults",
}


def load(path):
    with open(path, "rb") as fh:
        return plistlib.load(fh)


def main():
    os.makedirs(OUT, exist_ok=True)
    files = sorted(f for f in os.listdir(MAN) if f.endswith(".xcprivacy"))

    # aggregate
    api_by_cat = defaultdict(set)          # category -> {reason codes}
    api_cat_sources = defaultdict(set)     # category -> {sdk file}
    tracking_any = False
    tracking_domains = set()
    collected = {}                          # data type -> {linked, tracking, purposes}
    collected_sources = defaultdict(set)    # data type -> {sdk}
    per_sdk = {}

    for f in files:
        try:
            d = load(os.path.join(MAN, f))
        except Exception as e:
            per_sdk[f] = {"error": str(e)}
            continue
        sdk = f.replace("__PrivacyInfo.xcprivacy", "").replace("_PrivacyInfo", "")
        rec = {"apis": [], "domains": [], "data": [], "tracking": bool(d.get("NSPrivacyTracking"))}

        for api in d.get("NSPrivacyAccessedAPITypes", []) or []:
            cat = api.get("NSPrivacyAccessedAPIType", "?")
            reasons = api.get("NSPrivacyAccessedAPITypeReasons", []) or []
            api_by_cat[cat].update(reasons)
            api_cat_sources[cat].add(sdk)
            rec["apis"].append({"category": CAT_SHORT.get(cat, cat), "reasons": reasons})

        for dom in d.get("NSPrivacyTrackingDomains", []) or []:
            tracking_domains.add(dom)
            rec["domains"].append(dom)

        for dt in d.get("NSPrivacyCollectedDataTypes", []) or []:
            name = dt.get("NSPrivacyCollectedDataType", "?").replace("NSPrivacyCollectedDataType", "")
            purposes = [p.replace("NSPrivacyCollectedDataTypePurpose", "")
                        for p in dt.get("NSPrivacyCollectedDataTypePurposes", []) or []]
            entry = collected.setdefault(name, {"linked": False, "tracking": False, "purposes": set()})
            entry["linked"] |= bool(dt.get("NSPrivacyCollectedDataTypeLinked"))
            entry["tracking"] |= bool(dt.get("NSPrivacyCollectedDataTypeTracking"))
            entry["purposes"].update(purposes)
            collected_sources[name].add(sdk)
            rec["data"].append({"type": name, "linked": bool(dt.get("NSPrivacyCollectedDataTypeLinked")),
                                "tracking": bool(dt.get("NSPrivacyCollectedDataTypeTracking")),
                                "purposes": purposes})
        per_sdk[sdk] = rec

    tracking_any = any(v.get("tracking") for v in per_sdk.values() if isinstance(v, dict))

    # root Info.plist app-probe list
    schemes = []
    try:
        info = load(os.path.join(MAN, "Info.plist"))
        schemes = info.get("LSApplicationQueriesSchemes", []) or []
    except Exception:
        pass

    out = {
        "manifest_count": len(files),
        "required_reason_apis": {
            CAT_SHORT.get(c, c): {
                "reasons": sorted({f"{r} ({REASONS.get(r, '?')})" for r in rs}),
                "declared_by": sorted(api_cat_sources[c]),
            } for c, rs in sorted(api_by_cat.items())
        },
        "tracking_enabled": tracking_any,
        "tracking_domains": sorted(tracking_domains),
        "collected_data_types": {
            name: {
                "linked_to_identity": v["linked"],
                "used_for_tracking": v["tracking"],
                "purposes": sorted(v["purposes"]),
                "declared_by": sorted(collected_sources[name]),
            } for name, v in sorted(collected.items())
        },
        "declared_app_query_schemes": sorted(schemes),
        "per_sdk": per_sdk,
    }
    with open(os.path.join(OUT, "tiktok_declared.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, default=str)

    # ---- readable summary ----
    def rule(c="="): print(c * 78)
    rule()
    print(f"  TikTok DECLARED privacy surface  ({len(files)} manifests: app + {len(files)-1} SDKs/extensions)")
    rule()
    print("\n  REQUIRED-REASON APIs it admits using:")
    for cat, info2 in out["required_reason_apis"].items():
        print(f"\n   • {cat}   (declared by {len(info2['declared_by'])} module(s))")
        for r in info2["reasons"]:
            print(f"       {r}")
    print(f"\n  TRACKING enabled anywhere: {tracking_any}")
    print(f"  TRACKING DOMAINS declared: {len(tracking_domains)}")
    for d in sorted(tracking_domains):
        print(f"     {d}")
    print(f"\n  COLLECTED DATA TYPES declared: {len(collected)}")
    for name, v in out["collected_data_types"].items():
        flags = []
        if v["linked_to_identity"]: flags.append("LINKED-to-you")
        if v["used_for_tracking"]: flags.append("TRACKING")
        print(f"     {name:24} {'  '.join(flags)}")
        print(f"         purposes: {', '.join(v['purposes']) or '-'}")
        print(f"         declared by: {', '.join(v['declared_by'][:6])}" + (" ..." if len(v['declared_by']) > 6 else ""))
    print(f"\n  DECLARED APP-QUERY SCHEMES (Info.plist LSApplicationQueriesSchemes): {len(schemes)}")
    rule()
    print(f"  wrote {os.path.join('coverage', 'tiktok_declared.json')}")


if __name__ == "__main__":
    main()
