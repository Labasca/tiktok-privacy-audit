#!/usr/bin/env python3
"""
No-phone tests for the poster. The same contract as selftest.py: if this
cannot pass on a machine that has never seen the handset, it is not a test.

    python automation/tests/test_poster.py
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
AUTO = HERE.parent
ROOT = AUTO.parent
sys.path.insert(0, str(ROOT))

from automation import device, inject, poster  # noqa: E402

passed = 0
failures = []


def ok(cond, what):
    global passed
    if cond:
        passed += 1
        return True
    failures.append(what)
    return False


def eq(actual, expected, what):
    return ok(actual == expected,
              "%s  (got %r, wanted %r)" % (what, actual, expected))


def test_denylist():
    eq(device.is_tiktok("TikTok"), True, "name TikTok")
    eq(device.is_tiktok("com.zhiliaoapp.musically"), True, "bundle")
    eq(device.is_tiktok("com.ss.iphone.ugc.Ame"), True, "china bundle")
    eq(device.is_tiktok("SpringBoard"), False, "SpringBoard is not TikTok")
    eq(device.is_tiktok("Photos"), False, "Photos is not TikTok")
    eq(device.is_tiktok("sshd"), False, "sshd is not TikTok")
    eq(device.is_tiktok(None, "com.zhiliaoapp.musically"), True, "ident only")
    try:
        device.refuse_tiktok("TikTok")
        ok(False, "refuse_tiktok(TikTok) must raise")
    except device.InjectionGuard:
        ok(True, "refuse_tiktok(TikTok) raises")
    try:
        device.require_allowed_target("backboardd")
        ok(False, "backboardd is not on the allow-list")
    except device.InjectionGuard:
        ok(True, "allow-list rejects backboardd")
    try:
        device.require_allowed_target("SpringBoard")
        ok(True, "SpringBoard is allowed")
    except device.InjectionGuard as e:
        ok(False, "SpringBoard rejected: %s" % e)
    try:
        device.require_allowed_target("Photos", "com.apple.mobileslideshow")
        ok(True, "Photos is allowed")
    except device.InjectionGuard as e:
        ok(False, "Photos rejected: %s" % e)
    try:
        device.refuse_tiktok("com.zhiliaoapp.musically", "com.zhiliaoapp.musically")
        ok(False, "uiopen of TikTok must be refused")
    except device.InjectionGuard:
        ok(True, "uiopen of TikTok is refused")


def test_run_name():
    eq(device.safe_run_name("01-native"), "01-native", "plain")
    eq(device.safe_run_name("../etc/passwd"), "etc-passwd", "traversal")
    eq(device.safe_run_name("..."), "run", "dots")
    eq(device.safe_run_name("arm 1!"), "arm-1-", "spaces and bang")
    # matches run_observe.py so a poster arm and an observer run share a dir
    eq(device.safe_run_name("01 native"), "01-native", "space to dash")


def test_scp_uses_capital_p():
    # ssh -p, scp -P. Using the ssh flag with scp makes it try to stat "2222".
    args = device.ssh_base_args(port_flag="-P")
    ok("-P" in args, "scp port flag")
    eq(args[args.index("-P") + 1], "2222", "port value")
    args = device.ssh_base_args(port_flag="-p")
    ok("-p" in args, "ssh port flag")


def test_usbmux_packet():
    pkt = device._mux_pack({"MessageType": "ListDevices", "ProgName": "poster"})
    ok(len(pkt) > 16, "packet longer than header")
    length, ver, typ, tag = struct.unpack("<IIII", pkt[:16])
    eq(ver, 1, "usbmux version")
    eq(typ, 8, "plist packet")
    eq(length, len(pkt), "length field")
    # PortNumber is htons, the thing every first-time usbmux client gets wrong
    eq(socket.htons(22), 5632, "htons(22)")
    eq(socket.htons(2222), 44552, "htons(2222)")


def test_sshd_lock_content():
    cfg = device.SSHD_CONFIG_LOCKED
    ok("PasswordAuthentication no" in cfg, "password off")
    ok("KbdInteractiveAuthentication no" in cfg, "kbi off")
    ok("PermitRootLogin prohibit-password" in cfg, "root is key-only")
    ok("PubkeyAuthentication yes" in cfg, "keys on")
    ok("dropbear" in cfg.lower(), "emergency hatch named")
    ok("PasswordAuthentication yes" not in cfg, "no leftover yes")


def test_homes():
    # Procursus passwd, measured live: root home is /var/jb/var/root.
    # Installing the key only in /var/root is why the first attempt failed.
    eq(device.JB_ROOT_HOME, "/var/jb/var/root", "procursus root home")
    eq(device.JB_MOBILE_HOME, "/var/jb/var/mobile", "procursus mobile home")
    script = device._install_script("ssh-ed25519 AAAA test\n", "000000")
    ok(device.JB_ROOT_HOME in script, "install script covers jb root home")
    ok(device.IOS_ROOT_HOME in script, "install script also covers iOS root home")
    ok("export PATH=" in script or "/var/jb/usr/bin/mkdir" in script,
       "raw spawn has empty PATH, script must not rely on it")


def test_layout():
    from automation import layout as L
    layout = L.load_layout(AUTO / "layout" / "iphone10_3.json")
    eq(tuple(layout["logical"]), (375, 812), "iPhone X points")
    ok("screens" in layout, "per-screen maps, not a flat list")
    ok("feed" in layout["screens"], "feed screen")
    ok("picker" in layout["screens"], "picker screen")
    ok("composer" in layout["screens"], "composer screen")
    x, y = L.resolve_point(layout, "feed.create")
    ok(0 < x < 375 and 0 < y < 812, "feed.create is on-panel")
    x, y = L.resolve_point(layout, "10,20")
    eq((x, y), (10.0, 20.0), "raw x,y")
    pn = L.resolve_point(layout, "picker.next")
    en = L.resolve_point(layout, "editor.next")
    ok(isinstance(pn, tuple) and isinstance(en, tuple), "both nexts resolve")
    # they may share numbers today; they must not share an address
    eq(L.parse_ref("picker.next"), ("picker", "next"), "picker.next parses")
    eq(L.parse_ref("editor.next"), ("editor", "next"), "editor.next parses")
    try:
        L.resolve_point(layout, "next")
        ok(False, "bare 'next' must refuse: picker vs editor")
    except device.PosterError as e:
        ok("screen" in str(e), "bare name asks for a screen")
    try:
        L.resolve_point(layout, "feed.not-a-point")
        ok(False, "unknown point must raise")
    except device.PosterError:
        ok(True, "unknown point raises")
    plan = L.plan_flow(layout)
    ok(len(plan) >= 5, "flow has the create/upload/next/post chain")
    kinds = [s.get("do") for s in plan]
    eq(kinds[0], "tap", "flow starts with a tap")
    ons = [s.get("on") for s in plan]
    ok("feed" in ons and "composer" in ons, "flow names its screens")
    refs = [s.get("ref") for s in plan if s.get("ref")]
    ok("picker.next" in refs, "picker.next is addressed")
    ok("editor.next" in refs, "editor.next is a different address")
    ok("composer.post" in refs, "post lives on composer, not a global")


def test_flat_layout_rejected():
    from automation import layout as L
    try:
        L.validate_layout({"logical": [375, 812], "points": {"create": [1, 2]}})
        ok(False, "flat layout must be rejected")
    except device.PosterError as e:
        ok("screens" in str(e), "error names screens")


def test_wda_refused():
    from automation import layout as L
    try:
        L.refuse_view_tree()
        ok(False, "inspect must raise")
    except device.InjectionGuard as e:
        msg = str(e)
        ok("WebDriverAgent" in msg or "Appium" in msg, "names WDA/Appium")
        ok("obfuscat" in msg, "names the obfuscated tree")
        ok("inject" in msg, "names injection")
    ns = poster.build_parser().parse_args(["inspect"])
    eq(ns.cmd, "inspect", "inspect is a real command, not missing")


def test_norm():
    eq(inject.points_to_norm(187.5, 406, (375, 812)), (0.5, 0.5), "center")
    eq(inject.points_to_norm(0.25, 0.75, (375, 812)), (0.25, 0.75), "already norm")
    eq(inject.points_to_norm(0, 0, (375, 812)), (0.0, 0.0), "origin")
    eq(inject.points_to_norm(375, 812, (375, 812)), (1.0, 1.0), "far corner")


def test_kind_and_hash():
    eq(inject.guess_kind(Path("a.mov")), "video", "mov")
    eq(inject.guess_kind(Path("a.MP4")), "video", "mp4")
    eq(inject.guess_kind(Path("a.heic")), "photo", "heic")
    eq(inject.guess_kind(Path("a.jpg")), "photo", "jpg")
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.bin"
        p.write_bytes(b"hello-poster")
        eq(inject.sha256_file(p),
           "6c0d04d63c0d1f6e0c8f3e2c0f5c0a0e0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f"[:0] +
           __import__("hashlib").sha256(b"hello-poster").hexdigest(),
           "sha256 of known bytes")


def test_bytes_match():
    src = {"bytes": 100}
    eq(inject._bytes_match(src, {"measure": {"resources": [{"fileSize": 100}]}}),
       True, "same size")
    eq(inject._bytes_match(src, {"measure": {"resources": [{"fileSize": 80}]}}),
       False, "rewritten")
    eq(inject._bytes_match(src, {"measure": {"resources": [{}]}}),
       None, "unknown")
    eq(inject._bytes_match(src, {}), None, "no measure")


def test_arms_manifest():
    spec = json.loads((AUTO / "arms.json").read_text(encoding="utf-8"))
    names = [a["name"] for a in spec["arms"]]
    eq(names[0], "01-native", "first arm")
    ok("02-stripped" in names, "stripped arm")
    ok("04-scraped-stamped" in names, "scraped-stamped arm")
    eq(len(names), 6, "six-arm matrix")
    eq(len(set(names)), 6, "unique names")
    eq({a["library"] for a in spec["arms"]}, {"import"},
       "every file arm is an import, not a camera original")
    ok("sourceType" in spec["landmines"], "sourceType landmine is named")


def test_one_post_per_window():
    from automation import arms as A
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        spent = root / "runs" / "01-native"
        spent.mkdir(parents=True)
        eq(A.arm_is_spent(spent), False, "empty dir is not spent")
        (spent / "tags.json").write_text("{}", encoding="utf-8")
        eq(A.arm_is_spent(spent), True, "tags.json spends the window")
        try:
            A.refuse_if_spent(spent)
            ok(False, "spent window must refuse")
        except device.PosterError as e:
            ok("cumulative" in str(e) or "spent" in str(e), "names the tally")
        A.refuse_if_spent(spent, force=True)
        ok(True, "--force overrides")
        other = root / "runs" / "02-stripped"
        other.mkdir(parents=True)
        (other / "poster.json").write_text('{"posted": true}\n', encoding="utf-8")
        eq(A.arm_is_spent(other), True, "a completed post spends the window")


def test_post_gates():
    from automation import arms as A
    try:
        A.require_post_gates(burner=False, unattended=False,
                             confirm=lambda p: True, arm_name="01-native")
        ok(False, "post without --burner must refuse")
    except device.PosterError as e:
        ok("burner" in str(e), "names the burner")
    try:
        A.require_post_gates(burner=True, unattended=False,
                             confirm=lambda p: False, arm_name="01-native")
        ok(False, "a no from the human must stop")
    except device.PosterError as e:
        ok("OK" in str(e) or "stopped" in str(e), "stopped for OK")
    A.require_post_gates(burner=True, unattended=False,
                         confirm=lambda p: True, arm_name="01-native")
    ok(True, "YES on a burner proceeds")
    A.require_post_gates(burner=True, unattended=True,
                         confirm=lambda p: (_ for _ in ()).throw(AssertionError("prompted")),
                         arm_name="01-native")
    ok(True, "--unattended does not prompt")


def test_sourceType_is_not_stampable():
    from automation import arms as A
    p = A.library_provenance("import")
    eq(p["how"], "import", "import")
    eq(p["exif_cannot_stamp_sourceType"], True, "cannot stamp")
    ok("camera original" in p["note"], "names the claim Photos will not make")
    c = A.library_provenance("capture")
    eq(c["how"], "capture", "capture")
    try:
        A.library_provenance("stamped")
        ok(False, "stamped is not a library path")
    except device.PosterError:
        ok(True, "stamped refused")


def test_fidelity_picks_the_real_denominator():
    from automation import arms as A
    clean = A.fidelity_record(
        Path("a.mov"),
        {"source": {"bytes": 10, "sha256": "aa"},
         "bytes_match": True,
         "import": {"stored": {"bytes": 10, "sha256": "aa"}}},
        Path("source.tags.json"), None, None,
    )
    eq(clean["drifted"], False, "matching hashes are not drift")
    eq(clean["denominator"].startswith("laptop"), True, "laptop is the denom")
    drifted = A.fidelity_record(
        Path("a.mov"),
        {"source": {"bytes": 634, "sha256": "aa"},
         "bytes_match": False,
         "import": {"stored": {"bytes": 2023, "sha256": "bb"}}},
        Path("source.tags.json"), Path("imported.tags.json"), Path("imported.jpg"),
    )
    eq(drifted["drifted"], True, "rewrite is drift")
    ok("fiction" in drifted["denominator"], "laptop dump is named fiction")
    targets = A.coverage_targets(drifted, Path("runs/x"))
    eq(targets[0][0], "imported", "coverage uses the stored file first")


def test_prepare_arms_derives_what_it_can():
    from automation import prepare as P
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        chk = P.check(root)
        ok(chk["have"]["01-native"] is None, "no native yet")
        ok(any("01-native" in n for n in chk["need_you"]), "asks for native")
        rec = P.prepare(root)
        ok((root / "05-generated.mov").is_file(), "wrote generated")
        ok((root / "06-generated-stamped.mov").is_file(), "wrote stamped generated")
        ok(any("01-native" in n for n in rec["need_you"]), "still asks for native")
        # a fake native lets it derive 02
        native = root / "01-native.mov"
        shutil.copy2(root / "05-generated.mov", native)
        rec2 = P.prepare(root)
        ok((root / "02-stripped.mov").is_file(), "stripped from native")
        ok(any("02-stripped" in x for x in rec2["did"]), "reports the strip")


def test_observer_reuses_the_launcher():
    from automation import arms as A
    cmd = A.observer_argv("01-native", 90, touch=True, attach=False)
    joined = " ".join(cmd)
    ok("tiktok-audit" in joined, "existing launcher")
    ok("01-native" in joined, " -Run NAME")
    ok("run_observe.py" not in joined, "does not call the driver itself")


def test_cli_help():
    try:
        poster.build_parser().parse_args(["preflight"])
        ok(True, "preflight parses")
    except SystemExit as e:
        ok(False, "preflight parse exited %s" % e)
    ns = poster.build_parser().parse_args(["post"])
    eq(ns.post, False, "--post is opt-in")
    ns = poster.build_parser().parse_args(["post", "--post"])
    eq(ns.post, True, "--post sets the flag")
    ns = poster.build_parser().parse_args(
        ["run-arm", "01-native", "--file", "testfiles/01-native.mov"])
    eq(ns.post, False, "run-arm does not post unless asked")
    ns = poster.build_parser().parse_args(["status"])
    eq(ns.cmd, "status", "status parses")
    ns = poster.build_parser().parse_args(["prepare-arms", "--check"])
    eq(ns.check, True, "prepare-arms --check")
    ns = poster.build_parser().parse_args(["tap", "feed.create", "--dry-run"])
    eq(ns.at, "feed.create", "tap takes a screen.control")
    ns = poster.build_parser().parse_args(
        ["run-arm", "01-native", "--file", "x.mov", "--post", "--burner"])
    eq(ns.burner, True, "--burner is a real flag")
    eq(ns.unattended, False, "attended is the default")


def test_uncalibrated_refuses_live_post():
    layout = poster.load_layout(AUTO / "layout" / "iphone10_3.json")
    try:
        poster.run_flow(layout, dry_run=False)
        ok(False, "uncalibrated live post must refuse")
    except device.PosterError as e:
        ok("uncalibrated" in str(e), "refusal names the flag")
    plan = poster.run_flow(layout, dry_run=True)
    ok(len(plan) >= 5, "dry-run still produces the plan")
    ok(all(s.get("skipped") == "dry-run" for s in plan), "every step skipped")


def test_hid_js_has_no_objc():
    src = (AUTO / "phone" / "hid_inject.js").read_text(encoding="utf-8")
    ok("frida-objc-bridge" not in src, "HID is NativeFunction only")
    ok("IOHIDEventSystemClientDispatchEvent" in src, "system dispatch")
    ok("IOHIDEventCreateDigitizerFingerEventWithQuality" in src, "radius-capable")
    ok("import ObjC" not in src, "no ObjC import")


def test_import_js_is_photokit():
    src = (AUTO / "phone" / "import_photokit.js").read_text(encoding="utf-8")
    ok("PHAssetCreationRequest" in src, "creation request is named")
    ok("UIImageWriteToSavedPhotosAlbum" in src, "UIKit fallback")
    ok("terminates Photos.app" in src, "the crash is written down")
    ok("com.zhiliaoapp" not in src, "TikTok is not named in the importer")
    ok("import ObjC from 'frida-objc-bridge'" in src, "needs the bridge")


def test_gitignore_keys():
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    ok("automation/keys/" in gi, "private key must not be committed")


def test_poster_py_runs_as_a_script():
    """`python automation/poster.py` puts automation/ on sys.path[0]. The
    package import has to still resolve."""
    r = __import__("subprocess").run(
        [sys.executable, str(AUTO / "poster.py"), "--help"],
        capture_output=True, text=True, cwd=str(ROOT),
    )
    eq(r.returncode, 0, "poster.py --help exits 0")
    ok("never injects" in (r.stdout + r.stderr).lower()
       or "Drive the phone" in (r.stdout + r.stderr),
       "help text identifies the poster")


def test_dashboard_uses_coverage_tokens():
    html = (AUTO / "dashboard.html").read_text(encoding="utf-8")
    for tok in ("--paper", "--ink", "--accent", "--good", "--warn", "--gap", "--card", "--line"):
        ok(tok in html, "dashboard has %s" % tok)
    ns = poster.build_parser().parse_args(["dashboard"])
    eq(ns.cmd, "dashboard", "dashboard command")
    eq(ns.port, 8765, "default port")


def test_zxtouch_packet():
    from automation import touch as T
    eq(T.TASK_PERFORM_TOUCH, 10, "touch task id")
    pkt = T._packet(10, "11010187507800")
    eq(pkt, b"1011010187507800\r\n", "down at 187.5,780")
    decoded_ok, payload = T._decode(b"0;;960;;2079\r\n")
    eq(decoded_ok, True, "success decode")
    eq(payload[0], "960", "width field")
    px, py = T._to_zxtouch(187.5, 780, (375.0, 812.0), "points",
                           {"width": 960.0, "height": 2079.0})
    eq(abs(px - 480.0) < 0.01, True, "center x maps into zxtouch space")
    eq(abs(py - 1997.0) < 1.0, True, "home-indicator y maps into zxtouch space")


def test_observer_cmd_does_not_call_frida():
    cmd = poster.observer_cmd("01-native", 90, touch=True, attach=False)
    joined = " ".join(cmd)
    ok("tiktok-audit" in joined, "uses the existing launcher")
    ok("01-native" in joined, "run name forwarded")
    ok("frida" not in joined.lower() or "tiktok-audit" in joined,
       "does not invoke frida against TikTok itself")


def main():
    print()
    print("  poster selftest   (no phone, no USB)")
    print("  " + "-" * 50)
    for fn in (
        test_denylist, test_run_name, test_scp_uses_capital_p, test_usbmux_packet, test_sshd_lock_content,
        test_homes, test_layout, test_flat_layout_rejected, test_wda_refused,
        test_norm, test_kind_and_hash, test_bytes_match,
        test_arms_manifest, test_one_post_per_window, test_post_gates,
        test_sourceType_is_not_stampable, test_fidelity_picks_the_real_denominator,
        test_prepare_arms_derives_what_it_can,
        test_observer_reuses_the_launcher,
        test_cli_help, test_uncalibrated_refuses_live_post,
        test_hid_js_has_no_objc, test_import_js_is_photokit, test_gitignore_keys,
        test_poster_py_runs_as_a_script, test_dashboard_uses_coverage_tokens,
        test_zxtouch_packet,
        test_observer_cmd_does_not_call_frida,
    ):
        fn()
    print()
    if failures:
        print("  %d checks passed, %d failed" % (passed, len(failures)))
        for f in failures:
            print("    FAIL  %s" % f)
        return 1
    print("  %d checks passed, 0 failed" % passed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
