#!/usr/bin/env python3
"""
poster.py  —  drive the phone from outside TikTok.

The observation half is the Frida rig in the project root. This is the
other half: a separate process that imports a test file, posts it, and
steps the arms while that rig watches.

    python automation/poster.py preflight
    python automation/poster.py setup-ssh
    python automation/poster.py tunnel          # leave running; other cmds need it
    python automation/poster.py import FILE
    python automation/poster.py ping-hid         # ZXTouch :6000, else Frida IOHID
    python automation/poster.py wake             # undim, unlock, plant sender, screenshot
    python automation/poster.py tap feed.create
    python automation/poster.py post --dry-run
    python automation/poster.py inspect          # refuses: no view-tree
    python automation/poster.py run-arm 01-native --file testfiles/01-native.mov
    python automation/poster.py dashboard
    python automation/poster.py status
    python automation/poster.py prepare-arms
    python automation/poster.py run-arm 01-native --file testfiles/01-native.mov --post --burner

Hard rule, enforced in code: this process never attaches to, spawns, or
injects into TikTok. HID goes through SpringBoard. PhotoKit goes through
Photos.app. The shell is OpenSSH over USB. The observer is started as a
sibling (`tiktok-audit.ps1` / `tiktok-audit.sh`) and is the only thing
that is allowed to enter com.zhiliaoapp.musically.

WebDriverAgent / Appium are not a fallback. They inject, and TikTok
obfuscates the view tree they would read. Taps are per-screen
coordinate maps (`feed.create`, `picker.next`, `editor.next`). `--post`
is opt-in, stops for your OK, and refuses unless `--burner` is set.
One post per `runs/NAME/` window. The existing launcher is started as
a sibling and is the only thing that enters TikTok.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
# Running as `python automation/poster.py` puts automation/ on sys.path[0].
# The package import needs the project root.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from automation.device import (  # noqa: E402
    HOST, HOST_PORT, KEYS_DIR, POSTER_KEY, UsbTunnel,
    PosterError, InjectionGuard,
    probe_ssh_banner, safe_run_name, setup_ssh, ssh, ssh_preflight,
)
from automation.dash import serve as serve_dashboard  # noqa: E402
from automation.inject import (  # noqa: E402
    hid_ping, hid_swipe, hid_tap, plant_digitizer_sender, push_and_import,
    screenshot, wake_and_unlock, write_import_record,
)
from automation.arms import (  # noqa: E402
    arm_dir, compare_input, coverage_targets, default_confirm,
    dump_tags, fidelity_record, library_provenance, observer_argv,
    pull_stored, refuse_if_spent, require_post_gates,
)
from automation.prepare import check as prepare_check, prepare as prepare_arms  # noqa: E402
from automation.layout import (  # noqa: E402
    load_layout, logical_of, plan_flow, refuse_view_tree, require_calibrated,
    resolve_point, screens_of, screens_used_by_flow,
    uncalibrated_screens,
)


LAYOUT_DIR = HERE / "layout"
DEFAULT_LAYOUT = LAYOUT_DIR / "iphone10_3.json"
DEFAULT_ARMS = HERE / "arms.json"


def print_report(title: str, data) -> None:
    print()
    print("  " + title)
    print("  " + "-" * max(40, len(title)))
    print(json.dumps(data, indent=2, default=str))
    print()


def cmd_preflight(_args, tunnel: UsbTunnel) -> int:
    info = ssh_preflight(tunnel)
    # Frida reachability without attaching to anything in particular.
    try:
        import frida
        dev = frida.get_usb_device(timeout=5)
        procs = [p.name for p in dev.enumerate_processes()]
        info["frida"] = {
            "device": str(dev),
            "tiktok_running": any("TikTok" == n or "tiktok" in n.lower() for n in procs),
            "springboard": "SpringBoard" in procs,
            "photos": any(n in procs for n in ("Photos", "MobileSlideShow")),
            "sshd_process": "sshd" in procs,
        }
        info["note_sshd_process"] = (
            "sshd not in ps is expected: OpenSSH is inetd/socket-activated. "
            "Trust banner_22, not the process list."
        )
    except Exception as e:
        info["frida"] = {"error": str(e)}
    print_report("poster preflight", info)
    ok = bool(info.get("usbmux_devices")) and "OpenSSH" in (info.get("banner_22") or "")
    return 0 if ok else 2


def cmd_setup_ssh(_args, tunnel: UsbTunnel) -> int:
    report = setup_ssh(tunnel)
    print_report("setup-ssh", report.as_dict())
    return 0 if report.ssh_ok else 2


def cmd_tunnel(args, tunnel: UsbTunnel) -> int:
    print("  USB tunnel %s:%d -> device:22  (ctrl+c to stop)" % (HOST, HOST_PORT))
    print("  key %s" % POSTER_KEY)
    try:
        banner = probe_ssh_banner(22)
        print("  banner %s" % banner)
    except Exception as e:
        print("  banner failed: %s" % e)
    if args.once:
        return 0
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n  tunnel stopped")
        return 0


def cmd_ssh(args, _tunnel: UsbTunnel) -> int:
    r = ssh(args.command)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    return r.returncode


def cmd_import(args, _tunnel: UsbTunnel) -> int:
    rec = push_and_import(Path(args.file), kind=args.kind)
    dest = None
    if args.record:
        dest = write_import_record(rec, Path(args.record))
    elif args.run:
        name = safe_run_name(args.run)
        dest = write_import_record(rec, ROOT / "runs" / name / "import.json")
    print_report("import", rec)
    if dest:
        print("  wrote %s" % dest)
    if rec.get("bytes_match") is False:
        print("  NOTE: Photos stored a different size than the source.")
        print("  That is a finding about the import, not a crash.")
    return 0 if rec.get("import", {}).get("ok") else 2


def cmd_screenshot(args, _tunnel: UsbTunnel) -> int:
    dest = Path(args.out) if args.out else HERE / ".cache" / "screen.png"
    path = screenshot(dest)
    print("  screenshot %s  (%d bytes)" % (path, path.stat().st_size))
    return 0 if path.is_file() and path.stat().st_size > 100 else 2


def cmd_dashboard(args, _tunnel: UsbTunnel) -> int:
    host = args.host
    port = int(args.port)
    httpd = serve_dashboard(host, port)
    url = "http://%s:%d/poster" % (host, port)
    print("  dashboard %s" % url)
    print("  same color tokens as coverage/coverage-report.html")
    print("  ctrl+c to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  dashboard stopped")
    finally:
        httpd.server_close()
    return 0


def cmd_ping_hid(_args, _tunnel: UsbTunnel) -> int:
    info = hid_ping()
    print_report("hid ping (SpringBoard, not TikTok)", info)
    return 0 if info.get("ok") else 2


def cmd_wake(_args, _tunnel: UsbTunnel) -> int:
    rec = wake_and_unlock()
    print_report("wake/unlock (SpringBoard)", rec)
    try:
        planted = plant_digitizer_sender()
        print_report("digitizer sender", planted)
    except Exception as e:
        print_report("digitizer sender", {"ok": False, "error": str(e)})
    dest = HERE / ".cache" / "screen.png"
    path = screenshot(dest)
    print("  screenshot %s  (%d bytes)" % (path, path.stat().st_size))
    return 0


def cmd_tap(args, _tunnel: UsbTunnel) -> int:
    layout = load_layout(Path(args.layout) if args.layout else DEFAULT_LAYOUT)
    x, y = resolve_point(layout, args.at, screen=args.screen)
    if args.dry_run:
        print_report("tap dry-run", {
            "at": args.at, "screen": args.screen,
            "xy": [x, y], "logical": layout["logical"],
        })
        return 0
    rec = hid_tap(x, y, logical_of(layout))
    print_report("tap", {"at": args.at, "xy": [x, y], "sent": rec})
    return 0


def cmd_swipe(args, _tunnel: UsbTunnel) -> int:
    layout = load_layout(Path(args.layout) if args.layout else DEFAULT_LAYOUT)
    x1, y1 = resolve_point(layout, args.a, screen=args.screen)
    x2, y2 = resolve_point(layout, args.b, screen=args.screen)
    if args.dry_run:
        print_report("swipe dry-run", {"a": [x1, y1], "b": [x2, y2]})
        return 0
    rec = hid_swipe(x1, y1, x2, y2, logical_of(layout), ms=args.ms)
    print_report("swipe", rec)
    return 0


def run_flow(layout: dict, dry_run: bool) -> list[dict]:
    plan = plan_flow(layout)
    if not dry_run:
        require_calibrated(layout)
    done = []
    for step in plan:
        rec = {"step": step, "t": time.time()}
        if dry_run:
            rec["skipped"] = "dry-run"
            done.append(rec)
            continue
        kind = step.get("do")
        on = step.get("on")
        if kind == "tap":
            x, y = resolve_point(layout, step["at"], screen=on)
            rec["sent"] = hid_tap(x, y, logical_of(layout))
            rec["screen"] = on
        elif kind == "swipe":
            a = resolve_point(layout, step["a"], screen=on)
            b = resolve_point(layout, step["b"], screen=on)
            rec["sent"] = hid_swipe(*a, *b, logical_of(layout), ms=step.get("ms") or 280)
            rec["screen"] = on
        elif kind == "wait":
            time.sleep(float(step.get("wait") or 0))
        else:
            raise PosterError("unknown flow step %r" % kind)
        wait = float(step.get("wait") or 0)
        if wait and kind != "wait":
            time.sleep(wait)
        done.append(rec)
    return done


def cmd_post(args, _tunnel: UsbTunnel) -> int:
    layout = load_layout(Path(args.layout) if args.layout else DEFAULT_LAYOUT)
    dry = not args.post
    if dry:
        print("  dry-run (pass --post to actually tap). flow:")
    done = run_flow(layout, dry_run=dry)
    print_report("post flow", done)
    return 0


def cmd_inspect(_args, _tunnel: UsbTunnel) -> int:
    refuse_view_tree()
    return 3


def cmd_calibrate(args, _tunnel: UsbTunnel) -> int:
    layout_path = Path(args.layout) if args.layout else DEFAULT_LAYOUT
    layout = load_layout(layout_path)
    used = screens_used_by_flow(layout)
    print()
    print("  layout %s" % layout_path)
    print("  device %s  logical %s" % (layout.get("device"), layout.get("logical")))
    print("  %s" % (layout.get("why_not_wda") or ""))
    print()
    print("  screens (uncalibrated means --post will refuse that screen):")
    for name, screen in screens_of(layout).items():
        flag = "UNCALIBRATED" if screen.get("uncalibrated", True) else "calibrated"
        in_flow = "  in flow" if name in used else ""
        print("    %-12s %-14s%s" % (name, flag, in_flow))
        if args.screen and args.screen != name:
            continue
        for pname, xy in (screen.get("points") or {}).items():
            print("      %-16s %s" % (name + "." + pname, xy))
    print()
    print("  Address a tap as screen.control:")
    print("    python automation/poster.py tap feed.create --dry-run")
    print("    python automation/poster.py calibrate --screen feed --mark create")
    print()
    print("  picker.next and editor.next are different taps. When a")
    print("  screen's points land on the right controls, set that")
    print("  screen's uncalibrated flag to false. --post refuses until")
    print("  every screen the flow walks is marked.")
    print()
    still = uncalibrated_screens(layout, used)
    if still:
        print("  still uncalibrated in the flow: %s" % ", ".join(still))
        print()
    if args.mark:
        x, y = resolve_point(layout, args.mark, screen=args.screen)
        print("  tapping %s at %s (visual check, not a post)" % (args.mark, [x, y]))
        hid_tap(x, y, logical_of(layout))
    return 0


def cmd_status(_args, _tunnel: UsbTunnel) -> int:
    from automation.layout import uncalibrated_screens, screens_used_by_flow
    layout = load_layout(DEFAULT_LAYOUT)
    files = prepare_check()
    still = uncalibrated_screens(layout, screens_used_by_flow(layout))
    you, me = [], []
    you.append("keep the phone unlocked and plugged in. do not reboot "
               "(semi-tethered: Frida and sshd die until palera1n).")
    you.append("watch the glass for one SpringBoard tap "
               "(say when you are looking, then we tap 187.5,780).")
    if files["need_you"]:
        you.extend(files["need_you"])
    if still:
        you.append("after the SpringBoard tap works: open TikTok and we "
                   "calibrate one screen at a time while you watch. "
                   "still uncalibrated: %s." % ", ".join(still))
    you.append("when a post is about to fire: confirm this is a burner "
               "and type YES. I will not post unattended.")
    me.append("SSH key-only and HID ping are in. I will not tap until you watch.")
    me.append("no clang on the phone: byte-exact PhotoKit helper cannot "
              "be built here. import rewrite stays a measured finding.")
    if not files["have"].get("05-generated"):
        me.append("I can write 05-generated and 06-generated-stamped now "
                  "(prepare-arms). 02/04 wait on your 01-native / 03-scraped.")
    print()
    print("  YOU")
    for i, line in enumerate(you, 1):
        print("    %d. %s" % (i, line))
    print()
    print("  ME")
    for i, line in enumerate(me, 1):
        print("    %d. %s" % (i, line))
    print()
    print_report("files", files["have"])
    return 0


def cmd_prepare(args, _tunnel: UsbTunnel) -> int:
    if args.check:
        print_report("prepare-arms --check", prepare_check())
        return 0
    rec = prepare_arms()
    print_report("prepare-arms", rec)
    return 0 if not rec.get("need_you") else 0


def load_arms(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def observer_cmd(run_name: str, duration: int, touch: bool, attach: bool) -> list[str]:
    return observer_argv(run_name, duration, touch, attach, root=ROOT)


def cmd_run_arm(args, _tunnel: UsbTunnel) -> int:
    name = safe_run_name(args.name)
    src = Path(args.file)
    if not src.is_file():
        raise PosterError("arm file missing: %s" % src)
    how = getattr(args, "library", None) or "import"
    out_dir = arm_dir(name, ROOT)
    out_dir.mkdir(parents=True, exist_ok=True)
    refuse_if_spent(out_dir, force=getattr(args, "force", False))

    # laptop denominator, BEFORE import rewrites anything
    source_copy = out_dir / ("source" + src.suffix)
    shutil.copy2(src, source_copy)
    source_tags = dump_tags(source_copy, out_dir / "source.tags.json", root=ROOT)

    rec = None
    imported_local = None
    imported_tags = None
    if how == "import":
        rec = push_and_import(src)
        rec["library"] = library_provenance("import")
        write_import_record(rec, out_dir / "import.json")
        print_report("import %s" % name, rec)
        stored = (rec.get("import") or {}).get("stored") or {}
        if stored.get("path"):
            imported_local = out_dir / ("imported" + Path(stored["path"]).suffix)
            pull_stored(stored["path"], imported_local)
            imported_tags = dump_tags(imported_local, out_dir / "imported.tags.json",
                                      root=ROOT)
        fid = fidelity_record(src, rec, source_tags, imported_tags, imported_local)
    else:
        rec = {"library": library_provenance("capture"), "import": {"ok": True}}
        fid = {
            "drifted": False, "denominator": "on-device capture (no laptop file)",
            "source_tags": str(source_tags) if source_tags else None,
        }
    print_report("fidelity %s" % name, fid)
    if fid.get("drifted"):
        print("  LANDMINE: import rewrote the file. laptop dump is not the")
        print("  denominator. coverage will use imported.tags.json against INPUT.")

    want_post = bool(args.post)
    if want_post:
        require_post_gates(
            burner=bool(getattr(args, "burner", False)),
            unattended=bool(getattr(args, "unattended", False)),
            confirm=getattr(args, "confirm", default_confirm),
            arm_name=name,
        )

    duration = int(args.duration)
    obs = observer_cmd(name, duration, touch=not args.no_touch, attach=args.attach)
    print("  starting observer (unchanged launcher): %s" % " ".join(obs))
    child = None
    flow_rec = None
    try:
        child = subprocess.Popen(obs, cwd=str(ROOT))
        settle = 14.0 if not args.attach else 3.0
        print("  settling %.0fs before any HID" % settle)
        time.sleep(settle)
        if want_post:
            layout = load_layout(Path(args.layout) if args.layout else DEFAULT_LAYOUT)
            flow_rec = run_flow(layout, dry_run=False)
            print_report("post flow", flow_rec)
        else:
            print("  --post not set; observer is running, drive the phone yourself")
        child.wait(timeout=duration + 40)
    except subprocess.TimeoutExpired:
        print("  observer overran, killing")
        child.kill()
    finally:
        if child is not None and child.poll() is None:
            child.terminate()

    tags_path = out_dir / "tags.json"
    coverage = []
    for label, denom in coverage_targets(fid, out_dir):
        dest = out_dir / ("coverage-%s.txt" % label.split()[0])
        got = compare_input(denom, tags_path, dest, root=ROOT)
        coverage.append({"against": label, "report": str(got) if got else None})

    summary = {
        "arm": name,
        "file": str(src),
        "library": rec.get("library"),
        "import": rec,
        "fidelity": fid,
        "posted": want_post,
        "flow": flow_rec,
        "coverage": coverage,
        "observer_exit": None if child is None else child.returncode,
        "out": str(out_dir),
    }
    (out_dir / "poster.json").write_text(
        json.dumps(summary, indent=2, default=str) + "\n", encoding="utf-8")
    print_report("arm %s done" % name, {
        "observer_exit": summary["observer_exit"],
        "fidelity": fid.get("denominator"),
        "coverage": coverage,
        "out": summary["out"],
    })
    return 0 if rec.get("import", {}).get("ok") else 2


def cmd_run_matrix(args, tunnel: UsbTunnel) -> int:
    spec = load_arms(Path(args.arms) if args.arms else DEFAULT_ARMS)
    rc = 0
    for arm in spec.get("arms") or []:
        file_path = ROOT / arm["file"]
        if not file_path.is_file():
            print("  skip %s: no file at %s" % (arm["name"], file_path))
            continue
        sub = argparse.Namespace(
            name=arm["name"], file=str(file_path),
            duration=args.duration or spec.get("observer", {}).get("duration", 90),
            post=args.post, layout=args.layout,
            no_touch=args.no_touch,
            attach=args.attach or spec.get("observer", {}).get("attach", False),
            burner=getattr(args, "burner", False),
            unattended=getattr(args, "unattended", False),
            force=getattr(args, "force", False),
            library=arm.get("library", "import"),
            confirm=getattr(args, "confirm", default_confirm),
        )
        try:
            arm_rc = cmd_run_arm(sub, tunnel)
        except PosterError as e:
            print("  arm %s failed: %s" % (arm["name"], e))
            arm_rc = 2
        rc = rc or arm_rc
        if args.one:
            break
    return rc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="poster.py",
        description="Drive the phone from outside TikTok. Never injects into it.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="what you do next vs what I can do")
    p_prep = sub.add_parser("prepare-arms", help="derive 02/04/05/06 from dropped originals")
    p_prep.add_argument("--check", action="store_true", help="report gaps, write nothing")
    sub.add_parser("preflight", help="USB, banners, key, Frida, no attach to TikTok")
    sub.add_parser("setup-ssh", help="install the poster key and lock sshd to key-only")

    t = sub.add_parser("tunnel", help="USB SSH tunnel on 127.0.0.1:2222 (iproxy 2222 22)")
    t.add_argument("--once", action="store_true", help="start-check only, do not hold")

    s = sub.add_parser("ssh", help="run a remote command as root over the tunnel")
    s.add_argument("command")

    i = sub.add_parser("import", help="push a file and PhotoKit-import it (Photos.app)")
    i.add_argument("file")
    i.add_argument("--kind", choices=["auto", "photo", "video"], default="auto")
    i.add_argument("--run", help="also write runs/NAME/import.json")
    i.add_argument("--record", help="write the measurement JSON here")

    shot = sub.add_parser("screenshot", help="full display PNG via SpringBoard (not TikTok)")
    shot.add_argument("--out", help="PNG path (default automation/.cache/screen.png)")
    dash = sub.add_parser("dashboard", help="local control page, coverage-report color tokens")
    dash.add_argument("--host", default="127.0.0.1")
    dash.add_argument("--port", type=int, default=8765)
    sub.add_parser("ping-hid", help="ZXTouch :6000 if up, else Frida IOHID ping (SpringBoard)")
    sub.add_parser("wake", help="undim + unlock SpringBoard, plant digitizer sender, screenshot")

    tap = sub.add_parser("tap", help="HID tap: screen.control or x,y")
    tap.add_argument("at", help="feed.create, picker.next, or 187.5,778")
    tap.add_argument("--screen", help="default screen if 'at' is a bare control name")
    tap.add_argument("--layout", default=str(DEFAULT_LAYOUT))
    tap.add_argument("--dry-run", action="store_true")

    sw = sub.add_parser("swipe", help="HID swipe between two points on one screen")
    sw.add_argument("a")
    sw.add_argument("b")
    sw.add_argument("--screen")
    sw.add_argument("--ms", type=int, default=280)
    sw.add_argument("--layout", default=str(DEFAULT_LAYOUT))
    sw.add_argument("--dry-run", action="store_true")

    post = sub.add_parser("post", help="walk the per-screen flow (dry-run unless --post)")
    post.add_argument("--layout", default=str(DEFAULT_LAYOUT))
    post.add_argument("--post", action="store_true",
                      help="actually tap. without this, print the plan and stop")

    cal = sub.add_parser("calibrate", help="list per-screen maps; optionally tap one point")
    cal.add_argument("--layout", default=str(DEFAULT_LAYOUT))
    cal.add_argument("--screen", help="only show / mark this screen")
    cal.add_argument("--mark", help="tap screen.control (or --screen NAME --mark control)")

    sub.add_parser("inspect", help="refuses: TikTok obfuscates its view tree; WDA injects")

    arm = sub.add_parser("run-arm", help="one file, one window, existing rig as sibling")
    arm.add_argument("name")
    arm.add_argument("--file", required=True)
    arm.add_argument("--duration", type=int, default=90)
    arm.add_argument("--post", action="store_true",
                     help="drive the post flow after your OK; default is import + observe")
    arm.add_argument("--burner", action="store_true",
                     help="required with --post: this account can be burned")
    arm.add_argument("--unattended", action="store_true",
                     help="skip the YES prompt. start without this.")
    arm.add_argument("--force", action="store_true",
                     help="reuse a spent runs/NAME/ window (blends the tally)")
    arm.add_argument("--library", choices=["import", "capture"], default="import",
                     help="how the file entered Photos. import cannot fake capture.")
    arm.add_argument("--layout", default=str(DEFAULT_LAYOUT))
    arm.add_argument("--no-touch", action="store_true")
    arm.add_argument("--attach", action="store_true",
                     help="ask the observer to -Attach (TikTok must already be open)")

    mx = sub.add_parser("run-matrix", help="walk automation/arms.json, skipping missing files")
    mx.add_argument("--arms", default=str(DEFAULT_ARMS))
    mx.add_argument("--duration", type=int, default=0)
    mx.add_argument("--post", action="store_true")
    mx.add_argument("--burner", action="store_true")
    mx.add_argument("--unattended", action="store_true")
    mx.add_argument("--force", action="store_true")
    mx.add_argument("--layout", default=str(DEFAULT_LAYOUT))
    mx.add_argument("--no-touch", action="store_true")
    mx.add_argument("--attach", action="store_true")
    mx.add_argument("--one", action="store_true", help="stop after the first arm that has a file")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    # Every command that talks to the phone wants the tunnel, including
    # setup-ssh (it proves the key at the end). preflight can run with
    # or without it; we start it anyway so a later ssh check works.
    tunnel = UsbTunnel()
    try:
        tunnel.start()
    except OSError as e:
        # already bound: another poster tunnel (or iproxy) is up. Fine.
        if "already in use" not in str(e).lower() and getattr(e, "winerror", None) != 10048:
            raise
    try:
        cmd = {
            "status": cmd_status,
            "dashboard": cmd_dashboard,
            "prepare-arms": cmd_prepare,
            "preflight": cmd_preflight,
            "setup-ssh": cmd_setup_ssh,
            "tunnel": cmd_tunnel,
            "ssh": cmd_ssh,
            "import": cmd_import,
            "screenshot": cmd_screenshot,
            "ping-hid": cmd_ping_hid,
            "wake": cmd_wake,
            "tap": cmd_tap,
            "swipe": cmd_swipe,
            "post": cmd_post,
            "inspect": cmd_inspect,
            "calibrate": cmd_calibrate,
            "run-arm": cmd_run_arm,
            "run-matrix": cmd_run_matrix,
        }[args.cmd]
        return cmd(args, tunnel)
    except InjectionGuard as e:
        print("  HARD STOP: %s" % e, file=sys.stderr)
        return 3
    except PosterError as e:
        print("  poster: %s" % e, file=sys.stderr)
        return 2
    finally:
        if args.cmd != "tunnel":
            tunnel.stop()


if __name__ == "__main__":
    sys.exit(main())
