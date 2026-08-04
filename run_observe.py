#!/usr/bin/env python3
# Non-interactive Frida driver: spawn TikTok, load observe.js (read-only),
# stream its log messages for a fixed duration, then detach cleanly.
# Cross-platform (macOS / Windows / Linux): needs the `frida` python package
# whose version matches the phone's frida-server, and (on Windows) Apple's
# usbmux layer from iTunes / the Apple Devices app.
import sys, os, time, frida

# run from the script's own directory so observe.compiled.js resolves anywhere
os.chdir(os.path.dirname(os.path.abspath(__file__)))

BUNDLE = "com.zhiliaoapp.musically"
DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 35

def on_message(msg, data):
    t = msg.get("type")
    if t == "log":
        print(msg.get("payload", ""), flush=True)
    elif t == "send":
        print(msg["payload"], flush=True)
    elif t == "error":
        print("[script-error] " + msg.get("stack", msg.get("description", "?")), flush=True)

def main():
    dev = frida.get_usb_device(timeout=8)
    print(f"[*] device: {dev.name}", flush=True)
    with open("observe.compiled.js", "r") as f:
        src = f.read()
    pid = dev.spawn([BUNDLE])
    print(f"[*] spawned {BUNDLE} pid={pid}", flush=True)
    session = dev.attach(pid)
    script = session.create_script(src)
    script.on("message", on_message)
    script.load()
    dev.resume(pid)
    print(f"[*] resumed. observing for {DURATION}s (read-only)...\n", flush=True)
    t0 = time.time()
    try:
        while time.time() - t0 < DURATION:
            time.sleep(0.4)
    except KeyboardInterrupt:
        pass
    print("\n[*] done, detaching (app keeps running).", flush=True)
    try:
        session.detach()
    except Exception:
        pass

if __name__ == "__main__":
    main()
