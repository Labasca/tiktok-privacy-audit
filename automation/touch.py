"""ZXTouch client over usbmux.

The Frida IOHID path in hid_inject.js can construct a typed-0 client
and dispatch events; the glass ignores them. The working press path on
this palera1n-rootless phone is ZXTouch's pccontrol.dylib, injected
into SpringBoard only, listening on device TCP 6000.

appdelegate.dylib ships with a UIKit-wide filter. We rewrite that
filter to SpringBoard before the first respring so nothing from this
package is loaded into TikTok.

Protocol is the public ZXTouch socket format (task type + ;; payload
+ CRLF). Coordinates are logical points, not pixels.
"""
from __future__ import annotations

import socket
import time
from typing import Optional

from .device import PosterError, usbmux_connect

ZXTOUCH_PORT = 6000

TASK_PERFORM_TOUCH = 10
TASK_SHOW_ALERT_BOX = 12
TASK_SHOW_TOAST = 22
TASK_COLOR_PICKER = 23
TASK_GET_DEVICE_INFO = 25

TOUCH_UP = 0
TOUCH_DOWN = 1
TOUCH_MOVE = 2

DEVICE_INFO_SCREEN_SIZE = 1
DEVICE_INFO_ORIENTATION = 2
DEVICE_INFO_SCALE = 3

TOAST_SUCCESS = 4
TOAST_MESSAGE = 3

IPHONE_X_POINTS = (375.0, 812.0)


class TouchError(PosterError):
    pass


def _packet(task_type: int, *datas) -> bytes:
    return (str(task_type) + ";;".join(str(x) for x in datas) + "\r\n").encode("utf-8")


def _decode(raw: bytes) -> tuple[bool, list[str] | str]:
    text = raw.decode("utf-8", "replace").replace("\r\n", "")
    parts = text.split(";;")
    if not text or text[0] != "0":
        return False, parts[1] if len(parts) >= 2 else text
    return True, parts[1:]


def probe_zxtouch(timeout: float = 2.0) -> bool:
    try:
        sock = usbmux_connect(ZXTOUCH_PORT, timeout=timeout)
    except Exception:
        return False
    try:
        sock.settimeout(timeout)
        sock.sendall(_packet(TASK_GET_DEVICE_INFO, DEVICE_INFO_SCREEN_SIZE))
        data = sock.recv(1024)
        ok, _ = _decode(data)
        return ok
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


class ZXTouch:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.sock = usbmux_connect(ZXTOUCH_PORT, timeout=timeout)
        self.sock.settimeout(timeout)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self) -> "ZXTouch":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _send(self, payload: bytes) -> None:
        assert self.sock is not None
        self.sock.sendall(payload)

    def _rpc(self, payload: bytes, buf: int = 1024) -> tuple[bool, list[str] | str]:
        assert self.sock is not None
        self._send(payload)
        data = self.sock.recv(buf)
        return _decode(data)

    def touch(self, kind: int, finger: int, x: float, y: float) -> None:
        blob = "1{:d}{:02d}{:05d}{:05d}".format(
            int(kind), int(finger), int(round(x * 10)), int(round(y * 10))
        )
        self._send(_packet(TASK_PERFORM_TOUCH, blob))

    def tap(self, x: float, y: float, hold_ms: int = 70, finger: int = 1) -> dict:
        self.touch(TOUCH_DOWN, finger, x, y)
        time.sleep(max(hold_ms, 1) / 1000.0)
        self.touch(TOUCH_UP, finger, x, y)
        return {"ok": True, "via": "zxtouch", "xy": [x, y], "hold_ms": hold_ms}

    def swipe(self, x1: float, y1: float, x2: float, y2: float,
              ms: int = 280, finger: int = 1, steps: int = 12) -> dict:
        steps = max(2, int(steps))
        self.touch(TOUCH_DOWN, finger, x1, y1)
        dt = max(ms, 1) / 1000.0 / steps
        for i in range(1, steps):
            t = i / steps
            self.touch(TOUCH_MOVE, finger, x1 + (x2 - x1) * t, y1 + (y2 - y1) * t)
            time.sleep(dt)
        self.touch(TOUCH_UP, finger, x2, y2)
        return {"ok": True, "via": "zxtouch", "a": [x1, y1], "b": [x2, y2], "ms": ms}

    def screen_size(self) -> dict:
        ok, payload = self._rpc(_packet(TASK_GET_DEVICE_INFO, DEVICE_INFO_SCREEN_SIZE))
        if not ok:
            raise TouchError("screen_size failed: %s" % payload)
        return {"width": float(payload[0]), "height": float(payload[1])}

    def toast(self, text: str, duration: float = 1.5) -> tuple[bool, list[str] | str]:
        return self._rpc(_packet(TASK_SHOW_TOAST, TOAST_SUCCESS, text, duration, 0, 0))

    def pick_color(self, x: float, y: float) -> dict:
        ok, payload = self._rpc(_packet(TASK_COLOR_PICKER, x, y))
        if not ok:
            raise TouchError("pick_color failed: %s" % payload)
        return {
            "red": float(payload[0]),
            "green": float(payload[1]),
            "blue": float(payload[2]),
        }

    def alert(self, title: str, content: str, duration: float = 2.0) -> tuple[bool, list[str] | str]:
        return self._rpc(_packet(TASK_SHOW_ALERT_BOX, title, content, duration))


def points_from_norm(nx: float, ny: float,
                     logical: tuple[float, float] = IPHONE_X_POINTS) -> tuple[float, float]:
    w, h = logical
    if 0.0 <= nx <= 1.0 and 0.0 <= ny <= 1.0:
        return nx * w, ny * h
    return nx, ny


def zxtouch_tap(x: float, y: float, logical: tuple[float, float] = IPHONE_X_POINTS,
                space: str = "norm", hold_ms: int = 70) -> dict:
    with ZXTouch() as z:
        size = z.screen_size()
        px, py = _to_zxtouch(x, y, logical, space, size)
        rec = z.tap(px, py, hold_ms=hold_ms)
    rec["space"] = space
    rec["sent_xy"] = [px, py]
    rec["zxtouch_screen"] = size
    return rec


def zxtouch_swipe(x1: float, y1: float, x2: float, y2: float,
                  logical: tuple[float, float] = IPHONE_X_POINTS,
                  space: str = "norm", ms: int = 280) -> dict:
    with ZXTouch() as z:
        size = z.screen_size()
        a = _to_zxtouch(x1, y1, logical, space, size)
        b = _to_zxtouch(x2, y2, logical, space, size)
        rec = z.swipe(*a, *b, ms=ms)
    rec["space"] = space
    rec["zxtouch_screen"] = size
    return rec


def _to_zxtouch(x: float, y: float, logical: tuple[float, float],
                space: str, size: dict) -> tuple[float, float]:
    """Map layout coordinates into ZXTouch's get_screen_size space.

    On this iPhone X that space is 960x2079, not 375x812 points. Touches
    are divided by that size inside pccontrol, so we must speak it.
    """
    zw, zh = float(size["width"]), float(size["height"])
    if space == "zxtouch":
        return float(x), float(y)
    if 0.0 <= float(x) <= 1.0 and 0.0 <= float(y) <= 1.0 and space != "points":
        return float(x) * zw, float(y) * zh
    lw, lh = logical
    return float(x) / lw * zw, float(y) / lh * zh


def ping() -> dict:
    try:
        with ZXTouch() as z:
            size = z.screen_size()
        return {"ok": True, "via": "zxtouch", "port": ZXTOUCH_PORT, "screen": size}
    except Exception as e:
        return {"ok": False, "via": "zxtouch", "error": str(e)}
