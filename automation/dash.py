"""Local poster dashboard. Same color tokens as coverage-report.html."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .device import ssh_preflight, usbmux_list_devices
from .inject import screenshot
from .touch import ZXTouch, ping as zxtouch_ping, probe_zxtouch, zxtouch_tap

HERE = Path(__file__).resolve().parent
HTML = HERE / "dashboard.html"
CACHE = HERE / ".cache"
PAGE = "/poster"


def status_payload() -> dict[str, Any]:
    out: dict[str, Any] = {
        "usb": [],
        "ssh": None,
        "zxtouch": {"ok": False},
        "screenshot": False,
        "errors": [],
    }
    try:
        out["usb"] = [
            {"id": d.get("DeviceID"), "udid": (d.get("Properties") or {}).get("SerialNumber")}
            for d in usbmux_list_devices()
        ]
    except Exception as e:
        out["errors"].append("usbmux: %s" % e)
        return out
    try:
        pre = ssh_preflight()
        ssh = pre.get("ssh")
        out["ssh"] = ssh
        if ssh is None and pre.get("banner_22"):
            out["ssh"] = {"ok": "OpenSSH" in (pre.get("banner_22") or ""), "banner": pre.get("banner_22")}
    except Exception as e:
        out["errors"].append("ssh: %s" % e)
    z = zxtouch_ping()
    out["zxtouch"] = z
    return out


def take_screen() -> Path:
    dest = CACHE / "dash-screen.png"
    return screenshot(dest)


class Handler(BaseHTTPRequestHandler):
    server_version = "poster-dash/1"

    def log_message(self, fmt: str, *args) -> None:
        print("  dash " + (fmt % args))

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, data: Any) -> None:
        blob = json.dumps(data, default=str).encode("utf-8")
        self._send(code, blob, "application/json; charset=utf-8")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", PAGE, PAGE + "/"):
            self._send(200, HTML.read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/api/status":
            rec = status_payload()
            rec["screenshot"] = True
            self._json(200, rec)
            return
        if path.startswith("/api/screen"):
            try:
                p = take_screen()
                self._send(200, p.read_bytes(), "image/png")
            except Exception as e:
                self._json(503, {"ok": False, "error": str(e)})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            body = {}
        try:
            if path == "/api/tap":
                if not probe_zxtouch():
                    self._json(503, {"ok": False, "error": "zxtouch :6000 is down"})
                    return
                nx = float(body.get("nx", 0.5))
                ny = float(body.get("ny", 0.5))
                rec = zxtouch_tap(nx, ny, space="norm")
                self._json(200, rec)
                return
            if path == "/api/toast":
                with ZXTouch() as z:
                    rec = {"ok": True, "toast": z.toast("poster dashboard", 1.5)}
                self._json(200, rec)
                return
            if path == "/api/seed":
                from .inject import _Session
                js = (HERE / "phone" / "seed_sender.js").read_text(encoding="utf-8")
                with _Session("SpringBoard", js) as s:
                    rec = dict(s.api.discover())
                rec.pop("services", None)
                self._json(200, rec)
                return
        except Exception as e:
            self._json(500, {"ok": False, "error": str(e)})
            return
        self._json(404, {"error": "not found"})


def serve(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    CACHE.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer((host, port), Handler)
    return httpd
