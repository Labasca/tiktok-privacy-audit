"""
Per-screen coordinate maps.

WebDriverAgent and Appium would be the robust way to tap "the Post
button". They work by injecting an XCTest runner into the app and
reading its view tree. TikTok's launch sweep is exactly the class of
check that looks for that, and the tree itself is obfuscated: labels
and hierarchy are not a stable API. So this file does not inspect
TikTok. It names screens, and each screen has a map of points you
calibrate by eye.

A point is addressed as `screen.control` (feed.create, picker.next,
composer.post). `next` on the picker and `next` on the editor are
different taps; a flat map would collapse them.

`--post` requires every screen the flow walks to be marked calibrated.
One screen being right is not enough. We cannot confirm arrival on the
next screen from the view tree, so the flow waits, then taps. The
observer is what confirms a post actually left.
"""
from __future__ import annotations

from typing import Optional

from .device import PosterError, InjectionGuard

# Named so a grepped "Appium" or "WebDriverAgent" in this package hits
# a refusal, not an implementation.
WDA_APPIUM_REFUSAL = (
    "refusing to inspect TikTok's view tree. WebDriverAgent / Appium "
    "are robust and they inject; TikTok obfuscates the tree besides. "
    "Drive with per-screen coordinate maps (layout/iphone10_3.json)."
)


def refuse_view_tree(why: str = "") -> None:
    raise InjectionGuard(WDA_APPIUM_REFUSAL + ((" " + why) if why else ""))


def load_layout(path) -> dict:
    import json
    from pathlib import Path
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_layout(data, source=str(path))
    return data


def validate_layout(data: dict, source: str = "layout") -> None:
    if "logical" not in data:
        raise PosterError("%s has no logical size" % source)
    screens = data.get("screens")
    if not screens or not isinstance(screens, dict):
        raise PosterError(
            "%s is a flat point list. TikTok's screens do not share a "
            "coordinate space: picker.next and editor.next are different "
            "taps. Split them under screens.{name}.points." % source
        )
    for name, screen in screens.items():
        if not isinstance(screen, dict) or "points" not in screen:
            raise PosterError("%s screen %r has no points" % (source, name))
    flow = data.get("flow") or []
    for i, step in enumerate(flow):
        if step.get("do") in ("tap", "swipe") and not step.get("on"):
            raise PosterError(
                "%s flow step %d has no 'on' screen. Every tap is "
                "relative to a screen, not to the device." % (source, i)
            )


def logical_of(layout: dict) -> tuple[float, float]:
    w, h = layout["logical"]
    return float(w), float(h)


def screens_of(layout: dict) -> dict:
    return layout.get("screens") or {}


def screen_names(layout: dict) -> list[str]:
    return list(screens_of(layout))


def uncalibrated_screens(layout: dict, used: Optional[set[str]] = None) -> list[str]:
    out = []
    for name, screen in screens_of(layout).items():
        if used is not None and name not in used:
            continue
        if screen.get("uncalibrated", True):
            out.append(name)
    return out


def screens_used_by_flow(layout: dict) -> set[str]:
    used = set()
    for step in layout.get("flow") or []:
        if step.get("on"):
            used.add(step["on"])
        if step.get("then"):
            used.add(step["then"])
    return used


def parse_ref(name_or_xy: str, default_screen: Optional[str] = None
              ) -> tuple[Optional[str], str]:
    """'feed.create' -> ('feed','create'); '187.5,778' -> (None,'187.5,778')."""
    if "," in name_or_xy and name_or_xy[0].isdigit():
        return None, name_or_xy
    if "." in name_or_xy:
        screen, _, rest = name_or_xy.partition(".")
        if screen and rest:
            return screen, rest
    if default_screen:
        return default_screen, name_or_xy
    return None, name_or_xy


def resolve_point(layout: dict, name_or_xy: str,
                  screen: Optional[str] = None) -> tuple[float, float]:
    scr, rest = parse_ref(name_or_xy, default_screen=screen)
    if "," in rest:
        x_s, y_s = rest.split(",", 1)
        return float(x_s), float(y_s)
    if not scr:
        raise PosterError(
            "point %r has no screen. Use screen.control (feed.create) "
            "or pass --screen. A bare name is how picker.next and "
            "editor.next get mixed up." % name_or_xy
        )
    screens = screens_of(layout)
    if scr not in screens:
        raise PosterError(
            "no screen %r. have: %s" % (scr, ", ".join(sorted(screens)))
        )
    pts = screens[scr].get("points") or {}
    if rest not in pts:
        raise PosterError(
            "no point %r on screen %r. have: %s"
            % (rest, scr, ", ".join(sorted(pts)))
        )
    x, y = pts[rest]
    return float(x), float(y)


def require_calibrated(layout: dict) -> None:
    used = screens_used_by_flow(layout)
    missing = uncalibrated_screens(layout, used)
    if missing:
        raise PosterError(
            "screens still uncalibrated: %s. TikTok obfuscates its view "
            "tree, so a guessed tap is the only thing that will run, and "
            "a guessed Post spends a real upload. Walk each screen with "
            "`poster.py calibrate --screen NAME --mark POINT`, then set "
            "uncalibrated to false on that screen." % ", ".join(missing)
        )


def plan_flow(layout: dict) -> list[dict]:
    plan = []
    for step in layout.get("flow") or []:
        row = dict(step)
        if step.get("do") == "tap" and "at" in step:
            row["xy"] = list(resolve_point(layout, step["at"], screen=step.get("on")))
            row["ref"] = "%s.%s" % (step.get("on"), step["at"])
        elif step.get("do") == "swipe":
            row["a_xy"] = list(resolve_point(layout, step["a"], screen=step.get("on")))
            row["b_xy"] = list(resolve_point(layout, step["b"], screen=step.get("on")))
        plan.append(row)
    return plan
