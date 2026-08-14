#!/usr/bin/env python3
"""Build the project-artifact style metadata page from live dumps."""
from __future__ import annotations

import datetime
import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dump_tags import collect  # noqa: E402

OUT = Path(__file__).resolve().parent


def esc(s) -> str:
    return html.escape(str(s), quote=True)


PROV = (
    "make", "model", "gps", "software", "creationdate", "location",
    "encoder", "compressor", "lavf", "duration", "filesize",
)


def load_run(name: str) -> dict:
    return json.loads((ROOT / "runs" / name / "tags.json").read_text(encoding="utf-8"))


def prov_rows(tags: dict) -> list[tuple[str, str]]:
    rows = []
    for k, v in tags.items():
        lk = k.lower()
        if (
            any(s in lk for s in PROV)
            or k.startswith("File:")
            or k.startswith("Keys:")
            or k.startswith("UserData:")
        ):
            rows.append((k, v["value"]))
    return rows


def tag_rows(tags_obj: dict) -> list:
    rows = []
    for name, info in tags_obj.get("tags", {}).items():
        val = info.get("value")
        if isinstance(val, list):
            val = " | ".join(str(x) for x in val)
        rows.append((info.get("first_seen_s"), info.get("reads"), name, val))
    rows.sort(key=lambda r: (r[0] is None, r[0] or 0, str(r[2])))
    return rows


def find_val(run: dict, *needles: str) -> str:
    for name, info in run.get("tags", {}).items():
        ln = name.lower()
        if all(n.lower() in ln for n in needles):
            val = info.get("value")
            if isinstance(val, list):
                return " | ".join(str(x) for x in val)
            return str(val)
    return "—"


def files_block(run: dict) -> str:
    out = ""
    for k, v in run.get("files", {}).items():
        items = "".join("<li><code>%s</code></li>" % esc(x) for x in v)
        out += "<h3>%s</h3><ul>%s</ul>" % (esc(k), items)
    return out


def table_from_prov(tags: dict) -> str:
    return "".join(
        "<tr><td><code>%s</code></td><td>%s</td></tr>" % (esc(k), esc(v))
        for k, v in prov_rows(tags)
    )


def tag_table_rows(run: dict) -> str:
    rows = ""
    for t, reads, name, val in tag_rows(run):
        rows += (
            "<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>"
            % (esc(t), esc(reads), esc(name), esc(val))
        )
    return rows


def bodies_html(run: dict, note: str | None = None) -> str:
    bodies = run.get("bodies") or []
    if not bodies:
        return (
            "<p>No plaintext HTTP bodies were written for this window.</p>"
        )
    rows = ""
    for b in bodies:
        rows += (
            "<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>"
            % (esc(b.get("file")), esc(b.get("from")), esc(b.get("bytes")))
        )
    default_note = (
        "AppsFlyer / Snap Kit / Facebook SDK posts the socket hook wrote to disk, "
        "unless the request line says SSL_write /upload/v1 (that is the CDN media post). "
        "Tag values longer than 72 characters are already truncated in tags.json."
    )
    return (
        "<div class=\"scroll\"><table><tr><th>File</th><th>Request</th>"
        "<th>Bytes</th></tr>%s</table></div>"
        "<p class=\"meta\">%s</p>" % (rows, esc(note or default_note))
    )


def read_run_text(name: str, filename: str) -> str:
    path = ROOT / "runs" / name / filename
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def raw_arm_html(name: str, title: str, run: dict) -> str:
    meta = run.get("run") or {}
    session = read_run_text(name, "session.log")
    tags_pretty = json.dumps(run, indent=2, ensure_ascii=False)
    return """
<h2 id="raw-%(slug)s">%(title)s <span class="pill done">%(n)s tags</span></h2>
<p class="meta">run <code>%(name)s</code> · pid %(pid)s · observed %(obs)ss · %(window)s · died %(died)s · attached %(att)s</p>
%(files)s
<h3>Captured HTTP bodies</h3>
%(bodies)s
<h3>Every tag Frida recorded (%(n)s)</h3>
<p class="meta">Source: runs/%(name)s/tags.json. Image PixelWidth/Height lists are UI chrome, not the video.</p>
<div class="scroll">
<table>
  <tr><th>t (s)</th><th>reads</th><th>Tag</th><th>Value</th></tr>
  %(rows)s
</table>
</div>
<details class="rawdump">
  <summary>Raw tags.json</summary>
  <pre class="raw">%(tags)s</pre>
</details>
<details class="rawdump">
  <summary>Raw session.log (%(slog)s characters)</summary>
  <pre class="raw">%(session)s</pre>
</details>
""" % {
        "slug": esc(name),
        "title": esc(title),
        "n": esc(run.get("tag_count")),
        "name": esc(name),
        "pid": esc(meta.get("pid")),
        "obs": esc(meta.get("observed_s")),
        "window": esc(meta.get("window")),
        "died": esc(meta.get("died_reason")),
        "att": esc(meta.get("attached")),
        "files": files_block(run),
        "bodies": bodies_html(run),
        "rows": tag_table_rows(run),
        "tags": esc(tags_pretty),
        "slog": f"{len(session):,}",
        "session": esc(session),
    }


def main() -> None:
    r1 = load_run("unique-1-solo")
    r2 = load_run("unique-2-solo")
    r3 = load_run("unique-3-sintel")
    r4 = load_run("unique-4-bunny")
    r5 = load_run("unique-5-camera")
    r6 = load_run("unique-6-canary-2")
    r6pub = load_run("unique-6-publish")
    src1 = collect(str(ROOT / "testfiles/unique-1-clean.mov"))
    src2 = collect(str(ROOT / "testfiles/unique-2-stamped.mov"))
    src5 = collect(str(ROOT / "gallery-id/IMG_0026-camera.MOV"))
    src6 = collect(str(ROOT / "testfiles/unique-6-canary.mov"))
    recode_path = ROOT / "gallery-id/publish_video_local_canary.mp4"
    src6out = collect(str(recode_path)) if recode_path.is_file() else {}
    canaries = json.loads(
        (ROOT / "testfiles/unique-6-canary.json").read_text(encoding="utf-8")
    )
    as_of = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    raw_html = (
        raw_arm_html("unique-1-solo", "1 · CLEAN · IMG_0021", r1)
        + raw_arm_html("unique-2-solo", "2 · STAMPED · IMG_0022", r2)
        + raw_arm_html("unique-3-sintel", "3 · Sintel · IMG_0010", r3)
        + raw_arm_html("unique-4-bunny", "4 · Bunny · IMG_0009", r4)
        + raw_arm_html("unique-5-camera", "5 · Camera · IMG_0026", r5)
        + raw_arm_html("unique-6-canary-2", "6 · CANARY · IMG_0027 (reads)", r6)
        + raw_arm_html("unique-6-publish", "6b · CANARY CDN upload (attach)", r6pub)
    )

    state = {
        "as_of": as_of,
        "workstreams": [
            {"id": "1-clean", "status": "done", "owner": "you+frida"},
            {"id": "2-stamped", "status": "done", "owner": "you+frida"},
            {"id": "3-sintel", "status": "done", "owner": "you+frida"},
            {"id": "4-bunny", "status": "done", "owner": "you+frida"},
            {"id": "5-camera", "status": "done", "owner": "you+frida"},
            {"id": "6-canary", "status": "done", "owner": "you+frida"},
            {"id": "cdn-upload", "status": "done", "owner": "rig"},
            {"id": "aweme-json", "status": "blocked", "owner": "rig"},
        ],
    }
    state_json = json.dumps(state).replace("<", "\\u003c")

    css = """
  :root { --fg:#1a1a1a; --bg:#fdfdfd; --accent:#0a7d4a; --warn:#b45309; --red:#b91c1c; --muted:#666; --border:#ddd; --code-bg:#f5f5f5; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e4e4e4; --bg:#1a1a1a; --accent:#4ade80; --warn:#fbbf24; --red:#f87171; --muted:#999; --border:#333; --code-bg:#262626; }
  }
  * { box-sizing:border-box; }
  body { font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; color:var(--fg); background:var(--bg); max-width:1100px; margin:1.5em auto; padding:0 1.5em 3em; }
  h1,h2,h3,h4 { font-weight:600; margin-top:1.6em; line-height:1.3; }
  h1 { font-size:1.7em; margin-bottom:.2em; }
  h2 { font-size:1.35em; border-bottom:1px solid var(--border); padding-bottom:.2em; }
  h3 { font-size:1.1em; }
  a { color:var(--accent); }
  code { background:var(--code-bg); padding:.15em .35em; border-radius:3px; font-size:.92em; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-all; }
  .scroll { overflow-x:auto; }
  table { border-collapse:collapse; width:100%; margin:.8em 0; font-size:.93em; }
  th,td { border:1px solid var(--border); padding:.45em .7em; vertical-align:top; text-align:left; }
  th { font-weight:600; background:var(--code-bg); }
  ul { padding-left:1.4em; } li { margin:.25em 0; }
  .meta { color:var(--muted); font-size:.85em; }
  .sub { color:var(--muted); font-size:.95em; margin-top:.3em; }
  .status { background:color-mix(in srgb, var(--accent) 12%, var(--bg)); border:1px solid var(--accent); border-radius:8px; padding:.9em 1.2em; margin:1.2em 0; }
  .status .badge { display:inline-block; background:var(--accent); color:var(--bg); padding:.1em .6em; border-radius:4px; font-size:.78em; font-weight:600; }
  .status p { margin:.5em 0 0; font-size:.92em; }
  .next { border:1px solid var(--warn); border-left:4px solid var(--warn); border-radius:8px; padding:.8em 1.2em; margin:1.2em 0; background:color-mix(in srgb, var(--warn) 8%, var(--bg)); }
  .next > summary { cursor:pointer; font-weight:600; font-size:1.02em; padding:0; }
  .next ol { margin:.5em 0 .1em 1.3em; padding:0; }
  .next .who { font-weight:600; }
  .pill { display:inline-block; font-size:.78em; padding:.1em .55em; border-radius:10px; background:var(--code-bg); color:var(--muted); margin-left:.4em; }
  .pill.done { background:var(--accent); color:var(--bg); }
  .pill.now  { background:var(--warn);   color:var(--bg); }
  .pill.next { background:var(--code-bg); color:var(--fg); border:1px solid var(--border); }
  .pill.warn { background:var(--red);    color:var(--bg); }
  .callout { border:1px solid var(--border); border-left:3px solid var(--accent); border-radius:4px; padding:.7em 1em; margin:1em 0; font-size:.93em; background:color-mix(in srgb, var(--accent) 5%, var(--bg)); }
  .tabbar { display:flex; flex-wrap:wrap; gap:.2em; border-bottom:2px solid var(--border); margin:1.2em 0 1.5em; }
  .tabbar .tab { padding:.55em 1em; cursor:pointer; border:1px solid transparent; border-bottom:none; border-radius:6px 6px 0 0; font:inherit; font-weight:500; font-size:.95em; color:var(--muted); background:none; margin-bottom:-2px; }
  .tabbar .tab.active { color:var(--fg); border-color:var(--border); border-bottom:2px solid var(--bg); background:var(--bg); font-weight:600; }
  .pane { display:none; } .pane.active { display:block; }
  h4.warnish { color:var(--red); }
  details.rawdump { margin:1em 0; border:1px solid var(--border); border-radius:6px; padding:.5em 1em; }
  details.rawdump > summary { cursor:pointer; font-weight:600; }
  pre.raw { font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace; overflow:auto; max-height:36em; background:var(--code-bg); padding:1em; border-radius:4px; white-space:pre-wrap; word-break:break-word; }
  .jumplist { display:flex; flex-wrap:wrap; gap:.4em; margin:1em 0; }
  .jumplist a { font-size:.9em; }
"""

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TikTok privacy audit — metadata</title>
<style>{css}</style>
</head>
<body>
<header>
  <h1>TikTok privacy audit</h1>
  <div class="sub">Read-only Frida observation of what TikTok reads from a post on a jailbroken iPhone X · burner account · observer never injects to post</div>
</header>

<div class="status">
  <span class="badge">LIVE · 6 ARMS + CDN UPLOAD</span>
  <span class="meta" style="float:right">As of {esc(as_of)}</span>
  <p>TikTok <strong>reads</strong> whatever QuickTime Keys / UserData the file actually holds — including fake canaries (<code>CANARYMK-7F3A</code>, GPS <code>11.1111,22.2222</code>). The local re-encode and the CDN <code>POST /upload/v1</code> we captured have <strong>none</strong> of those fields. The video is on the burner profile. A separate <code>aweme_v1</code> JSON call was not seen; attach+TLS still kills the app after the success buzz.</p>
</div>

<details class="next">
  <summary>Status <span class="meta">· closed for this matrix</span></summary>
  <ol>
    <li><span class="who">Finding</span> — file injection is read on picker/encode, stripped before the CDN media upload <span class="meta">— reading ≠ uploading</span></li>
    <li><span class="who">Operator</span> — no more posts needed. Leave iCloud Photos off on this phone. Do not retry <code>-Full -Attach</code> <span class="meta">— it crashes TikTok</span></li>
  </ol>
</details>

<div class="tabbar">
  <button class="tab active" data-pane="over">1 · Overview</button>
  <button class="tab" data-pane="work">2 · Arms</button>
  <button class="tab" data-pane="find">3 · Matrix</button>
  <button class="tab" data-pane="den">4 · File denominators</button>
  <button class="tab" data-pane="bg">5 · Background</button>
  <button class="tab" data-pane="plan">6 · Plan</button>
  <button class="tab" data-pane="risk">7 · Risks</button>
  <button class="tab" data-pane="faq">8 · FAQ</button>
  <button class="tab" data-pane="raw">9 · Raw reads</button>
  <button class="tab" data-pane="inj">10 · Injection</button>
</div>

<main>
<section class="pane active" id="over">
  <div class="callout">Measure which provenance tags in a video file TikTok actually reads on post, versus what the file held, versus what we can prove left the phone. One clip, one Recents library, one Frida window.</div>
  <h2>Success criteria</h2>
  <table>
    <tr><th>Criterion</th><th>Statement</th><th>Check</th><th>Status</th></tr>
    <tr><td>Clean INPUT</td><td>A generated file with no Apple/GPS tags is opened as itself, not blended with other Recents items.</td><td><code>files.INPUT</code> names only IMG_0021 (plus its own draft/export). No iPhone X / GPS / Bunny strings.</td><td><span class="pill done">met</span></td></tr>
    <tr><td>Denominator</td><td>exiftool dump of the laptop file exists before post.</td><td>unique-1-clean.mov has Lavf only; stamped sibling has Apple/iPhone X/16.7.16; camera dump has GPS.</td><td><span class="pill done">met</span></td></tr>
    <tr><td>Encode observed</td><td>TikTok re-encodes the file and writes its own product block.</td><td>Every solo wrote product:tiktok / TEEditor / isFastImport into export.</td><td><span class="pill done">met</span></td></tr>
    <tr><td>Stamped contrast</td><td>Same pipeline on blue 2 shows Apple make/model/OS/date being read.</td><td>unique-2-solo INPUT has Apple / iPhone X / 16.7.16 / 2026-08-11T14:02:31. GPS was never on this file.</td><td><span class="pill done">met</span></td></tr>
    <tr><td>Camera GPS</td><td>A real Camera recording is read with ISO6709 + accuracy, without OS location permission.</td><td>unique-5-camera INPUT only IMG_0026; GPS +54.6389+024.9351+161.972/ 17×; no CLLocationManager.</td><td><span class="pill done">met</span></td></tr>
    <tr><td>Five-arm matrix</td><td>compare_runs.py --normalize --container INPUT across the five solos.</td><td>Apple/GPS only on stamped + camera; Bunny credits only on bunny; CLEAN/Sintel invent neither.</td><td><span class="pill done">met</span></td></tr>
    <tr><td>Canary injection</td><td>Unique fake make/model/OS/date/GPS/title survive Photos and are read as themselves, not rewritten to Apple/Vilnius.</td><td>unique-6-canary-2 INPUT only IMG_0027; every CANARY* and 11.1111/22.2222 read; no iPhone X / 54.6389 invented.</td><td><span class="pill done">met</span></td></tr>
    <tr><td>Re-encode strip</td><td>Local publish_video_local_* no longer holds the canaries.</td><td>exiftool on 14311 B copy: only TEEditor / Lavf57.71.100. No CANARY / GPS.</td><td><span class="pill done">met</span></td></tr>
    <tr><td>CDN media upload</td><td>See the file that actually left toward TikTok storage.</td><td>unique-6-publish SSL_write POST /upload/v1 to tiktokcdn-eu.com, 34384 B, no canaries. Video live on profile.</td><td><span class="pill done">met</span></td></tr>
    <tr><td>aweme JSON body</td><td>See whether a second publish API still carries the canaries as form fields.</td><td>Not captured. App died ~1s after success haptic. Hook now self-detaches after 2 TLS posts.</td><td><span class="pill warn">not seen</span></td></tr>
    <tr><td>Settled OUTPUT</td><td>Dump tags on the finished re-encode.</td><td>Sintel / Bunny settled. Canary local copy dumped by hand. CLEAN / stamped / camera OUTPUT never settled (wav/m4a).</td><td><span class="pill now">partial</span></td></tr>
  </table>
  <h2>Out of scope</h2>
  <ul>
    <li>Calling TikTok HTTP APIs from the laptop (skips PhotoKit/encoder; replays session auth).</li>
    <li>Injecting into <code>com.zhiliaoapp.musically</code> to tap Post.</li>
    <li>Faking PHAsset.sourceType via EXIF — every file arm is a library import.</li>
    <li>Deleting photos from iCloud on other devices (CloudPhotos off on this phone only).</li>
  </ul>
</section>

<section class="pane" id="work">
  <h2>Status</h2>
  <div class="scroll">
  <table>
    <tr><th>ID</th><th>What you see</th><th>File</th><th>Metadata intent</th><th>Status</th></tr>
    <tr><td>1</td><td>Red screen, giant 1, CLEAN</td><td><code>IMG_0021.MOV</code> 9065 B</td><td>Generated, Lavf only, no Apple</td><td><span class="pill done">solo window done</span></td></tr>
    <tr><td>2</td><td>Blue screen, giant 2, STAMPED</td><td><code>IMG_0022.MOV</code> 16524 B</td><td>Apple / iPhone X / 16.7.16 / 2026-08-11T14:02:31+0300 · no GPS</td><td><span class="pill done">solo window done</span></td></tr>
    <tr><td>3</td><td>Sintel / snow girl</td><td><code>IMG_0010.MOV</code> 1048174 B</td><td>Fake native import (Lavf)</td><td><span class="pill done">solo window done</span></td></tr>
    <tr><td>4</td><td>Bunny / tree hole</td><td><code>IMG_0009.MOV</code> 990971 B</td><td>Scraped BBB title/artist/CC</td><td><span class="pill done">solo window done</span></td></tr>
    <tr><td>5</td><td>Fresh Camera clip (not old desk)</td><td><code>IMG_0026.MOV</code> 4177966 B</td><td>Real iPhone X camera HEVC + GPS +54.6389+024.9351+161.972</td><td><span class="pill done">solo window done</span></td></tr>
    <tr><td>6</td><td>Yellow screen, giant 6, CANARY</td><td><code>IMG_0027.MOV</code> 17213 B</td><td>Fake canaries (not Apple): CANARYMK/MD/SW-7F3A, GPS 11.1111 22.2222, title/comment</td><td><span class="pill done">read + CDN upload</span></td></tr>
  </table>
  </div>
  <h2>5 · Camera <span class="pill done">done</span></h2>
  <h3>Done so far</h3>
  <ul>
    <li>Recents reduced to the new Camera recording (old desk IMG_0005 stayed in stash so Photos would not re-import it as a library copy).</li>
    <li>Frida spawn 120s, pid 10298, 85 tags, run <code>unique-5-camera</code>.</li>
    <li>TikTok opened IMG_0026.MOV 4177966 B; draft same size; export/publish 4156740 B.</li>
    <li>INPUT walk at 12.7s read make Apple, model iPhone X, software 16.7.16, creationdate 2026-08-14T19:31:34+0300, GPS <code>+54.6389+024.9351+161.972/</code>, accuracy 35.</li>
    <li>Video-metadata geotag 17 reads at 14.3s. Codec hvc1. Library 1920×1080.</li>
    <li>Success haptic at 48.6s. product:tiktok / TEEditor / isFastImport written into export.</li>
    <li>No CLLocationManager. Location permission unused. No UPLOADED / aweme_v1.</li>
  </ul>
  <h3>How it was verified</h3>
  <p>tags.json files.INPUT names only IMG_0026 and same-size draft/export/publish. GPS altitude 161.972 and date 2026-08-14T19:31:34 match the laptop dump of the new camera file, not the old desk clip (161.228 / 2026-08-06). String search: no Bunny / Sintel / CLEAN sizes as named INPUT.</p>
  <h2>6 · Canary <span class="pill done">done</span></h2>
  <h3>Done so far</h3>
  <ul>
    <li>New yellow 6 clip stamped with unique strings (not Apple / not Vilnius GPS). QuickTime <code>Keys:GPSCoordinates</code>, not XMP — unique-2’s GPS only landed in XMP and TikTok never read it.</li>
    <li>Recents reduced to IMG_0027.MOV 17213 B. Laptop pull after copy still had every canary.</li>
    <li>First window missed (AFK). <code>unique-6-canary-2</code> 180s spawn, pid 10334: INPUT only IMG_0027. Every canary read at 65.7s. GPS 18×. Success 74.3s.</li>
    <li>Pulled <code>publish_video_local_7673935059631590678.mp4</code> 14311 B from TikTok’s Documents folder. Canaries gone. Keys are TEEditor / Lavf57.71.100.</li>
    <li><code>unique-6-publish</code> attach + one SSL_write: CDN <code>POST /upload/v1</code> 34384 B, no canaries, success buzz, video later appeared on profile. App died at 51.4s. Hook now self-detaches after 2 bodies.</li>
  </ul>
  <h2>Earlier windows (do not use as per-file columns)</h2>
  <div class="scroll">
  <table>
    <tr><th>Run</th><th>What happened</th><th>Use?</th></tr>
    <tr><td><code>matrix-batch-3</code></td><td>One 300s window, picker walked 7 named INPUTs including long Bunny and desk GPS.</td><td><span class="pill warn">blended</span></td></tr>
    <tr><td><code>05-generated-post</code></td><td>Intended oldest rainbow; picker opened all 7; encode size suggested 0008.</td><td><span class="pill warn">blended</span></td></tr>
    <tr><td><code>unique-1-clean</code></td><td>60s; IMG_0021 opened but also 0022/0005/0009/0010 + old rainbow draft. Apple+GPS+Bunny in same log.</td><td><span class="pill warn">blended</span></td></tr>
    <tr><td><code>05-generated-manual</code></td><td>First live post attempt; INPUT mixed 0008/0003; no UPLOADED.</td><td><span class="pill warn">blended</span></td></tr>
    <tr><td><code>unique-6-canary</code></td><td>120s spawn; operator was AFK; no IMG_0027 INPUT.</td><td><span class="pill warn">missed post</span></td></tr>
    <tr><td><code>unique-6-aweme</code></td><td>-Full -Attach on compose. Encode started (export 14311). iOS killed TikTok at 50s. Post did not land.</td><td><span class="pill warn">crash</span></td></tr>
  </table>
  </div>
</section>

<section class="pane" id="find">
  <h2>What TikTok read (INPUT) across five solos</h2>
  <p class="meta">Source: compare_runs.py --normalize --container INPUT on unique-1-solo … unique-5-camera. A dash means that field was not in this window’s INPUT walk.</p>
  <div class="scroll">
  <table>
    <tr><th>Field</th><th>1 CLEAN</th><th>2 STAMPED</th><th>3 Sintel</th><th>4 Bunny</th><th>5 Camera</th><th>6 CANARY</th></tr>
    <tr><td>Named INPUT file</td><td>IMG_0021 9065</td><td>IMG_0022 16524</td><td>IMG_0010 1048174</td><td>IMG_0009 990971</td><td>IMG_0026 4177966</td><td>IMG_0027 17213</td></tr>
    <tr><td>Export / publish</td><td>9691</td><td>13706</td><td>1054614</td><td>1000150</td><td>4156740</td><td>14311 local / 34384 CDN</td></tr>
    <tr><td>Settled OUTPUT</td><td>—</td><td>—</td><td>1052041</td><td>995177</td><td>—</td><td>local dump 14311</td></tr>
    <tr><td>make</td><td>—</td><td>Apple</td><td>—</td><td>—</td><td>Apple</td><td>CANARYMK-7F3A</td></tr>
    <tr><td>model</td><td>—</td><td>iPhone X</td><td>—</td><td>—</td><td>iPhone X</td><td>CANARYMD-7F3A</td></tr>
    <tr><td>software</td><td>—</td><td>16.7.16</td><td>—</td><td>—</td><td>16.7.16</td><td>CANARYSW-7F3A</td></tr>
    <tr><td>creationdate</td><td>—</td><td>2026-08-11T14:02:31+0300</td><td>—</td><td>—</td><td>2026-08-14T19:31:34+0300</td><td>2025-01-02T03:04:05+0000</td></tr>
    <tr><td>GPS ISO6709</td><td>—</td><td>—</td><td>—</td><td>—</td><td>+54.6389+024.9351+161.972/</td><td>+11.1111+022.2222+33.300/</td></tr>
    <tr><td>GPS accuracy</td><td>—</td><td>—</td><td>—</td><td>—</td><td>35.000000</td><td>12.0</td></tr>
    <tr><td>udta make/model</td><td>—</td><td>Apple / iPhone X</td><td>—</td><td>—</td><td>—</td><td>CANARYMK / CANARYMD</td></tr>
    <tr><td>title / name</td><td>—</td><td>—</td><td>—</td><td>Big Buck Bunny, Sunflower version</td><td>—</td><td>CANARY-TITLE-7F3A</td></tr>
    <tr><td>artist</td><td>—</td><td>—</td><td>—</td><td>Blender Foundation 2008, Janus Bager Kristensen 2013</td><td>—</td><td>—</td></tr>
    <tr><td>comment / CC</td><td>—</td><td>—</td><td>—</td><td>Creative Commons Attribution 3.0</td><td>—</td><td>CANARY-CMT-7F3A</td></tr>
    <tr><td>genre</td><td>—</td><td>—</td><td>—</td><td>Animation</td><td>—</td><td>—</td></tr>
    <tr><td>file software (Lavf on source)</td><td>Lavf63.1.101</td><td>Lavf63.1.101</td><td>Lavf63.1.101</td><td>Lavf63.1.101</td><td>—</td><td>Lavf63.1.101</td></tr>
    <tr><td>codec (track)</td><td>avc1 family</td><td>avc1 family</td><td>avc1 family</td><td>avc1 family</td><td>hvc1</td><td>avc1 family</td></tr>
    <tr><td>product:tiktok written</td><td>yes</td><td>yes</td><td>yes</td><td>yes</td><td>yes</td><td>yes</td></tr>
    <tr><td>On local re-encode</td><td>—</td><td>—</td><td>—</td><td>—</td><td>—</td><td>stripped</td></tr>
    <tr><td>On CDN /upload/v1</td><td>—</td><td>—</td><td>—</td><td>—</td><td>—</td><td>stripped (no canary bytes)</td></tr>
    <tr><td>aweme_v1 JSON</td><td>—</td><td>—</td><td>—</td><td>—</td><td>—</td><td>not seen</td></tr>
  </table>
  </div>
  <h2>What this means in one sentence</h2>
  <p>TikTok’s picker and encoder read whatever provenance the chosen file actually carries — Apple stamps, Bunny credits, camera geotag, or fake canaries — and do not invent those fields for files that lack them. The local re-encode and the CDN media upload we captured are stripped. A separate aweme JSON post was not seen. Full per-clip dumps are on Raw reads; the injection write-up is tab 10.</p>
</section>

<section class="pane" id="den">
  <h2>Laptop dump is the denominator</h2>
  <p>exiftool on the files we posted. A tag here that the rig never names is either unread or unhooked.</p>
  <h3>unique-1-clean.mov (red 1) — what the file holds</h3>
  <div class="scroll"><table><tr><th>Tag</th><th>Value</th></tr>{table_from_prov(src1)}</table></div>
  <h3>unique-2-stamped.mov (blue 2) — what the file holds</h3>
  <div class="scroll"><table><tr><th>Tag</th><th>Value</th></tr>{table_from_prov(src2)}</table></div>
  <h3>IMG_0026-camera.MOV — what the file holds</h3>
  <div class="scroll"><table><tr><th>Tag</th><th>Value</th></tr>{table_from_prov(src5)}</table></div>
  <h3>unique-6-canary.mov — what we injected</h3>
  <div class="scroll"><table><tr><th>Tag</th><th>Value</th></tr>{table_from_prov(src6)}</table></div>
  <h3>publish_video_local canary copy — after TikTok encode</h3>
  <p class="meta">Pulled from TikTok Documents/kAWEPublishLocalVideoStorageFolder. Same atoms as the export. Canaries are gone.</p>
  <div class="scroll"><table><tr><th>Tag</th><th>Value</th></tr>{table_from_prov(src6out) if src6out else "<tr><td colspan=2>file not on disk</td></tr>"}</table></div>
  <h3>Other stashed clips (from earlier dumps)</h3>
  <div class="scroll">
  <table>
    <tr><th>Clip</th><th>Provenance on disk</th></tr>
    <tr><td>Desk IMG_0005 (not posted this matrix)</td><td>Keys:Make Apple · Model iPhone X · Software 16.7.16 · CreationDate 2026-08-06 18:37:01+03:00 · GPS 54.6389 24.935 161.228 · HEVC 1920×1080 · 3.165s</td></tr>
    <tr><td>Desk stripped IMG_0006</td><td>Same scene, HEVC, no Make/Model/GPS in the dump. Removed from Recents (looked identical).</td></tr>
    <tr><td>Bunny IMG_0009</td><td>UserData Artist Blender Foundation · Comment CC-BY · Software Lavf63.1.101 · 640×360 · 10s</td></tr>
    <tr><td>Sintel IMG_0010</td><td>Lavf63.1.101 · 640×360 · 10s · no Apple Keys</td></tr>
  </table>
  </div>
</section>

<section class="pane" id="bg">
  <div class="callout">If you only read one tab, read this — why a batch window lies and why sourceType cannot be faked.</div>
  <h2>The two halves</h2>
  <p><strong>Observer</strong> (tiktok-audit.ps1 / observe.js) is the only process allowed inside TikTok. It hooks file/metadata/network reads. <strong>Poster / control plane</strong> talks to SpringBoard (HID) and Photos (import) over SSH. It never attaches to com.zhiliaoapp.musically.</p>
  <h2>Landmines</h2>
  <ul>
    <li><strong>Picker walk.</strong> Opening Recents makes TikTok stat and sometimes deep-walk every visible asset. Those tags land in the same tags.json. One post per empty Recents is the fix.</li>
    <li><strong>sourceType.</strong> Photos reports user library for every file we import. Stamping EXIF cannot make an import a camera original. The fresh Camera clip was recorded on-device so Photos would not reclassify it as a re-import after a sqlite rebuild.</li>
    <li><strong>Fidelity.</strong> If Photos or TikTok rewrites the bytes, the laptop dump is not the INPUT denominator. Stamped IMG_0022 was restored from the laptop 16524 B original after Photos stripped it to ~9459.</li>
    <li><strong>OUTPUT never settled.</strong> The FragmentVideo / wav / m4a files keep changing on some arms; Sintel and Bunny did produce a settled OUTPUT mov.</li>
    <li><strong>XMP GPS is not enough.</strong> unique-2-stamped wrote GPS only as XMP-exif. TikTok never read it. unique-6 wrote <code>Keys:GPSCoordinates</code> (QuickTime mdta) and TikTok did read it.</li>
    <li><strong>CDN upload is the re-encode.</strong> unique-6-publish captured HTTP/1.1 <code>POST /upload/v1</code> to tiktokcdn-eu.com. No canaries in those bytes. The profile video is that stripped file.</li>
    <li><strong>Attach + TLS kills Post.</strong> <code>-Full -Attach</code> and slim <code>-Publish -Attach</code> both died ~50–51s (process-terminated). Spawn without TLS (the six solos) survived. Publish hook now self-detaches after two bodies.</li>
    <li><strong>No aweme JSON.</strong> We never saw <code>/aweme/v1/aweme/post/</code>. selftest aweme files are fixtures, not live captures.</li>
  </ul>
  <h2>Device</h2>
  <p>iPhone X (iPhone10,3), iOS 16.7.16, palera1n rootless, Frida 17.16.4, timezone Europe/Vilnius. IDFV in the CLEAN solo: 49ACD603-7CA9-47C9-B56B-B542BE2E1C44 (rotated vs earlier 1F6679FF-… after library rebuild / app relaunch). IDFA all zeros. Location permission not determined. Camera GPS came from the file, not CLLocationManager.</p>
</section>

<section class="pane" id="plan">
  <h2>Approach</h2>
  <p>Five visually unique clips. For each: stash every other file out of DCIM, rebuild Photos so Recents has one item, start Frida (~90–120s), operator posts that one clip, stay on feed, then pull tags.json. Compare to the exiftool dump.</p>
  <h2>Phases</h2>
  <table>
    <tr><th>Phase</th><th>Goal</th><th>Depends on</th></tr>
    <tr><td>0</td><td>Unique visuals + Recents hygiene (done)</td><td>—</td></tr>
    <tr><td>1</td><td>CLEAN solo INPUT (done)</td><td>0</td></tr>
    <tr><td>2</td><td>STAMPED solo INPUT (done)</td><td>1</td></tr>
    <tr><td>3</td><td>Sintel / Bunny / camera solos (done)</td><td>2</td></tr>
    <tr><td>4</td><td>CDN media POST captured; aweme JSON not seen (closed)</td><td>6</td></tr>
    <tr><td>5</td><td>compare_runs.py --normalize --container INPUT matrix (done)</td><td>1–3</td></tr>
    <tr><td>6</td><td>Canary injection + re-encode dump + CDN check (done)</td><td>5</td></tr>
  </table>
</section>

<section class="pane" id="risk">
  <h2>Risks</h2>
  <table>
    <tr><th>Risk</th><th>Likelihood / impact</th><th>Mitigation</th><th>Owner</th></tr>
    <tr><td>iCloud Photos refills Recents</td><td>High / high</td><td>CloudPhotos dataclass disabled on this phone; CPL dir mode 000. Re-check Recents count before each window.</td><td>operator</td></tr>
    <tr><td>Picker still opens leftover drafts / publish_video_local</td><td>Med / med</td><td>Those showed up as same-size copies of the posted clip, not foreign provenance. Camera file-size stats still listed older publish copies; they were not named INPUT.</td><td>rig</td></tr>
    <tr><td>Watchdog cuts the window</td><td>Med / high for upload</td><td>120s spawn works. Do not use -Full -Attach on Post. Publish hook self-detaches after 2 TLS bodies.</td><td>operator</td></tr>
    <tr><td>Attach + SSL_write during success scene</td><td>High / kills app</td><td>unique-6-aweme and unique-6-publish both died ~51s. Video can still land (it did the second time).</td><td>rig</td></tr>
    <tr><td>Photos rewrites imported files</td><td>High / high</td><td>Already stripped stamped 0022. Restore laptop original before Frida. Prefer on-device Camera for the native arm.</td><td>operator</td></tr>
    <tr><td>Semi-tethered reboot drops Frida/sshd</td><td>Low / terminal</td><td>Do not reboot. Re-apply palera1n from palen1x USB if it happens.</td><td>operator</td></tr>
  </table>
  <h4 class="warnish">The honest caveat</h4>
  <p>File tags TikTok reads are not the same as tags on the file it uploads. Canaries were read 18×, then absent from the local re-encode and from the CDN <code>/upload/v1</code> we captured. A possible extra JSON publish call was not seen. That is the ceiling of this rig.</p>
  <h2>Open questions</h2>
  <ul>
    <li>Does any post-upload <code>aweme_v1</code> JSON still list make/GPS? Not observed. Not worth another crash tonight.</li>
    <li>What is bd_….mp4 (INPUT never settled) — leftover candidate, not needed now that CDN POST is named.</li>
  </ul>
</section>

<section class="pane" id="faq">
  <h3>Why not post all five in one Frida window?</h3>
  <p>We did that in matrix-batch-3. The picker walks every Recents item. GPS from the desk and Bunny credits show up even if you posted a rainbow. The tally cannot be split reliably except by unique values.</p>
  <h3>Why not stamp EXIF to look like a camera original?</h3>
  <p>Photos sets PHAsset.sourceType. EXIF cannot change that. Every file we import is user library. The camera clip was recorded on the phone so it would stay a real Camera original after the library rebuild.</p>
  <h3>Why a new camera clip instead of the old desk Red Bull video?</h3>
  <p>After wiping Photos.sqlite, importing the old desk MOV made it a user-library file. A fresh Camera recording kept native capture metadata (HEVC, GPS, make/model) without that re-import path.</p>
  <h3>Why did three rainbows exist?</h3>
  <p>05-generated, 06-generated-stamped, and a Photos/TikTok rewrite were the same testsrc2 picture. Replaced with red 1 / blue 2.</p>
  <h3>What does done look like?</h3>
  <p>Six solo tags.json files, the INPUT matrix, a canary re-encode dump, and one CDN <code>/upload/v1</code> capture with no canaries. aweme JSON remains unseen.</p>
  <h3>Is “inject EXIF so it looks like this iPhone” enough?</h3>
  <p>TikTok will <em>read</em> those atoms if they are in QuickTime Keys (not XMP). It will not keep them on the file it sends to the CDN. Phone Settings (locale, DNS, proxy) are a different layer and were out of scope for the file test.</p>
</section>

<section class="pane" id="raw">
  <div class="callout">Every Frida tag from the six solo posts plus the attach CDN window, with raw <code>tags.json</code> and <code>session.log</code>. unique-6-publish is the only live TLS media POST. It is not <code>aweme_v1</code>.</div>
  <div class="jumplist">
    <a href="#raw-unique-1-solo">1 CLEAN</a>
    <a href="#raw-unique-2-solo">2 STAMPED</a>
    <a href="#raw-unique-3-sintel">3 Sintel</a>
    <a href="#raw-unique-4-bunny">4 Bunny</a>
    <a href="#raw-unique-5-camera">5 Camera</a>
    <a href="#raw-unique-6-canary-2">6 CANARY reads</a>
    <a href="#raw-unique-6-publish">6b CDN upload</a>
  </div>
  {raw_html}
</section>

<section class="pane" id="inj">
  <div class="callout">This session’s file-injection test, mapped against the phone-farm claim that rewriting EXIF to look like a native iPhone camera roll is “the part that actually moves rankings.”</div>
  <h2>What “inject” meant here</h2>
  <p>Not injecting into TikTok. Rewriting atoms on a generated MOV with exiftool, putting only that file in Recents, posting by hand, watching with Frida. Phone Settings / proxy / DNS were treated as already solved and not changed.</p>
  <h3>Canary values (id {esc(canaries.get("id"))})</h3>
  <div class="scroll">
  <table>
    <tr><th>Field</th><th>Injected</th><th>On laptop file</th><th>TikTok INPUT</th><th>Local re-encode</th><th>CDN POST /upload/v1</th></tr>
    <tr><td>make</td><td><code>{esc(canaries.get("make"))}</code></td><td>yes (Keys + UserData)</td><td>yes</td><td>no</td><td>no</td></tr>
    <tr><td>model</td><td><code>{esc(canaries.get("model"))}</code></td><td>yes</td><td>yes</td><td>no</td><td>no</td></tr>
    <tr><td>software</td><td><code>{esc(canaries.get("software"))}</code></td><td>yes</td><td>yes</td><td>no (Lavf57.71.100 / TEEditor)</td><td>no</td></tr>
    <tr><td>title</td><td><code>{esc(canaries.get("title"))}</code></td><td>yes</td><td>yes</td><td>no</td><td>no</td></tr>
    <tr><td>comment</td><td><code>{esc(canaries.get("comment"))}</code></td><td>yes</td><td>yes</td><td>no</td><td>no</td></tr>
    <tr><td>creation</td><td><code>{esc(canaries.get("created"))}</code></td><td>yes</td><td>yes 2025-01-02T03:04:05+0000</td><td>no</td><td>no</td></tr>
    <tr><td>GPS</td><td>{esc(canaries.get("gps_lat"))}, {esc(canaries.get("gps_lon"))} alt {esc(canaries.get("gps_alt"))} acc {esc(canaries.get("gps_acc"))}</td><td>Keys:GPSCoordinates</td><td>+11.1111+022.2222+33.300/ 18×</td><td>no</td><td>no</td></tr>
    <tr><td>Apple / iPhone X / Vilnius</td><td>must be absent</td><td>absent</td><td>absent (not invented)</td><td>absent</td><td>absent</td></tr>
  </table>
  </div>
  <h2>How to stamp so TikTok actually reads it</h2>
  <ul>
    <li>Use QuickTime <code>Keys:Make/Model/Software/CreationDate/GPSCoordinates/LocationAccuracyHorizontal</code> plus UserData title/comment.</li>
    <li>Do not rely on XMP GPS or <code>GPSLatitude</code> alone. That is what unique-2 did; TikTok ignored it.</li>
    <li>exiftool has no <code>Keys:LocationISO6709</code>; <code>Keys:GPSCoordinates</code> is the atom that shows up as mdta ISO6709 when TikTok reads it.</li>
    <li>Photos can still rewrite an import. Confirm the DCIM copy after index, or restore the laptop bytes before Frida.</li>
  </ul>
  <h2>Wire capture (unique-6-publish)</h2>
  <p>Attach + one <code>SSL_write</code> hook. TikTok used its own uploader, not <code>NSURLSession</code> uploadTask. We saved two HTTP/1.1 requests to <code>tos-no1a16-up.tiktokcdn-eu.com</code>:</p>
  {bodies_html(r6pub, "CDN media upload headers/start. No Authorization values are copied into this table’s meaning — treat the .bin files as secrets. Neither body contains CANARY or 11.1111.")}
  <p>Content-Length on the transfer was 34384 (matches the new export ~34375, not the 17213 source). Success haptic at 50.2s. Process died at 51.4s. Operator confirmed the video later appeared on the profile.</p>
  <h2>Farm claim vs this evidence</h2>
  <table>
    <tr><th>Claim</th><th>This session</th></tr>
    <tr><td>Rewrite EXIF to this iPhone / iOS / GPS</td><td>TikTok reads those atoms if they are in QuickTime Keys. Arbitrary fake strings work. They do not have to say Apple.</td></tr>
    <tr><td>That rewrite “moves rankings”</td><td>Unmeasured. The file that left toward the CDN did not carry the rewrite. Rank would have to use picker-time reads we cannot see on the wire, or ignore the stamp.</td></tr>
    <tr><td>Live Photo / native camera roll</td><td>Not tested. PHAsset.sourceType is still user library for every import. EXIF cannot fake a Camera original.</td></tr>
    <tr><td>30+ phone settings</td><td>Out of scope here (operator said already solved).</td></tr>
  </table>
  <h2>Runs this session</h2>
  <table>
    <tr><th>Run</th><th>Mode</th><th>Result</th></tr>
    <tr><td><code>unique-6-canary</code></td><td>spawn 120s</td><td>AFK, no post</td></tr>
    <tr><td><code>unique-6-canary-2</code></td><td>spawn 180s</td><td>All canaries read. Clean INPUT IMG_0027.</td></tr>
    <tr><td><code>unique-6-aweme</code></td><td>-Full -Attach</td><td>Encode started, app killed, post did not land</td></tr>
    <tr><td><code>unique-6-publish</code></td><td>-Publish -Attach</td><td>CDN POST captured, no canaries, app killed, video later live</td></tr>
  </table>
</section>
</main>

<script type="application/json" id="artifact-state">{state_json}</script>
<script>
document.querySelectorAll('.tabbar .tab').forEach(function(btn){{
  btn.addEventListener('click', function(){{
    document.querySelectorAll('.tabbar .tab').forEach(function(b){{ b.classList.remove('active'); }});
    document.querySelectorAll('.pane').forEach(function(p){{ p.classList.remove('active'); }});
    btn.classList.add('active');
    document.getElementById(btn.getAttribute('data-pane')).classList.add('active');
  }});
}});
</script>
</body>
</html>
"""
    html_path = OUT / "tiktok-metadata.html"
    html_path.write_text(page, encoding="utf-8")
    (OUT / "config.md").write_text(
        f"""# TikTok privacy audit artifact

## Project
- name: TikTok privacy audit
- slug: tiktok-metadata
- description: Frida observation of what TikTok reads from posted videos
- audience: operator running the iPhone X burner posts

## Artifact
- url: (not published — no claude.ai Artifact tool in this session)
- favicon: phone+magnifier
- title: TikTok privacy audit — metadata
- html: artifacts/tiktok-metadata.html

## Sources
- runs/unique-1-solo/tags.json (CLEAN)
- runs/unique-2-solo/tags.json (STAMPED)
- runs/unique-3-sintel/tags.json
- runs/unique-4-bunny/tags.json
- runs/unique-5-camera/tags.json (fresh Camera + GPS)
- runs/unique-6-canary-2/tags.json (canary reads)
- runs/unique-6-publish/tags.json + bodies (CDN /upload/v1)
- testfiles/unique-1-clean.mov / unique-2-stamped.mov / unique-6-canary.mov
- gallery-id/IMG_0026-camera.MOV and publish_video_local_canary.mp4
- earlier blended runs kept only as caveats

## Notes
- {as_of} canary injection read, stripped on re-encode and CDN upload; aweme JSON not seen
""",
        encoding="utf-8",
    )
    print("wrote", html_path, html_path.stat().st_size)


if __name__ == "__main__":
    main()
