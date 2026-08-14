"""
Orchestrate one arm: reuse the existing rig, do not rebuild it.

    dump_tags.py FILE -o runs/NAME/source.tags.json
    tiktok-audit.ps1 DURATION -Run NAME [-Touch]
    compare_runs.py runs/NAME/source.tags.json runs/NAME/tags.json \
        --normalize --container INPUT

One post per run window. The tally is cumulative, so a second post in
the same runs/NAME/ blends two files into one tags.json and the matrix
cannot attribute a field to either. A spent window is refused.

Landmines, encoded rather than commented:

  1. Detection surface. This module starts the existing launcher as a
     sibling. It never attaches to TikTok.
  2. PHAsset.sourceType. An import is an import. EXIF stamping writes
     inside the file; it cannot make Photos call that file a camera
     original. Every file arm is tagged library=import. A true capture
     arm does not go through push_and_import.
  3. Transfer fidelity. If import re-encodes, the laptop dump is not
     the denominator for what TikTok opened. From arm one we dump the
     laptop file, pull the stored DCIM file, dump that too, and after
     the observer we compare both against the rig's INPUT.
  4. Account burn + semi-tethered. --post requires --burner. A reboot
     drops Frida and sshd until palera1n is re-applied.

Autonomy defaults to stop-for-OK before each post. --unattended is how
you take that off later, not how you start.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

from .device import PosterError, safe_run_name, scp_get

ROOT = Path(__file__).resolve().parent.parent

ConfirmFn = Callable[[str], bool]


def default_confirm(prompt: str) -> bool:
    print()
    print("  " + prompt)
    try:
        ans = input("  type YES to continue: ")
    except EOFError:
        return False
    return ans.strip() == "YES"


def arm_dir(name: str, root: Path = ROOT) -> Path:
    return root / "runs" / safe_run_name(name)


def arm_is_spent(out_dir: Path) -> bool:
    """A window that already has a tags.json or a posted poster.json is
    spent. compare_runs.py would then be reading a blend."""
    tags = out_dir / "tags.json"
    if tags.is_file() and tags.stat().st_size > 0:
        return True
    poster = out_dir / "poster.json"
    if poster.is_file():
        try:
            data = json.loads(poster.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        if data.get("posted"):
            return True
    return False


def refuse_if_spent(out_dir: Path, force: bool = False) -> None:
    if force:
        return
    if arm_is_spent(out_dir):
        raise PosterError(
            "run window %s is already spent (tags.json or a completed post). "
            "The tally is cumulative: a second post here cannot be attributed. "
            "Use a new --name, or --force if you are throwing this window away."
            % out_dir
        )


def dump_tags(path: Path, dest: Path, root: Path = ROOT) -> Optional[Path]:
    script = root / "dump_tags.py"
    if not script.is_file():
        return None
    if not shutil.which("exiftool"):
        return None
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        [sys.executable, str(script), str(path), "--out", str(dest)],
        cwd=str(root), capture_output=True, text=True,
    )
    if r.returncode != 0 or not dest.is_file():
        raise PosterError("dump_tags.py failed on %s:\n%s" % (path, r.stderr or r.stdout))
    return dest


def compare_input(denominator: Path, tags: Path, dest: Path,
                  root: Path = ROOT) -> Optional[Path]:
    """The coverage check the stamping work actually asks: laptop (or
    imported) dump vs the rig's INPUT container."""
    script = root / "compare_runs.py"
    if not script.is_file() or not denominator.is_file() or not tags.is_file():
        return None
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        [sys.executable, str(script), str(denominator), str(tags),
         "--normalize", "--container", "INPUT"],
        cwd=str(root), capture_output=True, text=True,
    )
    dest.write_text((r.stdout or "") + (r.stderr or ""), encoding="utf-8")
    return dest


def observer_argv(run_name: str, duration: int, touch: bool, attach: bool,
                  root: Path = ROOT) -> list[str]:
    """The existing launcher, unchanged. We do not call run_observe.py
    or frida ourselves."""
    import os
    if os.name == "nt":
        launcher = root / "tiktok-audit.ps1"
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
               "-File", str(launcher), str(duration), "-Run", run_name]
        if touch:
            cmd.append("-Touch")
        if attach:
            cmd.append("-Attach")
        return cmd
    launcher = root / "tiktok-audit.sh"
    cmd = [str(launcher), str(duration), "--run", run_name]
    if touch:
        cmd.append("--touch")
    if attach:
        cmd.append("--attach")
    return cmd


def pull_stored(remote: str, dest: Path) -> Path:
    r = scp_get(remote, dest)
    if r.returncode != 0 or not dest.is_file():
        raise PosterError("scp pull of stored file failed: %s" % (r.stderr or r.stdout))
    return dest


def fidelity_record(source_path: Path, import_rec: dict,
                    source_tags: Optional[Path], imported_tags: Optional[Path],
                    imported_local: Optional[Path]) -> dict:
    src_hash = import_rec.get("source", {}).get("sha256")
    stored = (import_rec.get("import") or {}).get("stored") or {}
    drifted = import_rec.get("bytes_match") is False
    if src_hash and stored.get("sha256"):
        drifted = drifted or (src_hash != stored.get("sha256"))
    return {
        "drifted": drifted,
        "bytes_match": import_rec.get("bytes_match"),
        "source_bytes": import_rec.get("source", {}).get("bytes"),
        "stored_bytes": stored.get("bytes"),
        "source_sha256": src_hash,
        "stored_sha256": stored.get("sha256"),
        "source_tags": str(source_tags) if source_tags else None,
        "imported_tags": str(imported_tags) if imported_tags else None,
        "imported_file": str(imported_local) if imported_local else None,
        "denominator": (
            "imported file (laptop dump is fiction once import rewrites)"
            if drifted else "laptop file (zero drift)"
        ),
        "note": (
            "If import re-encodes, a PC denominator is fiction. The rig "
            "brackets INPUT after the fact; compare_runs --normalize "
            "--container INPUT is the readout."
        ),
    }


def library_provenance(how: str = "import") -> dict:
    if how not in ("import", "capture"):
        raise PosterError("library provenance must be import or capture, not %r" % how)
    return {
        "how": how,
        "exif_cannot_stamp_sourceType": True,
        "note": (
            "PHAsset.sourceType is the library's claim, not a file tag. "
            "The rig reads it as 'library sourceType'. Stamping EXIF "
            "cannot make Photos call an import a camera original. If "
            "TikTok weights this, no EXIF work reaches it."
            if how == "import" else
            "This arm is a camera capture. Do not push a file. The in-app "
            "shutter is the path; camera.upload is the one we must not hit."
        ),
    }


def require_post_gates(burner: bool, unattended: bool, confirm: ConfirmFn,
                       arm_name: str) -> None:
    if not burner:
        raise PosterError(
            "refusing to post: pass --burner to acknowledge this account "
            "can be logged out or banned. Test automation on a burner first. "
            "A reboot is semi-tethered: Frida and sshd are gone until "
            "palera1n is re-applied."
        )
    if unattended:
        return
    ok = confirm(
        "about to drive the Post tap on arm %r. type YES, or anything "
        "else to stop. --unattended is how you skip this later." % arm_name
    )
    if not ok:
        raise PosterError("stopped for your OK before the post (arm %s)" % arm_name)


def coverage_targets(fidelity: dict, out_dir: Path) -> list[tuple[str, Path]]:
    """Which dump is the denominator for the rig's INPUT.

    Drifted import: the stored file is what TikTok opened. The laptop
    dump is still written, and we compare it too, but it is not the
    coverage denominator.
    """
    out = []
    imported = fidelity.get("imported_tags")
    source = fidelity.get("source_tags")
    if fidelity.get("drifted") and imported:
        out.append(("imported", Path(imported)))
        if source:
            out.append(("laptop-vs-input (fiction if drifted)", Path(source)))
    elif source:
        out.append(("source", Path(source)))
    elif imported:
        out.append(("imported", Path(imported)))
    return out
