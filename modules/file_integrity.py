"""
File Integrity Monitor
-----------------------
Creates a SHA-256 baseline of a folder and later reports files that were
modified, added or deleted — a quick tamper check for configs, web roots and
bot knowledge bases. Also hashes single files.

Developer: Muhammad Mughees Abbasi
"""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

from .base import SecurityModule, Finding
from .errors import BASE_DIR, ConfigError
from .validators import choice, existing_path

BASELINE = BASE_DIR / "data" / "integrity_baseline.json"
SKIP = {".git", "__pycache__", "node_modules", ".venv"}
MAX_FILES = 20_000


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(root: Path) -> dict:
    out = {}
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP]
        for n in names:
            p = Path(d) / n
            try:
                out[str(p.relative_to(root))] = sha256(p)
            except OSError:
                continue
            if len(out) >= MAX_FILES:
                return out
    return out


class FileIntegrityMonitor(SecurityModule):
    key = "fim"
    name = "File Integrity Monitor"
    description = "SHA-256 baseline + tamper detection"
    category = "Security Utilities"

    def collect(self, ui) -> dict:
        mode = ui.prompt("(1) Create baseline  (2) Verify against baseline  (3) Hash one file", "2", choice({"1": "init", "2": "verify", "3": "hash"}))
        return {"mode": mode, "path": ui.prompt("Folder" if mode != "hash" else "File", validator=existing_path)}

    def run(self, mode: str = "verify", path: str = ".", **kwargs) -> list[Finding]:
        self.clear()
        root = Path(path).expanduser()
        if mode == "hash":
            self.add_finding("info", f"SHA-256 {root.name}", sha256(root), str(root))
            return self.findings
        if mode == "init":
            snap = snapshot(root)
            BASELINE.parent.mkdir(exist_ok=True)
            BASELINE.write_text(json.dumps({"root": str(root), "created": datetime.now().isoformat(timespec="seconds"), "files": snap}, indent=2))
            self.add_finding("info", "Baseline created", f"{len(snap)} file(s) recorded from {root}", str(BASELINE))
            return self.findings
        if not BASELINE.exists():
            raise ConfigError("No baseline found", code="E5001", hint="Run this module with option 1 first to create a baseline.")
        base = json.loads(BASELINE.read_text())
        now = snapshot(root)
        old = base["files"]
        for f in sorted(set(old) & set(now)):
            if old[f] != now[f]:
                self.add_finding("high", f"Modified: {f}", f"hash {old[f][:12]}… -> {now[f][:12]}…", str(root), "Verify the change was authorised; restore from backup if not.")
        for f in sorted(set(old) - set(now)):
            self.add_finding("medium", f"Deleted: {f}", "", str(root), "Investigate unexpected deletions.")
        for f in sorted(set(now) - set(old)):
            self.add_finding("low", f"New file: {f}", "", str(root), "Confirm the file belongs here (webshells appear as new files).")
        if not self.findings:
            self.add_finding("info", "No changes since baseline", f"{len(now)} file(s) verified (baseline {base['created']}).", str(root))
        return self.findings
