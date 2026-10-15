"""
Secrets & PII Scanner / Redactor
----------------------------------
Finds API keys, tokens, private keys, passwords, CNIC numbers, phone numbers
and payment cards in files or folders (values are always masked in output),
and can write a redacted copy that is safe to share or feed to an LLM.

Developer: Muhammad Mughees Abbasi
"""

import os
from pathlib import Path

from . import guard_engine as guard
from .base import SecurityModule, Finding
from .errors import BASE_DIR
from .validators import choice, existing_path

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "reports", "logs"}
MAX_FINDINGS = 300


class SecretsScanner(SecurityModule):
    key = "secrets"
    name = "Secrets & PII Scanner / Redactor"
    description = "API keys, CNIC, cards in files; redact copies"
    category = "Security Utilities"

    def collect(self, ui) -> dict:
        mode = ui.prompt("(1) Scan  (2) Write redacted copy", "1", choice({"1": "scan", "2": "redact"}))
        path = ui.prompt("File or folder", ".", existing_path)
        return {"path": path, "redact": mode == "redact"}

    def run(self, path: str = ".", redact: bool = False, **kwargs) -> list[Finding]:
        self.clear()
        root = Path(path).expanduser()
        if not root.exists():
            self.add_finding("info", "Path not found", str(root))
            return self.findings
        files = 0
        redacted_out = BASE_DIR / "reports" / "redacted"
        for f in self._walk(root):
            try:
                if f.stat().st_size > 2_000_000:
                    continue
                with f.open("rb") as fh:
                    if b"\0" in fh.read(1024):
                        continue
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            files += 1
            matches = guard.scan_text(text)
            for m in matches:
                if len(self.findings) >= MAX_FINDINGS:
                    break
                line = text.count("\n", 0, m.start) + 1
                self.add_finding(m.severity.lower(), f"{m.name} in {f.name}:{line}", f"{f} -> {guard.mask(m.text)}", "scanner",
                                 "Rotate the credential and move it to a secrets manager." if m.kind == "secret" else "Remove or pseudonymise personal data.")
            if redact and matches:
                out = redacted_out / f.name
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(guard.redact(text), encoding="utf-8")
        if redact:
            self.add_finding("info", "Redacted copies written", str(redacted_out), "scanner")
        self.add_finding("info", "Scan complete", f"{files} file(s) scanned. Secret values are masked in this output.", "scanner")
        return self.findings

    @staticmethod
    def _walk(root: Path):
        if root.is_file():
            yield root
            return
        for d, dirs, names in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            for n in names:
                yield Path(d) / n
