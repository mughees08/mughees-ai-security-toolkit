"""
AI Prompt-Injection / Jailbreak Detector
------------------------------------------
Scans text (user prompts, uploaded documents, chat logs) for patterns commonly
associated with prompt injection or jailbreak attempts against LLM
applications. Obfuscation-aware: decodes base64 / rot13 / leetspeak / spaced
letters / look-alike characters before matching, and covers Roman Urdu,
Spanish and French. Defensive scanning only.

Developer: Muhammad Mughees Abbasi
"""

from pathlib import Path

from . import guard_engine as guard
from .base import SecurityModule, Finding
from .errors import BASE_DIR
from .validators import choice, existing_file

SAMPLE = BASE_DIR / "data" / "samples" / "prompts.txt"


class PromptInjectionDetector(SecurityModule):
    key = "inject"
    name = "Prompt-Injection Detector"
    description = "Obfuscation-aware LLM jailbreak scan"
    category = "Detection & Analysis"

    def collect(self, ui) -> dict:
        mode = ui.prompt("Scan a (1) file or (2) pasted text", "2", choice({"1": "file", "2": "text"}))
        if mode == "1":
            default = str(SAMPLE) if SAMPLE.exists() else ""
            return {"file_path": ui.prompt("File path (Enter = demo sample)" if default else "File path", default, existing_file)}
        ui.info("Paste text, finish with an empty line.")
        lines = []
        while True:
            try:
                ln = input()
            except EOFError:
                break
            if not ln.strip() and lines:
                break
            lines.append(ln)
        return {"text": "\n".join(lines)}

    def run(self, text: str = "", file_path: str = "", **kwargs) -> list[Finding]:
        self.clear()
        if file_path:
            p = Path(file_path)
            if not p.exists():
                self.add_finding("info", "No input file found", f"Path does not exist: {file_path}")
                return self.findings
            text = p.read_text(errors="ignore")[:2_000_000]
            source = str(p)
        else:
            source = "direct input"
        if not text.strip():
            self.add_finding("info", "No input provided", "Nothing to scan.", remediation="Provide a prompt, document or chat log.")
            return self.findings

        seen: set = set()
        chunks = [(0, text)] + [(i, ln) for i, ln in enumerate(text.splitlines(), start=1) if ln.strip()]
        for lineno, chunk in chunks:
            hits = guard.scan_input(chunk)
            score = guard.combine(h.weight for h in hits)
            for h in hits:
                key = (h.rule, h.snippet)
                if key in seen:
                    continue
                seen.add(key)
                sev = "critical" if score >= 0.9 else "high" if score >= 0.75 else "medium" if score >= 0.4 else "low"
                where = f"line {lineno}" if lineno else "whole text"
                via = "" if h.variant == "plain" else f" (hidden via {h.variant})"
                self.add_finding(sev, f"{h.desc}{via}", f"{h.rule} at {where}: '{h.snippet}' — risk {score:.2f}", source,
                                 "Block or sandbox this input; treat retrieved content as untrusted data.")
        if not self.findings:
            self.add_finding("info", "Clean", "No known injection/jailbreak patterns detected (heuristic scan, not a guarantee).", source)
        return self.findings
