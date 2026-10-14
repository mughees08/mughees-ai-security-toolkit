
"""
AI Prompt-Injection / Jailbreak Detector
------------------------------------------
Scans text (user-submitted prompts, uploaded documents, chat logs) for patterns
commonly associated with prompt injection or jailbreak attempts against LLM
applications. Pattern/heuristic based — defensive scanning only.

Developer: Muhammad Mughees Abbasi
"""

import re
from pathlib import Path

from .base import SecurityModule, Finding

INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore (all )?(previous|above|prior) instructions", "Instruction override attempt"),
    (r"disregard (all )?(previous|above|prior)", "Instruction override attempt"),
    (r"you are now (dan|in developer mode|unrestricted)", "Known jailbreak persona pattern"),
    (r"pretend (you have no|there are no) (restrictions|rules|guidelines)", "Restriction-bypass framing"),
    (r"act as if you have no (filter|restriction|guardrail)", "Restriction-bypass framing"),
    (r"reveal (your )?(system prompt|instructions|hidden prompt)", "System-prompt exfiltration attempt"),
    (r"print (the )?(system prompt|your instructions)", "System-prompt exfiltration attempt"),
    (r"\bDAN\b.{0,20}(mode|prompt)", "Known 'DAN' jailbreak reference"),
    (r"base64|rot13|hex decode", "Possible encoded-payload smuggling"),
    (r"</?(system|assistant|user)>", "Fake role/tag injection attempt"),
    (r"this is a (hypothetical|fictional) scenario.{0,40}(no rules|no restrictions)", "Fictional-framing bypass attempt"),
    (r"for (educational|research) purposes only.{0,30}(bypass|ignore|disable)", "Suspicious justification + bypass request"),
]

COMPILED = [(re.compile(p, re.I), label) for p, label in INJECTION_PATTERNS]


class PromptInjectionDetector(SecurityModule):
    name = "Prompt-Injection / Jailbreak Detector"
    description = "Flags text containing known LLM prompt-injection or jailbreak patterns."

    def run(self, text: str = "", file_path: str = "", **kwargs) -> list[Finding]:
        self.clear()

        if file_path:
            p = Path(file_path)
            if not p.exists():
                self.add_finding("info", "No input file found", f"Path does not exist: {file_path}")
                return self.findings
            text = p.read_text(errors="ignore")
            source = str(p)
        else:
            source = "direct input"

        if not text.strip():
            self.add_finding("info", "No input provided", "Nothing to scan.")
            return self.findings

        lines = text.splitlines() or [text]
        for i, line in enumerate(lines, start=1):
            for pattern, label in COMPILED:
                if pattern.search(line):
                    self.add_finding(
                        "high", label,
                        f"Line {i}: {line.strip()[:200]}",
                        source=source,
                    )

        if not self.findings:
            self.add_finding("info", "Clean", "No known injection/jailbreak patterns detected.")

        return self.findings
