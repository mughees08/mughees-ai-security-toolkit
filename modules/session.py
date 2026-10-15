"""
Session: collects findings from every module run, supports triage suppression.

Developer: Muhammad Mughees Abbasi
"""

import hashlib
from datetime import datetime

from .base import Finding, SEVERITIES, risk_label, risk_score


def fingerprint(module: str, finding: Finding) -> str:
    # stable id: same module + same title (+ source) = same issue across runs
    raw = f"{module}|{finding.title}|{finding.source}".encode()
    return hashlib.sha1(raw).hexdigest()[:12]


DERIVED = {"AI Security Analyst"}   # analyst output is derived from other findings: never counted in risk


class Session:
    def __init__(self, suppressed: dict | None = None) -> None:
        self.results: dict[str, list[Finding]] = {}
        self.suppressed: dict = suppressed or {}      # fingerprint -> note
        self.summary: str = ""
        self.started = datetime.now().isoformat(timespec="seconds")

    def add(self, module: str, findings: list[Finding]) -> None:
        self.results[module] = list(findings)

    def pairs(self, include_suppressed: bool = False, include_derived: bool = False) -> list[tuple[str, Finding]]:
        out = []
        for module, fs in self.results.items():
            if module in DERIVED and not include_derived:
                continue
            for f in fs:
                if include_suppressed or fingerprint(module, f) not in self.suppressed:
                    out.append((module, f))
        return out

    def flat(self) -> list[Finding]:
        return [f for _m, f in self.pairs()]

    def counts(self) -> dict:
        c = {s: 0 for s in SEVERITIES}
        for f in self.flat():
            c[f.severity] += 1
        return c

    def score(self) -> int:
        return risk_score(self.flat())

    def label(self) -> str:
        return risk_label(self.score())

    def suppressed_count(self) -> int:
        return len(self.pairs(include_suppressed=True)) - len(self.pairs())
