
"""
Base classes for AI Security Toolkit modules.
Developer: Muhammad Mughees Abbasi
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Finding:
    """A single result produced by a module (an anomaly, a flagged item, etc.)."""
    severity: str          # "info" | "low" | "medium" | "high" | "critical"
    title: str
    detail: str
    source: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "source": self.source,
            "timestamp": self.timestamp,
        }


class SecurityModule(ABC):
    """Abstract base class every module implements. Keeps the menu + reporting generic."""

    name: str = "Unnamed Module"
    description: str = ""

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add_finding(self, severity: str, title: str, detail: str, source: str = "") -> None:
        self.findings.append(Finding(severity, title, detail, source))

    def clear(self) -> None:
        self.findings = []

    @abstractmethod
    def run(self, **kwargs) -> list[Finding]:
        """Execute the module's analysis and return findings. Must not perform any
        network attack, exploitation, or credential-cracking action — analysis/detection only."""
        raise NotImplementedError

    def summary(self) -> str:
        if not self.findings:
            return f"[{self.name}] No findings."
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        parts = ", ".join(f"{k}:{v}" for k, v in counts.items())
        return f"[{self.name}] {len(self.findings)} finding(s) — {parts}"
