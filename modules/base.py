"""
Base classes for AI Security Toolkit modules.
Developer: Muhammad Mughees Abbasi
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_POINTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}


@dataclass
class Finding:
    """A single result produced by a module (an anomaly, a flagged item, etc.)."""
    severity: str          # "info" | "low" | "medium" | "high" | "critical"
    title: str
    detail: str
    source: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def __post_init__(self) -> None:
        self.severity = self.severity.lower()
        if self.severity not in SEVERITIES:
            self.severity = "info"

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "source": self.source,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }


def risk_score(findings: list[Finding]) -> int:
    return min(100, sum(SEVERITY_POINTS[f.severity] for f in findings))


def risk_label(score: int) -> str:
    return "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 15 else "LOW"


class SecurityModule(ABC):
    """Abstract base class every module implements. Keeps the menu + reporting generic."""

    key: str = "module"
    name: str = "Unnamed Module"
    description: str = ""
    category: str = "Detection & Analysis"
    needs_session: bool = False      # True: run() also receives all_findings (AI analyst)
    sends_traffic: bool = False      # True: asks the operator for authorisation first

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add_finding(self, severity: str, title: str, detail: str, source: str = "", remediation: str = "") -> None:
        self.findings.append(Finding(severity, title, detail, source, remediation))

    def clear(self) -> None:
        self.findings = []

    def collect(self, ui) -> dict:
        """Prompt the operator and return keyword arguments for run(). Override per module."""
        return {}

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
