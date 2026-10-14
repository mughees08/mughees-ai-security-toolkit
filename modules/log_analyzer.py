
"""
Log / Traffic Analyzer
-----------------------
Parses text log files (auth logs, web server logs, or saved Nmap output) and
flags suspicious patterns using simple heuristics (no live scanning, no network
calls — reads files the user already has on disk).

Developer: Muhammad Mughees Abbasi
"""

import re
from collections import Counter
from pathlib import Path

from .base import SecurityModule, Finding

FAILED_LOGIN_PATTERNS = [
    re.compile(r"failed password", re.I),
    re.compile(r"authentication failure", re.I),
    re.compile(r"invalid user", re.I),
    re.compile(r"401 unauthorized", re.I),
]

SQLI_PATTERNS = [
    re.compile(r"union\s+select", re.I),
    re.compile(r"or\s+1=1", re.I),
    re.compile(r"--\s*$"),
    re.compile(r"drop\s+table", re.I),
]

SCAN_SIGNATURE_PATTERNS = [
    re.compile(r"nmap", re.I),
    re.compile(r"sqlmap", re.I),
    re.compile(r"nikto", re.I),
    re.compile(r"\bgobuster\b", re.I),
]

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class LogAnalyzer(SecurityModule):
    name = "Log / Traffic Analyzer"
    description = "Parses saved log files and flags brute-force, SQLi, and scanner signatures."

    def run(self, log_path: str = "", brute_force_threshold: int = 5, **kwargs) -> list[Finding]:
        self.clear()
        path = Path(log_path)

        if not path.exists() or not path.is_file():
            self.add_finding("info", "No log file found", f"Path does not exist: {log_path}")
            return self.findings

        lines = path.read_text(errors="ignore").splitlines()
        failed_login_ips: Counter[str] = Counter()

        for i, line in enumerate(lines, start=1):
            ip_match = IP_PATTERN.search(line)
            ip = ip_match.group(0) if ip_match else "unknown"

            if any(p.search(line) for p in FAILED_LOGIN_PATTERNS):
                failed_login_ips[ip] += 1

            if any(p.search(line) for p in SQLI_PATTERNS):
                self.add_finding(
                    "high", "Possible SQL injection attempt",
                    f"Line {i}: {line.strip()[:200]}", source=str(path)
                )

            if any(p.search(line) for p in SCAN_SIGNATURE_PATTERNS):
                self.add_finding(
                    "medium", "Scanner signature detected in log",
                    f"Line {i}: {line.strip()[:200]}", source=str(path)
                )

        for ip, count in failed_login_ips.items():
            if count >= brute_force_threshold:
                self.add_finding(
                    "critical" if count >= brute_force_threshold * 3 else "high",
                    "Possible brute-force attempt",
                    f"{count} failed login attempts from {ip}",
                    source=str(path),
                )

        if not self.findings:
            self.add_finding("info", "Clean", "No suspicious patterns found in log file.")

        return self.findings
