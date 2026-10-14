
"""
Passive OSINT Aggregator
---------------------------
Collects PUBLICLY PUBLISHED information about a domain using passive sources
only: DNS records and certificate-transparency logs (crt.sh). No active
scanning, no port probing, no login attempts against the target.

Developer: Muhammad Mughees Abbasi
"""

import json
import socket
import urllib.request
from pathlib import Path

from .base import SecurityModule, Finding


class OsintAggregator(SecurityModule):
    name = "Passive OSINT Aggregator"
    description = "Collects public DNS + certificate-transparency data for a domain (passive only)."

    def run(self, domain: str = "", **kwargs) -> list[Finding]:
        self.clear()

        if not domain:
            self.add_finding("info", "No domain provided", "Supply a domain to look up.")
            return self.findings

        self._dns_lookup(domain)
        self._crtsh_subdomains(domain)

        if not self.findings:
            self.add_finding("info", "No data found", f"No public records found for {domain}.")

        return self.findings

    def _dns_lookup(self, domain: str) -> None:
        try:
            ip = socket.gethostbyname(domain)
            self.add_finding("info", "A record resolved", f"{domain} -> {ip}", source="DNS")
        except socket.gaierror as e:
            self.add_finding("info", "DNS resolution failed", f"{domain}: {e}", source="DNS")

    def _crtsh_subdomains(self, domain: str) -> None:
        """Queries crt.sh's public certificate-transparency JSON API (read-only HTTP GET)."""
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ai-security-toolkit/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read().decode(errors="ignore")
            entries = json.loads(raw)
        except Exception as e:
            self.add_finding("info", "crt.sh lookup failed", str(e), source="crt.sh")
            return

        subdomains = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for line in name_value.splitlines():
                subdomains.add(line.strip().lstrip("*."))

        if subdomains:
            self.add_finding(
                "info",
                f"{len(subdomains)} subdomain(s) found via certificate transparency",
                ", ".join(sorted(subdomains)[:50]),
                source="crt.sh",
            )
