"""
Passive OSINT Aggregator
---------------------------
Collects PUBLICLY PUBLISHED information about a domain using passive sources
only: DNS (resolver + DNS-over-HTTPS) and certificate-transparency logs
(crt.sh with a certspotter fallback). No port probing, no logins, no scanning.

Developer: Muhammad Mughees Abbasi
"""

import re
import socket
from urllib.parse import quote

from .base import SecurityModule, Finding
from .errors import ToolkitError, classify
from .net import http_json
from .validators import domain as validate_domain

INTERESTING = re.compile(r"(^|\.)(dev|staging|stage|test|admin|vpn|internal|jenkins|git|backup|old|beta|uat|sandbox)\.", re.I)


class OsintAggregator(SecurityModule):
    key = "osint"
    name = "Passive OSINT Aggregator"
    description = "DNS, SPF/DMARC, certificate-transparency (passive)"
    category = "Detection & Analysis"

    def collect(self, ui) -> dict:
        return {"domain": ui.prompt("Domain (e.g. example.com)", validator=validate_domain)}

    def run(self, domain: str = "", **kwargs) -> list[Finding]:
        self.clear()
        if not domain:
            self.add_finding("info", "No domain provided", "Supply a domain to look up.")
            return self.findings
        self._addresses(domain)
        self._dns_records(domain)
        self._email_auth(domain)
        self._subdomains(domain)
        if not self.findings:
            self.add_finding("info", "No data found", f"No public records found for {domain}.")
        return self.findings

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _doh(name: str, rtype: str) -> list[str]:
        data = http_json(f"https://cloudflare-dns.com/dns-query?name={quote(name)}&type={rtype}",
                         headers={"accept": "application/dns-json"}, timeout=10, retries=2, context="DNS-over-HTTPS")
        return [a.get("data", "").strip('"') for a in data.get("Answer", [])]

    def _unavailable(self, what: str, exc: Exception, source: str) -> None:
        err = classify(exc, source)
        self.add_finding("info", f"{what} unavailable — {err.code} {err.title}", err.detail or "",
                         source, err.hint or "Retry later.")

    def _addresses(self, domain: str) -> None:
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None)})
            self.add_finding("info", "Address records resolved", f"{domain} -> {', '.join(ips)}", "DNS")
        except OSError as exc:
            self._unavailable("DNS resolution", exc, "DNS")

    def _dns_records(self, domain: str) -> None:
        for rtype in ("NS", "MX"):
            try:
                vals = self._doh(domain, rtype)
                if vals:
                    self.add_finding("info", f"{rtype} records", "; ".join(vals[:6]), "DoH")
            except ToolkitError as exc:
                self._unavailable(f"{rtype} lookup", exc, "DoH")
                return

    def _email_auth(self, domain: str) -> None:
        try:
            txt = self._doh(domain, "TXT")
            spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
            if not spf:
                self.add_finding("medium", "No SPF record", "Anyone can send mail that appears to come from this domain.", "DoH",
                                 "Publish a TXT record such as `v=spf1 include:<provider> -all`.")
            elif "+all" in spf:
                self.add_finding("high", "SPF allows any sender (+all)", spf, "DoH", "Replace +all with -all or ~all.")
            elif "~all" in spf or "?all" in spf:
                self.add_finding("low", "SPF is soft-fail only", spf, "DoH", "Move to -all once all senders are listed.")
            else:
                self.add_finding("info", "SPF present", spf, "DoH")
            dmarc = next((t for t in self._doh("_dmarc." + domain, "TXT") if t.lower().startswith("v=dmarc1")), None)
            if not dmarc:
                self.add_finding("medium", "No DMARC record", "No policy against spoofed mail.", "DoH",
                                 "Publish `_dmarc` TXT: v=DMARC1; p=quarantine; rua=mailto:...")
            elif "p=none" in dmarc.lower():
                self.add_finding("low", "DMARC policy is p=none (monitor only)", dmarc, "DoH", "Move to p=quarantine, then p=reject.")
            else:
                self.add_finding("info", "DMARC enforced", dmarc, "DoH")
        except ToolkitError as exc:
            self._unavailable("SPF / DMARC check", exc, "DoH")

    def _subdomains(self, domain: str) -> None:
        names: set[str] = set()
        source = "crt.sh"
        try:
            rows = http_json(f"https://crt.sh/?q=%25.{quote(domain)}&output=json", timeout=25, retries=2, context="crt.sh")
            names = {n.lower().lstrip("*.") for r in rows for n in r.get("name_value", "").split("\n")}
        except ToolkitError as first:
            try:
                source = "certspotter"
                rows = http_json(f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}&include_subdomains=true&expand=dns_names",
                                 timeout=25, retries=2, context="certspotter")
                names = {n.lower().lstrip("*.") for r in rows for n in r.get("dns_names", [])}
                self.add_finding("info", f"crt.sh unavailable ({first.code}) — used certspotter fallback", first.title, "crt.sh")
            except ToolkitError as second:
                self.add_finding("info", f"Certificate-transparency lookup unavailable — {second.code} {second.title}",
                                 f"crt.sh: {first.code} {first.title}; certspotter: {second.code} {second.title}", "CT logs",
                                 "Both public CT services failed (common on VPN / unstable links). Retry later or switch network.")
                return
        names = {n for n in names if n.endswith(domain)}
        if names:
            self.add_finding("info", f"{len(names)} hostname(s) in certificate transparency",
                             ", ".join(sorted(names)[:40]), source)
            for n in sorted(names):
                if INTERESTING.search(n):
                    self.add_finding("low", f"Potentially sensitive hostname exposed: {n}",
                                     "Internal-sounding names in public certificates help attackers map your estate.", source,
                                     "Use wildcard or private CA certificates for internal hosts.")
