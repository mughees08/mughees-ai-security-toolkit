"""
IOC Extractor
--------------
Pulls indicators of compromise out of reports, logs or pasted text: IPs,
domains, URLs, emails, hashes and CVE ids. Understands defanged input
(hxxp, [.]) and can export a CSV for blocklists / SIEM enrichment.

Developer: Muhammad Mughees Abbasi
"""

import csv
import ipaddress
import re
from datetime import datetime
from pathlib import Path

from .base import SecurityModule, Finding
from .errors import BASE_DIR
from .validators import choice, existing_file

PATTERNS = {
    "url": re.compile(r"https?://[^\s<>\"')]+", re.I),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "domain": re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|info|biz|xyz|top|ru|cn|pk|co|me|cc|tk|ml|ga|cf|gq|click|zip)\b", re.I),
}


def refang(text: str) -> str:
    text = re.sub(r"hxxp", "http", text, flags=re.I)
    return text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[at]", "@").replace("[@]", "@")


class IocExtractor(SecurityModule):
    key = "ioc"
    name = "IOC Extractor"
    description = "IPs, domains, hashes, CVEs from text (defang aware)"
    category = "Security Utilities"

    def collect(self, ui) -> dict:
        mode = ui.prompt("Input (1) file  (2) paste", "1", choice({"1": "f", "2": "p"}))
        kw: dict = {}
        if mode == "1":
            kw["path"] = ui.prompt("File path", validator=existing_file)
        else:
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
            kw["text"] = "\n".join(lines)
        kw["export"] = ui.confirm("Export a CSV to reports/", False)
        return kw

    def run(self, text: str = "", path: str = "", export: bool = False, **kwargs) -> list[Finding]:
        self.clear()
        if path:
            text = Path(path).read_text(errors="ignore")[:10_000_000]
        text = refang(text)
        found: dict[str, set] = {k: set() for k in PATTERNS}
        for kind, rx in PATTERNS.items():
            found[kind] = {m.group(0).lower().rstrip(".,;") for m in rx.finditer(text)}
        found["domain"] -= {u.split("/")[2] for u in found["url"] if u.count("/") >= 2}
        found["domain"] = {d for d in found["domain"] if not any(d.endswith("." + e.split("@")[-1]) or d == e.split("@")[-1] for e in found["email"])}
        total = 0
        for kind, vals in found.items():
            if not vals:
                continue
            total += len(vals)
            sev = "medium" if kind in ("cve", "sha256", "sha1", "md5") else "low" if kind in ("url", "domain", "ipv4") else "info"
            self.add_finding(sev, f"{len(vals)} {kind} indicator(s)", ", ".join(sorted(vals)[:12]) + (" ..." if len(vals) > 12 else ""), "ioc",
                             "Enrich and block / watch these in your SIEM, DNS filter or firewall." if kind in ("url", "domain", "ipv4") else "")
        for ip in sorted(found["ipv4"]):
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                self.add_finding("info", f"Non-routable address {ip}", "Private / reserved range — internal host, not an external attacker.", "ioc")
        if export and total:
            out = BASE_DIR / "reports" / f"iocs_{datetime.now():%Y%m%d_%H%M%S}.csv"
            out.parent.mkdir(exist_ok=True)
            with out.open("w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["type", "indicator"])
                for kind, vals in found.items():
                    w.writerows((kind, v) for v in sorted(vals))
            self.add_finding("info", "IOC CSV exported", str(out), "ioc")
        if not total:
            self.add_finding("info", "No indicators found", "Nothing matched the IOC patterns.", "ioc")
        return self.findings
