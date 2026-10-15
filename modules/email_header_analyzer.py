"""
Email Header Analyzer
----------------------
Paste or load the raw headers of a suspicious email. Checks SPF / DKIM / DMARC
results, sender mismatches, display-name spoofing and the relay chain.
Offline analysis only.

Developer: Muhammad Mughees Abbasi
"""

import re
from email import utils
from email.parser import Parser
from pathlib import Path

from .base import SecurityModule, Finding
from .errors import ParseError
from .validators import choice, existing_file

BRANDS = ["paypal", "microsoft", "google", "apple", "amazon", "bank", "netflix", "dhl", "fedex", "hbl", "meezan", "jazzcash", "easypaisa"]
URGENT = re.compile(r"(urgent|verify|suspend|immediately|action required|password|invoice|payment|gift card|final notice)", re.I)
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _dom(addr: str) -> str:
    return utils.parseaddr(addr or "")[1].rpartition("@")[2].lower()


class EmailHeaderAnalyzer(SecurityModule):
    key = "email"
    name = "Email Header Analyzer"
    description = "SPF/DKIM/DMARC, spoofing, relay chain"
    category = "Security Utilities"

    def collect(self, ui) -> dict:
        mode = ui.prompt("Headers from (1) file  (2) paste", "2", choice({"1": "f", "2": "p"}))
        if mode == "1":
            return {"path": ui.prompt("File path", validator=existing_file)}
        ui.info("Paste the raw headers, finish with an empty line.")
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

    def run(self, text: str = "", path: str = "", **kwargs) -> list[Finding]:
        self.clear()
        if path:
            text = Path(path).read_text(errors="ignore")[:500_000]
        msg = Parser().parsestr(text, headersonly=True)
        if not msg.keys() or not (msg.get("From") or msg.get("Received")):
            raise ParseError("No email headers recognised", code="E3004", hint="Paste the full raw headers (From:, Received:, Authentication-Results: ...).")
        src = "email"
        auth = " ".join(msg.get_all("Authentication-Results") or []) + " " + " ".join(msg.get_all("Received-SPF") or [])
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}=(\w+)", auth, re.I)
            res = m.group(1).lower() if m else "none"
            if res == "pass":
                self.add_finding("info", f"{mech.upper()} pass", "", src)
            elif res in ("fail", "softfail", "permerror", "temperror"):
                self.add_finding("high" if res == "fail" else "medium", f"{mech.upper()} {res}", "Sender authentication failed.", src,
                                 "Treat the message as untrusted; do not click links or open attachments.")
            else:
                self.add_finding("medium", f"{mech.upper()} result missing", "No authentication verdict in the headers.", src, "Check at the receiving mail server.")
        name, addr = utils.parseaddr(msg.get("From", ""))
        frm, rp, rt, mid = _dom(msg.get("From")), _dom(msg.get("Return-Path")), _dom(msg.get("Reply-To")), msg.get("Message-ID", "").rpartition("@")[2].strip("> ").lower()
        if rp and frm and rp != frm:
            self.add_finding("medium", "Return-Path domain differs from From domain", f"From {frm} vs Return-Path {rp}", src, "Common in spoofed or relayed bulk mail.")
        if rt and frm and rt != frm:
            self.add_finding("high", "Reply-To points to a different domain", f"From {frm} vs Reply-To {rt}", src, "Replies would go to the attacker.")
        if mid and frm and mid.split(".")[-2:] != frm.split(".")[-2:]:
            self.add_finding("low", "Message-ID domain differs from sender", f"{mid} vs {frm}", src)
        if name and "@" in name and name.lower() != addr.lower():
            self.add_finding("high", "Display name contains a different email address", name, src, "Classic display-name spoof.")
        for b in BRANDS:
            if b in name.lower() and b not in frm:
                self.add_finding("high", f"Display name impersonates '{b}' but sender domain is {frm}", name, src, "Report as phishing and block the sender.")
                break
        subj = msg.get("Subject", "")
        if URGENT.search(subj):
            self.add_finding("low", "Urgency / credential keywords in subject", subj[:100], src)
        hops = msg.get_all("Received") or []
        ips = [i for h in hops for i in IP.findall(h)]
        origin = next((i for i in reversed(ips) if not i.startswith(("10.", "192.168.", "127.", "172.16."))), None)
        self.add_finding("info", f"{len(hops)} relay hop(s)", f"Likely originating IP: {origin or 'unknown'}", src,
                         "Look the IP up in your threat-intel tools." if origin else "")
        if msg.get("X-Mailer") or msg.get("User-Agent"):
            self.add_finding("info", "Mail client", msg.get("X-Mailer") or msg.get("User-Agent"), src)
        return self.findings
