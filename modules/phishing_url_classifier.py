"""
Phishing / Malicious URL Classifier
--------------------------------------
Heuristic classifier that scores a URL's likelihood of being phishing based on
lexical red flags (no live browsing, no network request to the target URL —
pure string/structure analysis of a URL the user supplies).

Developer: Muhammad Mughees Abbasi
"""

import os
import re
from urllib.parse import urlsplit

from .base import SecurityModule, Finding
from .validators import url_list

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "country", "support",
                   "work", "loan", "icu", "buzz", "rest", "cyou", "cfd"}
BRAND_KEYWORDS = ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram", "netflix", "binance",
                  "whatsapp", "outlook", "office365", "jazzcash", "easypaisa", "meezan", "alfalah", "nadra", "dhl",
                  "fedex", "telegram", "github", "linkedin", "daraz", "hbl"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly"}
URGENCY_WORDS = ["login", "verify", "secure", "update", "account", "confirm", "banking", "password", "suspend", "urgent",
                 "wallet", "signin", "billing", "unlock", "reward", "prize", "gift", "claim", "otp", "kyc"]
TWO_PART_TLDS = {"co.uk", "com.pk", "org.pk", "gov.pk", "com.au", "co.in"}
IP_HOST_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_UNLEET = str.maketrans("10354", "loesa")


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def score_url(url: str) -> tuple[int, list[str]]:
    raw = url.strip()
    parts = urlsplit(raw if "://" in raw else "http://" + raw)
    host = (parts.hostname or "").lower()
    score, reasons = 0, []

    def add(points: int, why: str) -> None:
        nonlocal score
        score += points
        reasons.append(why)

    if IP_HOST_PATTERN.match(host):
        add(30, "Host is a raw IP address instead of a domain name")
    if "@" in parts.netloc:
        add(25, "'@' in URL can hide the real destination host")
    if "xn--" in host:
        add(25, "Punycode host — possible look-alike characters")
    labels = host.split(".")
    if len(labels) >= 5:
        add(15, "Excessive subdomain nesting")
    elif len(labels) == 4:
        add(8, "Deep subdomain nesting")
    if host.count("-") >= 3:
        add(10, "Unusually many hyphens in hostname")
    if len(raw) > 75:
        add(10, "Unusually long URL")
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        add(15, f"Uses commonly-abused TLD: .{tld}")
    if host in SHORTENERS:
        add(20, "URL shortener hides the real destination")
    if parts.scheme != "https":
        add(10, "Not using HTTPS")
    if parts.port and parts.port not in (80, 443):
        add(10, f"Non-standard port {parts.port}")
    words = [w for w in URGENCY_WORDS if w in raw.lower()]
    if words:
        add(min(20, 5 * len(words)), "Urgency / credential keywords: " + ", ".join(words[:4]))
    if re.search(r"(url|redirect|next|goto)=https?", raw, re.I):
        add(10, "Open-redirect style parameter")
    if len(re.findall(r"%[0-9a-f]{2}", raw, re.I)) > 6:
        add(10, "Heavy percent-encoding")
    if len(labels) >= 2:
        reg = ".".join(labels[-3:]) if ".".join(labels[-2:]) in TWO_PART_TLDS else ".".join(labels[-2:])
        core = reg.split(".")[0]
        host_n = host.translate(_UNLEET)
        for brand in BRAND_KEYWORDS:
            if core == brand:
                break
            if brand in host_n:
                add(30, f"Brand '{brand}' (or look-alike) present in a non-official domain '{reg}'")
                break
            if 0 < _lev(core, brand) <= 2 and len(core) >= 5:
                add(35, f"Looks like a typosquat of '{brand}'")
                break
    return min(score, 100), reasons


class PhishingUrlClassifier(SecurityModule):
    key = "phish"
    name = "Phishing URL Classifier"
    description = "Heuristic phishing-risk scoring for URLs"
    category = "Detection & Analysis"

    def collect(self, ui) -> dict:
        ui.info("Never opens the URL. Enter one or many (comma / space separated) or a file path.")
        raw = ui.prompt("URL(s) or file", validator=lambda v: v)
        if os.path.isfile(os.path.expanduser(raw)):
            with open(os.path.expanduser(raw), encoding="utf-8", errors="replace") as fh:
                raw = " ".join(ln.strip() for ln in fh if ln.strip())[:200_000]
        return {"urls": url_list(raw)[:300]}

    def run(self, url: str = "", urls: list[str] | None = None, **kwargs) -> list[Finding]:
        self.clear()
        targets = urls if urls else ([url] if url else [])
        if not targets:
            self.add_finding("info", "No URL provided", "Supply a URL or list of URLs.",
                             remediation="Example: http://paypa1-secure-login.xyz/verify")
            return self.findings
        for u in targets:
            u = u.strip()
            if not u:
                continue
            score, reasons = score_url(u)
            if score >= 60:
                sev, label = "high", "likely phishing"
            elif score >= 30:
                sev, label = "medium", "suspicious"
            elif score >= 10:
                sev, label = "low", "minor red flags"
            else:
                sev, label = "info", "no strong indicators"
            self.add_finding(sev, f"Phishing risk {score}/100 ({label}): {u[:80]}",
                             "; ".join(reasons) or "No known phishing indicators matched.", "heuristic",
                             "Do not enter credentials. Report / block the domain." if sev in ("high", "medium") else "")
        return self.findings
