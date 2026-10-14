
"""
Phishing / Malicious URL Classifier
--------------------------------------
Heuristic classifier that scores a URL's likelihood of being phishing based on
well-known lexical red flags (no live browsing, no network request to the
target URL — pure string/structure analysis of a URL the user supplies).

Developer: Muhammad Mughees Abbasi
"""

import re
from urllib.parse import urlparse

from .base import SecurityModule, Finding

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "gq", "tk", "ml", "cf", "work", "click"}

BRAND_KEYWORDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "netflix", "bank", "whatsapp", "outlook", "office365",
]

URGENCY_WORDS = ["verify", "suspend", "urgent", "confirm-account", "unlock", "secure-login", "update-payment"]

IP_HOST_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


class PhishingUrlClassifier(SecurityModule):
    name = "Phishing URL Classifier"
    description = "Scores URLs for phishing-style red flags using lexical heuristics."

    def run(self, url: str = "", urls: list[str] | None = None, **kwargs) -> list[Finding]:
        self.clear()
        targets = urls if urls else ([url] if url else [])

        if not targets:
            self.add_finding("info", "No URL provided", "Supply a URL or list of URLs.")
            return self.findings

        for u in targets:
            self._classify(u.strip())

        return self.findings

    def _classify(self, url: str) -> None:
        if not url:
            return

        score = 0
        reasons = []

        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()

        if IP_HOST_PATTERN.match(host.split(":")[0]):
            score += 3
            reasons.append("Host is a raw IP address instead of a domain name")

        if host.count("-") >= 3:
            score += 1
            reasons.append("Unusually many hyphens in hostname")

        if host.count(".") >= 4:
            score += 1
            reasons.append("Excessive subdomain nesting")

        tld = host.split(".")[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            score += 2
            reasons.append(f"Uses commonly-abused TLD: .{tld}")

        for brand in BRAND_KEYWORDS:
            if brand in host and not host.endswith(f"{brand}.com"):
                score += 3
                reasons.append(f"Brand keyword '{brand}' present in a non-official domain")
                break

        for word in URGENCY_WORDS:
            if word in full:
                score += 2
                reasons.append(f"Urgency/social-engineering keyword in URL: '{word}'")

        if "@" in url:
            score += 3
            reasons.append("'@' in URL can hide the real destination host")

        if len(url) > 100:
            score += 1
            reasons.append("Unusually long URL")

        if score >= 6:
            severity = "high"
        elif score >= 3:
            severity = "medium"
        elif score >= 1:
            severity = "low"
        else:
            severity = "info"

        if reasons:
            self.add_finding(
                severity,
                f"Phishing risk score {score}: {url}",
                "; ".join(reasons),
                source="heuristic",
            )
        else:
            self.add_finding("info", f"No red flags: {url}", "No known phishing indicators matched.", source="heuristic")
