"""
Password Auditor & Generator
------------------------------
Offline strength audit (length, entropy estimate, common-password and pattern
checks). Optionally checks the Have I Been Pwned range API using k-anonymity:
only the first 5 characters of the SHA-1 hash leave the device; the password
itself never does. Never prints or stores the password.

Developer: Muhammad Mughees Abbasi
"""

import hashlib
import math
import re
import secrets
import string

from .base import SecurityModule, Finding
from .errors import ToolkitError
from .net import http_get
from .validators import choice

COMMON = {"password", "123456", "12345678", "qwerty", "abc123", "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon",
          "football", "login", "passw0rd", "password1", "123456789", "111111", "000000", "pakistan", "allah", "bismillah", "ali123",
          "khan123", "karachi", "lahore123", "p@ssw0rd", "changeme", "qwerty123", "1q2w3e4r", "zaq12wsx"}
WALKS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz"]
_UNLEET = str.maketrans("01345$@!", "oleassai")


def entropy_bits(pw: str) -> float:
    pool = 0
    for cls, size in ((string.ascii_lowercase, 26), (string.ascii_uppercase, 26), (string.digits, 10), (string.punctuation, 32)):
        if any(c in cls for c in pw):
            pool += size
    return len(pw) * math.log2(pool) if pool else 0.0


class PasswordAuditor(SecurityModule):
    key = "password"
    name = "Password Auditor & Generator"
    description = "Strength audit, breach check (k-anonymity), generator"
    category = "Security Utilities"

    def collect(self, ui) -> dict:
        mode = ui.prompt("(1) Audit a password  (2) Generate a strong password", "1", choice({"1": "audit", "2": "gen"}))
        if mode == "gen":
            return {"generate": True}
        pw = ui.prompt("Password (hidden)", secret=True)
        return {"password": pw, "breach": ui.confirm("Check breach corpus (sends only a 5-char hash prefix)", False)}

    def run(self, password: str = "", breach: bool = False, generate: bool = False, **kwargs) -> list[Finding]:
        self.clear()
        if generate:
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+?"
            pw = "".join(secrets.choice(alphabet) for _ in range(20))
            self.add_finding("info", "Generated 20-character password", pw, "generator",
                             "Store it in a password manager; this value is not saved by the toolkit.")
            return self.findings
        low = password.lower()
        bits = entropy_bits(password)
        if len(password) < 12:
            self.add_finding("high" if len(password) < 8 else "medium", f"Short password ({len(password)} characters)", "", "audit", "Use 14+ characters or a 4-word passphrase.")
        plain = low.translate(_UNLEET)
        stem = re.sub(r"[\d\W_]+$", "", plain)
        if low in COMMON or plain in COMMON or stem in COMMON or any(len(c) >= 6 and c in plain for c in COMMON):
            self.add_finding("critical", "Matches or is built on a very common password", "Wordlist attacks try these (plus digits / leet) first.", "audit", "Choose something unique.")
        if re.search(r"(.)\1{2,}", password):
            self.add_finding("medium", "Repeated characters", "", "audit")
        if any(w in low or w[::-1] in low for walk in WALKS for w in [walk[i:i + 4] for i in range(len(walk) - 3)]):
            self.add_finding("medium", "Keyboard / alphabet sequence", "", "audit")
        if re.search(r"(19|20)\d{2}\b", password):
            self.add_finding("low", "Contains a year", "Dates are cheap to guess.", "audit")
        if len(set(password)) <= max(3, len(password) // 3):
            self.add_finding("medium", "Very low character variety", "", "audit")
        if breach:
            digest = hashlib.sha1(password.encode()).hexdigest().upper()
            try:
                body = http_get(f"https://api.pwnedpasswords.com/range/{digest[:5]}", headers={"Add-Padding": "true"}, timeout=10, retries=2, context="breach API")
                hit = next((int(l.split(":")[1]) for l in body.splitlines() if l.startswith(digest[5:]) and int(l.split(":")[1]) > 0), 0)
                if hit:
                    self.add_finding("critical", f"Found in {hit:,} known breaches", "Never use this password anywhere.", "HIBP", "Change it everywhere it is used.")
                else:
                    self.add_finding("info", "Not found in the breach corpus", "", "HIBP")
            except ToolkitError as err:
                self.add_finding("info", f"Breach check unavailable — {err.code} {err.title}", err.detail, "HIBP", err.hint)
        sev = "info" if bits >= 70 else "low" if bits >= 55 else "medium" if bits >= 40 else "high"
        self.add_finding(sev, f"Estimated strength ~{bits:.0f} bits", "Rough upper bound; patterns lower the real value.", "audit")
        return self.findings
