"""
JWT Inspector
--------------
Decodes a JSON Web Token locally (never sent anywhere) and flags insecure
algorithms, missing / excessive lifetimes, dangerous header fields and
sensitive claims. Does not verify or crack signatures.

Developer: Muhammad Mughees Abbasi
"""

import base64
import json
import re
import time

from . import guard_engine as guard
from .base import SecurityModule, Finding
from .errors import ParseError

SENSITIVE = re.compile(r"(pass(word)?|secret|ssn|cnic|card|private|api[_-]?key)", re.I)


def _b64(part: str) -> dict:
    try:
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:
        raise ParseError("JWT segment is not valid base64url JSON", code="E3004",
                         hint="Paste the complete token: header.payload.signature") from None


class JwtInspector(SecurityModule):
    key = "jwt"
    name = "JWT Inspector"
    description = "Decode + audit a token offline"
    category = "Security Utilities"

    def collect(self, ui) -> dict:
        return {"token": ui.prompt("JWT (hidden input)", secret=True)}

    def run(self, token: str = "", **kwargs) -> list[Finding]:
        self.clear()
        parts = token.strip().split(".")
        if len(parts) != 3:
            raise ParseError("Not a JWT (expected 3 dot-separated parts)", code="E3004", hint="Format: header.payload.signature")
        head, body = _b64(parts[0]), _b64(parts[1])
        src = "jwt"
        alg = str(head.get("alg", "")).lower()
        self.add_finding("info", f"Algorithm {head.get('alg')}, type {head.get('typ', '?')}", "Claims: " + ", ".join(body.keys())[:150], src)
        if alg in ("none", ""):
            self.add_finding("critical", "Unsigned token (alg=none)", "Anyone can forge this token.", src, "Reject alg=none server-side; enforce an algorithm allow-list.")
        if alg.startswith("hs"):
            self.add_finding("medium", "Symmetric HMAC signature", "The same secret signs and verifies; leaked or weak secrets allow forging.", src,
                             "Use a long random secret (>=32 bytes) or switch to RS256/ES256.")
        if not parts[2]:
            self.add_finding("high", "Empty signature segment", "", src, "Validate signatures on every request.")
        for field in ("jku", "x5u", "jwk"):
            if field in head:
                self.add_finding("high", f"Header '{field}' present", "Attacker-controlled key sources enable key-confusion attacks.", src, "Ignore key URLs from the token; use pinned keys.")
        if "kid" in head and re.search(r"(\.\./|/|\||;|')", str(head["kid"])):
            self.add_finding("high", "Suspicious 'kid' value", str(head["kid"])[:80], src, "Treat kid as an opaque lookup key; never use it in file paths or queries.")
        now = time.time()
        exp, iat, nbf = body.get("exp"), body.get("iat"), body.get("nbf")
        if exp is None:
            self.add_finding("medium", "No expiry (exp) claim", "Token never expires.", src, "Issue short-lived tokens.")
        elif isinstance(exp, (int, float)):
            if exp < now:
                self.add_finding("info", "Token is expired", f"{int((now - exp) // 3600)} h ago", src)
            elif iat and isinstance(iat, (int, float)) and exp - iat > 86400 * 7:
                self.add_finding("medium", "Very long lifetime", f"{int((exp - iat) // 86400)} days", src, "Prefer minutes/hours with refresh tokens.")
        if isinstance(nbf, (int, float)) and nbf > now + 300:
            self.add_finding("low", "nbf is in the future", "", src)
        for k in body:
            if SENSITIVE.search(str(k)):
                self.add_finding("high", f"Sensitive claim '{k}' stored in the token", "JWT payloads are readable by anyone.", src, "Never put secrets or personal data in tokens.")
        for m in guard.scan_text(json.dumps(body)):
            self.add_finding(m.severity.lower(), f"{m.name} inside payload", guard.mask(m.text), src)
        for aud in ("iss", "aud"):
            if aud not in body:
                self.add_finding("low", f"Missing '{aud}' claim", "", src, "Validate issuer and audience server-side.")
        return self.findings
