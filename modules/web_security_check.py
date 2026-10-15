"""
Web Security Headers & TLS Checker
------------------------------------
Reviews a website's TLS certificate and HTTP security headers using ordinary
browser-style requests (one TLS handshake, one GET over HTTPS, one GET over
HTTP to check the redirect). No fuzzing, no payloads. Use on sites you own or
are authorised to assess.

Developer: Muhammad Mughees Abbasi
"""

import http.client
import socket
import ssl
import time

from .base import SecurityModule, Finding
from .errors import classify
from .validators import domain as validate_domain

HEADERS = [
    ("strict-transport-security", "high", "Missing HSTS", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", "medium", "Missing Content-Security-Policy", "Add a CSP that restricts script and frame sources."),
    ("x-content-type-options", "low", "Missing X-Content-Type-Options", "Add X-Content-Type-Options: nosniff"),
    ("referrer-policy", "low", "Missing Referrer-Policy", "Add Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", "low", "Missing Permissions-Policy", "Restrict camera, microphone and geolocation."),
]


class WebSecurityChecker(SecurityModule):
    key = "web"
    name = "Web Security Headers & TLS Checker"
    description = "TLS certificate + HTTP security headers"
    category = "Security Utilities"
    sends_traffic = True

    def collect(self, ui) -> dict:
        ui.warn("This sends ordinary browser-style requests to the target.", "Only check sites you own or are authorised to assess.")
        if not ui.confirm("I am authorised to check this site"):
            from .errors import UserCancelled
            raise UserCancelled()
        return {"domain": ui.prompt("Domain", validator=validate_domain)}

    def run(self, domain: str = "", **kwargs) -> list[Finding]:
        self.clear()
        if not domain:
            self.add_finding("info", "No domain provided", "")
            return self.findings
        self._tls(domain)
        self._headers(domain)
        self._redirect(domain)
        return self.findings

    def _fail(self, what: str, exc: Exception, src: str) -> None:
        err = classify(exc, src)
        self.add_finding("info", f"{what} unavailable — {err.code} {err.title}", err.detail, src, err.hint)

    def _tls(self, host: str) -> None:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock, ctx.wrap_socket(sock, server_hostname=host) as s:
                cert, version, cipher = s.getpeercert(), s.version(), s.cipher()
        except Exception as exc:
            self._fail("TLS check", exc, host)
            return
        days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        sev = "critical" if days < 0 else "high" if days < 7 else "medium" if days < 30 else "info"
        self.add_finding(sev, f"Certificate expires in {days} day(s)", f"Issuer: {issuer.get('organizationName', '?')}; valid until {cert['notAfter']}", host,
                         "Renew now (automate with ACME / certbot)." if days < 30 else "")
        self.add_finding("info" if version in ("TLSv1.2", "TLSv1.3") else "high", f"Negotiated {version}", f"Cipher: {cipher[0] if cipher else '?'}", host,
                         "" if version in ("TLSv1.2", "TLSv1.3") else "Disable TLS 1.0/1.1 and old ciphers.")

    def _headers(self, host: str) -> None:
        try:
            conn = http.client.HTTPSConnection(host, timeout=10, context=ssl.create_default_context())
            conn.request("GET", "/", headers={"User-Agent": "ai-security-toolkit/3.0"})
            resp = conn.getresponse()
            hdr = {k.lower(): v for k, v in resp.getheaders()}
            cookies = resp.msg.get_all("Set-Cookie") or []
            conn.close()
        except Exception as exc:
            self._fail("Header check", exc, host)
            return
        for name, sev, title, fix in HEADERS:
            if name not in hdr:
                self.add_finding(sev, title, f"HTTP {resp.status} response lacks {name}.", host, fix)
        if "x-frame-options" not in hdr and "frame-ancestors" not in hdr.get("content-security-policy", ""):
            self.add_finding("medium", "No clickjacking protection", "Neither X-Frame-Options nor CSP frame-ancestors present.", host,
                             "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.")
        for h in ("server", "x-powered-by"):
            if h in hdr and any(c.isdigit() for c in hdr[h]):
                self.add_finding("low", f"Version disclosure in {h}", hdr[h], host, "Hide product/version banners.")
        for c in cookies:
            low = c.lower()
            missing = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in low]
            if missing:
                self.add_finding("medium", f"Cookie '{c.split('=')[0]}' missing {', '.join(missing)}", "", host, "Set Secure; HttpOnly; SameSite=Lax (or Strict).")
        self.add_finding("info", f"HTTPS GET / -> {resp.status}", f"{len(hdr)} response headers inspected.", host)

    def _redirect(self, host: str) -> None:
        try:
            conn = http.client.HTTPConnection(host, timeout=10)
            conn.request("GET", "/", headers={"User-Agent": "ai-security-toolkit/3.0"})
            resp = conn.getresponse()
            loc = resp.getheader("Location", "")
            conn.close()
        except Exception as exc:
            self._fail("HTTP->HTTPS redirect check", exc, host)
            return
        if resp.status in (301, 302, 307, 308) and loc.startswith("https://"):
            self.add_finding("info", "HTTP redirects to HTTPS", loc, host)
        else:
            self.add_finding("high", "HTTP does not redirect to HTTPS", f"Status {resp.status}", host, "Redirect all HTTP traffic to HTTPS.")
