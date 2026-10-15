"""
Log / Traffic Analyzer
-----------------------
Parses text log files (web access logs in combined format, SSH/auth logs) and
flags suspicious patterns using heuristics (no live scanning, no network
calls — reads files the user already has on disk).

Developer: Muhammad Mughees Abbasi
"""

import re
from collections import Counter
from pathlib import Path
from urllib.parse import unquote

from .base import SecurityModule, Finding
from .errors import BASE_DIR
from .validators import existing_file

SAMPLE = BASE_DIR / "data" / "samples" / "access.log"

ACCESS_RX = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?')
AUTH_FAIL = re.compile(r"(failed password|authentication failure|invalid user)", re.I)
AUTH_OK = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
LOGIN_PATH = re.compile(r"(login|signin|wp-login|admin|auth)", re.I)

ATTACKS = [
    ("SQL injection", "high", re.compile(r"(union(\s|\+|%20)+select|or(\s|\+|%20)+1=1|sleep\(\d+\)|information_schema|drop\s+table|'\s*or\s*'1'\s*=\s*'1)", re.I),
     "Use parameterised queries and put a WAF in front of the endpoint."),
    ("XSS attempt", "medium", re.compile(r"(<script|%3cscript|onerror=|javascript:)", re.I),
     "Encode output and set a strict Content-Security-Policy."),
    ("Path traversal", "high", re.compile(r"(\.\./|%2e%2e%2f|/etc/passwd)", re.I),
     "Canonicalise paths server-side and reject '..' segments."),
    ("Command injection", "high", re.compile(r"(;|\||`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc)\b", re.I),
     "Never pass request data to a shell; use allow-lists."),
    ("Sensitive file probe", "medium", re.compile(r"(/\.env|/\.git/|wp-config|phpmyadmin|id_rsa|\.bak$)", re.I),
     "Remove exposed files and block dotfiles at the web server."),
]
SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra|nuclei|zgrab|acunetix|burpsuite)", re.I)
MAX_LINES = 500_000


class LogAnalyzer(SecurityModule):
    key = "logs"
    name = "Log / Traffic Analyzer"
    description = "Parse logs, flag brute-force / SQLi / scanners"
    category = "Detection & Analysis"

    def collect(self, ui) -> dict:
        default = str(SAMPLE) if SAMPLE.exists() else ""
        ui.info("Supports web access logs (combined format) and SSH/auth logs.")
        path = ui.prompt("Log file path (Enter = demo sample)" if default else "Log file path", default, existing_file)
        return {"log_path": path}

    def run(self, log_path: str = "", brute_force_threshold: int = 5, **kwargs) -> list[Finding]:
        self.clear()
        path = Path(log_path)
        if not path.exists() or not path.is_file():
            self.add_finding("info", "No log file found", f"Path does not exist: {log_path}",
                             remediation="Check the path, or run the module again and press Enter to use the demo sample.")
            return self.findings

        attacks: Counter = Counter()
        scanners: Counter = Counter()
        not_found: Counter = Counter()
        login_posts: Counter = Counter()
        fails: Counter = Counter()
        ok_logins: list = []
        ips: Counter = Counter()
        total = parsed = 0
        src = str(path)

        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                total += 1
                if total > MAX_LINES:
                    self.add_finding("low", "Log truncated", f"Only the first {MAX_LINES:,} lines were analysed.", src)
                    break
                m = ACCESS_RX.match(line)
                if m:
                    parsed += 1
                    ip, _ts, method, req_path, status, ua = m.groups()
                    ips[ip] += 1
                    target = req_path + " " + unquote(unquote(req_path))
                    for name, _sev, rx, _fix in ATTACKS:
                        if rx.search(target):
                            attacks[(ip, name)] += 1
                    if ua and SCANNER_UA.search(ua):
                        scanners[ip] += 1
                    if status == "404":
                        not_found[ip] += 1
                    if method == "POST" and LOGIN_PATH.search(req_path):
                        login_posts[ip] += 1
                    continue
                if AUTH_FAIL.search(line):
                    parsed += 1
                    ip_m = IP_PATTERN.search(line)
                    fails[ip_m.group(0) if ip_m else "unknown"] += 1
                    continue
                m = AUTH_OK.search(line)
                if m:
                    parsed += 1
                    ok_logins.append((m.group(1), m.group(2)))

        meta = {n: (s, fix) for n, s, _r, fix in ATTACKS}
        for (ip, name), count in attacks.most_common(30):
            sev, fix = meta[name]
            self.add_finding(sev, f"{name} from {ip}", f"{count} matching request(s)", src, fix)
        for ip, count in scanners.most_common(10):
            self.add_finding("medium", f"Known scanner user-agent from {ip}", f"{count} request(s)", src,
                             "Rate-limit or block the source; review exposed paths.")
        for ip, count in not_found.items():
            if count >= 20:
                self.add_finding("medium", f"Possible directory / URL scan from {ip}", f"{count} x HTTP 404", src,
                                 "Throttle repeated 404s (fail2ban / WAF rule).")
        for ip, count in login_posts.items():
            if count >= 10:
                self.add_finding("high", f"Possible web-login brute force from {ip}", f"{count} login POST requests", src,
                                 "Add rate limiting, CAPTCHA and MFA on the login endpoint.")
        for ip, count in fails.items():
            if count >= brute_force_threshold:
                sev = "critical" if count >= brute_force_threshold * 3 else "high"
                self.add_finding(sev, f"Possible brute-force attempt from {ip}", f"{count} failed login attempts", src,
                                 "Enable fail2ban, disable password SSH logins, enforce key-based auth + MFA.")
        for user, ip in ok_logins:
            if fails.get(ip, 0) >= brute_force_threshold:
                self.add_finding("critical", f"Successful login after {fails[ip]} failures", f"user={user} source={ip} — possible account compromise", src,
                                 "Force a credential reset, review the session, rotate keys.")
        top = ", ".join(f"{ip}({n})" for ip, n in ips.most_common(3)) or "n/a"
        self.add_finding("info", "Log summary", f"{total:,} lines read, {parsed:,} recognised, {len(ips)} unique client IPs. Top talkers: {top}", src)
        return self.findings
