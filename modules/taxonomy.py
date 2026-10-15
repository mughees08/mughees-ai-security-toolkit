"""
Security taxonomy and knowledge base used by the AI Security Analyst:
OWASP Top 10 for LLM Applications (2025), MITRE ATT&CK / ATLAS hints,
plain-language explanations and threat-hunting query templates.
Mappings are indicative (keyword based) and meant to guide triage.

Developer: Muhammad Mughees Abbasi
"""

import re

OWASP_LLM = {
    "LLM01": "Prompt Injection", "LLM02": "Sensitive Information Disclosure", "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning", "LLM05": "Improper Output Handling", "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage", "LLM08": "Vector and Embedding Weaknesses", "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}
ATTACK = {
    "T1110": "Brute Force", "T1190": "Exploit Public-Facing Application", "T1595": "Active Scanning",
    "T1566": "Phishing", "T1078": "Valid Accounts", "T1021": "Remote Services", "T1552": "Unsecured Credentials",
    "T1567": "Exfiltration Over Web Service", "T1499": "Endpoint Denial of Service", "T1083": "File and Directory Discovery",
    "T1059": "Command and Scripting Interpreter", "T1596": "Search Open Technical Databases",
    "AML.T0051": "LLM Prompt Injection", "AML.T0054": "LLM Jailbreak", "AML.T0056": "System prompt extraction",
    "AML.T0057": "LLM Data Leakage",
}

# (regex on "title detail", [OWASP], [ATT&CK/ATLAS])
MAP = [
    (r"brute.?force|failed login|failed password", [], ["T1110"]),
    (r"successful login after", [], ["T1078", "T1110"]),
    (r"sql injection|xss|path traversal|command injection|cve-\d", [], ["T1190"]),
    (r"sensitive file probe|\.env|wp-config", [], ["T1083", "T1190"]),
    (r"scanner|directory.*scan|url scan|404", [], ["T1595"]),
    (r"phishing|typosquat|look-?alike|spoof|spf|dmarc", [], ["T1566"]),
    (r"open port.*(telnet|rdp|smb|vnc|3389|445|23\b|5900)|rdp|smb", [], ["T1021"]),
    (r"api key|secret|password|token|private key|jwt|credential", [], ["T1552"]),
    (r"exfil", ["LLM02"], ["T1567", "AML.T0057"]),
    (r"inject|jailbreak|override|persona|delimiter|ignore (all )?previous", ["LLM01"], ["AML.T0051", "AML.T0054"]),
    (r"system prompt|canary|prompt leak|extraction", ["LLM07"], ["AML.T0056"]),
    (r"pii|cnic|credit card|sensitive data|personal data|email address|phone number", ["LLM02"], ["AML.T0057"]),
    (r"tool|agent|shell|excessive|permission|mcp|filesystem|autonomy|confirmation", ["LLM06"], []),
    (r"rag|poison|hidden (text|instruction)|indirect|document|invisible|unicode tag", ["LLM01", "LLM04", "LLM08"], ["AML.T0051"]),
    (r"output handling|executable|script content|markdown image", ["LLM05"], []),
    (r"consumption|rate limit|too long|longer than|token budget|unbounded|divergence", ["LLM10"], ["T1499"]),
    (r"unpinned|supply chain|latest|typosquat package|dependency|npx", ["LLM03"], []),
    (r"hallucinat|misinformation", ["LLM09"], []),
]

# (regex, what it is, impact, fix)
KB = [
    (r"brute.?force|failed login", "Automated guessing of passwords against a login service.",
     "Account takeover, especially if a guess eventually succeeds.", "Rate-limit, fail2ban, MFA, key-only SSH, lockouts + alerts."),
    (r"sql injection", "User input is interpreted as SQL by the database.",
     "Data theft, authentication bypass, data destruction.", "Parameterised queries / ORM, least-privilege DB user, WAF, input validation."),
    (r"xss", "Attacker-controlled script runs in another user's browser.",
     "Session theft, defacement, phishing inside your domain.", "Contextual output encoding, CSP, HttpOnly cookies."),
    (r"path traversal", "'../' sequences escape the intended directory.",
     "Reading config files, keys and source code.", "Canonicalise + allow-list paths, run with minimal file permissions."),
    (r"scanner|directory.*scan", "Automated reconnaissance looking for exposed paths or software.",
     "Usually precedes exploitation of whatever it finds.", "Rate-limit 404s, hide version banners, remove unused endpoints."),
    (r"open port", "A network service is reachable from where the scan was run.",
     "Every exposed service is attack surface; legacy ones (Telnet, SMB, RDP, Redis) are frequent entry points.",
     "Close or firewall unused ports; patch exposed services; put admin ports behind VPN."),
    (r"spf|dmarc", "Email authentication records that stop domain spoofing.",
     "Phishers can send mail that appears to come from your domain.", "Publish a strict SPF record and enforce DMARC (quarantine/reject)."),
    (r"inject|jailbreak|override|persona|delimiter", "Input crafted to make an LLM ignore its instructions.",
     "Policy bypass, data leakage, or unauthorised tool actions (OWASP LLM01).",
     "Input/output guardrails, treat all external text as data, least-privilege tools, human approval for risky actions."),
    (r"system prompt|canary|prompt leak", "The hidden instructions of the bot were exposed.",
     "Reveals business logic and guardrails, making later attacks easier (OWASP LLM07).",
     "Never put secrets in prompts, use canary tokens, filter outputs, assume the prompt will leak."),
    (r"pii|cnic|credit card|sensitive data|api key|secret|private key", "Sensitive data is present where it should not be.",
     "Privacy breach, fraud, credential compromise (OWASP LLM02).", "Redact at ingestion and output, rotate exposed secrets, use a secrets manager."),
    (r"tool|agent|shell|excessive|permission|mcp", "An AI agent has broader capabilities than its task needs.",
     "A single injected instruction can cause real-world damage (OWASP LLM06).",
     "Least privilege per tool, allow-lists, human-in-the-loop for destructive actions, audit logs."),
    (r"rag|poison|hidden|indirect|invisible|unicode tag", "Malicious instructions hidden inside documents the AI reads.",
     "The user never typed the attack, yet the model obeys it (indirect injection).",
     "Sanitise retrieved content, strip invisible characters, label untrusted context, restrict what retrieved text can trigger."),
    (r"output handling|executable|markdown image", "Model output is passed to a browser, shell or renderer unchecked.",
     "XSS, command execution and silent data exfiltration via images/links (OWASP LLM05).",
     "Encode/validate all model output; block external image rendering; sandbox code."),
    (r"phishing", "A URL or message designed to steal credentials.", "Credential theft and account takeover.",
     "Block the domain, warn users, enforce MFA, report to the brand and registrar."),
    (r"jwt|alg.*none", "Token handling weaknesses (unsigned tokens, long lifetimes).", "Authentication bypass or token replay.",
     "Enforce an algorithm allow-list, short expiry, rotate keys, validate audience/issuer."),
    (r"hsts|csp|header|tls|certificate", "Missing browser/transport hardening.", "Downgrade, clickjacking, XSS impact amplification.",
     "Add HSTS, CSP, X-Content-Type-Options, X-Frame-Options; renew certificates before expiry."),
    (r"password", "Weak or reused password material.", "Credential stuffing and guessing succeed quickly.",
     "Use long passphrases, a password manager and MFA; check against breach corpora."),
]

HUNT = [
    (r"brute|failed", ["grep -E 'Failed password|Invalid user' /var/log/auth.log | grep '{ip}' | tail -50",
                       "grep 'Accepted' /var/log/auth.log | grep '{ip}'   # any success from the same source?"]),
    (r"sql injection|xss|traversal|command injection|probe", ["grep '{ip}' access.log | grep -Ei 'union|select|\\.\\./|<script|\\.env' | tail -50",
                                                              "awk '{print $1}' access.log | sort | uniq -c | sort -rn | head   # top talkers"]),
    (r"scanner|scan", ["grep -c ' 404 ' access.log   # volume of 404s", "grep -Ei 'sqlmap|nikto|nmap|gobuster|nuclei' access.log | head"]),
    (r"open port", ["nmap -sV -p {port} {host}   # re-verify (authorised targets only)"]),
    (r"phishing|spf|dmarc", ["dig +short TXT {domain}", "dig +short TXT _dmarc.{domain}"]),
    (r"secret|api key|token", ["git log -p -S'{hint}' --all | head   # when did it enter the repo?", "grep -rn '{hint}' . | head"]),
]

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)


def classify(finding) -> dict:
    text = f"{finding.title} {finding.detail}".lower()
    owasp, attack = [], []
    for rx, o, a in MAP:
        if re.search(rx, text):
            owasp += [x for x in o if x not in owasp]
            attack += [x for x in a if x not in attack]
    return {"owasp": owasp, "attack": attack}


def explain(finding) -> dict:
    text = f"{finding.title} {finding.detail}".lower()
    for rx, what, impact, fix in KB:
        if re.search(rx, text):
            return {"what": what, "impact": impact, "fix": finding.remediation or fix}
    return {"what": finding.detail or finding.title, "impact": "Depends on context; review manually.",
            "fix": finding.remediation or "Investigate the source and apply least-privilege / patching."}


def hunting_queries(finding) -> list[str]:
    text = f"{finding.title} {finding.detail}".lower()
    ip = (_IP.search(finding.title + " " + finding.detail) or [None])[0] or "<ip>"
    dom = (_DOMAIN.search(finding.title + " " + finding.detail) or [None])[0] or "<domain>"
    port = (re.search(r"(?:port:?\s*|:)(\d{2,5})", finding.title) or [None, "<port>"])[1]
    out = []
    for rx, templates in HUNT:
        if re.search(rx, text):
            out += [t.format(ip=ip, domain=dom, port=port, host=ip, hint="<secret-prefix>") for t in templates]
    return out
