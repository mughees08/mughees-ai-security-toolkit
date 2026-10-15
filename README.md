# AI Security Toolkit

**Defensive & AI-security analysis in one dependency-free Python project — 20 tools, an AI Security Analyst, chatbot guardrails and a pro terminal UI.**

Developer: **Muhammad Mughees Abbasi**

![AI Security Toolkit banner and menu](assets/banner-preview.png)

> A browser replay of a real session (`demo.html`) is included — open it locally in any browser.

---

## Scope & intent

Defensive / analysis toolkit. It deliberately does **not** include exploit or payload generation, password / hash cracking,
wireless attacks, malware, or code that attacks, brute-forces or scans a remote target. Modules that touch the network
(`Web Headers & TLS`, live chatbot test) ask you to confirm you are authorised first. Use only on systems and data you own or
are explicitly authorised to assess.

## Install & run

```bash
# Termux:  pkg install python git
git clone https://github.com/mughees08/mughees-ai-security-toolkit.git
cd mughees-ai-security-toolkit
./ai-sec-toolkit.sh            # or: python3 main.py
```
Requires Python 3.10+. **No pip installs.**

| Flag | Purpose |
|---|---|
| `--theme cyber\|matrix\|crimson\|midnight\|light` | colour theme (also in Settings) |
| `--no-bg` | do not paint the terminal background |
| `--debug` | show tracebacks for unexpected errors |
| `--scan-prompt "text"` | screen one prompt, exit code 2 if flagged |
| `--selftest` | grade the guard (CI friendly) |

## Tools

**Detection & Analysis**
| # | Tool | What it does |
|---|---|---|
| 1 | Log / Traffic Analyzer | web + SSH logs: SQLi, XSS, traversal, scanners, web/SSH brute force, login-after-failures |
| 2 | Prompt-Injection Detector | 30+ rules, decodes base64 / rot13 / leetspeak / spaced / look-alike / invisible Unicode; Roman Urdu, Urdu, Arabic, Spanish, French, German |
| 3 | Vulnerability Report Summarizer | Nmap XML / JSON → prioritised findings, risky ports, CVEs, fixes |
| 4 | Passive OSINT Aggregator | DNS, SPF/DMARC audit, certificate transparency (crt.sh + certspotter fallback, retries) |
| 5 | Phishing URL Classifier | 0-100 score, typosquat / brand look-alike, punycode, shorteners; never opens the URL |

**AI Security**
| # | Tool | What it does |
|---|---|---|
| 6 | AI Chatbot Guard Console | input firewall → model → output guard; multi-turn escalation, lockout, rate limit, canary token, PII/secret redaction, policy file |
| 7 | LLM Red-Team Self-Test | graded (A–F) resilience check of the guard, OWASP-mapped; optional test of **your own** chatbot endpoint |
| 8 | System Prompt Auditor | strength score, backdoor / secret / permissive-wording checks, writes a hardened rewrite |
| 9 | RAG / Document Poisoning Scanner | hidden instructions in docs & web pages, invisible Unicode, exfil beacons, sanitised copies |
| 10 | AI Agent & MCP Tool Auditor | excessive agency, poisoned tool descriptions, unconstrained params, MCP config secrets / unpinned packages |
| 11 | Chat Log Auditor | attacks, leaks and possible jailbreak successes in transcripts, repeat attackers |
| 12 | Guard Integration Kit | exports the guard + policy + example to protect your own bot |
| 13 | **AI Security Analyst** | summary · remediation plan · attack-chain correlation · OWASP LLM / MITRE mapping · explain · Q&A · incident report · trend/diff · triage · hunting queries |

**Security Utilities** — 14 Secrets & PII scanner/redactor · 15 Web headers & TLS checker · 16 Email header analyzer ·
17 JWT inspector · 18 IOC extractor (defang aware, CSV export) · 19 Password auditor/generator (HIBP k-anonymity optional) · 20 File integrity monitor.

## AI features

* Works **offline**. Set `ANTHROPIC_API_KEY` for live chatbot replies and a deeper analyst narrative. Findings are redacted first and wrapped as untrusted data.
* Guard policy lives in `data/guard_policy.json` (edit in **Settings**): thresholds, blocked phrases, max length, lockout, PII handling.
* Findings are tagged with the **OWASP Top 10 for LLM Applications (2025)** and indicative **MITRE ATT&CK / ATLAS** techniques.

## Professional error handling

Every failure is shown as a coded, actionable message — never a raw traceback:

```
✖ E4003 TLS handshake timed out (crt.sh)
   ├─ detail _ssl.c:1064: The handshake operation timed out
   └─ fix    Usually a slow link, VPN or proxy. Retry, or try another network.
```
Menu **[e]** lists all codes. Unexpected errors get a reference id and are logged to `logs/toolkit.log`; use `--debug` for the traceback.

## Themes & reports

Five themes (cyber, matrix, crimson, midnight, light) with a full-screen background; toggle in **Settings**.
Reports (**[r]**): interactive HTML dashboard (risk gauge, filters, search, trend), Markdown, JSON, CSV — timestamped in `reports/`.

## Project layout

```
main.py                    # app shell, menu, settings
ai-sec-toolkit.sh          # launcher
modules/
  ui.py errors.py validators.py net.py store.py session.py taxonomy.py reporter.py registry.py
  guard_engine.py llm.py base.py
  (one file per tool)
data/samples/              # demo logs, scans, prompts, tools, transcripts
tests/                     # 24 unit tests   ·   .github/workflows/ci.yml
```
Add a tool: subclass `SecurityModule` (`collect()` for prompts, `run()` for findings) and list it in `modules/registry.py`.

## Test

```bash
python3 -m unittest discover -s tests -v
python3 main.py --selftest
```

## License
MIT — see `LICENSE`.
