# Changelog

## 3.0.0
* New terminal UI engine: 5 themes (cyber, matrix, crimson, midnight, light), full-screen background, gradient banner, severity badges, risk bar, spinner.
* Professional error system: stable codes (E1xxx input, E2xxx file, E3xxx parse, E4xxx network, E6xxx AI API, E9xxx internal), fixes shown to the user, tracebacks only with `--debug`, rotating log in `logs/`.
* Input validation with re-prompts (no more silent fall-through on bad input).
* AI security: chatbot guard console (policy, lockout, canary, output redaction), red-team self-test (graded, OWASP-mapped), system prompt auditor, RAG poisoning scanner, agent/MCP tool auditor, chat log auditor, guard integration kit.
* AI Security Analyst: executive summary, remediation plan, attack-chain correlation, OWASP LLM / MITRE mapping, explain, Q&A, incident report, trend/diff, triage, hunting queries.
* New utilities: secrets/PII scanner + redactor, web headers & TLS checker, email header analyzer, JWT inspector, IOC extractor, password auditor, file integrity monitor.
* Reports: interactive HTML dashboard (filter/search), Markdown, JSON, CSV; timestamped, never overwritten.
* Fixes: committed `__pycache__` removed + `.gitignore`, README image paths, invalid report-format input, empty-URL handling, crt.sh failures (retry + certspotter fallback), non-executable launcher.
* 24 unit tests + CI workflow.

## 1.0.0
* Initial release: log analyzer, prompt-injection detector, vulnerability summarizer, passive OSINT, phishing classifier, reporter.
