# Security & responsible use

This toolkit is **defensive**. It analyses data you already have, screens text for prompt injection,
audits AI-agent and prompt configuration, and queries public passive sources.

* Modules that send traffic (Web Headers & TLS, live chatbot test) require you to confirm authorisation first.
* The toolkit contains no exploit, password-cracking, wireless or malware code and will not accept PRs that add them.
* Secrets and personal data are masked in every output; the password auditor never prints or stores the password.
* Findings sent to the optional AI analyst are redacted first and treated as untrusted data.

Report vulnerabilities in this project by opening a private security advisory on GitHub.
