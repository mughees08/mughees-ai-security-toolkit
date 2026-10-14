#!/usr/bin/env python3
"""
AI Security Toolkit
=====================
A defensive security + AI-security analysis toolkit.

Developer : Muhammad Mughees Abbasi
License   : MIT

IMPORTANT / SCOPE
------------------
This tool is for DEFENSIVE and ANALYSIS purposes only:
  - It reads logs/scan files you already have and flags suspicious patterns.
  - It detects prompt-injection / jailbreak attempts in text.
  - It summarizes vulnerability scan output you already generated.
  - It collects PUBLIC passive OSINT data (DNS, certificate transparency).
  - It scores URLs for phishing-style red flags.

It does NOT perform exploitation, credential cracking, wireless attacks,
or send any traffic designed to attack a target. Use only on systems and
data you own or are explicitly authorized to analyze.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from modules.log_analyzer import LogAnalyzer
from modules.prompt_injection_detector import PromptInjectionDetector
from modules.vuln_report_summarizer import VulnReportSummarizer
from modules.osint_aggregator import OsintAggregator
from modules.phishing_url_classifier import PhishingUrlClassifier
from modules import reporter

BANNER = r"""
    _    ___   ____                      _ _          _____           _ _    _ _
   / \  |_ _| / ___|  ___  ___ _   _ _ __(_) |_ _   _  |_   _|__   ___ | | | _(_) |_
  / _ \  | |  \___ \ / _ \/ __| | | | '__| | __| | | |   | |/ _ \ / _ \| | |/ / | __|
 / ___ \ | |   ___) |  __/ (__| |_| | |  | | |_| |_| |   | | (_) | (_) | |   <| | |_
/_/   \_\___| |____/ \___|\___|\__,_|_|  |_|\__|\__, |   |_|\___/ \___/|_|_|\_\_|\__|
                                                 |___/
"""

RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"


class ToolkitApp:
    def __init__(self) -> None:
        self.modules = {
            "1": LogAnalyzer(),
            "2": PromptInjectionDetector(),
            "3": VulnReportSummarizer(),
            "4": OsintAggregator(),
            "5": PhishingUrlClassifier(),
        }
        self.last_run: dict[str, list] = {}

    def print_banner(self) -> None:
        print(f"{CYAN}{BANNER}{RESET}")
        print(f"{BOLD}AI Security Toolkit{RESET} — Defensive & AI-Security Analysis")
        print(f"Developer: {GREEN}Muhammad Mughees Abbasi{RESET}")
        print("Scope: analysis & detection only — no exploitation, no cracking, no live attacks.\n")

    def print_menu(self) -> None:
        print(f"{YELLOW}[*] Select a Module:{RESET}")
        print("  [1] Log / Traffic Analyzer        - Parse logs, flag brute-force / SQLi / scanners")
        print("  [2] Prompt-Injection Detector      - Scan text/files for LLM jailbreak patterns")
        print("  [3] Vulnerability Report Summarizer - Turn Nmap XML / JSON scan output into a report")
        print("  [4] Passive OSINT Aggregator        - DNS + certificate-transparency lookup (passive)")
        print("  [5] Phishing URL Classifier          - Heuristic phishing-risk scoring for URLs")
        print("  [6] Generate Combined Report         - Export all findings so far (Markdown/HTML/JSON)")
        print("  [0] Exit")
        print()

    def run(self) -> None:
        self.print_banner()
        while True:
            self.print_menu()
            choice = input(f"{BOLD}[*] Enter your choice: {RESET}").strip()

            if choice == "0":
                print("Goodbye.")
                break
            elif choice == "1":
                self._run_log_analyzer()
            elif choice == "2":
                self._run_prompt_injection()
            elif choice == "3":
                self._run_vuln_summarizer()
            elif choice == "4":
                self._run_osint()
            elif choice == "5":
                self._run_phishing()
            elif choice == "6":
                self._generate_report()
            else:
                print(f"{YELLOW}Invalid choice.{RESET}\n")

    def _print_findings(self, mod) -> None:
        for f in mod.findings:
            print(f"  [{f.severity.upper():8}] {f.title} — {f.detail[:120]}")
        print(f"\n{GREEN}{mod.summary()}{RESET}\n")
        self.last_run[mod.name] = mod.findings

    def _run_log_analyzer(self) -> None:
        path = input("Log file path: ").strip()
        mod = self.modules["1"]
        mod.run(log_path=path)
        self._print_findings(mod)

    def _run_prompt_injection(self) -> None:
        print("Scan a (1) file or (2) pasted text?")
        sub = input("> ").strip()
        mod = self.modules["2"]
        if sub == "1":
            path = input("File path: ").strip()
            mod.run(file_path=path)
        else:
            text = input("Paste text: ")
            mod.run(text=text)
        self._print_findings(mod)

    def _run_vuln_summarizer(self) -> None:
        path = input("Scan report path (.xml nmap or .json): ").strip()
        mod = self.modules["3"]
        mod.run(report_path=path)
        self._print_findings(mod)

    def _run_osint(self) -> None:
        domain = input("Domain (e.g. example.com): ").strip()
        mod = self.modules["4"]
        mod.run(domain=domain)
        self._print_findings(mod)

    def _run_phishing(self) -> None:
        url = input("URL to score: ").strip()
        mod = self.modules["5"]
        mod.run(url=url)
        self._print_findings(mod)

    def _generate_report(self) -> None:
        if not self.last_run:
            print(f"{YELLOW}No findings yet — run a module first.{RESET}\n")
            return
        print("Format: (1) Markdown  (2) HTML  (3) JSON")
        fmt = input("> ").strip()
        out_dir = Path("reports")
        out_dir.mkdir(exist_ok=True)
        if fmt == "2":
            out = reporter.generate_html(self.last_run, str(out_dir / "report.html"))
        elif fmt == "3":
            out = reporter.generate_json(self.last_run, str(out_dir / "report.json"))
        else:
            out = reporter.generate_markdown(self.last_run, str(out_dir / "report.md"))
        print(f"{GREEN}Report written to: {out}{RESET}\n")


if __name__ == "__main__":
    try:
        ToolkitApp().run()
    except KeyboardInterrupt:
        print("\nInterrupted. Goodbye.")
