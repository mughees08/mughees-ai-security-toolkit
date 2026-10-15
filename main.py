#!/usr/bin/env python3
"""
AI Security Toolkit
=====================
A defensive security + AI-security analysis toolkit.

Developer : Muhammad Mughees Abbasi
License   : MIT

SCOPE
------
Defensive and analysis use only. It reads logs / scans / transcripts you
already have, screens text for prompt injection, audits AI agent and prompt
configuration, queries public passive data sources, and (for modules that
touch a network) asks you to confirm you are authorised first.
It contains no exploit, password-cracking, wireless or malware code.
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from modules import errors, llm, registry, reporter, store
from modules.errors import InputError, ToolkitError, UserCancelled, classify
from modules.session import Session
from modules.ui import THEMES, UI

VERSION = "3.0.0"
DEVELOPER = "Muhammad Mughees Abbasi"


class ToolkitApp:
    def __init__(self, debug: bool = False, theme: str | None = None, no_bg: bool = False) -> None:
        errors.setup_logging(debug)
        self.debug = debug
        try:
            self.cfg = store.load_config()
        except ToolkitError:
            self.cfg = dict(store.DEFAULT_CONFIG)
        if theme:
            self.cfg["theme"] = theme
        if no_bg:
            self.cfg["fullbg"] = False
        self.ui = UI(self.cfg["theme"] if self.cfg["theme"] in THEMES else "cyber", self.cfg["fullbg"], self.cfg.get("ascii", False))
        try:
            suppressed = store.load_suppressions()
        except ToolkitError as err:
            self.ui.error(err)
            suppressed = {}
        self.session = Session(suppressed)
        self.modules = registry.build()

    # ------------------------------------------------------------- screens
    def menu(self) -> None:
        groups = []
        for cat in registry.CATEGORIES:
            items = [(k, m.name, m.description) for k, m in self.modules.items() if m.category == cat]
            groups.append((cat, items))
        groups.append(("System", [("r", "Generate report", "Markdown / HTML dashboard / JSON / CSV"),
                                  ("s", "Settings", "Theme, background, guard policy"),
                                  ("e", "Error codes", "What each Exxxx code means"),
                                  ("0", "Exit", "")]))
        self.ui.menu(groups)

    def status(self) -> None:
        total = len(self.session.pairs())
        self.ui.out(self.ui.paint(f"  session: {total} finding(s) · risk {self.session.score()}/100 {self.session.label()}"
                                  + (f" · {self.session.suppressed_count()} triaged" if self.session.suppressed_count() else ""), "dim"))

    def run(self) -> int:
        ui = self.ui
        ui.apply_background()
        ui.banner(VERSION, DEVELOPER, llm.available())
        while True:
            self.menu()
            self.status()
            try:
                choice = ui.prompt("Select", allow_empty=True, attempts=1).lower()
            except UserCancelled:
                choice = "0"
            if choice in ("0", "exit", "quit"):
                break
            if not choice:
                continue
            self.dispatch(choice)
        self.shutdown()
        return 0

    def dispatch(self, choice: str) -> None:
        ui = self.ui
        try:
            if choice == "r":
                self.report_menu()
            elif choice == "s":
                self.settings()
            elif choice == "e":
                self.error_codes()
            elif choice in self.modules:
                self.run_module(self.modules[choice])
            else:
                raise InputError("Menu choice not recognised", code="E1004", detail=f"'{choice}'",
                                 hint="Type a number from the list, or r / s / e / 0.")
        except UserCancelled:
            ui.info("Cancelled.\n")
        except KeyboardInterrupt:
            ui.out()
            ui.info("Interrupted.\n")
        except Exception as exc:  # last line of defence: never show a raw traceback
            err = classify(exc, choice)
            ui.error(err)
            if self.debug:
                raise

    # ------------------------------------------------------------- modules
    def run_module(self, mod) -> None:
        ui = self.ui
        ui.out()
        ui.bar(mod.name, "accent")
        kwargs = mod.collect(ui)
        if mod.needs_session:
            kwargs["session"] = self.session
        start = time.time()
        interactive = mod.key in ("guard", "analyst")
        if interactive:
            findings = mod.run(**kwargs)
        else:
            with ui.spinner(f"Running {mod.name}"):
                findings = mod.run(**kwargs)
        elapsed = time.time() - start
        if mod.key == "analyst":
            if getattr(mod, "narrative", "") and mod.findings and mod.findings[0].title.startswith("Executive summary"):
                self.session.summary = mod.narrative
            ui.out(ui.paint(f"  analyst finished in {elapsed:.1f}s\n", "dim"))
            self.session.add(mod.name, findings)
            return
        self.session.add(mod.name, findings)
        ui.findings(mod.name, [f for f in findings if True])
        ui.risk_bar(self.session.score(), self.session.label())
        ui.out(ui.paint(f"  completed in {elapsed:.1f}s\n", "dim"))

    # -------------------------------------------------------------- report
    def report_menu(self) -> None:
        ui = self.ui
        if not self.session.pairs(include_suppressed=True):
            ui.warn("No findings yet", "Run a module first, then generate a report.")
            return
        opts = {"1": "md", "2": "html", "3": "json", "4": "csv", "5": "all"}
        ui.kv([("[1]", "Markdown"), ("[2]", "HTML dashboard (interactive)"), ("[3]", "JSON"), ("[4]", "CSV"), ("[5]", "All formats")])
        pick = ui.prompt("Format", "2", lambda v: v if v in opts else (_ for _ in ()).throw(
            InputError("Format not recognised", code="E1004", detail=f"'{v}'", hint="Enter 1-5 (q to go back).")))
        for fmt in (["md", "html", "json", "csv"] if opts[pick] == "all" else [opts[pick]]):
            path = reporter.write_report(self.session, fmt)
            ui.success(f"Report written to: {path}")
        store.add_snapshot(self.session)
        ui.out()

    # ------------------------------------------------------------ settings
    def settings(self) -> None:
        ui = self.ui
        ui.kv([("[1]", f"Theme            ({ui.theme_name})"), ("[2]", f"Full-screen background  ({'on' if ui.fullbg else 'off'})"),
               ("[3]", "Show guard policy"), ("[4]", "Edit guard policy"), ("[5]", "Preview all themes")])
        pick = ui.prompt("Setting", "1")
        if pick == "1":
            ui.kv([(n, "") for n in THEMES])
            name = ui.prompt("Theme name", ui.theme_name).lower()
            ui.set_theme(name)
            self.cfg["theme"] = name
            ui.apply_background()
            ui.success(f"Theme set to {name}")
        elif pick == "2":
            ui.fullbg = ui.enabled and not ui.fullbg
            self.cfg["fullbg"] = ui.fullbg
            ui.apply_background() if ui.fullbg else ui.restore()
            ui.success(f"Background {'on' if ui.fullbg else 'off'}")
        elif pick == "3":
            ui.kv([(k, str(v)) for k, v in store.load_policy().__dict__.items()])
            return
        elif pick == "4":
            self.edit_policy()
            return
        elif pick == "5":
            for name in THEMES:
                ui.set_theme(name)
                ui.panel(name, ["Preview of the " + name + " theme"])
            ui.set_theme(self.cfg["theme"])
            return
        else:
            raise InputError("Setting not recognised", code="E1004", detail=f"'{pick}'", hint="Enter 1-5.")
        store.save_config(self.cfg)

    def edit_policy(self) -> None:
        ui = self.ui
        pol = store.load_policy()
        pol.block_at = float(ui.prompt("Block threshold 0-1", str(pol.block_at), _frac))
        pol.warn_at = float(ui.prompt("Warn threshold 0-1", str(pol.warn_at), _frac))
        pol.max_input_chars = int(ui.prompt("Max input characters", str(pol.max_input_chars), lambda v: str(_intr(v, 100, 200000))))
        pol.lockout_after = int(ui.prompt("Lock session after N blocks (0 = never)", str(pol.lockout_after), lambda v: str(_intr(v, 0, 100))))
        words = ui.prompt("Blocked phrases (comma separated, Enter keeps current)", ", ".join(pol.blocked_phrases), allow_empty=True)
        pol.blocked_phrases = [w.strip() for w in words.split(",") if w.strip()]
        pol.block_pii_input = ui.confirm("Block (not just warn) when users paste secrets / PII", pol.block_pii_input)
        store.save_policy(pol)
        ui.success("Guard policy saved to data/guard_policy.json")

    def error_codes(self) -> None:
        ui = self.ui
        ui.bar("Error codes", "accent")
        for code, (meaning, fix) in errors.CATALOG.items():
            ui.out(f"  {ui.paint(code, 'err', bold=True)}  {meaning}")
            ui.out(f"         {ui.paint('fix: ' + fix, 'dim')}")
        ui.out()

    def shutdown(self) -> None:
        if self.session.pairs(include_suppressed=True):
            try:
                store.add_snapshot(self.session)
            except ToolkitError:
                pass
        self.ui.out(self.ui.paint("Goodbye. Stay safe.", "accent"))
        self.ui.restore()


def _frac(v: str) -> str:
    try:
        x = float(v)
    except ValueError:
        raise InputError("Expected a number between 0 and 1", code="E1005", detail=f"'{v}'", hint="Example: 0.75") from None
    if not 0 <= x <= 1:
        raise InputError("Number out of range", code="E1005", detail=v, hint="Use a value from 0 to 1.")
    return str(x)


def _intr(v: str, lo: int, hi: int) -> int:
    from modules.validators import integer
    return integer(lo, hi)(v)


def cli(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ai-sec-toolkit", description="AI Security Toolkit (defensive)")
    p.add_argument("--theme", choices=list(THEMES), help="colour theme")
    p.add_argument("--no-bg", action="store_true", help="do not paint the terminal background")
    p.add_argument("--debug", action="store_true", help="show tracebacks for unexpected errors")
    p.add_argument("--scan-prompt", metavar="TEXT", help="screen one prompt with the guard and exit")
    p.add_argument("--selftest", action="store_true", help="run the guard evaluation (exit 1 if a technique slips through)")
    p.add_argument("--version", action="version", version=f"AI Security Toolkit {VERSION}")
    args = p.parse_args(argv)
    errors.setup_logging(args.debug)
    if args.scan_prompt:
        from modules import guard_engine as g
        res = g.ChatGuard().check_input(args.scan_prompt)
        print(f"{res['verdict']} risk={res['score']}")
        for r in res["reasons"]:
            print("  -", r)
        return 0 if res["verdict"] == "ALLOW" else 2
    if args.selftest:
        from modules.llm_redteam import evaluate_guard, grade
        r = evaluate_guard()
        print(f"detected {r['detected']}/{r['total']}  false-positives {len(r['false_pos'])}/{r['benign_total']}  grade {grade(r['rate'], r['fp_rate'])}")
        return 0 if not r["missed"] and not r["false_pos"] else 1
    try:
        return ToolkitApp(debug=args.debug, theme=args.theme, no_bg=args.no_bg).run()
    except KeyboardInterrupt:
        print("\nInterrupted. Goodbye.")
        return 130
    except ToolkitError as err:
        UI(fullbg=False).error(err)
        return 1


if __name__ == "__main__":
    sys.exit(cli())
