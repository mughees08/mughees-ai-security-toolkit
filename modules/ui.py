"""
Terminal UI engine: themes, full-screen background, panels, badges, prompts.

Pure standard library. Falls back to plain text when output is not a TTY,
NO_COLOR is set, or TOOLKIT_ASCII=1 is exported.

Developer: Muhammad Mughees Abbasi
"""

from __future__ import annotations

import itertools
import os
import re
import shutil
import sys
import textwrap
import threading
import time
from contextlib import contextmanager

from .errors import InputError, ToolkitError, UserCancelled

RGB = tuple[int, int, int]

THEMES: dict[str, dict[str, RGB]] = {
    "cyber": dict(bg=(9, 13, 22), panel=(18, 26, 42), fg=(214, 222, 235), dim=(110, 125, 148),
                  accent=(56, 189, 248), accent2=(129, 140, 248), ok=(52, 211, 153), warn=(251, 191, 36), err=(248, 113, 113)),
    "matrix": dict(bg=(0, 9, 0), panel=(3, 24, 8), fg=(170, 255, 180), dim=(70, 135, 85),
                   accent=(0, 255, 65), accent2=(140, 255, 170), ok=(0, 255, 65), warn=(235, 235, 70), err=(255, 85, 85)),
    "crimson": dict(bg=(15, 8, 10), panel=(32, 15, 19), fg=(238, 226, 228), dim=(145, 112, 118),
                    accent=(244, 63, 94), accent2=(251, 146, 60), ok=(74, 222, 128), warn=(250, 204, 21), err=(255, 110, 110)),
    "midnight": dict(bg=(12, 10, 28), panel=(24, 19, 52), fg=(226, 222, 247), dim=(125, 116, 165),
                     accent=(167, 139, 250), accent2=(34, 211, 238), ok=(74, 222, 128), warn=(252, 211, 77), err=(251, 113, 133)),
    "light": dict(bg=(247, 249, 252), panel=(231, 236, 244), fg=(24, 32, 44), dim=(100, 112, 128),
                  accent=(2, 106, 199), accent2=(109, 40, 217), ok=(4, 120, 87), warn=(180, 83, 9), err=(185, 28, 28)),
}

SEV_COLORS: dict[str, tuple[RGB, RGB]] = {  # severity -> (badge background, badge foreground)
    "critical": ((200, 30, 50), (255, 255, 255)),
    "high": ((234, 88, 12), (255, 255, 255)),
    "medium": ((234, 179, 8), (20, 20, 20)),
    "low": ((14, 165, 198), (255, 255, 255)),
    "info": ((100, 116, 139), (255, 255, 255)),
}

BANNER_WIDE = r"""
    _    ___   ____                      _ _          _____           _ _    _ _
   / \  |_ _| / ___|  ___  ___ _   _ _ __(_) |_ _   _  |_   _|__   ___ | | | _(_) |_
  / _ \  | |  \___ \ / _ \/ __| | | | '__| | __| | | |   | |/ _ \ / _ \| | |/ / | __|
 / ___ \ | |   ___) |  __/ (__| |_| | |  | | |_| |_| |   | | (_) | (_) | |   <| | |_
/_/   \_\___| |____/ \___|\___|\__,_|_|  |_|\__|\__, |   |_|\___/ \___/|_|_|\_\_|\__|
                                                 |___/""".strip("\n")

BANNER_SMALL = r"""
 ┌─┐ ┬  ┌─┐┌─┐┌─┐┌─┐┬ ┬┬─┐┬┌┬┐┬ ┬
 ├─┤ │  └─┐├┤ │  │ │ │├┬┘│ │ └┬┘
 ┴ ┴ ┴  └─┘└─┘└─┘└─┘└─┘┴└─┴ ┴  ┴ """.strip("\n")

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def visible_len(text: str) -> int:
    return len(_ANSI_RE.sub("", text))


def _to256(rgb: RGB) -> int:
    r, g, b = rgb
    return 16 + 36 * round(r / 255 * 5) + 6 * round(g / 255 * 5) + round(b / 255 * 5)


class UI:
    def __init__(self, theme: str = "cyber", fullbg: bool = True, ascii_only: bool = False) -> None:
        self.enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        self.truecolor = os.environ.get("TOOLKIT_COLOR", "").lower() != "256"
        encoding = (sys.stdout.encoding or "").lower()
        self.ascii = ascii_only or os.environ.get("TOOLKIT_ASCII") == "1" or "utf" not in encoding
        self.fullbg = fullbg and self.enabled
        self.theme_name = "cyber"
        self.t = THEMES["cyber"]
        self.set_theme(theme)

    # ------------------------------------------------------------ theme
    def set_theme(self, name: str) -> None:
        if name not in THEMES:
            raise InputError(f"Unknown theme '{name}'", code="E1004", hint="Choose: " + ", ".join(THEMES))
        self.theme_name = name
        self.t = THEMES[name]

    def _fg(self, rgb: RGB) -> str:
        return f"\033[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m" if self.truecolor else f"\033[38;5;{_to256(rgb)}m"

    def _bg(self, rgb: RGB) -> str:
        return f"\033[48;2;{rgb[0]};{rgb[1]};{rgb[2]}m" if self.truecolor else f"\033[48;5;{_to256(rgb)}m"

    @property
    def base(self) -> str:
        return (self._bg(self.t["bg"]) + self._fg(self.t["fg"])) if self.fullbg else ""

    @property
    def reset(self) -> str:
        return "\033[0m" + self.base

    def paint(self, text: str, role: str | None = None, *, fg: RGB | None = None, bg: RGB | None = None,
              bold: bool = False, dim: bool = False) -> str:
        if not self.enabled:
            return text
        codes = ""
        if bold:
            codes += "\033[1m"
        if dim:
            codes += "\033[2m"
        if role:
            codes += self._fg(self.t[role])
        if fg:
            codes += self._fg(fg)
        if bg:
            codes += self._bg(bg)
        return f"{codes}{text}{self.reset}"

    def apply_background(self) -> None:
        if self.fullbg:
            sys.stdout.write(self.base + "\033[2J\033[H")
            sys.stdout.flush()

    def restore(self) -> None:
        if self.enabled:
            sys.stdout.write("\033[0m\033[?25h")
            sys.stdout.flush()

    def clear(self) -> None:
        if self.enabled:
            sys.stdout.write(self.base + "\033[2J\033[H")
            sys.stdout.flush()

    def width(self) -> int:
        return max(40, min(shutil.get_terminal_size((90, 24)).columns, 110))

    # ------------------------------------------------------- primitives
    def _sym(self, fancy: str, plain: str) -> str:
        return plain if self.ascii else fancy

    def out(self, text: str = "") -> None:
        print(text)

    def line(self, char: str = "─", role: str = "dim") -> None:
        self.out(self.paint((char if not self.ascii else "-") * self.width(), role))

    def bar(self, text: str, role: str = "accent", filled: bool = True) -> None:
        """Full-width coloured header bar."""
        pad = max(0, self.width() - visible_len(text) - 2)
        body = f" {text}{' ' * pad} "
        if role == "panel":
            self.out(self.paint(body, fg=self.t["accent2"], bg=self.t["panel"], bold=True))
        elif filled:
            fg = self.t["bg"] if role in ("accent", "accent2", "ok", "warn", "err") else self.t["fg"]
            self.out(self.paint(body, fg=fg, bg=self.t[role], bold=True))
        else:
            self.out(self.paint(body, role, bold=True))

    def gradient(self, text: str, start: str = "accent", end: str = "accent2") -> str:
        if not self.enabled:
            return text
        a, b = self.t[start], self.t[end]
        n = max(1, len(text) - 1)
        out = []
        for i, ch in enumerate(text):
            rgb = tuple(int(a[k] + (b[k] - a[k]) * i / n) for k in range(3))
            out.append(self._fg(rgb) + ch)  # type: ignore[arg-type]
        return "".join(out) + self.reset

    def badge(self, severity: str) -> str:
        sev = severity.lower()
        bg, fg = SEV_COLORS.get(sev, SEV_COLORS["info"])
        return self.paint(f" {sev.upper():^8} ", fg=fg, bg=bg, bold=True)

    # ----------------------------------------------------------- blocks
    def banner(self, version: str, developer: str, api_live: bool) -> None:
        wide = self.width() >= 90
        art = BANNER_WIDE if wide else BANNER_SMALL
        for ln in art.splitlines():
            self.out(self.gradient(ln))
        self.out()
        self.out(self.paint(" AI Security Toolkit ", fg=self.t["bg"], bg=self.t["accent"], bold=True)
                 + self.paint(f" v{version} ", fg=self.t["bg"], bg=self.t["accent2"], bold=True)
                 + self.paint("  Defensive & AI-Security Analysis", "fg"))
        self.out(self.paint("  Developer ", "dim") + self.paint(developer, "ok", bold=True)
                 + self.paint("   Theme ", "dim") + self.paint(self.theme_name, "accent")
                 + self.paint("   AI ", "dim") + (self.paint("live", "ok") if api_live else self.paint("offline", "warn")))
        self.out(self.paint("  Scope: analysis & detection only. Use on systems you own or are authorised to assess.", "dim"))
        self.out()

    def menu(self, groups: list[tuple[str, list[tuple[str, str, str]]]]) -> None:
        compact = self.width() < 72
        w = self.width()
        for title, items in groups:
            self.bar(title.upper(), "panel", filled=False)
            for key, name, desc in items:
                k = self.paint(f"[{key:>2}]", "accent", bold=True)
                if compact or not desc:
                    self.out(f" {k} {name}")
                else:
                    gap = max(2, 34 - len(name))
                    room = w - 8 - len(name) - gap
                    d = desc if len(desc) <= room else desc[: max(0, room - 1)] + "…"
                    self.out(f" {k} {name}{' ' * gap}{self.paint(d, 'dim')}")
            self.out()

    def panel(self, title: str, rows: list[str], role: str = "accent") -> None:
        w = self.width()
        tl, tr, bl, br, h, v = ("╭", "╮", "╰", "╯", "─", "│") if not self.ascii else ("+", "+", "+", "+", "-", "|")
        head = f" {title} "
        self.out(self.paint(tl + h + head + h * (w - len(head) - 3) + tr, role))
        for row in rows:
            for part in (textwrap.wrap(row, w - 4) or [""]):
                self.out(self.paint(v, role) + " " + part + " " * (w - 4 - visible_len(part)) + " " + self.paint(v, role))
        self.out(self.paint(bl + h * (w - 2) + br, role))

    def kv(self, rows: list[tuple[str, str]]) -> None:
        width = max(len(k) for k, _ in rows)
        for k, v in rows:
            self.out("  " + self.paint(k.ljust(width), "dim") + "  " + v)

    # --------------------------------------------------------- messages
    def success(self, text: str) -> None:
        self.out(self.paint(self._sym("✔ ", "[ok] "), "ok", bold=True) + text)

    def info(self, text: str) -> None:
        self.out(self.paint(self._sym("ℹ ", "[i] "), "accent") + text)

    def warn(self, title: str, hint: str = "") -> None:
        self.out(self.paint(self._sym("▲ ", "[!] "), "warn", bold=True) + self.paint(title, "warn", bold=True))
        if hint:
            self.out("  " + self.paint(self._sym("└─ ", "`- "), "dim") + hint)

    def error(self, err: ToolkitError) -> None:
        mark = self.paint(self._sym("✖ ", "[x] "), "err", bold=True)
        tag = self.paint(f"{err.code}", fg=self.t["bg"], bg=self.t["err"], bold=True)
        self.out(f"{mark}{tag} {self.paint(err.title, 'err', bold=True)}")
        rows = []
        if err.detail:
            rows.append(("detail", err.detail))
        if err.hint:
            rows.append(("fix", err.hint))
        if err.ref:
            rows.append(("ref", err.ref))
        for i, (k, v) in enumerate(rows):
            branch = (self._sym("└─", "`-") if i == len(rows) - 1 else self._sym("├─", "|-"))
            self.out(f"   {self.paint(branch, 'dim')} {self.paint(k.ljust(6), 'dim')} {v}")
        self.out()

    # --------------------------------------------------------- findings
    def findings(self, module: str, findings: list, limit: int = 60) -> None:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        items = sorted(findings, key=lambda f: order.get(f.severity, 5))
        self.bar("Results · " + module, "accent2")
        if not items:
            self.out(self.paint("  No findings.", "dim"))
        w = self.width()
        for f in items[:limit]:
            self.out(f" {self.badge(f.severity)} {self.paint(f.title, bold=True)}")
            for part in textwrap.wrap(f.detail or "", w - 6)[:4]:
                self.out("          " + self.paint(part, "dim"))
            if getattr(f, "remediation", ""):
                for i, part in enumerate(textwrap.wrap(f.remediation, w - 16)[:3]):
                    lead = self.paint("fix ", "ok") if i == 0 else "    "
                    self.out("          " + lead + part)
        if len(items) > limit:
            self.out(self.paint(f"  … {len(items) - limit} more finding(s) are in the exported report", "dim"))
        self.out()
        self.summary_line(items)

    def summary_line(self, items: list) -> None:
        counts: dict[str, int] = {}
        for f in items:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        chips = " ".join(self.badge(s) + self.paint(f" {counts[s]}", bold=True)
                         for s in ("critical", "high", "medium", "low", "info") if counts.get(s))
        self.out(f"  {self.paint('Σ', 'accent', bold=True)} {len(items)} finding(s)   {chips}\n")

    def risk_bar(self, score: int, label: str) -> None:
        cells = 30
        filled = round(score / 100 * cells)
        role = "err" if score >= 70 else "warn" if score >= 40 else "ok"
        full, empty = ("█", "░") if not self.ascii else ("#", ".")
        self.out(f"  Risk  {self.paint(full * filled, role)}{self.paint(empty * (cells - filled), 'dim')}  "
                 f"{self.paint(f'{score}/100 {label}', role, bold=True)}")

    # ----------------------------------------------------------- input
    def _rl(self, text: str) -> str:
        return _ANSI_RE.sub(lambda m: "\001" + m.group(0) + "\002", text)

    def prompt(self, label: str, default: str = "", validator=None, *, allow_empty: bool = False,
               attempts: int = 3, secret: bool = False) -> str:
        """Ask for a value. Validation errors are shown professionally and the question repeats."""
        suffix = f" [{default}]" if default else ""
        for attempt in range(attempts):
            text = self.paint(self._sym("❯ ", "> "), "accent", bold=True) + self.paint(label, bold=True) + self.paint(suffix, "dim") + ": "
            try:
                if secret:
                    import getpass
                    raw = getpass.getpass(self._rl(text))
                else:
                    raw = input(self._rl(text))
            except (EOFError, KeyboardInterrupt):
                self.out()
                raise UserCancelled()
            value = raw.strip() or default
            if value.lower() in ("q", "quit", "back") and not secret:
                raise UserCancelled()
            if not value and allow_empty:
                return ""
            try:
                if not value:
                    raise InputError("A value is required", code="E1001", hint="Type a value, or q to go back.")
                return validator(value) if validator else value
            except ToolkitError as err:
                self.error(err)
        raise UserCancelled()

    def confirm(self, question: str, default: bool = False) -> bool:
        hint = "Y/n" if default else "y/N"
        try:
            raw = input(self._rl(self.paint(self._sym("? ", "? "), "warn", bold=True) + question + self.paint(f" ({hint}) ", "dim")))
        except (EOFError, KeyboardInterrupt):
            self.out()
            return False
        raw = raw.strip().lower()
        return default if not raw else raw in ("y", "yes")

    @contextmanager
    def spinner(self, label: str):
        if not self.enabled:
            yield
            return
        frames = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if not self.ascii else "|/-\\")
        stop = threading.Event()
        start = time.time()

        def spin() -> None:
            while not stop.is_set():
                sys.stdout.write(f"\r\033[2K{self.paint(next(frames), 'accent')} {self.paint(label, 'dim')} {self.paint(f'{time.time() - start:0.1f}s', 'dim')}")
                sys.stdout.flush()
                time.sleep(0.09)

        thread = threading.Thread(target=spin, daemon=True)
        thread.start()
        try:
            yield
        finally:
            stop.set()
            thread.join(timeout=1)
            sys.stdout.write("\r\033[2K")
            sys.stdout.flush()
