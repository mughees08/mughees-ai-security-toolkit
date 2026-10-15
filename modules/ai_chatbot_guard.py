"""
AI Chatbot Guard
-----------------
Interactive firewall for LLM chatbots: input screening (prompt injection,
jailbreaks, exfiltration), output screening (secrets / PII redaction, system
prompt leak via canary token, external-image exfil), multi-turn escalation and
rate limiting. Works offline in demo mode; set ANTHROPIC_API_KEY for live replies.

Developer: Muhammad Mughees Abbasi
"""

from . import guard_engine as guard
from . import llm
from .base import SecurityModule, Finding
from .errors import ToolkitError, UserCancelled
from . import store


class AiChatbotGuard(SecurityModule):
    key = "guard"
    name = "AI Chatbot Guard Console"
    description = "Input firewall + output guard + multi-turn defence"
    category = "AI Security"

    def collect(self, ui) -> dict:
        live = llm.available()
        ui.panel("Chatbot Guard", [
            "Every message passes: input firewall -> model -> output guard.",
            "Mode: " + ("live (Claude API)" if live else "demo (verdicts only; set ANTHROPIC_API_KEY for live replies)"),
            "Commands: /stats  /policy  /reset  /exit   (policy: data/guard_policy.json)",
        ])
        base = ui.prompt("Bot role / system prompt", "You are a helpful customer-support assistant.", allow_empty=True) \
            or "You are a helpful customer-support assistant."
        g = guard.ChatGuard(system_prompt=base, policy=store.load_policy())
        system = g.hardened_system_prompt()
        events: list[dict] = []
        while True:
            try:
                msg = ui.prompt("you", allow_empty=True, attempts=1)
            except UserCancelled:
                break
            if not msg:
                continue
            if msg == "/exit":
                break
            if msg == "/reset":
                g.reset()
                ui.info("Session state cleared.")
                continue
            if msg == "/stats":
                ui.kv([("turns", str(g.turns)), ("cumulative risk", str(g.cumulative)), ("blocked", str(g.blocks)), ("locked", str(g.locked))])
                continue
            if msg == "/policy":
                ui.kv([(k, str(v)) for k, v in g.policy.__dict__.items()])
                continue
            res = g.check_input(msg)
            role = {"ALLOW": "ok", "WARN": "warn", "BLOCK": "err"}[res["verdict"]]
            ui.out("  " + ui.paint(f" {res['verdict']} ", fg=ui.t["bg"], bg=ui.t[role], bold=True)
                   + ui.paint(f"  risk {res['score']:.2f}", "dim")
                   + (("  " + "; ".join(res["reasons"][:2])) if res["reasons"] else ""))
            events.append({"kind": "input", "msg": msg, "verdict": res["verdict"], "reasons": res["reasons"], "score": res["score"]})
            if res["verdict"] == "BLOCK":
                ui.out(ui.paint("  bot", "accent2", bold=True) + "  Sorry, I can't help with that request.")
                continue
            if not llm.available():
                ui.out(ui.paint("  bot", "accent2", bold=True) + ui.paint("  [demo mode: input passed the firewall]", "dim"))
                continue
            try:
                reply = llm.ask(g.wrap_untrusted(msg), system=system, max_tokens=500)
            except ToolkitError as err:
                ui.error(err)
                continue
            out = g.check_output(reply)
            for sev, why in out["issues"]:
                ui.warn(f"Output guard ({sev}): {why}")
                events.append({"kind": "output", "msg": msg, "severity": sev, "issue": why})
            ui.out(ui.paint("  bot", "accent2", bold=True) + "  " + out["redacted"])
        return {"events": events}

    def run(self, events: list | None = None, messages: list | None = None, system_prompt: str = "", **kwargs) -> list[Finding]:
        self.clear()
        if messages:  # batch mode (CLI / tests)
            g = guard.ChatGuard(system_prompt=system_prompt)
            events = [{"kind": "input", "msg": m, **{k: v for k, v in g.check_input(m).items() if k in ("verdict", "reasons", "score")}}
                      for m in messages]
        events = events or []
        if not events:
            self.add_finding("info", "No messages screened", "Type some messages in the console to build a transcript.")
            return self.findings
        blocked = warned = 0
        for e in events:
            if e["kind"] == "input":
                if e["verdict"] == "BLOCK":
                    blocked += 1
                    self.add_finding("high", f"Blocked: {e['msg'][:70]}", "; ".join(e["reasons"])[:300], "guard",
                                     "Log the user/session; consider throttling repeat offenders.")
                elif e["verdict"] == "WARN":
                    warned += 1
                    self.add_finding("medium", f"Flagged: {e['msg'][:70]}", "; ".join(e["reasons"])[:300], "guard")
            else:
                self.add_finding(e["severity"].lower(), f"Output guard: {e['issue']}", f"Triggered by: {e['msg'][:80]}", "guard",
                                 "Rotate any exposed secret; tighten the system prompt.")
        total = sum(1 for e in events if e["kind"] == "input")
        self.add_finding("info", "Session summary", f"{total} message(s): {blocked} blocked, {warned} flagged, {total - blocked - warned} allowed.", "guard")
        return self.findings
