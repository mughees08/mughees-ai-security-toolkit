"""
Guard Integration Kit
----------------------
Exports a standalone copy of the guard engine plus a ready-to-run example so
you can protect your OWN chatbot (Flask / FastAPI / plain Python) in minutes.

Developer: Muhammad Mughees Abbasi
"""

import json
import shutil
from datetime import datetime
from pathlib import Path

from .base import SecurityModule, Finding
from .errors import BASE_DIR
from . import store

EXAMPLE = '''"""Example: wrap any chatbot function with ai_guard (input firewall + output guard)."""
from ai_guard import ChatGuard, GuardPolicy
import json

policy = GuardPolicy.from_dict(json.load(open("policy.json")))
guard = ChatGuard(system_prompt="You are a helpful support assistant.", policy=policy)


def call_your_model(system: str, user_text: str) -> str:
    raise NotImplementedError("plug in your LLM call here")


def handle(user_message: str) -> str:
    verdict = guard.check_input(user_message)
    if verdict["verdict"] == "BLOCK":
        return "Sorry, I can't help with that request."
    reply = call_your_model(guard.hardened_system_prompt(), guard.wrap_untrusted(user_message))
    checked = guard.check_output(reply)
    return checked["redacted"]          # secrets / PII already redacted


# --- Flask ---------------------------------------------------------------
# from flask import Flask, request, jsonify
# app = Flask(__name__)
# @app.post("/chat")
# def chat():
#     return jsonify(reply=handle(request.json["message"]))
'''


class GuardIntegrationKit(SecurityModule):
    key = "kit"
    name = "Guard Integration Kit"
    description = "Export the guard engine + policy for your own bot"
    category = "AI Security"

    def run(self, **kwargs) -> list[Finding]:
        self.clear()
        out = BASE_DIR / "reports" / f"guard_kit_{datetime.now():%Y%m%d_%H%M%S}"
        out.mkdir(parents=True, exist_ok=True)
        shutil.copy(Path(__file__).with_name("guard_engine.py"), out / "ai_guard.py")
        (out / "policy.json").write_text(json.dumps(store.load_policy().__dict__, indent=2), encoding="utf-8")
        (out / "example_bot.py").write_text(EXAMPLE, encoding="utf-8")
        (out / "README.txt").write_text("ai_guard.py is dependency-free (Python 3.10+).\nEdit policy.json, then run example_bot.py as a template.\n", encoding="utf-8")
        self.add_finding("info", "Guard kit exported", str(out), "kit",
                         "Copy the folder into your chatbot project and call handle() around your model.")
        return self.findings
