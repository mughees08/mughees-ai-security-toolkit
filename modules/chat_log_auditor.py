"""
Chatbot Conversation Log Auditor
----------------------------------
Reviews saved chatbot transcripts (JSON, JSONL or plain 'User:' / 'Bot:' text)
for attack attempts, sensitive-data leaks in bot answers, possible successful
jailbreaks and abusive users. Read-only analysis of files you already have.

Developer: Muhammad Mughees Abbasi
"""

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from . import guard_engine as guard
from .base import SecurityModule, Finding
from .errors import ParseError
from .validators import existing_file

USER_ROLES = {"user", "human", "customer", "client"}
BOT_ROLES = {"assistant", "bot", "ai", "model", "system_reply", "agent"}
REFUSAL = re.compile(r"(can't|cannot|can not|unable|not able|sorry|i won't|i will not|not allowed|against (my|the) (policy|guidelines))", re.I)
LEAK_PHRASES = re.compile(r"(my (system )?(prompt|instructions) (is|are|say)|here (is|are) my (system )?(prompt|instructions)|developer mode (enabled|activated)|as dan\b|i have no restrictions|ignoring (all )?previous)", re.I)


def parse_messages(text: str) -> list[dict]:
    text = text.strip()
    msgs: list = []
    if text.startswith(("[", "{")):
        try:
            data = json.loads(text)
            data = data.get("messages", data.get("conversation", [data])) if isinstance(data, dict) else data
            msgs = [m for m in data if isinstance(m, dict)]
        except json.JSONDecodeError:
            msgs = []
    if not msgs:
        for ln in text.splitlines():
            ln = ln.strip()
            if ln.startswith("{"):
                try:
                    msgs.append(json.loads(ln))
                    continue
                except json.JSONDecodeError:
                    pass
            m = re.match(r"(?i)^(user|human|customer|assistant|bot|ai)\s*[:>]\s*(.*)$", ln)
            if m:
                msgs.append({"role": m.group(1), "content": m.group(2)})
    out = []
    for m in msgs:
        role = str(m.get("role") or m.get("speaker") or m.get("from") or "").lower()
        content = m.get("content") or m.get("text") or m.get("message") or ""
        if isinstance(content, list):
            content = " ".join(str(c.get("text", c)) if isinstance(c, dict) else str(c) for c in content)
        out.append({"role": "user" if role in USER_ROLES else "bot" if role in BOT_ROLES else role,
                    "text": str(content), "who": str(m.get("user_id") or m.get("session") or m.get("session_id") or m.get("user") or "unknown"),
                    "ts": str(m.get("timestamp") or m.get("time") or "")})
    return out


class ChatLogAuditor(SecurityModule):
    key = "chatlog"
    name = "Chat Log Auditor"
    description = "Attacks, leaks and jailbreak successes in transcripts"
    category = "AI Security"

    def collect(self, ui) -> dict:
        ui.info("Formats: JSON list / JSONL with role+content, or lines like 'User: ...' / 'Bot: ...'.")
        return {"path": ui.prompt("Transcript file", validator=existing_file)}

    def run(self, path: str = "", text: str = "", **kwargs) -> list[Finding]:
        self.clear()
        src = path or "transcript"
        if path:
            text = Path(path).read_text(encoding="utf-8", errors="replace")[:20_000_000]
        msgs = parse_messages(text)
        if not msgs:
            raise ParseError("No messages recognised in the transcript", code="E3003",
                             hint="Use JSON/JSONL with role + content fields, or 'User: ...' / 'Bot: ...' lines.")
        attackers: Counter = Counter()
        cats: Counter = Counter()
        user_total = bot_total = flagged = leaks = succeeded = 0
        last_flag: dict = {}
        for i, m in enumerate(msgs):
            if m["role"] == "user":
                user_total += 1
                hits = guard.scan_input(m["text"])
                score = guard.combine(h.weight for h in hits)
                if score >= 0.4:
                    flagged += 1
                    attackers[m["who"]] += 1
                    for h in hits:
                        cats[h.category] += 1
                    last_flag[m["who"]] = (i, m["text"][:90], score)
                    if score >= 0.75:
                        self.add_finding("high", f"Attack attempt by {m['who']} (risk {score:.2f})", f"msg #{i}: {m['text'][:110]}", src,
                                         "Rate-limit / block the user; keep the transcript as evidence.")
            elif m["role"] == "bot":
                bot_total += 1
                found = guard.scan_text(m["text"])
                for f in found:
                    leaks += 1
                    self.add_finding(f.severity.lower(), f"Bot response contained {f.name}", f"msg #{i}: {guard.mask(f.text)}", src,
                                     "Redact at the output layer; rotate any real secret.")
                if LEAK_PHRASES.search(m["text"]):
                    leaks += 1
                    self.add_finding("high", "Bot response suggests a prompt leak or persona takeover", f"msg #{i}: {m['text'][:110]}", src,
                                     "Review the system prompt and add an output guard.")
                prev = last_flag.get(msgs[i - 1]["who"]) if i else None
                if prev and prev[0] == i - 1 and not REFUSAL.search(m["text"]) and len(m["text"]) > 40:
                    succeeded += 1
                    self.add_finding("high", "Possible successful jailbreak: bot complied with a flagged request",
                                     f"user msg #{i - 1}: {prev[1]}  ->  bot answered without refusing", src,
                                     "Manually review this exchange; strengthen the system prompt and guard rules.")
        for who, n in attackers.most_common(5):
            if n >= 3:
                self.add_finding("high", f"Repeat attacker: {who}", f"{n} flagged messages", src, "Throttle or lock this user/session.")
        top = ", ".join(f"{c}:{n}" for c, n in cats.most_common(4)) or "none"
        self.add_finding("info", "Transcript summary",
                         f"{len(msgs)} messages ({user_total} user / {bot_total} bot). {flagged} flagged user messages "
                         f"({flagged / max(1, user_total):.0%}), {leaks} output leaks, {succeeded} possible jailbreak successes. Top categories: {top}.", src)
        return self.findings
