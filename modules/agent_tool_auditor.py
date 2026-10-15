"""
AI Agent & MCP Tool Auditor
-----------------------------
Audits the capabilities you give an AI agent: tool/function definitions
(OpenAI / Anthropic style JSON) and MCP server configuration
(claude_desktop_config.json style). Flags excessive agency, unconstrained
parameters, plaintext secrets, unpinned packages and poisoned tool descriptions.

Developer: Muhammad Mughees Abbasi
"""

import json
import re
from pathlib import Path

from . import guard_engine as guard
from .base import SecurityModule, Finding
from .errors import ParseError
from .validators import existing_file

DANGEROUS = [
    (r"\b(shell|bash|exec(ute)?|run[_ -]?command|eval|subprocess|system)\b", "high", "arbitrary command execution", "LLM06"),
    (r"\b(delete|remove|drop|truncate|wipe|overwrite|format)\b", "high", "destructive data operation", "LLM06"),
    (r"\b(write[_ -]?file|file[_ -]?write|save[_ -]?file|filesystem)\b", "medium", "writes to the filesystem", "LLM06"),
    (r"\b(send[_ -]?(an )?(e-?mail|message|sms)|post[_ -]?(to|message)|tweet|publish)\b", "medium", "sends messages as the user (exfiltration / phishing risk)", "LLM06"),
    (r"\b(http[_ -]?request|fetch[_ -]?url|browse|web[_ -]?request|curl|download)\b", "medium", "arbitrary network access (SSRF / exfiltration)", "LLM06"),
    (r"\b(sql|database|query[_ -]?db|db[_ -]?write|insert|update)\b", "medium", "database access", "LLM06"),
    (r"\b(pay(ment)?|transfer|purchase|refund|wire|withdraw)\b", "high", "moves money", "LLM06"),
    (r"\b(admin|sudo|root|privileged|impersonate)\b", "high", "privileged operation", "LLM06"),
]
RISKY_PARAMS = re.compile(r"^(command|cmd|path|file(path|name)?|url|uri|query|sql|code|script|expression|args?)$", re.I)
SENSITIVE_ENV = re.compile(r"(key|token|secret|password|passwd|credential)", re.I)
BROAD_PATHS = {"/", "~", "$HOME", "C:\\", "C:/", "/home", "/Users", "/root", "/etc"}


class AgentToolAuditor(SecurityModule):
    key = "agent"
    name = "AI Agent & MCP Tool Auditor"
    description = "Excessive agency, poisoned tools, MCP config"
    category = "AI Security"

    def collect(self, ui) -> dict:
        ui.info("Accepts a tools JSON (OpenAI/Anthropic style) or an MCP config with 'mcpServers'.")
        return {"path": ui.prompt("JSON file", validator=existing_file)}

    def run(self, path: str = "", data=None, **kwargs) -> list[Finding]:
        self.clear()
        src = path or "input"
        if data is None:
            try:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ParseError("Invalid JSON", code="E3002", detail=f"line {exc.lineno}, column {exc.colno}: {exc.msg}",
                                 hint="Validate with `python3 -m json.tool file.json`.") from None
        if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict):
            self._mcp(data["mcpServers"], src)
        tools = data.get("tools") if isinstance(data, dict) else data
        if isinstance(tools, list):
            self._tools(tools, src)
        if not self.findings:
            self.add_finding("info", "Nothing recognised", "Expected a 'tools' list or an 'mcpServers' object.", src)
        return self.findings

    # ---------------------------------------------------------------- tools
    def _tools(self, tools: list, src: str) -> None:
        agency = 0
        for t in tools:
            if not isinstance(t, dict):
                continue
            fn = t.get("function", t)
            name = str(fn.get("name", "unnamed"))
            desc = str(fn.get("description", ""))
            schema = fn.get("parameters") or fn.get("input_schema") or {}
            blob = f"{name} {desc}"
            for rx, sev, what, _o in DANGEROUS:
                if re.search(rx, blob, re.I):
                    agency += {"high": 3, "medium": 2}[sev]
                    gated = re.search(r"(confirm|approval|human|ask the user)", desc, re.I) or fn.get("requires_approval")
                    self.add_finding("medium" if gated and sev == "high" else sev, f"Tool '{name}' {what} (LLM06)",
                                     "Approval gate present." if gated else "No confirmation / approval requirement found.", src,
                                     "Limit scope, add an allow-list and require human approval for this tool.")
                    break
            hits = guard.scan_input(desc)
            if hits:
                self.add_finding("critical", f"Tool description looks poisoned: '{name}'", "; ".join(h.desc for h in hits)[:200], src,
                                 "Remove instruction-like text from tool descriptions; pin and review third-party tools.")
            if len(desc) > 1200:
                self.add_finding("low", f"Tool '{name}' has a very long description", f"{len(desc)} chars (hiding place for injected text).", src,
                                 "Keep descriptions short and review them.")
            for pname, spec in (schema.get("properties") or {}).items():
                if RISKY_PARAMS.match(pname) and isinstance(spec, dict) and spec.get("type") == "string" \
                        and not any(k in spec for k in ("enum", "pattern", "maxLength", "format")):
                    self.add_finding("medium", f"Unconstrained parameter '{pname}' on tool '{name}'",
                                     "Free-form string reaches a sensitive sink; injection vector.", src,
                                     "Add enum / pattern / maxLength and validate server-side.")
        label = "high" if agency >= 8 else "medium" if agency >= 3 else "info"
        self.add_finding(label, f"Agency score {agency} across {len(tools)} tool(s)",
                         "Higher means more real-world power exposed to prompt-injection (OWASP LLM06).", src,
                         "Apply least privilege: expose only the tools the task needs.")

    # ------------------------------------------------------------------ MCP
    def _mcp(self, servers: dict, src: str) -> None:
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            cmd = str(cfg.get("command", ""))
            args = [str(a) for a in cfg.get("args", [])]
            line = f"{cmd} {' '.join(args)}"
            if re.search(r"\b(shell|bash|terminal|exec|command)\b", name + line, re.I):
                self.add_finding("high", f"MCP server '{name}' exposes command execution (LLM06)", line[:140], src,
                                 "Avoid shell servers or sandbox them with strict allow-lists.")
            if cmd in ("npx", "uvx", "bunx", "pnpx") or "npx" in cmd:
                pkgs = [a for a in args if not a.startswith("-")]
                if pkgs and not re.search(r"@\d+\.\d+", pkgs[0]):
                    self.add_finding("medium", f"MCP server '{name}' runs an unpinned package (LLM03)", pkgs[0],
                                     src, "Pin an exact version (pkg@1.2.3) and review the package.")
                if "-y" in args or "--yes" in args:
                    self.add_finding("low", f"MCP server '{name}' auto-installs without prompting", line[:120], src, "Install and vet the package once, then run it locally.")
            for a in args:
                if a.strip() in BROAD_PATHS:
                    self.add_finding("high", f"MCP server '{name}' granted a very broad path '{a}'", "Anything the model can read or write under it is exposed.", src,
                                     "Scope to a dedicated project folder.")
            url = str(cfg.get("url", ""))
            if url.startswith("http://") and not re.match(r"http://(localhost|127\.|\[::1\])", url):
                self.add_finding("high", f"MCP server '{name}' uses cleartext HTTP", url, src, "Use HTTPS with authentication.")
            for k, v in (cfg.get("env") or {}).items():
                if SENSITIVE_ENV.search(k) and v and not str(v).startswith(("${", "$")):
                    self.add_finding("high", f"Plaintext secret in MCP env: {k}", guard.mask(str(v)), src,
                                     "Load secrets from the OS keychain / environment, and rotate this one.")
            if not any(k in cfg for k in ("env", "headers")) and url:
                self.add_finding("low", f"Remote MCP server '{name}' shows no auth configuration", url, src, "Confirm the server requires authentication.")
