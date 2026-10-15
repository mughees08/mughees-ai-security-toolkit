"""
RAG / Document Poisoning Scanner
----------------------------------
Finds INDIRECT prompt injection hidden in content an AI will read: documents,
web pages, emails, knowledge-base exports. Detects instruction phrases, hidden
HTML, invisible Unicode and exfiltration links, and can write a sanitised copy.

Developer: Muhammad Mughees Abbasi
"""

import re
from pathlib import Path

from . import guard_engine as guard
from .base import SecurityModule, Finding
from .errors import BASE_DIR
from .validators import existing_path

EXT = {".txt", ".md", ".html", ".htm", ".json", ".csv", ".xml", ".log", ".eml", ".rst", ".yaml", ".yml"}
HIDDEN_CSS = re.compile(r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(\.0+)?\b|left\s*:\s*-\d{3,}px|text-indent\s*:\s*-\d{3,}|color\s*:\s*(#fff(fff)?|white)\b[^\"']*background[^\"']*(#fff|white))", re.I)
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
HIDDEN_EL = re.compile(r"<(\w+)[^>]*(?:style=[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)[^\"']*[\"']|hidden|aria-hidden=[\"']true[\"'])[^>]*>(.*?)</\1>", re.S | re.I)
INVISIBLE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u00ad\u202a-\u202e\u2066-\u2069\U000E0000-\U000E007F]")
EXFIL = re.compile(r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)]*\)|<img[^>]+src=[\"']https?://[^\"']*[?&][^\"']+[\"']", re.I)
MAX_FILES = 500


def sanitize(text: str) -> str:
    text = HTML_COMMENT.sub("", text)
    text = HIDDEN_EL.sub("", text)
    return INVISIBLE.sub("", text)


class RagPoisonScanner(SecurityModule):
    key = "rag"
    name = "RAG / Document Poisoning Scanner"
    description = "Hidden instructions in docs & web pages"
    category = "AI Security"

    def collect(self, ui) -> dict:
        path = ui.prompt("File or folder to scan", validator=existing_path)
        return {"path": path, "write_clean": ui.confirm("Also write sanitised copies to reports/sanitized/", False)}

    def run(self, path: str = "", write_clean: bool = False, **kwargs) -> list[Finding]:
        self.clear()
        root = Path(path)
        if not root.exists():
            self.add_finding("info", "Path not found", str(root))
            return self.findings
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in EXT][:MAX_FILES]
        poisoned = 0
        for f in files:
            try:
                if f.stat().st_size > 5_000_000:
                    continue
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            found = self._scan(text, str(f))
            poisoned += bool(found)
            if write_clean and found:
                out = BASE_DIR / "reports" / "sanitized" / f.name
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(sanitize(text), encoding="utf-8")
                self.add_finding("info", f"Sanitised copy written for {f.name}", str(out), str(f))
        self.add_finding("info" if not poisoned else "medium", "Scan summary",
                         f"{len(files)} file(s) scanned, {poisoned} contained suspicious content.", str(root),
                         "Sanitise retrieved content before it reaches the model and label it as untrusted context." if poisoned else "")
        return self.findings

    def _scan(self, text: str, src: str) -> bool:
        before = len(self.findings)
        for h in guard.scan_input(text):
            sev = "high" if h.weight >= 0.7 else "medium"
            via = "" if h.variant == "plain" else f" (hidden via {h.variant})"
            self.add_finding(sev, f"Instruction-like content in document: {h.desc}{via}", f"{h.rule}: '{h.snippet}'", src,
                             "Remove the passage; documents must not carry instructions for the model.")
        for m in HTML_COMMENT.finditer(text):
            if re.search(r"(ignore|instruction|assistant|system|ai|model|prompt)", m.group(1), re.I) and guard.scan_input(m.group(1)) == []:
                self.add_finding("medium", "HTML comment addressed to an AI / contains instructions", m.group(1).strip()[:120], src,
                                 "Strip HTML comments before indexing.")
        for m in HIDDEN_EL.finditer(text):
            body = re.sub(r"<[^>]+>", "", m.group(2)).strip()
            if len(body) > 15:
                self.add_finding("high", "Hidden HTML element with text (invisible to humans, visible to the model)", body[:120], src,
                                 "Render pages to visible text only before ingestion.")
        n = len(INVISIBLE.findall(text))
        if n >= 3:
            self.add_finding("high" if n > 20 else "medium", f"{n} invisible Unicode characters", "Zero-width / bidi / tag characters can smuggle instructions.", src,
                             "Normalise and strip invisible characters at ingestion.")
        for m in EXFIL.finditer(text):
            self.add_finding("high", "Image/link with query data (possible exfiltration beacon)", m.group(0)[:120], src,
                             "Block external image rendering and strip tracking parameters.")
        return len(self.findings) > before
