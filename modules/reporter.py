"""
Report Generator
-------------------
Combines findings from every module into Markdown, HTML (interactive dashboard),
JSON or CSV. The HTML report is fully self-contained (no external assets).

Developer: Muhammad Mughees Abbasi
"""

import csv
import html
import json
from datetime import datetime
from pathlib import Path

from . import store, taxonomy
from .base import SEVERITIES
from .errors import BASE_DIR, FileError
from .session import Session

COLORS = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#06b6d4", "info": "#64748b"}
ORDER = {s: i for i, s in enumerate(SEVERITIES)}
FORMATS = {"md": "generate_markdown", "html": "generate_html", "json": "generate_json", "csv": "generate_csv"}


def _sorted(findings):
    return sorted(findings, key=lambda f: ORDER.get(f.severity, 5))


def _tags(f) -> list[str]:
    c = taxonomy.classify(f)
    return c["owasp"] + c["attack"]


def generate_markdown(session: Session, out_path: str) -> str:
    c = session.counts()
    lines = ["# AI Security Toolkit — Report", f"Generated: {datetime.now().isoformat(timespec='seconds')}",
             "Developer: Muhammad Mughees Abbasi", "",
             f"**Overall risk:** {session.label()} ({session.score()}/100)  ",
             "**Findings:** " + ", ".join(f"{k}: {v}" for k, v in c.items() if v), ""]
    if session.summary:
        lines += ["## Executive summary", "", session.summary.strip(), ""]
    for module, findings in session.results.items():
        active = [f for m, f in session.pairs(include_derived=True) if m == module]
        if not active:
            continue
        lines += [f"## {module}", "", "| Severity | Title | Detail | Fix | Tags |", "|---|---|---|---|---|"]
        for f in _sorted(active):
            cell = lambda s, n: str(s).replace("|", "\\|").replace("\n", " ")[:n]
            lines.append(f"| {f.severity.upper()} | {cell(f.title, 120)} | {cell(f.detail, 300)} | {cell(f.remediation, 200)} | {', '.join(_tags(f))} |")
        lines.append("")
    if session.suppressed_count():
        lines.append(f"_{session.suppressed_count()} finding(s) excluded by triage._")
    return _write(out_path, "\n".join(lines))


def generate_json(session: Session, out_path: str) -> str:
    data = {
        "tool": "AI Security Toolkit", "developer": "Muhammad Mughees Abbasi",
        "generated": datetime.now().isoformat(timespec="seconds"),
        "risk_score": session.score(), "risk_label": session.label(), "counts": session.counts(),
        "summary": session.summary, "suppressed": session.suppressed_count(),
        "modules": {m: [{**f.to_dict(), "tags": _tags(f)} for f in _sorted([x for mm, x in session.pairs(include_derived=True) if mm == m])] for m in session.results},
    }
    return _write(out_path, json.dumps(data, indent=2))


def generate_csv(session: Session, out_path: str) -> str:
    try:
        with open(out_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["module", "severity", "title", "detail", "source", "remediation", "tags", "timestamp"])
            for m, f in session.pairs(include_derived=True):
                w.writerow([m, f.severity, f.title, f.detail, f.source, f.remediation, " ".join(_tags(f)), f.timestamp])
    except OSError as exc:
        raise FileError("Could not write the report", code="E2002", detail=str(exc), hint="Check permissions / free space.") from None
    return out_path


def generate_html(session: Session, out_path: str) -> str:
    e = html.escape
    counts = session.counts()
    score, label = session.score(), session.label()
    circ = 2 * 3.14159 * 52
    dash = circ * score / 100
    ring = COLORS["critical"] if score >= 70 else COLORS["high"] if score >= 40 else COLORS["medium"] if score >= 15 else "#22c55e"
    chips = "".join(f"<button class='chip' data-sev='{s}' style='--c:{COLORS[s]}'>{s.upper()} <b>{counts[s]}</b></button>" for s in SEVERITIES)
    cards = []
    for module, f in session.pairs(include_derived=True):
        tags = "".join(f"<span class='tag'>{e(t)}</span>" for t in _tags(f))
        fix = f"<div class='fix'><b>Fix</b> {e(f.remediation)}</div>" if f.remediation else ""
        cards.append(f"<article class='card' data-sev='{f.severity}' data-mod='{e(module)}' style='--c:{COLORS[f.severity]}'>"
                     f"<header><span class='sev'>{f.severity.upper()}</span><h3>{e(f.title)}</h3></header>"
                     f"<p>{e(f.detail)}</p>{fix}<footer><span>{e(module)}</span>{tags}</footer></article>")
    cards.sort(key=lambda c: ORDER[c.split("data-sev='")[1].split("'")[0]])
    modules = "".join(f"<option>{e(m)}</option>" for m in session.results)
    summary = f"<section class='box'><h2>Executive summary</h2><pre>{e(session.summary.strip())}</pre></section>" if session.summary else ""
    hist = store.load_history()[-24:]
    spark = ""
    if len(hist) > 1:
        pts = " ".join(f"{i * 220 / (len(hist) - 1):.0f},{50 - h['risk'] * 0.46:.0f}" for i, h in enumerate(hist))
        spark = f"<section class='box'><h2>Risk trend</h2><svg viewBox='0 0 220 54' width='100%' height='70'><polyline fill='none' stroke='var(--accent)' stroke-width='2' points='{pts}'/></svg></section>"
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Security Toolkit Report</title><style>
:root{{--bg:#0b1020;--panel:#121a2e;--line:#22304f;--fg:#e2e8f0;--dim:#8b9bb8;--accent:#38bdf8;--accent2:#818cf8}}
@media (prefers-color-scheme:light){{:root.auto{{--bg:#f4f7fb;--panel:#fff;--line:#d8e0ee;--fg:#0f172a;--dim:#5b6b86}}}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(1200px 600px at 10% -10%,#1b2a55 0%,transparent 60%),var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}}
.wrap{{max-width:1000px;margin:0 auto;padding:20px 16px 60px}}
h1{{margin:0;font-size:26px;background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;color:transparent}}
.sub{{color:var(--dim);font-size:13px}}.top{{display:flex;gap:20px;align-items:center;flex-wrap:wrap;margin:18px 0}}
.gauge{{position:relative;width:120px;height:120px}}.gauge b{{position:absolute;inset:0;display:grid;place-items:center;font-size:26px}}
.chips{{display:flex;gap:8px;flex-wrap:wrap}}.chip{{background:var(--panel);color:var(--fg);border:1px solid var(--c);border-radius:999px;padding:6px 12px;cursor:pointer;font-size:12px}}
.chip.off{{opacity:.35}}.tools{{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0 18px}}
input,select{{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:9px 12px;font-size:14px}}input{{flex:1;min-width:180px}}
.box{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 16px;margin-bottom:16px}}.box h2{{margin:0 0 6px;font-size:15px;color:var(--accent)}}
pre{{white-space:pre-wrap;margin:0;font:13px/1.5 ui-monospace,Menlo,monospace}}
.card{{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:10px;padding:12px 14px;margin-bottom:10px}}
.card header{{display:flex;gap:10px;align-items:center}}.card h3{{margin:0;font-size:15px;word-break:break-word}}
.sev{{background:var(--c);color:#fff;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:700}}.card p{{margin:6px 0;color:var(--dim);word-break:break-word;font-size:13px}}
.fix{{font-size:13px;color:#86efac}}.fix b{{color:#4ade80}}footer{{display:flex;gap:6px;flex-wrap:wrap;font-size:11px;color:var(--dim);margin-top:6px}}
.tag{{border:1px solid var(--line);border-radius:6px;padding:0 6px}}.hide{{display:none}}@media print{{body{{background:#fff;color:#000}}.tools{{display:none}}}}
</style></head><body class="auto"><div class="wrap">
<h1>AI Security Toolkit — Report</h1><div class="sub">Generated {e(datetime.now().isoformat(timespec='seconds'))} · Developer: Muhammad Mughees Abbasi{f" · {session.suppressed_count()} triaged" if session.suppressed_count() else ""}</div>
<div class="top"><div class="gauge"><svg viewBox="0 0 120 120" width="120" height="120"><circle cx="60" cy="60" r="52" fill="none" stroke="var(--line)" stroke-width="10"/>
<circle cx="60" cy="60" r="52" fill="none" stroke="{ring}" stroke-width="10" stroke-linecap="round" stroke-dasharray="{dash:.1f} {circ:.1f}" transform="rotate(-90 60 60)"/></svg><b>{score}</b></div>
<div><div style="font-size:20px;font-weight:700;color:{ring}">{label} risk</div><div class="sub">score {score}/100</div><div class="chips" style="margin-top:8px">{chips}</div></div></div>
{summary}{spark}
<div class="tools"><input id="q" placeholder="Search findings…"><select id="m"><option value="">All modules</option>{modules}</select></div>
<div id="list">{''.join(cards) if cards else "<p class='sub'>No findings.</p>"}</div></div>
<script>
const off=new Set();const q=document.getElementById('q'),m=document.getElementById('m');
function apply(){{const t=q.value.toLowerCase();document.querySelectorAll('.card').forEach(c=>{{const ok=!off.has(c.dataset.sev)&&(!m.value||c.dataset.mod===m.value)&&(!t||c.textContent.toLowerCase().includes(t));c.classList.toggle('hide',!ok)}})}}
document.querySelectorAll('.chip').forEach(b=>b.onclick=()=>{{const s=b.dataset.sev;off.has(s)?off.delete(s):off.add(s);b.classList.toggle('off');apply()}});
q.oninput=apply;m.onchange=apply;
</script></body></html>"""
    return _write(out_path, page)


def _write(path: str, content: str) -> str:
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content, encoding="utf-8")
    except OSError as exc:
        raise FileError("Could not write the report", code="E2002", detail=str(exc), hint="Check permissions and free disk space.") from None
    return path


def write_report(session: Session, fmt: str, out_dir: Path | None = None) -> str:
    out_dir = out_dir or BASE_DIR / "reports"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return globals()[FORMATS[fmt]](session, str(out_dir / f"report_{stamp}.{fmt}"))
