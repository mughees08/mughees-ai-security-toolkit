
"""
Report Generator
-------------------
Combines findings from any modules that have been run into a single
Markdown/HTML report on disk.

Developer: Muhammad Mughees Abbasi
"""

import json
from datetime import datetime
from pathlib import Path

from .base import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SEVERITY_COLOR = {
    "critical": "#ff4d4d",
    "high": "#ff9933",
    "medium": "#ffcc00",
    "low": "#66ccff",
    "info": "#999999",
}


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 5))


def generate_markdown(all_findings: dict[str, list[Finding]], out_path: str) -> str:
    lines = [
        "# AI Security Toolkit — Report",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        "Developer: Muhammad Mughees Abbasi",
        "",
    ]

    for module_name, findings in all_findings.items():
        if not findings:
            continue
        lines.append(f"## {module_name}")
        lines.append("")
        lines.append("| Severity | Title | Detail | Source |")
        lines.append("|---|---|---|---|")
        for f in _sorted_findings(findings):
            detail = f.detail.replace("|", "\\|")[:300]
            lines.append(f"| {f.severity.upper()} | {f.title} | {detail} | {f.source} |")
        lines.append("")

    content = "\n".join(lines)
    Path(out_path).write_text(content)
    return out_path


def generate_json(all_findings: dict[str, list[Finding]], out_path: str) -> str:
    data = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "developer": "Muhammad Mughees Abbasi",
        "modules": {
            name: [f.to_dict() for f in _sorted_findings(findings)]
            for name, findings in all_findings.items()
        },
    }
    Path(out_path).write_text(json.dumps(data, indent=2))
    return out_path


def generate_html(all_findings: dict[str, list[Finding]], out_path: str) -> str:
    rows = []
    for module_name, findings in all_findings.items():
        if not findings:
            continue
        rows.append(f"<h2>{module_name}</h2>")
        rows.append("<table><tr><th>Severity</th><th>Title</th><th>Detail</th><th>Source</th></tr>")
        for f in _sorted_findings(findings):
            color = SEVERITY_COLOR.get(f.severity, "#999")
            rows.append(
                f"<tr><td style='color:{color};font-weight:bold'>{f.severity.upper()}</td>"
                f"<td>{f.title}</td><td>{f.detail}</td><td>{f.source}</td></tr>"
            )
        rows.append("</table>")

    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>AI Security Toolkit Report</title>
<style>
body {{ font-family: -apple-system, Segoe UI, sans-serif; background:#0b0f14; color:#e6edf3; padding:24px; }}
h1 {{ color:#4fc3f7; }}
table {{ border-collapse: collapse; width:100%; margin-bottom:24px; }}
td, th {{ border:1px solid #30363d; padding:8px; text-align:left; font-size:14px; }}
th {{ background:#161b22; }}
</style></head>
<body>
<h1>AI Security Toolkit — Report</h1>
<p>Generated: {datetime.now().isoformat(timespec='seconds')}<br>Developer: Muhammad Mughees Abbasi</p>
{''.join(rows) if rows else '<p>No findings.</p>'}
</body></html>"""
    Path(out_path).write_text(html)
    return out_path
