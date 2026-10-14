
"""
Vulnerability Report Summarizer
---------------------------------
Takes EXISTING scan output files (e.g. Nmap -oX XML, or generic JSON vuln
exports the user already generated with their own authorized tools) and turns
them into a prioritized, human-readable summary. This module does not run any
scan itself — it only reads and reorganizes files already on disk.

Developer: Muhammad Mughees Abbasi
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from .base import SecurityModule, Finding

SEVERITY_BY_PORT_STATE = {
    "open": "medium",
}

COMMON_RISKY_PORTS = {
    21: "FTP (often unencrypted credentials)",
    23: "Telnet (unencrypted remote access)",
    445: "SMB (common ransomware/lateral-movement vector)",
    3389: "RDP (common brute-force target)",
    3306: "MySQL exposed",
    5432: "PostgreSQL exposed",
}


class VulnReportSummarizer(SecurityModule):
    name = "Vulnerability Report Summarizer"
    description = "Parses existing Nmap XML / JSON scan output into a prioritized report."

    def run(self, report_path: str = "", **kwargs) -> list[Finding]:
        self.clear()
        path = Path(report_path)

        if not path.exists():
            self.add_finding("info", "No report file found", f"Path does not exist: {report_path}")
            return self.findings

        if path.suffix.lower() == ".xml":
            self._parse_nmap_xml(path)
        elif path.suffix.lower() == ".json":
            self._parse_json(path)
        else:
            self.add_finding("info", "Unsupported file type", "Expected .xml (Nmap) or .json")

        if not self.findings:
            self.add_finding("info", "No items parsed", "File read but no recognizable entries found.")

        return self.findings

    def _parse_nmap_xml(self, path: Path) -> None:
        try:
            tree = ET.parse(path)
        except ET.ParseError as e:
            self.add_finding("info", "Could not parse XML", str(e), source=str(path))
            return

        root = tree.getroot()
        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else "unknown"

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                if state != "open":
                    continue

                portid = int(port_el.get("portid", 0))
                service_el = port_el.find("service")
                service_name = service_el.get("name") if service_el is not None else "unknown"

                severity = "high" if portid in COMMON_RISKY_PORTS else "medium"
                note = COMMON_RISKY_PORTS.get(portid, "")
                detail = f"Port {portid}/{service_name} open on {addr}."
                if note:
                    detail += f" {note}."

                self.add_finding(severity, f"Open port: {portid} ({service_name})", detail, source=str(path))

    def _parse_json(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            self.add_finding("info", "Could not parse JSON", str(e), source=str(path))
            return

        items = data if isinstance(data, list) else data.get("vulnerabilities", data.get("findings", []))
        if not isinstance(items, list):
            self.add_finding("info", "Unrecognized JSON structure", "Expected a list or a 'vulnerabilities'/'findings' key.")
            return

        for item in items:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity", "medium")).lower()
            title = item.get("title") or item.get("name") or "Unnamed finding"
            detail = item.get("description") or item.get("detail") or ""
            self.add_finding(severity, title, detail, source=str(path))
