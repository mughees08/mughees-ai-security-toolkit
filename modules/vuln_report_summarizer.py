"""
Vulnerability Report Summarizer
---------------------------------
Takes EXISTING scan output files (Nmap -oX XML, or generic JSON vuln exports
the user already generated with their own authorized tools) and turns them into
a prioritized, human-readable summary. This module does not run any scan itself.

Developer: Muhammad Mughees Abbasi
"""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .base import SecurityModule, Finding
from .errors import BASE_DIR, ParseError
from .validators import existing_file

SAMPLE = BASE_DIR / "data" / "samples" / "nmap_sample.xml"
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}")

COMMON_RISKY_PORTS = {
    21: ("FTP", "medium", "cleartext credentials", "Replace with SFTP/FTPS or restrict by firewall."),
    23: ("Telnet", "high", "cleartext remote shell", "Disable Telnet; use SSH."),
    135: ("MS-RPC", "medium", "Windows RPC exposed", "Firewall RPC from untrusted networks."),
    139: ("NetBIOS", "medium", "legacy file sharing", "Disable NetBIOS over TCP/IP."),
    161: ("SNMP", "medium", "default community strings common", "Use SNMPv3 and restrict sources."),
    445: ("SMB", "high", "ransomware / lateral movement vector", "Block SMB at the perimeter; patch; disable SMBv1."),
    1433: ("MSSQL", "medium", "database exposed", "Bind to localhost / VPN only."),
    3306: ("MySQL", "medium", "database exposed", "Bind to localhost / VPN only."),
    3389: ("RDP", "high", "common brute-force target", "Put RDP behind a VPN / gateway with MFA."),
    5432: ("PostgreSQL", "medium", "database exposed", "Bind to localhost / VPN only."),
    5900: ("VNC", "high", "weak authentication common", "Tunnel over SSH/VPN; enforce strong passwords."),
    6379: ("Redis", "high", "often unauthenticated", "Enable AUTH, bind to localhost, firewall the port."),
    9200: ("Elasticsearch", "high", "often unauthenticated", "Enable security features; never expose publicly."),
    11211: ("Memcached", "high", "data exposure / amplification", "Bind to localhost; disable UDP."),
    27017: ("MongoDB", "high", "often unauthenticated", "Enable auth and bind to private interfaces."),
}


class VulnReportSummarizer(SecurityModule):
    key = "vulns"
    name = "Vulnerability Report Summarizer"
    description = "Nmap XML / JSON scan output -> prioritised report"
    category = "Detection & Analysis"

    def collect(self, ui) -> dict:
        default = str(SAMPLE) if SAMPLE.exists() else ""
        ui.info("Accepts Nmap XML (nmap -oX) or JSON with a 'findings' / 'vulnerabilities' list.")
        return {"report_path": ui.prompt("Scan report path (Enter = demo sample)" if default else "Scan report path", default, existing_file)}

    def run(self, report_path: str = "", **kwargs) -> list[Finding]:
        self.clear()
        path = Path(report_path)
        if not path.exists():
            self.add_finding("info", "No report file found", f"Path does not exist: {report_path}")
            return self.findings
        ext = path.suffix.lower()
        if ext == ".xml":
            self._parse_nmap_xml(path)
        elif ext == ".json":
            self._parse_json(path)
        else:
            self.add_finding("info", "Unsupported file type", f"'{ext or 'no extension'}' — error E3003. Expected .xml (Nmap) or .json",
                             remediation="Re-export the scan as Nmap XML (-oX) or JSON.")
        if not self.findings:
            self.add_finding("info", "No items parsed", "File read but no recognizable entries found.")
        return self.findings

    def _parse_nmap_xml(self, path: Path) -> None:
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError as exc:
            self.add_finding("info", "E3001 Invalid XML — scan file could not be parsed", str(exc), str(path),
                             "Re-export with `nmap -oX file.xml` and try again.")
            return
        hosts = open_ports = 0
        for host in root.findall("host"):
            hosts += 1
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else "unknown"
            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state = port_el.find("state")
                if state is None or state.get("state") != "open":
                    continue
                open_ports += 1
                portid = int(port_el.get("portid", 0))
                svc = port_el.find("service")
                name = svc.get("name", "unknown") if svc is not None else "unknown"
                version = " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else ""
                risk = COMMON_RISKY_PORTS.get(portid)
                sev = risk[1] if risk else "low"
                detail = f"Port {portid}/{name} open on {addr}." + (f" Version: {version}." if version else "")
                if risk:
                    detail += f" {risk[2].capitalize()}."
                self.add_finding(sev, f"Open port: {portid} ({name}) on {addr}", detail, str(path),
                                 risk[3] if risk else "Close the port if the service is not required.")
                blob = " ".join((s.get("output") or "") for s in port_el.iter("script"))
                for cve in sorted(set(CVE_RX.findall(blob))):
                    self.add_finding("high", f"{cve} reported on {addr}:{portid}", "Referenced in NSE script output.", str(path),
                                     "Patch or upgrade the affected service; verify with an authorised rescan.")
        self.add_finding("info", "Scan summary", f"{hosts} host(s), {open_ports} open port(s).", str(path))

    def _parse_json(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            self.add_finding("info", "E3002 Invalid JSON — scan file could not be parsed",
                             f"line {exc.lineno}, column {exc.colno}: {exc.msg}", str(path),
                             "Validate with `python3 -m json.tool file.json`.")
            return
        items = data if isinstance(data, list) else next((data[k] for k in ("vulnerabilities", "findings", "results") if isinstance(data.get(k), list)), None) if isinstance(data, dict) else None
        if items is None:
            self.add_finding("info", "Unrecognized JSON structure", "Expected a list or a 'vulnerabilities' / 'findings' / 'results' key.", str(path))
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            host = item.get("host") or item.get("target") or ""
            title = item.get("title") or item.get("name") or "Unnamed finding"
            self.add_finding(str(item.get("severity", "medium")).lower(), f"{title} {host}".strip(),
                             str(item.get("description") or item.get("detail") or "")[:300], str(path),
                             str(item.get("remediation") or item.get("solution") or ""))
