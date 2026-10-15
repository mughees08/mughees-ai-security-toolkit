"""
Structured error handling
--------------------------
Every failure surfaces as a ToolkitError with a stable error code, a plain
description and an actionable fix. Unexpected exceptions never leak raw
tracebacks to the operator: they are logged with a reference id instead.

Developer: Muhammad Mughees Abbasi
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import socket
import ssl
import traceback
import urllib.error
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "toolkit.log"


class UserCancelled(Exception):
    """Raised when the operator backs out of a prompt (q / back / Ctrl+D)."""


class ToolkitError(Exception):
    code = "E9001"
    title = "Unexpected error"
    level = "error"  # "error" | "warning"

    def __init__(self, title: str | None = None, *, hint: str = "", detail: str = "",
                 code: str | None = None, level: str | None = None, ref: str = "") -> None:
        self.title = title or self.title
        self.hint = hint
        self.detail = detail
        self.code = code or self.code
        self.level = level or self.level
        self.ref = ref
        super().__init__(f"{self.code} {self.title}")


class InputError(ToolkitError):
    code = "E1001"
    title = "Invalid input"


class FileError(ToolkitError):
    code = "E2001"
    title = "File problem"


class ParseError(ToolkitError):
    code = "E3001"
    title = "Could not parse data"


class NetworkError(ToolkitError):
    code = "E4001"
    title = "Network problem"


class ConfigError(ToolkitError):
    code = "E5001"
    title = "Configuration problem"


class ServiceError(ToolkitError):
    code = "E6001"
    title = "External service problem"


class InternalError(ToolkitError):
    code = "E9001"
    title = "Internal error"


# code -> (meaning, typical fix). Printed by the in-app "Error codes" help screen.
CATALOG = {
    "E1001": ("Empty or invalid input", "Provide a value, or type q to go back"),
    "E1002": ("Invalid domain name", "Use a bare domain such as example.com"),
    "E1003": ("Invalid URL", "Include a host, e.g. https://example.com/path"),
    "E1004": ("Menu choice not recognised", "Pick one of the listed keys"),
    "E1005": ("Number out of range", "Stay inside the range shown in the prompt"),
    "E2001": ("File not found", "Check the path; relative paths start at the toolkit folder"),
    "E2002": ("Permission denied", "Run termux-setup-storage or fix file permissions"),
    "E2003": ("Path is a directory", "Pass a file, not a folder"),
    "E2004": ("File too large", "Split the file or raise the limit in Settings"),
    "E2005": ("File is binary / unreadable text", "Use a text export of the data"),
    "E3001": ("Invalid XML", "Re-export the scan with nmap -oX"),
    "E3002": ("Invalid JSON", "Validate the JSON file and retry"),
    "E3003": ("Unsupported file type", "Use .xml (Nmap) or .json"),
    "E3004": ("Malformed token / header block", "Paste the complete value, unmodified"),
    "E4001": ("DNS lookup failed", "Check the spelling of the host and your DNS / VPN"),
    "E4002": ("Network timeout", "Retry later or raise the timeout in Settings"),
    "E4003": ("TLS handshake failed", "Often a VPN / proxy / captive portal; retry on another network"),
    "E4004": ("Remote service returned an HTTP error", "Retry later; the service may be rate limiting"),
    "E4005": ("Connection refused / reset", "The host or port is closed or blocking you"),
    "E5001": ("Configuration problem", "Delete data/config.json to restore defaults"),
    "E6001": ("API key not configured", "export ANTHROPIC_API_KEY=... (optional feature)"),
    "E6002": ("AI API request failed", "Check the key, quota and connectivity"),
    "E9001": ("Internal error (logged)", "Re-run with --debug and report the reference id"),
}


def setup_logging(debug: bool = False) -> logging.Logger:
    logger = logging.getLogger("aisec")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=512_000, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    except OSError:
        logger.addHandler(logging.NullHandler())
    return logger


def log_exception(exc: BaseException, context: str = "") -> str:
    ref = uuid.uuid4().hex[:8].upper()
    logging.getLogger("aisec").error("ref=%s context=%s\n%s", ref, context,
                                     "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    return ref


def _root_reason(exc: BaseException) -> BaseException:
    while isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, BaseException):
        exc = exc.reason
    return exc


def classify(exc: BaseException, context: str = "") -> ToolkitError:
    """Translate any exception into a ToolkitError with a code and a fix."""
    if isinstance(exc, ToolkitError):
        return exc
    target = f" ({context})" if context else ""
    if isinstance(exc, FileNotFoundError):
        return FileError("File not found", code="E2001", detail=str(exc.filename or exc),
                         hint="Check the path. Press Enter at the prompt to use the demo sample where offered.")
    if isinstance(exc, PermissionError):
        return FileError("Permission denied", code="E2002", detail=str(exc.filename or exc),
                         hint="On Termux run `termux-setup-storage`, or choose a file inside the toolkit folder.")
    if isinstance(exc, IsADirectoryError):
        return FileError("Path is a directory", code="E2003", detail=str(exc.filename or exc),
                         hint="Pass a file, not a folder.")
    if isinstance(exc, UnicodeDecodeError):
        return FileError("File is not readable text", code="E2005", detail=str(exc)[:120],
                         hint="Provide a text/log export of the data.")
    if isinstance(exc, json.JSONDecodeError):
        return ParseError("Invalid JSON", code="E3002", detail=f"line {exc.lineno}, column {exc.colno}: {exc.msg}",
                          hint="Validate the file (python3 -m json.tool file.json).")
    if isinstance(exc, ET.ParseError):
        return ParseError("Invalid XML", code="E3001", detail=str(exc),
                          hint="Re-export the scan with `nmap -oX file.xml`.")
    if isinstance(exc, urllib.error.HTTPError):
        status = exc.code
        hint = {429: "Rate limited by the service. Wait a minute and retry.",
                502: "Upstream gateway error on the service side. Retry later.",
                503: "Service temporarily unavailable. Retry later.",
                504: "Gateway timeout on the service side. Retry later.",
                403: "The service refused the request (blocked or auth required).",
                404: "The endpoint or resource does not exist."}.get(status, "Retry later; the service may be having issues.")
        return NetworkError(f"HTTP {status} from remote service{target}", code="E4004", detail=str(exc.reason), hint=hint)
    root = _root_reason(exc)
    text = str(root).lower()
    if isinstance(root, socket.gaierror):
        return NetworkError(f"DNS lookup failed{target}", code="E4001", detail=str(root),
                            hint="Check the host spelling, your DNS or VPN, and connectivity.")
    if "handshake" in text and "timed out" in text:
        return NetworkError(f"TLS handshake timed out{target}", code="E4003", detail=str(root),
                            hint="Usually a slow link, VPN or proxy. Retry, or try another network.")
    if isinstance(root, ssl.SSLCertVerificationError):
        return NetworkError(f"Certificate verification failed{target}", code="E4003", detail=str(root)[:160],
                            hint="The certificate is invalid, expired or untrusted.")
    if isinstance(root, ssl.SSLError):
        return NetworkError(f"TLS error{target}", code="E4003", detail=str(root)[:160],
                            hint="Retry on another network; check the system clock.")
    if isinstance(root, (socket.timeout, TimeoutError)) or "timed out" in text:
        return NetworkError(f"Connection timed out{target}", code="E4002", detail=str(root),
                            hint="Retry later or raise the timeout in Settings.")
    if isinstance(root, (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError)):
        return NetworkError(f"Connection refused or reset{target}", code="E4005", detail=str(root),
                            hint="The host is down, the port is closed, or a firewall is blocking you.")
    if isinstance(root, OSError) and getattr(root, "errno", None) in (101, 113):
        return NetworkError(f"Network unreachable{target}", code="E4005", detail=str(root),
                            hint="Check Wi-Fi / mobile data and VPN.")
    if isinstance(exc, MemoryError):
        return InternalError("Out of memory", code="E2004", hint="Use a smaller input file.")
    if isinstance(exc, OSError):
        return FileError("I/O error", code="E2001", detail=str(exc)[:160], hint="Check disk space and permissions.")
    ref = log_exception(exc, context)
    return InternalError("Unexpected internal error", code="E9001", ref=ref,
                         detail=f"{type(exc).__name__}: {str(exc)[:120]}",
                         hint=f"Logged to logs/toolkit.log (ref {ref}). Re-run with --debug for the traceback.")


def short(exc: BaseException, context: str = "") -> str:
    """One-line professional description, used inside Finding titles."""
    err = classify(exc, context)
    return f"{err.code} {err.title}"
