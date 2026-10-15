"""
Input validators. Each returns the cleaned value or raises InputError with a fix.

Developer: Muhammad Mughees Abbasi
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from .errors import FileError, InputError

DOMAIN_RX = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MAX_FILE_BYTES = 25_000_000


def existing_file(value: str, max_bytes: int = MAX_FILE_BYTES) -> str:
    path = Path(value).expanduser()
    if not path.exists():
        raise FileError("File not found", code="E2001", detail=str(path),
                        hint="Check the spelling. Relative paths start in the toolkit folder; tip: press Tab to complete.")
    if path.is_dir():
        raise FileError("Path is a directory", code="E2003", detail=str(path), hint="Pass a file, not a folder.")
    if path.stat().st_size > max_bytes:
        raise FileError("File too large", code="E2004", detail=f"{path.stat().st_size / 1e6:.1f} MB (limit {max_bytes / 1e6:.0f} MB)",
                        hint="Split the file or analyse a smaller sample.")
    return str(path)


def existing_path(value: str) -> str:
    path = Path(value).expanduser()
    if not path.exists():
        raise FileError("Path not found", code="E2001", detail=str(path), hint="Check the spelling of the path.")
    return str(path)


def domain(value: str) -> str:
    raw = value.strip().lower()
    raw = re.sub(r"^[a-z]+://", "", raw).split("/")[0].split(":")[0].rstrip(".")
    if not DOMAIN_RX.match(raw):
        raise InputError("Not a valid domain name", code="E1002", detail=f"'{value}'",
                         hint="Use a bare domain such as example.com (no spaces, no path).")
    return raw


def url_list(value: str) -> list[str]:
    parts = [p for p in re.split(r"[,\s]+", value.strip()) if p]
    if not parts:
        raise InputError("No URL supplied", code="E1003", hint="Example: http://paypa1-secure-login.xyz/verify")
    for p in parts:
        host = urlsplit(p if "://" in p else "http://" + p).hostname
        if not host or " " in p:
            raise InputError("Not a valid URL", code="E1003", detail=p, hint="Include a host, e.g. https://example.com/path")
    return parts


def integer(lo: int, hi: int):
    def check(value: str) -> int:
        try:
            n = int(value)
        except ValueError:
            raise InputError("Expected a whole number", code="E1005", detail=f"'{value}'", hint=f"Enter a number from {lo} to {hi}.") from None
        if not lo <= n <= hi:
            raise InputError("Number out of range", code="E1005", detail=str(n), hint=f"Enter a number from {lo} to {hi}.")
        return n
    return check


def choice(options: dict[str, str]):
    def check(value: str) -> str:
        key = value.strip().lower()
        if key not in options:
            raise InputError("Option not recognised", code="E1004", detail=f"'{value}'",
                             hint="Valid: " + ", ".join(options) + " (q to go back)")
        return key
    return check


def http_url(value: str) -> str:
    parts = urlsplit(value.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise InputError("Not a valid http(s) URL", code="E1003", detail=value,
                         hint="Start with http:// or https:// and include a host.")
    return value.strip()
