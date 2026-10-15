"""
Resilient read-only HTTP helper (retries with backoff, classified errors).

Developer: Muhammad Mughees Abbasi
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request

from .errors import NetworkError, classify

USER_AGENT = "ai-security-toolkit/3.0 (+defensive-analysis)"
log = logging.getLogger("aisec")


def http_get(url: str, *, headers: dict | None = None, timeout: int = 15, retries: int = 3,
             context: str = "") -> str:
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(8_000_000).decode("utf-8", "replace")
        except Exception as exc:  # classified below
            last = exc
            err = classify(exc, context)
            log.warning("http_get %s attempt %d/%d failed: %s", url, attempt, retries, err.code)
            # 4xx other than 429 will not improve with a retry
            if err.code == "E4004" and "HTTP 4" in err.title and "429" not in err.title:
                break
            if attempt < retries:
                time.sleep(1.5 * attempt)
    assert last is not None
    err = classify(last, context)
    if isinstance(err, NetworkError):
        raise err
    raise err


def http_json(url: str, **kwargs):
    return json.loads(http_get(url, **kwargs))
