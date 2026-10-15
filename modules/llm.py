"""
Optional Claude API access (standard library only).
Set ANTHROPIC_API_KEY to enable. Without it every feature falls back to local rules.

Developer: Muhammad Mughees Abbasi
"""

from __future__ import annotations

import json
import os
import urllib.request

from .errors import ServiceError, classify

API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-5-5"


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def ask(prompt: str, system: str = "", max_tokens: int = 700, timeout: int = 60) -> str:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise ServiceError("AI API key not configured", code="E6001",
                           hint="export ANTHROPIC_API_KEY=your_key  (optional; the toolkit works offline)")
    body = {"model": os.environ.get("AISEC_MODEL", DEFAULT_MODEL), "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}]}
    if system:
        body["system"] = system
    req = urllib.request.Request(API_URL, data=json.dumps(body).encode(), method="POST",
                                 headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                                          "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:
        err = classify(exc, "AI API")
        raise ServiceError("AI API request failed", code="E6002", detail=f"{err.code} {err.title}",
                           hint="Check the key, quota and connectivity; the toolkit continues with local analysis.") from None
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
