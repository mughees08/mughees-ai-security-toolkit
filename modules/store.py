"""
Small JSON persistence layer: config, guard policy, triage suppressions, run history.
Writes are atomic (temp file + rename) and failures raise ConfigError.

Developer: Muhammad Mughees Abbasi
"""

import json
import os
from datetime import datetime
from pathlib import Path

from .errors import BASE_DIR, ConfigError
from .guard_engine import GuardPolicy

DATA = BASE_DIR / "data"
CONFIG_FILE = DATA / "config.json"
POLICY_FILE = DATA / "guard_policy.json"
SUPPRESS_FILE = DATA / "suppressions.json"
HISTORY_FILE = DATA / "history.json"

DEFAULT_CONFIG = {"theme": "cyber", "fullbg": True, "ascii": False}


def _read(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ConfigError(f"Could not read {path.name}", detail=str(exc)[:140],
                          hint=f"Delete data/{path.name} to restore defaults.") from None


def _write(path: Path, data) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        raise ConfigError(f"Could not save {path.name}", detail=str(exc)[:140],
                          hint="Check free space and write permission on the data/ folder.") from None


def load_config() -> dict:
    return {**DEFAULT_CONFIG, **_read(CONFIG_FILE, {})}


def save_config(cfg: dict) -> None:
    _write(CONFIG_FILE, cfg)


def load_policy() -> GuardPolicy:
    return GuardPolicy.from_dict(_read(POLICY_FILE, {}))


def save_policy(policy: GuardPolicy) -> None:
    _write(POLICY_FILE, policy.__dict__)


def load_suppressions() -> dict:
    return _read(SUPPRESS_FILE, {})


def save_suppressions(data: dict) -> None:
    _write(SUPPRESS_FILE, data)


def load_history() -> list:
    return _read(HISTORY_FILE, [])


def add_snapshot(session) -> dict:
    from .session import fingerprint
    snap = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "risk": session.score(), "label": session.label(), "counts": session.counts(),
        "fps": {fingerprint(m, f): {"module": m, "title": f.title[:120], "severity": f.severity} for m, f in session.pairs()},
    }
    hist = load_history()
    hist.append(snap)
    _write(HISTORY_FILE, hist[-50:])
    return snap
