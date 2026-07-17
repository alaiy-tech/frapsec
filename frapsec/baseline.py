"""Accept-current-state baseline so re-scans surface only NEW findings.

Keyed on rule_id + filename + the stripped text of the flagged line, not the
line number — an unrelated edit above a finding shifts line numbers but
shouldn't make an already-reviewed finding look new.
"""
import hashlib
import json
from pathlib import Path

from .model import Finding


def _key(f: Finding) -> str:
    try:
        line_text = Path(f.file).read_text(encoding="utf-8", errors="replace").splitlines()[f.line - 1].strip()
    except (OSError, IndexError):
        line_text = str(f.line)
    raw = f"{f.rule_id}|{Path(f.file).name}|{line_text}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def load(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    return set(json.loads(p.read_text()).get("accepted", []))


def save(path: str, findings: list[Finding]) -> int:
    keys = sorted({_key(f) for f in findings})
    Path(path).write_text(json.dumps({"accepted": keys}, indent=2))
    return len(keys)


def filter_new(findings: list[Finding], accepted: set[str]) -> list[Finding]:
    return [f for f in findings if _key(f) not in accepted]
