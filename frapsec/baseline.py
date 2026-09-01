"""Accept-current-state baseline so re-scans surface only NEW findings.

Keyed on rule_id + the path within the app + the stripped text of the flagged
line, not the line number — an unrelated edit above a finding shifts line
numbers but should not make an already-reviewed finding look new.

The path is kept RELATIVE to the app rather than absolute, so a baseline
committed on one machine still matches when the repo is checked out somewhere
else or scanned in CI.
"""
import hashlib
import json
from pathlib import Path

from .model import Finding

_SCHEMA = 2


def _rel_path(f: Finding) -> str:
    """Path from the app root down, as a stable POSIX string.

    Using only the basename collides: api/orders.py and shopify/orders.py both
    reduce to "orders.py", so an identical flagged line in the second file is
    silently treated as already accepted and never reported. Using the absolute
    path is the opposite failure -- the baseline stops matching the moment the
    repo lives at a different path, which is every CI run.

    Anchors on the app directory when the finding carries one, and falls back to
    the last two segments otherwise: still far more specific than a basename,
    and still independent of where the repo is checked out.
    """
    path = Path(f.file)
    if f.app:
        parts = list(path.parts)
        # The app name appears in the path for a normal apps/<name>/<name>
        # layout; anchor on its LAST occurrence, which is the inner package.
        idx = [i for i, seg in enumerate(parts) if seg == f.app]
        if idx:
            return "/".join(parts[idx[-1]:])
    return "/".join(path.parts[-2:]) if len(path.parts) > 1 else path.name


def _key(f: Finding) -> str:
    try:
        line_text = Path(f.file).read_text(
            encoding="utf-8", errors="replace").splitlines()[f.line - 1].strip()
    except (OSError, IndexError):
        line_text = str(f.line)
    raw = f"{f.rule_id}|{_rel_path(f)}|{line_text}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def load(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    data = json.loads(p.read_text())
    # v1 stored a bare list of hashes; v2 stores a record per finding. Both
    # read back as a set of keys, so an existing baseline keeps working --
    # its keys were computed from a basename and will simply stop matching
    # once a file moves, which is the bug this version fixes.
    accepted = data.get("accepted", [])
    if accepted and isinstance(accepted[0], dict):
        return {a["key"] for a in accepted}
    return set(accepted)


def save(path: str, findings: list[Finding]) -> int:
    """Write the accepted set, keeping enough context to audit it later.

    A bare list of hashes cannot be reviewed: there is no way to see what was
    accepted, when, or whether it is still the right call. Each entry now
    carries the rule, path, severity and a one-line summary alongside its key,
    so the file is readable in a diff and an accepted finding can be argued
    with.
    """
    seen = {}
    for f in findings:
        k = _key(f)
        if k in seen:
            continue
        seen[k] = {
            "key": k,
            "rule_id": f.rule_id,
            "severity": f.severity,
            "file": _rel_path(f),
            "line": f.line,
            "summary": (f.message or "")[:140],
        }
    out = {"schema": _SCHEMA, "accepted": [seen[k] for k in sorted(seen)]}
    Path(path).write_text(json.dumps(out, indent=2))
    return len(seen)


def filter_new(findings: list[Finding], accepted: set[str]) -> list[Finding]:
    return [f for f in findings if _key(f) not in accepted]
