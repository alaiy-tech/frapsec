"""Optional bandit layer. Shells out if bandit is installed; skipped otherwise.

Catches classes frapsec's own AST rules and semgrep don't: silent
except-pass (B110), weak hashes (B303/B324), pickle/yaml.load (B301/B506),
subprocess/shell injection (B602-B607), SQL string-building (B608 --
overlaps semgrep's frapsec-sql-format-injection on the same lines; kept,
since bandit's detector is independent and worth the confirmation).
"""
import json
import shutil
import subprocess
import sys

from .model import Finding

_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def run(target: str) -> list[Finding]:
    if not shutil.which("bandit"):
        print("bandit not found on PATH — skipping bandit layer", file=sys.stderr)
        return []
    proc = subprocess.run(
        ["bandit", "-r", target, "-f", "json", "-q"],
        capture_output=True, text=True,
    )
    if not proc.stdout.strip():
        print(f"bandit produced no output: {proc.stderr[:300]}", file=sys.stderr)
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"bandit output not valid JSON: {proc.stdout[:300]}", file=sys.stderr)
        return []
    return [
        Finding(
            rule_id=f"BANDIT:{r['test_id']}:{r['test_name']}",
            severity=_SEVERITY.get(r["issue_severity"], "info"),
            message=r["issue_text"].strip(),
            file=r["filename"],
            line=r["line_number"],
        )
        for r in data.get("results", [])
    ]
