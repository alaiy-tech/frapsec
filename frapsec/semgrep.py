"""Optional semgrep layer. Shells out if semgrep is installed; skipped otherwise.

Point it at a rules dir (e.g. frappe/semgrep-rules) with --semgrep-rules.
Semgrep has no native Windows support — expect this to run in CI/WSL.
"""
import json
import shutil
import subprocess
import sys

from .model import Finding

_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}
# overlaps with frapsec's own (smarter) rules
_SKIP = {"guest-whitelisted-method", "missing-argument-type-hint"}


def run(rules_dir: str, target: str) -> list[Finding]:
    if not shutil.which("semgrep"):
        print("semgrep not found on PATH — skipping semgrep layer", file=sys.stderr)
        return []
    proc = subprocess.run(
        ["semgrep", "scan", "--config", rules_dir, "--json", "--quiet", target],
        capture_output=True, text=True,
    )
    if proc.returncode not in (0, 1):  # 1 = findings, >1 = error
        print(f"semgrep failed: {proc.stderr[:500]}", file=sys.stderr)
        return []
    results = json.loads(proc.stdout).get("results", [])
    return [
        Finding(
            rule_id=f"SEMGREP:{r['check_id'].rsplit('.', 1)[-1]}",
            severity=_SEVERITY.get(r["extra"]["severity"], "info"),
            message=r["extra"]["message"].strip(),
            file=r["path"],
            line=r["start"]["line"],
        )
        for r in results
        if r["check_id"].rsplit(".", 1)[-1] not in _SKIP
    ]
