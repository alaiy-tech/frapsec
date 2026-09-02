"""Secrets scanning via detect-secrets (pip-installable, actively maintained,
many detector plugins) instead of a hand-rolled regex list — a dedicated
tool covers far more secret shapes (AWS keys, JWTs, Slack tokens, high-
entropy strings...) than a few regexes for known Frappe field names ever
could. Shells out; skipped with a stderr notice if not installed.
"""
import json
import shutil
import subprocess
from pathlib import Path
import sys

from .model import Finding

# Files frapsec itself writes into the app being scanned. Their contents are
# scanner output, not application code.
_SELF_WRITTEN = {".frapsec-baseline.json", "frapsec.sarif"}

# .md/.txt etc flag prose mentioning "secret"/"password" as if it were a
# literal value (confirmed false positive: a spec doc's "sh_webhook_secret
# reqd: 1" sentence). Scope to code/config files where a hit is a real value.
_CODE_GLOBS = ("*.py", "*.json", "*.js", "*.cfg", "*.ini", "*.env", "*.yaml", "*.yml")


def run(target: str) -> list[Finding]:
    if not shutil.which("detect-secrets"):
        print("detect-secrets not found on PATH — skipping secrets layer", file=sys.stderr)
        return []
    # detect-secrets has no --include-files flag; filter results by extension after the fact.
    proc = subprocess.run(["detect-secrets", "scan", target], capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.strip():
        print(f"detect-secrets failed: {proc.stderr[:300]}", file=sys.stderr)
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"detect-secrets output not valid JSON: {proc.stdout[:300]}", file=sys.stderr)
        return []

    findings = []
    for path, hits in data.get("results", {}).items():
        if not path.endswith(tuple(g.lstrip("*") for g in _CODE_GLOBS)):
            continue
        # A baseline is a file full of SHA1 keys, which is exactly what an
        # entropy check is looking for. Scanning it means every regeneration
        # accepts the previous generation's hashes and writes more of them --
        # 174 entries became 312 on one pass. They are not secrets.
        if Path(path).name in _SELF_WRITTEN:
            continue
        for h in hits:
            findings.append(Finding(
                rule_id=f"SECRETS:{h['type'].replace(' ', '_')}",
                severity="critical",
                message=f"possible {h['type']} — verify and move to site_config or a Password field",
                file=path, line=h["line_number"],
            ))
    return findings
