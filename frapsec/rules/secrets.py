"""Hardcoded secrets in source and fixtures. Regex-based, tuned for low noise."""
import re
from pathlib import Path

from . import rule
from ..model import App, Finding

# name-ish part = value that looks real (not a placeholder/lookup)
_ASSIGN = re.compile(
    r"""(?ix)
    \w*(api_key|api_secret|client_secret|access_token|auth_token|refresh_token|
        secret_key|private_key|password|webhook_secret|encryption_key)
    \s*[=:]\s*
    (["'])(?P<val>[^"']{8,})\2
    """)
_PEM = re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")
# values that are clearly not secrets
_PLACEHOLDER = re.compile(
    r"(?i)^(x+|\*+|<[^>]+>|\{\{.*\}\}|\{[0-9a-z_]*\}|your[_-]|changeme|example|dummy|placeholder|test|none|null|fake)")


def _looks_real(val: str) -> bool:
    if _PLACEHOLDER.match(val):
        return False
    # lookups, env reads, format strings are code, not literals worth flagging
    if any(t in val for t in ("os.environ", "get_password", "frappe.conf", "%s", "{}")):
        return False
    return True


@rule
def hardcoded_secrets(app: App) -> list[Finding]:
    findings = []
    pkg = Path(app.path)
    for f in list(pkg.rglob("*.py")) + list(pkg.rglob("*.json")):
        if f.name.startswith("test_") or "/node_modules/" in str(f).replace("\\", "/"):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _ASSIGN.finditer(text):
            if not _looks_real(m.group("val")):
                continue
            line = text.count("\n", 0, m.start()) + 1
            findings.append(Finding(
                rule_id="FRAP-SECRET-001", severity="critical", app=app.name,
                message=f"hardcoded {m.group(1)} in source — move to site_config or "
                        "a Password field (get_password)",
                file=str(f), line=line,
            ))
        if _PEM.search(text):
            line = text.count("\n", 0, _PEM.search(text).start()) + 1
            findings.append(Finding(
                rule_id="FRAP-SECRET-002", severity="critical", app=app.name,
                message="private key material committed in repo",
                file=str(f), line=line,
            ))
    return findings
