"""Output: terminal text, JSON, SARIF."""
import dataclasses
import html
import json
from collections import Counter

from .model import Finding

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_text(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    lines = []
    for f in findings:
        lines.append(f"[{f.severity.upper():8}] {f.rule_id}  {f.file}:{f.line}\n           {f.message}")
    lines.append(f"\n{len(findings)} finding(s).")
    return "\n".join(lines)


def to_json(findings: list[Finding]) -> str:
    return json.dumps([dataclasses.asdict(f) for f in findings], indent=2)


_COLORS = {"critical": "#d32f2f", "high": "#f57c00", "medium": "#fbc02d", "low": "#7cb342", "info": "#90a4ae"}


def to_html(findings: list[Finding], title: str = "frapsec report") -> str:
    counts = Counter(f.severity for f in findings)
    badges = "".join(
        f'<span class="badge" style="background:{_COLORS[s]}">{s} {counts[s]}</span>'
        for s in _COLORS if counts.get(s))
    rows = "".join(
        f'<tr><td><span class="badge" style="background:{_COLORS.get(f.severity, "#999")}">{f.severity}</span></td>'
        f'<td><code>{html.escape(f.rule_id)}</code></td>'
        f'<td>{html.escape(f.message)}</td>'
        f'<td><code>{html.escape(f.file)}:{f.line}</code></td></tr>'
        for f in findings)
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#222}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}}
td,th{{border:1px solid #ddd;padding:.5rem;text-align:left;vertical-align:top;font-size:.9rem}}
th{{background:#f5f5f5}}
.badge{{color:#fff;border-radius:4px;padding:.1rem .5rem;font-size:.8rem;white-space:nowrap}}
code{{font-size:.85rem}}
</style></head><body>
<h1>{html.escape(title)}</h1>
<p>{badges or "No findings."}</p>
<table><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Location</th></tr>{rows}</table>
</body></html>"""


_RIGHTS = ("read", "write", "create", "delete", "submit", "cancel", "amend", "report", "export", "share", "email", "print")


def permission_matrix(app) -> dict:
    """{role: {doctype: [rights]}} from DocType JSON perms."""
    matrix: dict = {}
    for dt in app.doctypes:
        for perm in dt.permissions:
            role = perm.get("role", "?")
            rights = [r for r in _RIGHTS if perm.get(r)]
            if perm.get("permlevel"):
                rights = [f"{r}@L{perm['permlevel']}" for r in rights]
            matrix.setdefault(role, {}).setdefault(dt.name, []).extend(rights)
    return matrix


def matrix_text(matrix: dict) -> str:
    lines = []
    for role in sorted(matrix):
        lines.append(role)
        for dt, rights in sorted(matrix[role].items()):
            lines.append(f"  {dt:40} {', '.join(rights)}")
    return "\n".join(lines) or "No DocType permissions found."


def to_sarif(findings: list[Finding]) -> str:
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "frapsec", "rules": [
                {"id": rid} for rid in sorted({f.rule_id for f in findings})
            ]}},
            "results": [{
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "note"),
                "message": {"text": f.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace("\\", "/")},
                    "region": {"startLine": f.line},
                }}],
            } for f in findings],
        }],
    }, indent=2)
