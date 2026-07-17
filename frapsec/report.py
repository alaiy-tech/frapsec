"""Output: terminal text, JSON, SARIF."""
import dataclasses
import json
from collections import Counter

from .model import Finding
from .rules.catalog import PERMISSION_RIGHTS, SARIF_LEVEL, SEVERITY_COLORS


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


def to_html(findings: list[Finding], title: str = "frapsec report") -> str:
    from jinja2 import Environment, PackageLoader
    env = Environment(loader=PackageLoader("frapsec", "templates"), autoescape=True)
    return env.get_template("report.html").render(
        title=title, findings=findings,
        counts=Counter(f.severity for f in findings), colors=SEVERITY_COLORS)


def permission_matrix(app) -> dict:
    """{role: {doctype: [rights]}} from DocType JSON perms."""
    matrix: dict = {}
    for dt in app.doctypes:
        for perm in dt.permissions:
            role = perm.get("role", "?")
            rights = [r for r in PERMISSION_RIGHTS if perm.get(r)]
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
                "level": SARIF_LEVEL.get(f.severity, "note"),
                "message": {"text": f.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace("\\", "/")},
                    "region": {"startLine": f.line},
                }}],
            } for f in findings],
        }],
    }, indent=2)
