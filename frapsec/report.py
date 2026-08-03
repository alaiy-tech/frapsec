"""Output: terminal text, JSON, SARIF."""
import dataclasses
import json
from collections import Counter

from .model import Finding
from .rules.catalog import PERMISSION_RIGHTS, SARIF_LEVEL, SEVERITY_COLORS

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """One merged list ordered by severity, regardless of which rule engine
    (native AST rules, config audit, semgrep) produced each finding — every
    output format calls this so semgrep results never land as a separate
    unsorted block appended after everything else."""
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.index(f.severity)
                  if f.severity in _SEVERITY_ORDER else len(_SEVERITY_ORDER))


def to_text(findings: list[Finding]) -> str:
    findings = sort_findings(findings)
    if not findings:
        return "No findings."
    lines = []
    for f in findings:
        lines.append(f"[{f.severity.upper():8}] {f.rule_id}  {f.file}:{f.line}\n           {f.message}")
    lines.append(f"\n{len(findings)} finding(s).")
    return "\n".join(lines)


def to_json(findings: list[Finding]) -> str:
    return json.dumps([dataclasses.asdict(f) for f in sort_findings(findings)], indent=2)


def to_markdown(findings: list[Finding]) -> str:
    findings = sort_findings(findings)
    if not findings:
        return "# frapsec report\n\nNo findings.\n"
    counts = Counter(f.severity for f in findings)
    summary = " ".join(f"**{s}**: {counts[s]}" for s in _SEVERITY_ORDER if counts.get(s))
    lines = [f"# frapsec report\n\n{summary}\n", "| Severity | Rule | Finding | Location |",
             "|---|---|---|---|"]
    for f in findings:
        msg = f.message.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {f.severity} | `{f.rule_id}` | {msg} | `{f.file}:{f.line}` |")
    lines.append(f"\n{len(findings)} finding(s).")
    return "\n".join(lines)


def to_html(findings: list[Finding], title: str = "frapsec report") -> str:
    findings = sort_findings(findings)
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
    findings = sort_findings(findings)
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
