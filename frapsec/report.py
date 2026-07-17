"""Output: terminal text, JSON, SARIF."""
import dataclasses
import json

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
