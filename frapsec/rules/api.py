"""API security rules."""
import ast
from pathlib import Path

from . import rule
from ..model import App, Finding

PERM_CALLS = {"has_permission", "check_permission", "only_for", "throw_if_not_permitted"}


@rule
def guest_api(app: App) -> list[Finding]:
    return [
        Finding(
            rule_id="FRAP-API-001", severity="high", app=app.name,
            message=f"Guest-accessible API: {ep.module}.{ep.name} (allow_guest=True). "
                    "Verify it exposes nothing sensitive and validates all input.",
            file=ep.file, line=ep.line,
        )
        for ep in app.endpoints if ep.allow_guest
    ]


@rule
def missing_permission_check(app: App) -> list[Finding]:
    """Whitelisted method that touches frappe.db but never checks permissions."""
    findings = []
    for ep in app.endpoints:
        if ep.allow_guest:
            continue  # covered by FRAP-API-001
        body = _function_source(ep.file, ep.line)
        if body is None:
            continue
        calls = {n.func.attr for n in ast.walk(body)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        touches_db = any(c in calls for c in ("sql", "set_value", "delete", "get_all", "get_list"))
        if touches_db and not (calls & PERM_CALLS) and "get_doc" not in calls:
            findings.append(Finding(
                rule_id="FRAP-API-002", severity="medium", app=app.name,
                message=f"{ep.module}.{ep.name} hits the database with no visible permission check "
                        "(frappe.db bypasses DocType permissions).",
                file=ep.file, line=ep.line,
            ))
    return findings


def _function_source(file: str, line: int) -> ast.FunctionDef | None:
    try:
        tree = ast.parse(Path(file).read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, OSError):
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno == line:
            return node
    return None
