"""API security rules."""
import ast
from pathlib import Path

from . import rule
from ..model import App, Finding

PERM_CALLS = {"has_permission", "check_permission", "only_for", "throw_if_not_permitted"}


@rule
def guest_api(app: App) -> list[Finding]:
    """Guest endpoints, graded by whether they verify a signature.

    - reads request body/headers AND verifies HMAC -> info (webhook done right)
    - reads request body/headers, no HMAC verification -> critical (unauthenticated writer)
    - anything else guest-accessible -> high (manual review)
    """
    findings = []
    for ep in app.endpoints:
        if not ep.allow_guest:
            continue
        body = _function_source(ep.file, ep.line)
        src = ast.unparse(body) if body else ""
        # ponytail: string-match on the handler body only — HMAC done in a called
        # helper reads as "no verification". Follow calls one level when that FP shows up.
        reads_request = "frappe.request" in src or "form_dict" in src
        verifies = "compare_digest" in src or "hmac.new" in src
        if reads_request and verifies:
            sev, msg = "info", "Guest webhook endpoint with HMAC verification"
        elif reads_request:
            sev, msg = "critical", ("Guest endpoint reads request data with NO signature "
                                    "verification — anyone on the internet can drive it")
        else:
            sev, msg = "high", ("Guest-accessible API — verify it exposes nothing sensitive "
                                "and validates all input")
        findings.append(Finding(
            rule_id="FRAP-API-001", severity=sev, app=app.name,
            message=f"{msg}: {ep.module}.{ep.name}", file=ep.file, line=ep.line,
        ))
    return findings


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
