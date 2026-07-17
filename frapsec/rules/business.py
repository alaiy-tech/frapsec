"""Business-logic rules, connector-flavoured. AST scans over every .py in the app."""
import ast
from pathlib import Path

from . import rule
from .catalog import IDEMPOTENCY_CHECKS
from ..model import App, Finding


def _iter_functions(app: App):
    pkg = Path(app.path) / app.name
    if not pkg.is_dir():
        pkg = Path(app.path)
    for py in pkg.rglob("*.py"):
        if py.name.startswith("test_"):
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield py, node


@rule
def admin_impersonation(app: App) -> list[Finding]:
    """frappe.set_user('Administrator') — privilege escalation if reachable from user input."""
    findings = []
    for py, fn in _iter_functions(app):
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call) and ast.unparse(node.func).endswith("set_user")
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == "Administrator"):
                findings.append(Finding(
                    rule_id="FRAP-BIZ-001", severity="high", app=app.name,
                    message=f"{fn.name}() switches session to Administrator — everything after runs "
                            "with full privileges; verify it can't be reached with attacker-controlled input",
                    file=str(py), line=node.lineno,
                ))
    return findings


@rule
def ignore_permissions(app: App) -> list[Finding]:
    """save/insert/delete with ignore_permissions=True — inventory, graded by context."""
    findings = []
    for py, fn in _iter_functions(app):
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            if any(kw.arg == "ignore_permissions" and isinstance(kw.value, ast.Constant)
                   and kw.value.value for kw in node.keywords):
                # user-reachable endpoint -> real bypass; background sync code -> inventory only
                whitelisted = any("whitelist" in ast.unparse(d) for d in fn.decorator_list)
                findings.append(Finding(
                    rule_id="FRAP-BIZ-002", severity="medium" if whitelisted else "info",
                    app=app.name,
                    message=f"{fn.name}(){' [whitelisted endpoint]' if whitelisted else ''} uses "
                            f"ignore_permissions=True on {ast.unparse(node.func)[:60]} — bypasses "
                            "the permission model" + ("" if whitelisted else " (background code — normal for sync jobs, keep as inventory)"),
                    file=str(py), line=node.lineno,
                ))
    return findings


@rule
def submitted_doc_mutation(app: App) -> list[Finding]:
    """Direct docstatus manipulation — bypasses submit/cancel workflow and its validations."""
    findings = []
    for py, fn in _iter_functions(app):
        for node in ast.walk(fn):
            # doc.docstatus = N  (N != 0) or db_set('docstatus', ...)
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Attribute)
                    and node.targets[0].attr == "docstatus"):
                findings.append(Finding(
                    rule_id="FRAP-BIZ-003", severity="high", app=app.name,
                    message=f"{fn.name}() assigns docstatus directly — bypasses submit/cancel "
                            "workflow validations; use doc.submit()/doc.cancel()",
                    file=str(py), line=node.lineno,
                ))
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("db_set", "set_value")
                    and any(isinstance(a, ast.Constant) and a.value == "docstatus" for a in node.args)):
                findings.append(Finding(
                    rule_id="FRAP-BIZ-003", severity="high", app=app.name,
                    message=f"{fn.name}() writes docstatus via {node.func.attr}() — bypasses "
                            "submit/cancel workflow validations",
                    file=str(py), line=node.lineno,
                ))
    return findings


@rule
def webhook_missing_idempotency(app: App) -> list[Finding]:
    """Webhook/event handler that inserts docs without any existence check first.

    Heuristic: function name mentions webhook/handle_* + calls .insert()/get_doc(dict).insert
    but never calls frappe.db.exists / get_value / get_all before it.
    """
    findings = []
    for py, fn in _iter_functions(app):
        name = fn.name.lower()
        if not ("webhook" in name or name.startswith("handle_") or name.startswith("process_")):
            continue
        src = ast.unparse(fn)
        inserts = ".insert(" in src or ".save(" in src
        checks = any(c in src for c in IDEMPOTENCY_CHECKS)
        if inserts and not checks:
            findings.append(Finding(
                rule_id="FRAP-BIZ-004", severity="medium", app=app.name,
                message=f"{fn.name}() looks like an event handler that inserts/saves docs with no "
                        "existence check — replayed/duplicate webhooks will create duplicates",
                file=str(py), line=fn.lineno,
            ))
    return findings
