"""Business-logic rules, connector-flavoured. AST scans over every .py in the app."""
import ast

from . import rule
from .catalog import IDEMPOTENCY_CHECKS
from ..callgraph import _iter_functions, reachable_from_endpoints
from ..model import App, Finding


def _restores_user_in_finally(fn: ast.AST) -> bool:
    """True if a try/finally in fn calls set_user with a non-literal (variable) arg —
    evidence of "elevate, then restore the original user" rather than a permanent switch.
    """
    for node in ast.walk(fn):
        if not isinstance(node, ast.Try) or not node.finalbody:
            continue
        for stmt in node.finalbody:
            for call in ast.walk(stmt):
                if (isinstance(call, ast.Call) and ast.unparse(call.func).endswith("set_user")
                        and call.args and not isinstance(call.args[0], ast.Constant)):
                    return True
    return False


@rule
def admin_impersonation(app: App) -> list[Finding]:
    """frappe.set_user('Administrator') — privilege escalation if reachable from user input.

    Graded two ways, both from real evidence rather than a flat severity:
    - scoped (try/finally restores the original user) drops it a tier — still
      worth a look, but it's not a permanent switch
    - unreachable from any whitelisted endpoint (call-graph check) drops it
      further — this is install/patch/background code, not attacker-facing
    """
    reachable = reachable_from_endpoints(app)
    findings = []
    for py, fn in _iter_functions(app):
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call) and ast.unparse(node.func).endswith("set_user")
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == "Administrator"):
                scoped = _restores_user_in_finally(fn)
                is_reachable = reachable.contains(str(py), fn.name)
                if not is_reachable:
                    sev, note = "info", " — not reachable from any whitelisted endpoint (background/install code)"
                elif scoped:
                    sev, note = "medium", (" inside a try/finally that restores the original user (scoped) — "
                                           "still verify the caller path is properly authenticated")
                else:
                    sev, note = "high", (" — everything after runs with full privileges; verify it can't be "
                                         "reached with attacker-controlled input")
                findings.append(Finding(
                    rule_id="FRAP-BIZ-001", severity=sev, app=app.name,
                    message=f"{fn.name}() switches session to Administrator{note}",
                    file=str(py), line=node.lineno,
                ))
    return findings


@rule
def ignore_permissions(app: App) -> list[Finding]:
    """save/insert/delete with ignore_permissions=True — graded by call-graph reachability
    from a whitelisted endpoint, not just whether the immediate function is one itself.
    A helper three calls deep from an endpoint is just as real a bypass as being in the
    endpoint's own body — this catches that case, which a direct-decorator check misses.
    """
    reachable = reachable_from_endpoints(app)
    findings = []
    for py, fn in _iter_functions(app):
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            if any(kw.arg == "ignore_permissions" and isinstance(kw.value, ast.Constant)
                   and kw.value.value for kw in node.keywords):
                whitelisted = any("whitelist" in ast.unparse(d) for d in fn.decorator_list)
                is_reachable = whitelisted or reachable.contains(str(py), fn.name)
                if whitelisted:
                    tag, note = "[whitelisted endpoint]", ""
                elif is_reachable:
                    tag, note = "[reachable from a whitelisted endpoint]", ""
                else:
                    tag, note = "", " (background code — normal for sync jobs, keep as inventory)"
                findings.append(Finding(
                    rule_id="FRAP-BIZ-002", severity="medium" if is_reachable else "info",
                    app=app.name,
                    message=f"{fn.name}() {tag} uses ignore_permissions=True on "
                            f"{ast.unparse(node.func)[:60]} — bypasses the permission model{note}",
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
