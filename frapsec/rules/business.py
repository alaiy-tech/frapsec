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


#  _submit/_cancel/_discard are Frappe's OWN canonical Document lifecycle
# method names -- this IS the real implementation .submit()/.cancel() calls
# into, not an app bypassing it. Confirmed on frappe/core: frappe/model/
# document.py's _submit()/_cancel() were false positives under the old
# blanket rule (flagging the framework's official implementation of the
# very thing the message told you to use instead).
_CANONICAL_LIFECYCLE_METHODS = {"_submit", "_cancel", "_discard", "discard"}


def _is_instance_method(fn: ast.AST) -> bool:
    return bool(fn.args.args) and fn.args.args[0].arg in ("self", "cls")


def _docstatus_value_severity(value: ast.expr) -> str:
    """Direction matters: going BACK to draft (0) is a common, benign
    undo/restore pattern (confirmed on frappe/core: deleted_document.py
    restore-as-draft, auto_repeat.py new-doc-starts-as-draft). Jumping
    directly to submitted/cancelled (1/2) without going through
    submit()/cancel()'s validations is the real risk. A non-literal value
    can't be proven either way -- medium, not a blanket high guess."""
    if isinstance(value, ast.Constant) and isinstance(value.value, int):
        return "info" if value.value == 0 else "high"
    if isinstance(value, ast.Attribute) and value.attr == "DRAFT":
        return "info"
    if isinstance(value, ast.Attribute) and value.attr in ("SUBMITTED", "CANCELLED"):
        return "high"
    return "medium"


@rule
def submitted_doc_mutation(app: App) -> list[Finding]:
    """Direct docstatus manipulation — bypasses submit/cancel workflow and its validations."""
    findings = []
    for py, fn in _iter_functions(app):
        # bare "discard" collides more easily with app-defined functions than
        # the underscore-prefixed names -- only skip it when it's an instance
        # method (self/cls first arg), matching how Frappe's Document class
        # actually defines it, not any function merely named "discard".
        if fn.name in _CANONICAL_LIFECYCLE_METHODS and (fn.name != "discard" or _is_instance_method(fn)):
            continue
        for node in ast.walk(fn):
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Attribute)
                    and node.targets[0].attr == "docstatus"):
                sev = _docstatus_value_severity(node.value)
                findings.append(Finding(
                    rule_id="FRAP-BIZ-003", severity=sev, app=app.name,
                    message=f"{fn.name}() assigns docstatus directly — bypasses submit/cancel "
                            "workflow validations; use doc.submit()/doc.cancel()",
                    file=str(py), line=node.lineno,
                ))
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("db_set", "set_value")
                    and any(isinstance(a, ast.Constant) and a.value == "docstatus" for a in node.args)):
                # value is the arg right after the "docstatus" literal, if any
                idx = next((i for i, a in enumerate(node.args)
                            if isinstance(a, ast.Constant) and a.value == "docstatus"), None)
                val = node.args[idx + 1] if idx is not None and idx + 1 < len(node.args) else None
                sev = _docstatus_value_severity(val) if val is not None else "medium"
                findings.append(Finding(
                    rule_id="FRAP-BIZ-003", severity=sev, app=app.name,
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

# Doctypes that ARE the permission model. Writing one grants access; writing one
# from code an outsider can reach is an escalation path, not a data change.
_PRIVILEGE_DOCTYPES = ("User", "Role", "Has Role", "Role Profile",
                       "User Permission", "Custom DocPerm", "DocPerm")

# Calls that CREATE or CHANGE a document. Naming a privilege doctype in a read
# -- get_all("Has Role", ...) to list who holds a role -- is not a grant, and
# treating it as one flagged every "who is on my team" endpoint in the codebase.
_WRITE_CALLS = ("new_doc", "get_doc", "insert", "save", "set_value", "delete",
                "delete_doc", "rename_doc")


def _grants_a_role(fn: ast.AST) -> bool:
    """True if this function assigns a role or writes a privilege doctype.

    Two shapes cover real code: appending to a User's `roles` child table, and
    creating/updating one of the doctypes that define who may do what.
    """
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        # user.append("roles", {...}) / doc.add_roles(...)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "add_roles":
                return True
            if node.func.attr == "append" and node.args \
                    and isinstance(node.args[0], ast.Constant) \
                    and node.args[0].value == "roles":
                return True
        # A privilege doctype named in a WRITE call. Reading one is not a grant
        # -- confirmed live: a "who is on my team" endpoint calls
        # get_all("User Permission", ...) and was flagged as granting a role.
        if isinstance(node.func, ast.Attribute) and node.func.attr in _WRITE_CALLS:
            for arg in node.args:
                if isinstance(arg, ast.Constant) and arg.value in _PRIVILEGE_DOCTYPES:
                    return True
                if isinstance(arg, ast.Dict):
                    for k, v in zip(arg.keys, arg.values):
                        if (isinstance(k, ast.Constant) and k.value == "doctype"
                                and isinstance(v, ast.Constant)
                                and v.value in _PRIVILEGE_DOCTYPES):
                            return True
    return False


def _bypasses_permissions(fn: ast.AST) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.keyword) and node.arg == "ignore_permissions":
            if isinstance(node.value, ast.Constant) and node.value.value:
                return True
        if isinstance(node, ast.Attribute) and node.attr == "ignore_permissions":
            return True
    return False


@rule
def privilege_grant_path(app: App) -> list[Finding]:
    """Code that grants a role or writes the permission model.

    FRAP-BIZ-001 catches an endpoint impersonating Administrator. This catches
    the other escalation shape, which is quieter and more permanent: code that
    hands out a role, creates a User, or writes Has Role / User Permission /
    Custom DocPerm. Where set_user is a switch that ends, a granted role
    persists after the request.

    Graded by who can reach it, the same signal BIZ-001 and BIZ-002 use. Almost
    every app legitimately assigns roles during install or onboarding, so a flat
    severity here would be pure noise -- what matters is whether the grant sits
    behind a whitelisted endpoint, and whether that path also bypasses the
    permission model on its way in.

    Found on real code: a whitelisted POST endpoint that creates a User, assigns
    a role, and inserts with ignore_permissions=True. That is a working
    escalation path if the caller is not tightly authenticated -- and the rule
    cannot know whether it is, which is exactly why a human should look.
    """
    reachable = reachable_from_endpoints(app)
    whitelisted = {(ep.file, ep.name) for ep in app.endpoints}
    findings = []
    for py, fn in _iter_functions(app):
        if not _grants_a_role(fn):
            continue
        is_endpoint = (str(py), fn.name) in whitelisted or any(
            isinstance(d, (ast.Attribute, ast.Call, ast.Name))
            and "whitelist" in ast.unparse(d) for d in getattr(fn, "decorator_list", [])
        )
        is_reachable = is_endpoint or reachable.contains(str(py), fn.name)
        bypasses = _bypasses_permissions(fn)

        if not is_reachable:
            sev = "info"
            note = " — not reachable from any whitelisted endpoint (install/onboarding code)"
        elif bypasses:
            sev = "high"
            note = (" — reachable from a whitelisted endpoint AND bypasses the permission model "
                    "on the way in; verify the caller cannot choose the role or the user")
        else:
            sev = "medium"
            note = (" — reachable from a whitelisted endpoint; verify the caller cannot choose "
                    "which role is granted")
        findings.append(Finding(
            rule_id="FRAP-BIZ-005", severity=sev, app=app.name,
            message=f"{fn.name}() grants a role or writes the permission model{note}",
            file=str(py), line=fn.lineno,
        ))
    return findings
