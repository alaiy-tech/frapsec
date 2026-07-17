"""API security rules."""
import ast
from pathlib import Path

from . import rule
from .catalog import DB_CALLS, PERM_CALLS, SECRET_REVEAL_CALLS, WRITE_CALLS
from ..model import App, Finding


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
        # critical needs consequence: guest handler that WRITES from unverified input.
        # Auth-shaped endpoints (login/oauth) read request data legitimately (frappe-core triage).
        writes = any(w in src for w in WRITE_CALLS)
        if reads_request and verifies:
            sev, msg = "info", "Guest webhook endpoint with HMAC verification"
        elif reads_request and writes:
            sev, msg = "critical", ("Guest endpoint writes documents from request data with NO "
                                    "signature verification — anyone on the internet can drive it")
        elif reads_request:
            sev, msg = "high", ("Guest endpoint reads request data without signature verification — "
                                "fine for auth/login flows, review anything else")
        elif not ep.args:
            # no request read, no args -> attacker has no input channel into this handler at all
            sev, msg = "info", "Guest-accessible API with no arguments and no request data read — low risk"
        else:
            sev, msg = "high", ("Guest-accessible API — verify it exposes nothing sensitive "
                                "and validates all input")
        findings.append(Finding(
            rule_id="FRAP-API-001", severity=sev, app=app.name,
            message=f"{msg}: {ep.module}.{ep.name}", file=ep.file, line=ep.line,
            endpoint=f"{ep.module}.{ep.name}",
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
        touches_db = any(c in calls for c in DB_CALLS)
        if touches_db and not (calls & PERM_CALLS) and "get_doc" not in calls:
            findings.append(Finding(
                rule_id="FRAP-API-002", severity="medium", app=app.name,
                message=f"{ep.module}.{ep.name} hits the database with no visible permission check "
                        "(frappe.db bypasses DocType permissions).",
                file=ep.file, line=ep.line,
                endpoint=f"{ep.module}.{ep.name}",
            ))
    return findings


@rule
def whitelisted_secret_reveal(app: App) -> list[Finding]:
    """Whitelisted method returns a decrypted Password field to the caller.

    get_password() exists to read secrets server-side (e.g. calling an
    external API) — a whitelisted endpoint that returns its result to the
    client hands the secret to whoever can call the endpoint.
    """
    findings = []
    for ep in app.endpoints:
        body = _function_source(ep.file, ep.line)
        if body is None:
            continue
        for node in ast.walk(body):
            if isinstance(node, ast.Return) and node.value is not None:
                for call in ast.walk(node.value):
                    if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                            and call.func.attr in SECRET_REVEAL_CALLS):
                        findings.append(Finding(
                            rule_id="FRAP-API-003", severity="high", app=app.name,
                            message=f"{ep.module}.{ep.name} returns a decrypted secret "
                                    f"({call.func.attr}()) to the caller — verify every role "
                                    "that can call this endpoint should see this value in plaintext",
                            file=ep.file, line=node.lineno,
                            endpoint=f"{ep.module}.{ep.name}",
                        ))
    return findings


@rule
def dynamic_dispatch_on_stored_data(app: App) -> list[Finding]:
    """frappe.get_attr(x) where x traces to a DocType field read a few lines up.

    Executing a dotted path that came from database-stored config is a
    dynamic-dispatch sink: whoever can write that field controls what code
    runs. Detected via a simple same-function heuristic (assignment then
    get_attr on the same name) — not a full dataflow trace.
    """
    findings = []
    for ep in app.endpoints:
        body = _function_source(ep.file, ep.line)
        if body is None:
            continue
        stored_names = set()
        for node in ast.walk(body):
            # $VAR = something.field  where field name suggests a stored method path
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and isinstance(node.value, ast.Attribute)
                    and any(h in node.value.attr for h in ("method", "handler", "callback"))):
                stored_names.add(node.targets[0].id)
        for node in ast.walk(body):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get_attr" and node.args
                    and isinstance(node.args[0], ast.Name) and node.args[0].id in stored_names):
                findings.append(Finding(
                    rule_id="FRAP-API-004", severity="high", app=app.name,
                    message=f"{ep.module}.{ep.name} calls frappe.get_attr({node.args[0].id}) where "
                            f"{node.args[0].id} comes from a DocType field — dynamic dispatch on "
                            "stored data; whoever can edit that field controls what code runs",
                    file=ep.file, line=node.lineno,
                    endpoint=f"{ep.module}.{ep.name}",
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
