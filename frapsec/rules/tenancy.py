"""Cross-company / cross-tenant rules. Real for this platform specifically:
many connector apps share one bench, several with multi-company data.

Scoped to avoid noise: only DocTypes that actually HAVE a `company` field
(known from parsed DocType JSON) are checked -- a get_list on a DocType with
no company concept isn't a cross-company risk, and flagging it would just
be more of the pattern-blind noise this project has spent the session
fixing. Only literal-dict filters are checked; a filters value passed as a
variable/Name can't be verified statically, so it's skipped rather than
guessed at (same principle as ignore_permissions grading elsewhere: don't
claim a verdict the AST can't actually support).
"""
import ast

from . import rule
from ..model import App, Finding

_LIST_CALLS = ("get_list", "get_all")


def _iter_functions(app_path, app_name):
    from pathlib import Path
    pkg = Path(app_path) / app_name
    if not pkg.is_dir():
        pkg = Path(app_path)
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


def _filters_has_company(node: ast.Call) -> bool | None:
    """True/False if filters is a literal dict/list we can inspect, None if
    it's a variable we can't verify (caller should skip, not guess)."""
    filt = None
    for kw in node.keywords:
        if kw.arg == "filters":
            filt = kw.value
            break
    if filt is None and len(node.args) >= 2:
        filt = node.args[1]
    if filt is None:
        return False  # no filters at all -- definitely no company filter
    if isinstance(filt, ast.Dict):
        keys = [k.value for k in filt.keys if isinstance(k, ast.Constant)]
        return "company" in keys
    if isinstance(filt, ast.List):
        for elt in filt.elts:
            if isinstance(elt, (ast.List, ast.Tuple)) and elt.elts:
                first = elt.elts[0]
                if isinstance(first, ast.Constant) and first.value == "company":
                    return True
        return False
    return None  # Name/Call/etc -- can't verify statically


@rule
def cross_company_query(app: App) -> list[Finding]:
    company_doctypes = {dt.name for dt in app.doctypes if "company" in dt.fieldnames}
    if not company_doctypes:
        return []

    findings = []
    for py, fn in _iter_functions(app.path, app.name):
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in _LIST_CALLS):
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            doctype_name = node.args[0].value
            if doctype_name not in company_doctypes:
                continue
            has_company = _filters_has_company(node)
            if has_company is False:
                findings.append(Finding(
                    rule_id="FRAP-TENANT-001", severity="medium", app=app.name,
                    message=f"{fn.name}() calls {node.func.attr}(\"{doctype_name}\") -- a "
                            "multi-company DocType -- with no company filter; may leak or "
                            "mix records across companies",
                    file=str(py), line=node.lineno,
                ))
    return findings
