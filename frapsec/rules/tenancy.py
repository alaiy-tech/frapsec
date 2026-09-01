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
from ..callgraph import _iter_functions
from ..model import App, Finding

_LIST_CALLS = ("get_list", "get_all")

# get_value/exists with a DICT filter is the same question as get_list: "find me
# a row matching this". Without a company filter it can match another company's
# record. A lookup by primary key -- get_value("Sales Order", so_name, ...) --
# is NOT this: the caller already knows which record it wants, and flagging
# those would bury the real ones under every ordinary lookup in the codebase.
_LOOKUP_CALLS = ("get_value", "exists")


def _iter_functions_local(app_path, app_name):
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


def company_doctypes_in(apps: list[App]) -> set[str]:
    """Bench-wide index: every DocType name that has a `company` field,
    across ALL scanned apps -- not just the one being checked. Needed
    because the risky call is usually a connector app querying a CORE
    doctype (Sales Order, etc) it doesn't itself define."""
    return {dt.name for a in apps for dt in a.doctypes if "company" in dt.fieldnames}


def cross_company_query(app: App, company_doctypes: set[str]) -> list[Finding]:
    if not company_doctypes:
        return []

    findings = []
    for py, fn in _iter_functions_local(app.path, app.name):
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


def cross_company_lookup(app: App, company_doctypes: set[str]) -> list[Finding]:
    """get_value/exists searching a multi-company DocType by filter, not by key.

    Same leak as an unfiltered get_list, in the shape people do not think of as
    a query: frappe.db.get_value("Sales Order", {"po_no": x}, "name") returns
    whichever company's order matches first.

    Only DICT filters count. A second argument that is a string is a primary-key
    lookup -- the caller already knows the record -- and flagging those would
    bury the real findings under every ordinary get_value in the codebase.
    """
    if not company_doctypes:
        return []

    findings = []
    for py, fn in _iter_functions_local(app.path, app.name):
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in _LOOKUP_CALLS):
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            doctype_name = node.args[0].value
            if doctype_name not in company_doctypes:
                continue
            # Second positional arg IS the filter for get_value/exists.
            if len(node.args) < 2 or not isinstance(node.args[1], ast.Dict):
                continue  # by key, or a filter we cannot read -- not a finding
            keys = [k.value for k in node.args[1].keys if isinstance(k, ast.Constant)]
            if "company" in keys:
                continue
            if not keys:
                continue  # get_value("X", {}, ...) -- "any row", flagged below
            findings.append(Finding(
                rule_id="FRAP-TENANT-003", severity="medium", app=app.name,
                message=f"{fn.name}() calls {node.func.attr}(\"{doctype_name}\") with a filter "
                        f"on {', '.join(sorted(keys))} but no company -- a multi-company "
                        "DocType, so this returns whichever company's record matches first",
                file=str(py), line=node.lineno,
            ))
    return findings


# Values that make a cache key site-specific or user-specific on their own.
# frappe.cache() is already per-site on a standard bench, but a bare literal
# key is shared by every worker and every site that runs the same code from
# the same bench -- and the connector apps here are installed on several
# client sites off one bench, which is exactly that case.
_SCOPING_HINTS = (
    "frappe.local.site", "frappe.session.sid", "frappe.session.user",
    "site_name", "get_site", "sid", "user",
)


def _key_arg(node: ast.Call):
    """The key argument of a cache get/set/delete call, or None."""
    for kw in node.keywords:
        if kw.arg == "key":
            return kw.value
    return node.args[0] if node.args else None


def _is_cache_call(node: ast.Call) -> str | None:
    """The cache method name if this is a frappe.cache().<op>() call."""
    if not isinstance(node.func, ast.Attribute):
        return None
    op = node.func.attr
    if op not in ("get_value", "set_value", "delete_value", "hget", "hset", "hdel"):
        return None
    # frappe.cache().get_value(...) -- the receiver is itself a cache() call,
    # or a name a local assignment gave the cache object (cache = frappe.cache()).
    recv = node.func.value
    if isinstance(recv, ast.Call) and isinstance(recv.func, ast.Attribute)             and recv.func.attr == "cache":
        return op
    if isinstance(recv, ast.Name) and recv.id in ("cache", "_cache", "redis"):
        return op
    return None


def _module_literals(py) -> dict:
    """{name: value} for module-level assignments of plain string literals.

    Cache keys are conventionally module-level constants -- _REDIS_BROKEN_KEY,
    _CACHE_PREFIX -- so resolving only names assigned inside the function would
    miss the common case entirely.
    """
    try:
        tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return {}
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1                 and isinstance(node.targets[0], ast.Name)                 and isinstance(node.value, ast.Constant)                 and isinstance(node.value.value, str):
            out[node.targets[0].id] = node.value.value
    return out


def _literal_key_source(fn: ast.AST, key_node, module_consts=None) -> str | None:
    """The literal string a key resolves to, or None if it is scoped/dynamic.

    Returns a value only when the key is provably a fixed string with nothing
    site- or user-specific in it. An f-string or concatenation carrying any
    scoping hint is treated as fine, and anything the AST cannot follow is
    skipped rather than guessed at -- the same posture the filters check above
    takes.
    """
    if key_node is None:
        return None

    # A plain literal: "deep_scrape:browser_broken"
    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
        return key_node.value

    # A module- or function-level name assigned a plain literal.
    if isinstance(key_node, ast.Name):
        if module_consts and key_node.id in module_consts:
            return module_consts[key_node.id]
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and len(node.targets) == 1                     and isinstance(node.targets[0], ast.Name)                     and node.targets[0].id == key_node.id                     and isinstance(node.value, ast.Constant)                     and isinstance(node.value.value, str):
                return node.value.value
        return None  # assigned something we cannot follow -- skip

    # An f-string or concatenation. Fine if any part is site/session scoped.
    if isinstance(key_node, (ast.JoinedStr, ast.BinOp)):
        src = ast.dump(key_node)
        if any(h in src for h in _SCOPING_HINTS):
            return None
        return None  # dynamic but unscoped -- too weak a signal to flag

    return None


@rule
def unscoped_cache_key(app: App) -> list[Finding]:
    """A cache key that is a fixed literal, shared across every site on the bench.

    frappe.cache() is per-site on a standard bench, so this is a real finding
    only where it is not -- but these connector apps are installed on several
    client sites from one bench, and a literal key means one client's cached
    state is the same entry as another's. Confirmed live: a scraper connector
    marks a browser broken under the bare key "deep_scrape:browser_broken", so
    one client's failure disables scraping for all of them.

    Only flags a key it can prove is a fixed string. A key built from
    frappe.local.site, the session id or the user is correctly scoped; anything
    the AST cannot resolve is skipped rather than guessed at.
    """
    findings = []
    consts_by_file = {}
    for py, fn in _iter_functions(app):
        if py not in consts_by_file:
            consts_by_file[py] = _module_literals(py)
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            op = _is_cache_call(node)
            if not op:
                continue
            literal = _literal_key_source(fn, _key_arg(node), consts_by_file[py])
            if literal is None:
                continue
            findings.append(Finding(
                rule_id="FRAP-TENANT-002", severity="medium", app=app.name,
                message=f"{fn.name}() calls cache {op} with the fixed key "
                        f"\"{literal}\" -- not scoped to a site or user, so every "
                        "site on this bench shares the entry; scope it with "
                        "frappe.local.site or the session/user if the value is "
                        "per-site",
                file=str(py), line=node.lineno,
            ))
    return findings
