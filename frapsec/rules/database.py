"""Dangerous database operations -- deletes/updates with no filter, raw
DELETE/UPDATE/TRUNCATE SQL with no WHERE clause. Distinct from
FRAP-SQL-format-injection (semgrep, catches f-string/.format() building the
query) -- this catches the SHAPE of the query itself, string-injected or not.
"""
import ast
import re
from pathlib import Path

from ..model import App, Finding

_UNSAFE_SQL_PREFIXES = ("delete", "truncate", "update")
_WHERE = re.compile(r"\bwhere\b", re.IGNORECASE)
# migration scripts and test infra do full-table operations by design --
# real risk (an attacker-reachable path), not a shape a hand-written
# migration takes. Downgrade to info rather than exclude entirely: still
# worth an inventory pass ("Migration Risks" is its own spec item), just
# not an alarm-tier critical/high.
_REVIEWED_CODE_DIRS = ("patches", "tests")


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


def _in_reviewed_dir(py: Path) -> bool:
    parts = {p.lower() for p in py.parts}
    return any(d in parts for d in _REVIEWED_CODE_DIRS)


def _graded(sev_if_reachable: str, sev_if_not: str, reachable: bool, in_reviewed_dir: bool) -> str:
    if in_reviewed_dir:
        return "info"
    return sev_if_reachable if reachable else sev_if_not


def unfiltered_db_delete(app: App, reach) -> list[Finding]:
    """frappe.db.delete(doctype) with no filters -- deletes EVERY row of
    that doctype. frappe.db.delete(doctype, filters) with filters present
    is the normal, safe usage and does not fire.

    Graded, not blanket-critical: patches/tests do full-table operations
    by design (confirmed on frappe/core -- all 5 initial hits there were
    legitimate migration/test/reset patterns, 0 real bugs) -> info.
    Otherwise graded by call-graph reachability from a whitelisted endpoint,
    same as BIZ-001/BIZ-002 -- a delete only an admin-tier internal flow can
    reach is a different risk than one a guest/user endpoint can trigger."""
    findings = []
    for py, fn in _iter_functions(app):
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "delete"
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == "db"):
                continue
            has_filters = len(node.args) >= 2 or any(kw.arg == "filters" for kw in node.keywords)
            if has_filters:
                continue
            doctype = ast.unparse(node.args[0]) if node.args else "?"
            sev = _graded("critical", "medium", reach.contains(str(py), fn.name), _in_reviewed_dir(py))
            findings.append(Finding(
                rule_id="FRAP-DB-001", severity=sev, app=app.name,
                message=f"{fn.name}() calls frappe.db.delete({doctype}) with no filters — "
                        "deletes EVERY row of this doctype",
                file=str(py), line=node.lineno,
            ))
    return findings


def raw_sql_no_where(app: App, reach) -> list[Finding]:
    """Literal DELETE/TRUNCATE/UPDATE SQL string with no WHERE clause.
    Constant strings only -- f-string/.format() query-building is already
    covered by the vendored semgrep SQLi rule, this is about the query's
    SHAPE (missing WHERE), independent of how it was built.

    Graded the same way as unfiltered_db_delete -- see there for why.
    WHERE detection is a word-boundary regex, not a literal " where "
    substring: a real bug in the first version of this rule flagged
    frappe/core's personal_data_deletion_request.py even though it DOES
    have a WHERE clause, just formatted across lines with tabs/newlines
    around it instead of single spaces."""
    findings = []
    for py, fn in _iter_functions(app):
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("sql", "multisql")
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                continue
            sql = node.args[0].value.strip()
            first_word = sql.split(None, 1)[0].lower() if sql else ""
            if first_word not in _UNSAFE_SQL_PREFIXES:
                continue
            if _WHERE.search(sql):
                continue
            reachable = reach.contains(str(py), fn.name)
            if first_word in ("delete", "truncate"):
                sev = _graded("critical", "medium", reachable, _in_reviewed_dir(py))
            else:
                sev = _graded("high", "low", reachable, _in_reviewed_dir(py))
            findings.append(Finding(
                rule_id="FRAP-DB-002", severity=sev, app=app.name,
                message=f"{fn.name}() runs a raw {first_word.upper()} with no WHERE clause "
                        f"— affects every row in the table",
                file=str(py), line=node.lineno,
            ))
    return findings
