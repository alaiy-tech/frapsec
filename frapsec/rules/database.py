"""Dangerous database operations -- deletes/updates with no filter, raw
DELETE/UPDATE/TRUNCATE SQL with no WHERE clause. Distinct from
FRAP-SQL-format-injection (semgrep, catches f-string/.format() building the
query) -- this catches the SHAPE of the query itself, string-injected or not.
"""
import ast
from pathlib import Path

from . import rule
from ..model import App, Finding

_UNSAFE_SQL_PREFIXES = ("delete", "truncate", "update")


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
def unfiltered_db_delete(app: App) -> list[Finding]:
    """frappe.db.delete(doctype) with no filters -- deletes EVERY row of
    that doctype. frappe.db.delete(doctype, filters) with filters present
    is the normal, safe usage and does not fire."""
    findings = []
    for py, fn in _iter_functions(app):
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "delete"
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == "db"):
                continue
            has_filters = len(node.args) >= 2 or any(kw.arg == "filters" for kw in node.keywords)
            if not has_filters:
                doctype = ast.unparse(node.args[0]) if node.args else "?"
                findings.append(Finding(
                    rule_id="FRAP-DB-001", severity="critical", app=app.name,
                    message=f"{fn.name}() calls frappe.db.delete({doctype}) with no filters — "
                            "deletes EVERY row of this doctype",
                    file=str(py), line=node.lineno,
                ))
    return findings


@rule
def raw_sql_no_where(app: App) -> list[Finding]:
    """Literal DELETE/TRUNCATE/UPDATE SQL string with no WHERE clause.
    Constant strings only -- f-string/.format() query-building is already
    covered by the vendored semgrep SQLi rule, this is about the query's
    SHAPE (missing WHERE), independent of how it was built."""
    findings = []
    for py, fn in _iter_functions(app):
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("sql", "multisql")
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                continue
            sql = node.args[0].value.strip().lower()
            first_word = sql.split(None, 1)[0] if sql else ""
            if first_word not in _UNSAFE_SQL_PREFIXES:
                continue
            if " where " in sql:
                continue
            sev = "critical" if first_word in ("delete", "truncate") else "high"
            findings.append(Finding(
                rule_id="FRAP-DB-002", severity=sev, app=app.name,
                message=f"{fn.name}() runs a raw {first_word.upper()} with no WHERE clause "
                        f"— affects every row in the table",
                file=str(py), line=node.lineno,
            ))
    return findings
