"""Minimal same-app call graph, used only to answer one question: is this
function reachable from a whitelisted endpoint?

Deliberately name-based, not import-resolved: nodes are bare function names,
edges are "function A calls something named X" (X resolved as a bare call or
self.X/cls.X method call). This over-approximates on name collisions across
files instead of under-approximating and hiding a real reachable path — for
a security scanner, a false "reachable" costs a human 30 seconds of review;
a false "not reachable" hides a real bug. Bias toward recall.

This is NOT a claim of full static analysis (no import resolution, no
higher-order calls, no dynamic dispatch through get_attr). It answers one
narrow question well; rules use it as one signal, not a verdict.
"""
import ast
from pathlib import Path

from .model import App


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


def _callees(fn: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.add(node.func.id)
        elif (isinstance(node.func, ast.Attribute)
              and isinstance(node.func.value, ast.Name)
              and node.func.value.id in ("self", "cls")):
            names.add(node.func.attr)
    return names


def reachable_from_endpoints(app: App) -> set[str]:
    """Function names transitively called by any @frappe.whitelist endpoint
    (guest or not — both are network-reachable). Returns bare names."""
    graph: dict[str, set[str]] = {}
    for _py, fn in _iter_functions(app):
        graph.setdefault(fn.name, set()).update(_callees(fn))

    reached: set[str] = set()
    queue = [ep.name for ep in app.endpoints]
    while queue:
        name = queue.pop()
        if name in reached:
            continue
        reached.add(name)
        queue.extend(graph.get(name, ()))
    return reached
