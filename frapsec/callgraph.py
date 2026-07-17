"""Minimal same-app call graph, used only to answer one question: is this
function reachable from a whitelisted endpoint?

Import-aware, not import-resolved: a call to name X inside file F first
tries "X defined in F" (same-file, matches normal Python scoping for most
helpers), then "X is imported into F from module G, and G defines X"
(follows real `import`/`from...import` statements). A bare name with no
same-file definition and no matching import is dropped rather than matched
against every same-named function in the app — two unrelated functions
sharing a name in unconnected files must NOT become one graph node just
because they're spelled the same (confirmed as a real false-positive source
scanning frappe/core: two distinct `add_default` functions were merged by a
bare-name graph, marking both reachable when only one was).

This still is NOT full static analysis: no relative-import resolution
beyond simple dotted paths, no wildcard imports, no cross-class method
resolution beyond self./cls. in the same file. It answers one narrow
question — "is there a followable path from an endpoint to this function?"
— conservatively; rules use it as one signal, not a verdict.
"""
import ast
from pathlib import Path

from .model import App

# calls whose first string-literal argument is a dotted path to code that
# actually runs later (background job, dynamic dispatch) — not a real call
# in the AST, but a real edge in practice.
_STRING_DISPATCH_CALLS = ("enqueue", "get_attr", "call")


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


def _module_of(py_file: Path, pkg_root: Path) -> str:
    try:
        return ".".join(py_file.relative_to(pkg_root.parent).with_suffix("").parts)
    except ValueError:
        return py_file.stem


def _imported_names(tree: ast.Module) -> dict[str, str]:
    """name used in this file -> module it was imported from (best-effort dotted path)."""
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                out[alias.asname or alias.name] = node.module
        elif isinstance(node, ast.Import):
            for alias in node.names:
                out[alias.asname or alias.name.split(".")[0]] = alias.name
    return out


def _called_names(fn: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            if (isinstance(node.func.value, ast.Name)
                    and node.func.value.id in ("self", "cls")):
                names.add(node.func.attr)
            if node.func.attr in _STRING_DISPATCH_CALLS and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str) and "." in first.value:
                    names.add(first.value.rsplit(".", 1)[-1])
    return names


def reachable_from_endpoints(app: App) -> set[str]:
    """Function names transitively reachable from any @frappe.whitelist endpoint
    (guest or not — both are network-reachable), via same-file or import-
    resolved calls only. Returns bare names (a name can legitimately be
    reachable via more than one file)."""
    pkg = Path(app.path) / app.name
    if not pkg.is_dir():
        pkg = Path(app.path)

    # module (dotted path) -> {name: node}; also name -> set of modules defining it
    by_module: dict[str, dict[str, ast.AST]] = {}
    defines: dict[str, set[str]] = {}
    imports_by_module: dict[str, dict[str, str]] = {}

    for py in pkg.rglob("*.py"):
        if py.name.startswith("test_"):
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        mod = _module_of(py, pkg)
        funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        by_module[mod] = funcs
        imports_by_module[mod] = _imported_names(tree)
        for name in funcs:
            defines.setdefault(name, set()).add(mod)

    def resolve(caller_mod: str, name: str) -> set[str]:
        if name in by_module.get(caller_mod, {}):
            return {caller_mod}
        imported_from = imports_by_module.get(caller_mod, {}).get(name)
        if imported_from:
            return {m for m in defines.get(name, ()) if m == imported_from or m.endswith("." + imported_from)}
        return set()

    reached: set[tuple[str, str]] = set()  # (module, name)
    queue = []
    for ep in app.endpoints:
        for mod, funcs in by_module.items():
            if ep.name in funcs:
                queue.append((mod, ep.name))

    while queue:
        item = queue.pop()
        if item in reached:
            continue
        reached.add(item)
        mod, name = item
        fn = by_module.get(mod, {}).get(name)
        if fn is None:
            continue
        for callee_name in _called_names(fn):
            for callee_mod in resolve(mod, callee_name) or {mod}:  # same-module fallback for self./cls.
                if callee_name in by_module.get(callee_mod, {}):
                    queue.append((callee_mod, callee_name))

    return {name for _mod, name in reached}
