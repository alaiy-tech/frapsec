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

A call to frappe.enqueue("a.b.c.func", ...) / frappe.get_attr("a.b.c.func")
is resolved separately by matching the full dotted string against known
modules directly — a raw string was never `import`-ed by the caller, so the
name-based resolver above can't see it, and matching only its last
component (an earlier version of this code did that) reintroduces the same
collision risk the whole file-based resolver exists to avoid.

self./cls. calls resolve through the class hierarchy: same class first,
then base classes (resolved same-file-or-import, same as any other name) --
not same-file-only. A base class imported from another file is followed;
a method not found anywhere in the chain falls back to the old same-file
bare lookup (loose, but no worse than before).

This still is NOT full static analysis: no relative-import resolution
beyond simple dotted paths, no wildcard imports, no multiple-inheritance
MRO (walks bases in listed order, first match wins), no metaclass/mixin
magic. It answers one narrow question — "is there a followable path from
an endpoint to this function?" — conservatively; rules use it as one
signal, not a verdict.
"""
import ast
from dataclasses import dataclass
from pathlib import Path

from .model import App


@dataclass
class Reachability:
    """Answers "is this specific function (identified by its file, not just
    its name) reachable from an endpoint?" — returning bare names here would
    silently re-merge two unrelated same-named functions in different files,
    the exact bug this module exists to avoid.
    """
    _reached: set[tuple[str, str]]         # (module, name)
    _module_by_file: dict[str, str]        # resolved file path -> module

    def contains(self, file: str, name: str) -> bool:
        mod = self._module_by_file.get(str(Path(file).resolve()))
        return mod is not None and (mod, name) in self._reached

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


def _called_names(fn: ast.AST) -> tuple[set[str], set[str]]:
    """(bare_names, method_names) -- kept separate because they resolve
    differently: bare names via same-file-then-import, method names via
    the class hierarchy (see `resolve_method`)."""
    bare, methods = set(), set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            bare.add(node.func.id)
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
                and node.func.value.id in ("self", "cls"):
            methods.add(node.func.attr)
    return bare, methods


def _classes_in(tree: ast.Module) -> dict[str, tuple[list[str], dict[str, ast.AST]]]:
    """class name -> (base class name strings, {method name: node})."""
    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = [ast.unparse(b) for b in node.bases]
        methods = {n.name: n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        out[node.name] = (bases, methods)
    return out


def _string_dispatch_targets(fn: ast.AST) -> set[str]:
    """Full dotted paths from enqueue("a.b.c", ...) / get_attr("a.b.c") calls —
    kept whole (not reduced to the last component) so they can be resolved
    directly against known modules instead of the generic same-file/import
    resolver, which only knows names actually imported by the caller. A raw
    dotted string was never imported, so the generic resolver can't see it —
    this is the one part of the graph that must match by dotted path, not by
    bare name, and it's still exact-path matching, not a bare-name search."""
    paths = set()
    for node in ast.walk(fn):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in _STRING_DISPATCH_CALLS and node.args):
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str) and "." in first.value:
                paths.add(first.value)
    return paths


def reachable_from_endpoints(app: App) -> Reachability:
    """Functions transitively reachable from any @frappe.whitelist endpoint
    (guest or not — both are network-reachable), via same-file or import-
    resolved calls only. Returns a Reachability, checked with
    .contains(file, name) — not a bare-name set, which would merge two
    unrelated same-named functions in different files."""
    pkg = Path(app.path) / app.name
    if not pkg.is_dir():
        pkg = Path(app.path)

    # module (dotted path) -> {name: node}; also name -> set of modules defining it
    by_module: dict[str, dict[str, ast.AST]] = {}
    defines: dict[str, set[str]] = {}
    imports_by_module: dict[str, dict[str, str]] = {}
    module_by_file: dict[str, str] = {}
    classes_by_module: dict[str, dict[str, tuple[list[str], dict[str, ast.AST]]]] = {}
    class_defines: dict[str, set[str]] = {}
    func_owner: dict[tuple[str, str], str] = {}  # (mod, func_name) -> class_name

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
        module_by_file[str(py.resolve())] = mod
        for name in funcs:
            defines.setdefault(name, set()).add(mod)

        classes = _classes_in(tree)
        classes_by_module[mod] = classes
        for cls_name, (_bases, cls_methods) in classes.items():
            class_defines.setdefault(cls_name, set()).add(mod)
            for method_name in cls_methods:
                func_owner.setdefault((mod, method_name), cls_name)

    def resolve(caller_mod: str, name: str) -> set[str]:
        if name in by_module.get(caller_mod, {}):
            return {caller_mod}
        imported_from = imports_by_module.get(caller_mod, {}).get(name)
        if imported_from:
            return {m for m in defines.get(name, ()) if m == imported_from or m.endswith("." + imported_from)}
        return set()

    def resolve_class(caller_mod: str, class_name: str) -> set[str]:
        if class_name in classes_by_module.get(caller_mod, {}):
            return {caller_mod}
        imported_from = imports_by_module.get(caller_mod, {}).get(class_name)
        if imported_from:
            return {m for m in class_defines.get(class_name, ()) if m == imported_from or m.endswith("." + imported_from)}
        return set()

    def resolve_method(mod: str, name: str, method_name: str) -> set[tuple[str, str]]:
        """self.foo()/cls.foo() inside function `name` (owned by some class
        in `mod`) -- search that class's own methods, then its base classes
        (possibly in other files via import), before falling back to the
        old same-file loose lookup."""
        cls_name = func_owner.get((mod, name))
        if cls_name is None:
            return set()  # not a method (plain function) -- caller falls back
        seen_classes = set()
        frontier = [(mod, cls_name)]
        while frontier:
            cur_mod, cur_cls = frontier.pop()
            if (cur_mod, cur_cls) in seen_classes:
                continue
            seen_classes.add((cur_mod, cur_cls))
            bases, methods = classes_by_module.get(cur_mod, {}).get(cur_cls, ([], {}))
            if method_name in methods:
                return {(cur_mod, method_name)}
            for base in bases:
                base = base.split(".")[-1]  # e.g. "module.Base" -> "Base"
                for base_mod in resolve_class(cur_mod, base):
                    frontier.append((base_mod, base))
        return set()

    def resolve_dotted(dotted: str) -> set[tuple[str, str]]:
        """"a.b.c.func_name" -> {(module, func_name)} for modules matching
        "a.b.c" (our module names are relative to the app package; the
        dotted string is absolute including the app name, so match by
        suffix). If the matched module doesn't define func_name directly
        but re-exports it (from x import func_name), follow that import —
        common for compatibility shim modules — via the same resolver used
        for ordinary calls."""
        mod_part, _, func_name = dotted.rpartition(".")
        hits = set()
        for mod in by_module:
            if not (mod == mod_part or mod_part.endswith("." + mod) or mod.endswith("." + mod_part)):
                continue
            if func_name in by_module[mod]:
                hits.add((mod, func_name))
            else:
                hits |= {(m, func_name) for m in resolve(mod, func_name)}
        return hits

    reached: set[tuple[str, str]] = set()  # (module, name)
    queue = []
    for ep in app.endpoints:
        # seed by the endpoint's own (file, line), not by bare name -- two
        # unrelated functions sharing a name (one the real endpoint, one
        # coincidentally named the same elsewhere) must not both become
        # roots. Confirmed as a real miss: api/sync.py's whitelisted
        # import_existing_orders and pull.py's unrelated same-named helper.
        mod = module_by_file.get(str(Path(ep.file).resolve()))
        fn = by_module.get(mod, {}).get(ep.name) if mod else None
        if fn is not None and fn.lineno == ep.line:
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
        bare_names, method_names = _called_names(fn)
        for callee_name in bare_names:
            for callee_mod in resolve(mod, callee_name) or {mod}:  # same-module fallback
                if callee_name in by_module.get(callee_mod, {}):
                    queue.append((callee_mod, callee_name))
        for method_name in method_names:
            hits = resolve_method(mod, name, method_name)
            if hits:
                queue.extend(hits)
            elif method_name in by_module.get(mod, {}):  # loose same-file fallback
                queue.append((mod, method_name))
        for dotted in _string_dispatch_targets(fn):
            queue.extend(resolve_dotted(dotted))

    return Reachability(reached, module_by_file)
