"""Walk a bench or app directory and build the model. Pure static — no Frappe import."""
import ast
import json
from pathlib import Path

from .model import App, DocType, Endpoint, Site


def discover_bench(bench_path: str) -> list[App]:
    """A bench has apps/ with one dir per app."""
    apps_dir = Path(bench_path) / "apps"
    if not apps_dir.is_dir():
        raise SystemExit(f"not a bench: no apps/ under {bench_path}")
    return [discover_app(str(p)) for p in sorted(apps_dir.iterdir()) if p.is_dir()]


def discover_sites(bench_path: str) -> list[Site]:
    """sites/*/site_config.json, each merged over common_site_config.json."""
    sites_dir = Path(bench_path) / "sites"
    common = _load_json(sites_dir / "common_site_config.json")
    out = []
    for cfg in sorted(sites_dir.glob("*/site_config.json")):
        out.append(Site(name=cfg.parent.name, file=str(cfg), config={**common, **_load_json(cfg)}))
    return out


def _load_json(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}


def discover_app(app_path: str) -> App:
    root = Path(app_path)
    # frappe app layout: apps/myapp/myapp/... — inner package shares the dir name
    pkg = root / root.name
    if not pkg.is_dir():
        pkg = root  # scanning the inner package directly
    app = App(name=root.name, path=str(root))
    app.hooks = _parse_hooks(pkg / "hooks.py")
    for py in pkg.rglob("*.py"):
        app.endpoints.extend(_find_endpoints(app.name, pkg, py))
    for dj in pkg.rglob("doctype/*/*.json"):
        dt = _parse_doctype(app.name, dj)
        if dt:
            app.doctypes.append(dt)
    return app


def _parse_hooks(hooks_file: Path) -> dict:
    """Extract top-level literal assignments from hooks.py (it's declarative by convention)."""
    if not hooks_file.is_file():
        return {}
    tree = ast.parse(hooks_file.read_text(encoding="utf-8", errors="replace"))
    hooks = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                hooks[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, SyntaxError):
                pass  # computed value — skip, rules that need it can flag "unparseable"
    return hooks


def _find_endpoints(app_name: str, pkg_root: Path, py_file: Path) -> list[Endpoint]:
    try:
        tree = ast.parse(py_file.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return []
    module = ".".join(py_file.relative_to(pkg_root.parent).with_suffix("").parts)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            info = _whitelist_info(dec)
            if info is None:
                continue
            out.append(Endpoint(
                app=app_name, module=module, name=node.name,
                file=str(py_file), line=node.lineno,
                allow_guest=info.get("allow_guest", False),
                methods=info.get("methods", []),
                args=[a.arg for a in node.args.args if a.arg not in ("self", "cls")],
            ))
    return out


def _whitelist_info(dec: ast.expr) -> dict | None:
    """Return kwargs dict if decorator is frappe.whitelist(...), else None."""
    target = dec.func if isinstance(dec, ast.Call) else dec
    name = ast.unparse(target)
    if name not in ("frappe.whitelist", "whitelist"):
        return None
    info = {}
    if isinstance(dec, ast.Call):
        for kw in dec.keywords:
            try:
                info[kw.arg] = ast.literal_eval(kw.value)
            except (ValueError, SyntaxError):
                pass
    return info


def _parse_doctype(app_name: str, json_file: Path) -> DocType | None:
    try:
        data = json.loads(json_file.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict) or data.get("doctype") != "DocType":
        return None
    fields = data.get("fields", [])
    fieldnames = [f.get("fieldname") for f in fields if isinstance(f, dict) and f.get("fieldname")]
    password_fields = [f.get("fieldname") for f in fields
                        if isinstance(f, dict) and f.get("fieldtype") == "Password"
                        and int(f.get("permlevel") or 0) == 0]
    return DocType(
        app=app_name, name=data.get("name", json_file.stem), file=str(json_file),
        is_child=bool(data.get("istable")), permissions=data.get("permissions", []),
        fieldnames=fieldnames, password_fields=password_fields,
    )
