"""Smoke test: build a fake Frappe app on disk, scan it, assert the rules fire."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from frapsec import discovery  # noqa: E402
from frapsec.rules import run_all  # noqa: E402

API_PY = '''
import frappe

@frappe.whitelist(allow_guest=True)
def public_thing():
    return "hi"

@frappe.whitelist()
def unsafe_update(name, value):
    frappe.db.set_value("Sales Order", name, "status", value)

@frappe.whitelist()
def safe_read(name):
    doc = frappe.get_doc("Sales Order", name)
    return doc.status

def not_an_endpoint():
    pass
'''

DOCTYPE_JSON = {
    "doctype": "DocType", "name": "Leaky Thing",
    "permissions": [
        {"role": "Guest", "read": 1, "write": 1},
        {"role": "Sales User", "write": 1},  # write without read
    ],
}


def make_app(root: Path) -> Path:
    app = root / "myapp"
    pkg = app / "myapp"
    (pkg / "api").mkdir(parents=True)
    (pkg / "hooks.py").write_text('app_name = "myapp"\ndoc_events = {}\n')
    (pkg / "api" / "orders.py").write_text(API_PY)
    dt = pkg / "mymodule" / "doctype" / "leaky_thing"
    dt.mkdir(parents=True)
    (dt / "leaky_thing.json").write_text(json.dumps(DOCTYPE_JSON))
    return app


def test():
    with tempfile.TemporaryDirectory() as tmp:
        app_path = make_app(Path(tmp))
        apps = [discovery.discover_app(str(app_path))]

        app = apps[0]
        assert app.hooks["app_name"] == "myapp"
        assert {e.name for e in app.endpoints} == {"public_thing", "unsafe_update", "safe_read"}
        assert [d.name for d in app.doctypes] == ["Leaky Thing"]

        rules = {f.rule_id for f in run_all(apps)}
        assert "FRAP-API-001" in rules, "guest API not flagged"
        assert "FRAP-API-002" in rules, "missing perm check not flagged"
        assert "FRAP-PERM-001" in rules, "guest write perm not flagged"
        assert "FRAP-PERM-003" in rules, "write-without-read not flagged"

        # CLI end to end, sarif output parses
        out = subprocess.run(
            [sys.executable, "-m", "frapsec.cli", "scan", "app", str(app_path), "--format", "sarif"],
            capture_output=True, text=True, cwd=Path(__file__).parent.parent,
        )
        assert out.returncode == 1, out.stderr  # high findings -> exit 1
        assert json.loads(out.stdout)["runs"][0]["results"]
    print("OK")


if __name__ == "__main__":
    test()
