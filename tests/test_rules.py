"""Per-rule positive/negative cases. Each case: source snippet -> rule must / must-not fire."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from frapsec import discovery  # noqa: E402
from frapsec.model import Site  # noqa: E402
from frapsec.rules import run_all  # noqa: E402
from frapsec.rules.config import run_config  # noqa: E402

# (name, file content, rule_id, should_fire)
PY_CASES = [
    # FRAP-API-001 grading
    ("guest_no_verify", '''
import frappe
@frappe.whitelist(allow_guest=True)
def h():
    data = frappe.request.data
    frappe.get_doc({"doctype": "X", "d": data}).insert()
''', "FRAP-API-001", "critical"),
    ("guest_hmac", '''
import frappe, hmac, hashlib
@frappe.whitelist(allow_guest=True)
def h():
    raw = frappe.request.data
    sig = hmac.new(b"k", raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, frappe.request.headers.get("X-Sig", "")):
        return
''', "FRAP-API-001", "info"),
    ("guest_plain_no_args", '''
import frappe
@frappe.whitelist(allow_guest=True)
def h():
    return "static"
''', "FRAP-API-001", "info"),
    ("guest_plain_with_args", '''
import frappe
@frappe.whitelist(allow_guest=True)
def h(name):
    return frappe.get_single("Settings").get(name)
''', "FRAP-API-001", "high"),
    # FRAP-API-003
    ("secret_returned", '''
import frappe
@frappe.whitelist()
def h(connector_id):
    doc = frappe.get_single("Settings")
    return doc.get_password("api_key")
''', "FRAP-API-003", True),
    ("secret_not_returned", '''
import frappe
@frappe.whitelist()
def h():
    doc = frappe.get_single("Settings")
    key = doc.get_password("api_key")
    call_external_api(key)
    return {"ok": True}
''', "FRAP-API-003", False),
    # FRAP-API-004
    ("dynamic_dispatch_stored", '''
import frappe
@frappe.whitelist()
def h(connector_id):
    registry = frappe.get_doc("Registry", connector_id)
    test_method = registry.test_method
    fn = frappe.get_attr(test_method)
    return fn()
''', "FRAP-API-004", True),
    ("dynamic_dispatch_hardcoded", '''
import frappe
@frappe.whitelist()
def h():
    fn = frappe.get_attr("myapp.tasks.run_check")
    return fn()
''', "FRAP-API-004", False),
    # FRAP-API-002
    ("db_no_check", '''
import frappe
@frappe.whitelist()
def h(name):
    return frappe.db.get_all("Sales Invoice", filters={"customer": name})
''', "FRAP-API-002", True),
    ("db_with_check", '''
import frappe
@frappe.whitelist()
def h(name):
    frappe.has_permission("Sales Invoice", throw=True)
    return frappe.db.get_all("Sales Invoice", filters={"customer": name})
''', "FRAP-API-002", False),
    # FRAP-BIZ-001
    ("set_admin", '''
import frappe
def job():
    frappe.set_user("Administrator")
''', "FRAP-BIZ-001", True),
    ("set_other", '''
import frappe
def job(u):
    frappe.set_user(u)
''', "FRAP-BIZ-001", False),
    # FRAP-BIZ-002 grading
    ("ign_perm_endpoint", '''
import frappe
@frappe.whitelist()
def h(d):
    frappe.get_doc(d).insert(ignore_permissions=True)
''', "FRAP-BIZ-002", "medium"),
    ("ign_perm_background", '''
import frappe
def sync_job(d):
    frappe.get_doc(d).insert(ignore_permissions=True)
''', "FRAP-BIZ-002", "info"),
    # FRAP-BIZ-003
    ("docstatus_assign", '''
def cancel_hack(doc):
    doc.docstatus = 2
''', "FRAP-BIZ-003", True),
    ("docstatus_proper", '''
def do_cancel(doc):
    doc.cancel()
''', "FRAP-BIZ-003", False),
    # FRAP-BIZ-004
    ("handler_no_idempotency", '''
import frappe
def handle_order_webhook(payload):
    frappe.get_doc({"doctype": "SO", "oid": payload["id"]}).insert()
''', "FRAP-BIZ-004", True),
    ("handler_with_check", '''
import frappe
def handle_order_webhook(payload):
    if frappe.db.exists("SO", {"oid": payload["id"]}):
        return
    frappe.get_doc({"doctype": "SO", "oid": payload["id"]}).insert()
''', "FRAP-BIZ-004", False),
    # FRAP-SECRET-001
    ("secret_real", '''
SHOPIFY_API_SECRET = "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"
''', "FRAP-SECRET-001", True),
    ("secret_placeholder", '''
api_key = "your_api_key_here_please"
''', "FRAP-SECRET-001", False),
    ("secret_lookup", '''
def get():
    api_key = "os.environ based lookup below"
    return None
''', "FRAP-SECRET-001", False),
]

HOOKS_CASES = [
    ("hooks_sensitive", 'app_name = "a"\nauth_hooks = ["a.auth.validate"]\n', "FRAP-HOOK-001", True),
    ("hooks_plain", 'app_name = "a"\n', "FRAP-HOOK-001", False),
    ("hooks_sched", 'app_name = "a"\nscheduler_events = {"daily": ["a.tasks.purge_old_logs"]}\n', "FRAP-HOOK-003", True),
]

PERM_CASES = [
    ("guest_write", [{"role": "Guest", "read": 1, "write": 1}], "FRAP-PERM-001", True),
    ("guest_read", [{"role": "Guest", "read": 1}], "FRAP-PERM-002", True),
    ("normal", [{"role": "Sales User", "read": 1, "write": 1}], "FRAP-PERM-001", False),
]


def build_app(tmp: Path, name: str, py_src: str = "", hooks_src: str = 'app_name = "a"\n', perms=None):
    pkg = tmp / name / name
    pkg.mkdir(parents=True)
    (pkg / "hooks.py").write_text(hooks_src)
    if py_src:
        (pkg / "code.py").write_text(py_src)
    if perms is not None:
        d = pkg / "mod" / "doctype" / "thing"
        d.mkdir(parents=True)
        (d / "thing.json").write_text(json.dumps(
            {"doctype": "DocType", "name": "Thing", "permissions": perms}))
    return str(tmp / name)


def check(findings, rule_id, expect, label):
    hits = [f for f in findings if f.rule_id == rule_id]
    if expect is True:
        assert hits, f"{label}: {rule_id} should fire"
    elif expect is False:
        assert not hits, f"{label}: {rule_id} should NOT fire: {[f.message for f in hits]}"
    else:  # expected severity
        assert hits, f"{label}: {rule_id} should fire"
        assert hits[0].severity == expect, f"{label}: expected {expect}, got {hits[0].severity}"


def test():
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        for i, (label, src, rid, expect) in enumerate(PY_CASES):
            app = discovery.discover_app(build_app(tmp, f"py{i}", py_src=src))
            check(run_all([app]), rid, expect, label)
        for i, (label, hooks_src, rid, expect) in enumerate(HOOKS_CASES):
            app = discovery.discover_app(build_app(tmp, f"hk{i}", hooks_src=hooks_src))
            check(run_all([app]), rid, expect, label)
        for i, (label, perms, rid, expect) in enumerate(PERM_CASES):
            app = discovery.discover_app(build_app(tmp, f"pm{i}", perms=perms))
            check(run_all([app]), rid, expect, label)

        # config cases
        s = Site(name="s", file="x", config={"developer_mode": 1})
        check(run_config([s]), "FRAP-CONF-001", True, "dev_mode")
        s = Site(name="s", file="x", config={"encryption_key": "k", "db_password": "long-random-thing"})
        check(run_config([s]), "FRAP-CONF-003", False, "good_password")
    print(f"OK ({len(PY_CASES) + len(HOOKS_CASES) + len(PERM_CASES) + 2} cases)")


if __name__ == "__main__":
    test()
