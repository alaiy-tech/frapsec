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
    ("guest_hmac_in_helper", '''
import frappe, hmac, hashlib
@frappe.whitelist(allow_guest=True)
def h():
    raw = frappe.request.data
    if not _verify_signature(raw, frappe.request.headers.get("X-Sig", "")):
        return
def _verify_signature(raw, sig):
    expected = hmac.new(b"k", raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)
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
    # FRAP-BIZ-001 -- reachability-graded: unreachable from any endpoint -> info,
    # reachable + unscoped -> high, reachable + scoped (try/finally restore) -> medium
    ("set_admin_unreachable", '''
import frappe
def install_job():
    frappe.set_user("Administrator")
''', "FRAP-BIZ-001", "info"),
    ("set_admin_reachable_unscoped", '''
import frappe
@frappe.whitelist()
def public_entry():
    elevate()
def elevate():
    frappe.set_user("Administrator")
''', "FRAP-BIZ-001", "high"),
    ("set_admin_reachable_via_enqueue", '''
import frappe
@frappe.whitelist(allow_guest=True)
def handle_webhook():
    frappe.enqueue("code.elevate_and_process")
def elevate_and_process():
    frappe.set_user("Administrator")
''', "FRAP-BIZ-001", "high"),
    ("set_other", '''
import frappe
def job(u):
    frappe.set_user(u)
''', "FRAP-BIZ-001", False),
    ("set_admin_scoped_restore", '''
import frappe
@frappe.whitelist()
def public_entry():
    elevate()
def elevate():
    original_user = frappe.session.user
    frappe.set_user("Administrator")
    try:
        do_thing()
    finally:
        frappe.set_user(original_user)
''', "FRAP-BIZ-001", "medium"),
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
    ("ign_perm_helper_reachable", '''
import frappe
@frappe.whitelist()
def public_entry(d):
    _save(d)
def _save(d):
    frappe.get_doc(d).insert(ignore_permissions=True)
''', "FRAP-BIZ-002", "medium"),
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
    # secrets rule moved to secrets_scan.py (detect-secrets wrapper),
    # tested separately in tests/test_secrets_scan.py, not part of run_all().
    # FRAP-DB-001
    ("db_delete_no_filter", '''
import frappe
def wipe(doctype):
    frappe.db.delete(doctype)
''', "FRAP-DB-001", True),
    ("db_delete_with_filter", '''
import frappe
def cleanup(doctype):
    frappe.db.delete(doctype, {"status": "Cancelled"})
''', "FRAP-DB-001", False),
    # FRAP-DB-002
    ("raw_delete_no_where", '''
import frappe
def wipe():
    frappe.db.sql("DELETE FROM `tabItem`")
''', "FRAP-DB-002", True),
    ("raw_delete_with_where", '''
import frappe
def cleanup():
    frappe.db.sql("DELETE FROM `tabItem` WHERE disabled = 1")
''', "FRAP-DB-002", False),
    ("raw_update_no_where", '''
import frappe
def reset():
    frappe.db.sql("UPDATE `tabItem` SET disabled = 0")
''', "FRAP-DB-002", "high"),
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

# (label, perms, fields, rule_id, should_fire)
FIELD_PERM_CASES = [
    ("password_writable_by_low_role", [{"role": "Sales User", "read": 1, "write": 1}],
     [{"fieldname": "api_secret", "fieldtype": "Password"}], "FRAP-PERM-004", True),
    ("password_only_admin_tier", [{"role": "System Manager", "read": 1, "write": 1}],
     [{"fieldname": "api_secret", "fieldtype": "Password"}], "FRAP-PERM-004", False),
    ("password_at_elevated_permlevel", [{"role": "Sales User", "read": 1, "write": 1}],
     [{"fieldname": "api_secret", "fieldtype": "Password", "permlevel": 1}], "FRAP-PERM-004", False),
    ("no_password_field", [{"role": "Sales User", "read": 1, "write": 1}],
     [{"fieldname": "status"}], "FRAP-PERM-004", False),
]

# (label, py_src, fields, rule_id, should_fire) -- doctype is always "Thing"
TENANT_CASES = [
    ("no_company_filter", '''
import frappe
def list_things():
    return frappe.get_list("Thing")
''', ["company", "status"], "FRAP-TENANT-001", True),
    ("with_company_filter", '''
import frappe
def list_things():
    return frappe.get_list("Thing", filters={"company": "Acme", "status": "Open"})
''', ["company", "status"], "FRAP-TENANT-001", False),
    ("doctype_has_no_company_field", '''
import frappe
def list_things():
    return frappe.get_list("Thing")
''', ["status"], "FRAP-TENANT-001", False),
    ("filters_is_a_variable_not_verifiable", '''
import frappe
def list_things(filt):
    return frappe.get_list("Thing", filters=filt)
''', ["company", "status"], "FRAP-TENANT-001", False),
]


def build_app(tmp: Path, name: str, py_src: str = "", hooks_src: str = 'app_name = "a"\n',
              perms=None, fields=None, doctype_name="Thing"):
    pkg = tmp / name / name
    pkg.mkdir(parents=True)
    (pkg / "hooks.py").write_text(hooks_src)
    if py_src:
        (pkg / "code.py").write_text(py_src)
    if perms is not None or fields is not None:
        d = pkg / "mod" / "doctype" / doctype_name.lower().replace(" ", "_")
        d.mkdir(parents=True)
        field_rows = [f if isinstance(f, dict) else {"fieldname": f} for f in (fields or [])]
        (d / f"{doctype_name.lower()}.json").write_text(json.dumps({
            "doctype": "DocType", "name": doctype_name,
            "permissions": perms or [],
            "fields": field_rows,
        }))
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
        for i, (label, perms, fields, rid, expect) in enumerate(FIELD_PERM_CASES):
            app = discovery.discover_app(build_app(tmp, f"fp{i}", perms=perms, fields=fields))
            check(run_all([app]), rid, expect, label)
        for i, (label, src, fields, rid, expect) in enumerate(TENANT_CASES):
            app = discovery.discover_app(build_app(tmp, f"tn{i}", py_src=src, fields=fields))
            check(run_all([app]), rid, expect, label)

        # config cases
        s = Site(name="s", file="x", config={"developer_mode": 1})
        check(run_config([s]), "FRAP-CONF-001", True, "dev_mode")
        s = Site(name="s", file="x", config={"encryption_key": "k", "db_password": "long-random-thing"})
        check(run_config([s]), "FRAP-CONF-003", False, "good_password")

        # cross-app case: DocType (with company field) defined in a CORE
        # app, queried with no company filter by a CONNECTOR app that
        # doesn't define it itself -- the real-world shape #25 was filed
        # about. Only fires when both apps are scanned together.
        core = discovery.discover_app(build_app(tmp, "core_app", fields=["company"],
                                                  doctype_name="Sales Order"))
        connector = discovery.discover_app(build_app(tmp, "connector_app", py_src='''
import frappe
def sync():
    return frappe.get_list("Sales Order")
'''))
        cross_findings = run_all([core, connector])
        check(cross_findings, "FRAP-TENANT-001", True, "cross_app_no_company_filter")
        # and confirm scanning the connector ALONE (old, narrower behavior)
        # correctly finds nothing -- it doesn't define Sales Order itself
        check(run_all([connector]), "FRAP-TENANT-001", False, "connector_alone_cant_see_core_doctype")
    print(f"OK ({len(PY_CASES) + len(HOOKS_CASES) + len(PERM_CASES) + len(FIELD_PERM_CASES) + len(TENANT_CASES) + 4} cases)")


if __name__ == "__main__":
    test()
