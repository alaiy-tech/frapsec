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
    ("db_no_check_but_unknown_decorator", '''
import frappe
@frappe.whitelist()
@administrator_only
def h(name):
    return frappe.db.get_all("Sales Invoice", filters={"customer": name})
''', "FRAP-API-002", "info"),

    # A READ with no check leaks data; a WRITE with no check lets any logged-in
    # user change another user's records. Grading both medium buried the second
    # among the first -- measured on ten real connector apps, 4 unauthenticated
    # writes sat in an undifferentiated pile of 21.
    ("db_write_no_check_is_high", '''
import frappe
@frappe.whitelist()
def h(name, status):
    frappe.db.set_value("Scraped Product", name, "review_status", status)
''', "FRAP-API-002", "high"),

    ("db_delete_no_check_is_high", '''
import frappe
@frappe.whitelist()
def h(name):
    frappe.db.delete("Scraped Product", {"name": name})
''', "FRAP-API-002", "high"),

    # A plain read stays medium -- leaking sync metadata is real but is not the
    # same finding as an unauthenticated write.
    ("db_read_no_check_stays_medium", '''
import frappe
@frappe.whitelist()
def h(name):
    return frappe.db.get_all("Sales Invoice", filters={"customer": name})
''', "FRAP-API-002", "medium"),

    # frappe.db.sql is not automatically a write. Counting every sql() as one
    # put 5 plain SELECTs at high out of 9 on real code -- precise enough to be
    # ignored, which is the failure this grading exists to prevent.
    ("db_sql_select_is_a_read", '''
import frappe
@frappe.whitelist()
def h():
    return frappe.db.sql("SELECT name FROM `tabThing`", as_dict=True)
''', "FRAP-API-002", "medium"),

    ("db_sql_update_is_a_write", '''
import frappe
@frappe.whitelist()
def h(name):
    frappe.db.sql("UPDATE `tabThing` SET status = 'x' WHERE name = %s", name)
''', "FRAP-API-002", "high"),

    # A CTE that ends in a SELECT is still a read.
    ("db_sql_with_cte_is_a_read", '''
import frappe
@frappe.whitelist()
def h():
    return frappe.db.sql("WITH t AS (SELECT 1) SELECT * FROM t", as_dict=True)
''', "FRAP-API-002", "medium"),

    # A query the AST cannot read as a literal is treated as a write: missing a
    # real write costs more than over-grading a read, and an f-string in SQL is
    # worth a look on its own account.
    ("db_sql_fstring_is_treated_as_a_write", '''
import frappe
@frappe.whitelist()
def h(col):
    return frappe.db.sql(f"SELECT {col} FROM `tabThing`", as_dict=True)
''', "FRAP-API-002", "high"),
    ("db_with_check", '''
import frappe
@frappe.whitelist()
def h(name):
    frappe.has_permission("Sales Invoice", throw=True)
    return frappe.db.get_all("Sales Invoice", filters={"customer": name})
''', "FRAP-API-002", False),
    # FRAP-BIZ-005 -- code that grants a role or writes the permission model.
    # The other escalation shape next to set_user("Administrator"), and the
    # quieter one: a granted role outlives the request.
    ("role_grant_from_endpoint_bypassing_perms", '''
import frappe
@frappe.whitelist()
def invite(email, role):
    user = frappe.new_doc("User")
    user.email = email
    user.append("roles", {"role": role})
    user.insert(ignore_permissions=True)
''', "FRAP-BIZ-005", "high"),

    ("role_grant_from_endpoint_no_bypass", '''
import frappe
@frappe.whitelist()
def invite(email):
    user = frappe.new_doc("User")
    user.append("roles", {"role": "Fixed Role"})
    user.insert()
''', "FRAP-BIZ-005", "medium"),

    # Install and onboarding code assigns roles legitimately and constantly.
    # Not reachable from an endpoint means it is not attacker-facing.
    ("role_grant_in_install_code", '''
import frappe
def create_roles():
    r = frappe.new_doc("Role")
    r.role_name = "My Role"
    r.insert(ignore_permissions=True)
''', "FRAP-BIZ-005", "info"),

    # READING a privilege doctype is not granting one. Confirmed live: a
    # "who is on my team" endpoint calling get_all("User Permission", ...) was
    # flagged as granting a role.
    ("reading_has_role_is_not_a_grant", '''
import frappe
@frappe.whitelist()
def my_team(brand):
    return frappe.get_all("Has Role", filters={"role": brand}, pluck="parent")
''', "FRAP-BIZ-005", False),

    # An ordinary doctype write is not the permission model.
    ("writing_a_normal_doctype_is_not_a_grant", '''
import frappe
@frappe.whitelist()
def make_thing():
    d = frappe.new_doc("Sales Order")
    d.insert(ignore_permissions=True)
''', "FRAP-BIZ-005", False),

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
    # FRAP-BIZ-003 -- direction-graded: jump to submitted/cancelled (1/2) is
    # the real risk (high); reset back to draft (0) is a common benign
    # undo/restore pattern (info); dynamic value can't be proven (medium)
    ("docstatus_assign_to_cancelled", '''
def cancel_hack(doc):
    doc.docstatus = 2
''', "FRAP-BIZ-003", "high"),
    ("docstatus_reset_to_draft", '''
def restore_as_draft(doc):
    doc.docstatus = 0
''', "FRAP-BIZ-003", "info"),
    ("docstatus_dynamic_value", '''
def maybe_reset(doc, new_status):
    doc.docstatus = new_status
''', "FRAP-BIZ-003", "medium"),
    ("docstatus_proper", '''
def do_cancel(doc):
    doc.cancel()
''', "FRAP-BIZ-003", False),
    ("docstatus_canonical_submit_impl", '''
class Document:
    def _submit(self):
        self.docstatus = 1
        return self.save()
''', "FRAP-BIZ-003", False),
    ("docstatus_discard_method_excluded", '''
class Document:
    def discard(self):
        self.docstatus = 2
''', "FRAP-BIZ-003", False),
    ("docstatus_discard_standalone_function_not_excluded", '''
def discard(doc):
    doc.docstatus = 2
''', "FRAP-BIZ-003", True),
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
    # FRAP-DB-001 -- reachability-graded like BIZ-001/002: unreachable -> medium,
    # reachable (via a whitelisted endpoint) -> critical
    ("db_delete_no_filter_unreachable", '''
import frappe
def wipe(doctype):
    frappe.db.delete(doctype)
''', "FRAP-DB-001", "medium"),
    ("db_delete_no_filter_reachable", '''
import frappe
@frappe.whitelist()
def entry(doctype):
    wipe(doctype)
def wipe(doctype):
    frappe.db.delete(doctype)
''', "FRAP-DB-001", "critical"),
    ("db_delete_with_filter", '''
import frappe
def cleanup(doctype):
    frappe.db.delete(doctype, {"status": "Cancelled"})
''', "FRAP-DB-001", False),
    # FRAP-DB-002
    ("raw_delete_no_where_reachable", '''
import frappe
@frappe.whitelist()
def entry():
    wipe()
def wipe():
    frappe.db.sql("DELETE FROM `tabItem`")
''', "FRAP-DB-002", "critical"),
    ("raw_delete_with_where", '''
import frappe
def cleanup():
    frappe.db.sql("DELETE FROM `tabItem` WHERE disabled = 1")
''', "FRAP-DB-002", False),
    ("raw_delete_where_across_lines", '''
import frappe
def cleanup():
    frappe.db.sql("""
        DELETE FROM `tabItem`
        WHERE disabled = 1
    """)
''', "FRAP-DB-002", False),
    ("raw_update_no_where_unreachable", '''
import frappe
def reset():
    frappe.db.sql("UPDATE `tabItem` SET disabled = 0")
''', "FRAP-DB-002", "low"),
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
    ("password_writable_but_owner_scoped", [{"role": "Desk User", "read": 1, "write": 1, "if_owner": 1}],
     [{"fieldname": "refresh_token", "fieldtype": "Password"}], "FRAP-PERM-004", False),

    # FRAP-PERM-005 -- money fields writable at permlevel 0 by a non-admin role.
    ("currency_field_writable_by_role", [{"role": "Sales User", "read": 1, "write": 1}],
     [{"fieldname": "price", "fieldtype": "Currency"}], "FRAP-PERM-005", True),
    ("discount_percent_writable_by_role", [{"role": "Sales User", "read": 1, "write": 1}],
     [{"fieldname": "discount_percentage", "fieldtype": "Percent"}], "FRAP-PERM-005", True),

    # Raised above permlevel 0 -- that IS the fix, must not fire.
    ("currency_field_gated_by_permlevel", [{"role": "Sales User", "read": 1, "write": 1}],
     [{"fieldname": "price", "fieldtype": "Currency", "permlevel": 1}], "FRAP-PERM-005", False),

    # Admin-tier roles are the intended answer to "who may edit this".
    ("currency_writable_only_by_admin_tier", [{"role": "System Manager", "read": 1, "write": 1}],
     [{"fieldname": "price", "fieldtype": "Currency"}], "FRAP-PERM-005", False),

    # Read-only cannot be written through the form regardless of permlevel.
    ("currency_field_read_only", [{"role": "Sales User", "read": 1, "write": 1}],
     [{"fieldname": "price", "fieldtype": "Currency", "read_only": 1}], "FRAP-PERM-005", False),

    # No write grant at all -- nothing to gate.
    ("currency_field_read_access_only", [{"role": "Sales User", "read": 1}],
     [{"fieldname": "price", "fieldtype": "Currency"}], "FRAP-PERM-005", False),

    # A name hint on a non-numeric fieldtype is NOT a money field. Confirmed
    # live: orders_selling_price_list is a Link naming which price list to use.
    ("price_in_name_but_a_link_field", [{"role": "Sales User", "read": 1, "write": 1}],
     [{"fieldname": "orders_selling_price_list", "fieldtype": "Link", "options": "Price List"}],
     "FRAP-PERM-005", False),

    # A Percent field that is not a discount must not fire on the hint list.
    ("percent_field_that_is_not_money", [{"role": "Sales User", "read": 1, "write": 1}],
     [{"fieldname": "completion_percent", "fieldtype": "Percent"}], "FRAP-PERM-005", False),
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

    # FRAP-TENANT-002 -- cache keys shared across every site on the bench.
    ("cache_key_literal_inline", '''
import frappe
def is_broken():
    return frappe.cache().get_value("scrape:browser_broken")
''', ["status"], "FRAP-TENANT-002", True),

    # The common real shape: the key is a module-level constant, not inline.
    ("cache_key_module_constant", '''
import frappe
_LOCK = "sync_running"
def acquire():
    return frappe.cache().set_value(_LOCK, "1")
''', ["status"], "FRAP-TENANT-002", True),

    # Scoped by site -- correct, must not fire.
    ("cache_key_scoped_by_site", '''
import frappe
def get_thing():
    return frappe.cache().get_value(f"thing::{frappe.local.site}")
''', ["status"], "FRAP-TENANT-002", False),

    # Scoped by session -- correct, must not fire. This is the real amazon
    # oauth-state shape, which was clean on a live scan.
    ("cache_key_scoped_by_session", '''
import frappe
def state_key():
    return frappe.cache().get_value(f"oauth_state::{frappe.session.sid}")
''', ["status"], "FRAP-TENANT-002", False),

    # Key computed by a call the AST cannot follow -- skipped, not guessed at.
    ("cache_key_from_unfollowable_call", '''
import frappe
def get_token(refresh):
    return frappe.cache().get_value(_key(refresh))
''', ["status"], "FRAP-TENANT-002", False),

    # A cache object held in a local, the other real shape.
    ("cache_via_local_variable", '''
import frappe
def slot():
    cache = frappe.cache()
    return cache.get_value("browser_slot")
''', ["status"], "FRAP-TENANT-002", True),

    # Not a cache call at all -- get_value on frappe.db must not fire.
    ("db_get_value_is_not_a_cache_call", '''
import frappe
def thing():
    return frappe.db.get_value("Thing", "x", "status")
''', ["status"], "FRAP-TENANT-002", False),

    # FRAP-TENANT-003 -- get_value/exists SEARCHING a multi-company DocType.
    # The same leak as an unfiltered get_list, in the shape people do not think
    # of as a query. Confirmed live: a connector looked up a channel by its
    # channel_id alone, so a second company with the same id would win.
    ("get_value_dict_filter_no_company", '''
import frappe
def find(chan):
    return frappe.db.get_value("Thing", {"channel_id": chan}, "customer_group")
''', ["company", "channel_id"], "FRAP-TENANT-003", True),

    ("exists_dict_filter_no_company", '''
import frappe
def check(ref):
    return frappe.db.exists("Thing", {"external_ref": ref})
''', ["company", "external_ref"], "FRAP-TENANT-003", True),

    ("get_value_dict_filter_with_company", '''
import frappe
def find(chan, comp):
    return frappe.db.get_value("Thing", {"channel_id": chan, "company": comp}, "x")
''', ["company", "channel_id"], "FRAP-TENANT-003", False),

    # A primary-key lookup is not a search -- the caller already knows the
    # record. Flagging these would bury the real findings under every ordinary
    # get_value in the codebase.
    ("get_value_by_primary_key", '''
import frappe
def find(name):
    return frappe.db.get_value("Thing", name, "status")
''', ["company", "status"], "FRAP-TENANT-003", False),

    # No company field on the DocType means no cross-company concept at all.
    ("get_value_doctype_has_no_company", '''
import frappe
def find(code):
    return frappe.db.get_value("Thing", {"code": code}, "name")
''', ["code"], "FRAP-TENANT-003", False),

    # A filter the AST cannot read is skipped, not guessed at -- same posture
    # the get_list check already takes.
    ("get_value_filter_is_a_variable", '''
import frappe
def find(filt):
    return frappe.db.get_value("Thing", filt, "name")
''', ["company", "code"], "FRAP-TENANT-003", False),
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

        # callgraph #18: self.foo() inherited from a base class in ANOTHER
        # file must resolve, not just same-file. base.py's dangerous() has
        # no @frappe.whitelist itself -- only reachable via Child.entry().
        cls_app_root = build_app(tmp, "cls_app")
        cls_pkg = Path(cls_app_root) / "cls_app"
        (cls_pkg / "base.py").write_text(
            'class Base:\n    def dangerous(self):\n        import frappe\n'
            '        frappe.set_user("Administrator")\n')
        (cls_pkg / "child.py").write_text(
            'import frappe\nfrom cls_app.base import Base\n\n'
            'class Child(Base):\n    @frappe.whitelist()\n    def entry(self):\n'
            '        self.dangerous()\n')
        cls_app = discovery.discover_app(cls_app_root)
        cls_findings = run_all([cls_app])
        biz001_hits = [f for f in cls_findings if f.rule_id == "FRAP-BIZ-001"]
        assert biz001_hits and biz001_hits[0].severity == "high", (
            f"self.dangerous() inherited cross-file should resolve as reachable+unscoped (high), "
            f"got: {[(h.severity, h.file) for h in biz001_hits]}")
    print(f"OK ({len(PY_CASES) + len(HOOKS_CASES) + len(PERM_CASES) + len(FIELD_PERM_CASES) + len(TENANT_CASES) + 4} cases)")


if __name__ == "__main__":
    test()
