"""Declarative rule data — tune severities/lists here without touching rule logic."""

# ---- api.py ----------------------------------------------------------------
# calls that count as a permission check inside a whitelisted method
PERM_CALLS = {"has_permission", "check_permission", "only_for", "throw_if_not_permitted"}

# frappe.db calls that mean "touches the database" (bypasses DocType perms)
DB_CALLS = ("sql", "set_value", "delete", "get_all", "get_list")

# calls that mean a guest endpoint WRITES from request data (-> critical)
WRITE_CALLS = (".insert(", ".save(", ".delete(", "delete_doc", "set_value", ".submit(", "enqueue(")

# ---- permissions.py ---------------------------------------------------------
WRITE_PERMS = ("write", "create", "delete", "submit", "cancel", "amend")

# Framework-built-in admin-tier roles present by default on every Frappe site
# (not an app-specific guess -- same class of framework primitive as
# "Administrator" already being special-cased in dynamic/cli.py). Used to
# decide whether a Password field being writable is "the admin managing
# their own settings" (normal) vs "some other role having it" (worth a look).
ADMIN_TIER_ROLES = {"Administrator", "System Manager"}

# ---- hooks.py ---------------------------------------------------------------
# hook key -> (severity, why it matters)
SENSITIVE_HOOKS = {
    "override_whitelisted_methods": ("high", "replaces core API endpoints — the override inherits the original's exposure, audit each replacement"),
    "auth_hooks": ("high", "custom authentication logic — a bug here bypasses login for the whole site"),
    "override_doctype_class": ("medium", "replaces core DocType controllers — can silently drop core validations/permission checks"),
    "before_request": ("medium", "runs on every request before auth-sensitive handlers — audit for early returns and state mutation"),
    "permission_query_conditions": ("info", "custom list-query filtering — verify conditions can't be bypassed via direct get_doc"),
    "has_permission": ("info", "custom permission logic — verify it fails closed"),
}

# scheduler job name fragments that suggest destructive scope
DESTRUCTIVE_JOB_WORDS = ("delete", "cleanup", "purge", "remove", "truncate", "reset")

# calls that decrypt/reveal a Password-fieldtype value
SECRET_REVEAL_CALLS = ("get_password",)

# ---- business.py ------------------------------------------------------------
# calls that count as an existence check before insert (idempotency)
IDEMPOTENCY_CHECKS = ("frappe.db.exists", "get_value", "get_all", "get_list", ".exists(")

# ---- config.py --------------------------------------------------------------
# site_config key present and truthy -> (severity, message)
CONFIG_FLAG_RULES = [
    ("developer_mode", "critical", "developer_mode is on — arbitrary code execution via UI, never in production"),
    ("allow_tests", "high", "allow_tests is on — test endpoints exposed"),
    ("ignore_csrf", "high", "ignore_csrf is on — CSRF protection disabled"),
    ("disable_website_cache", "info", "website cache disabled — performance, not security"),
    ("mute_emails", "info", "emails are muted"),
    ("server_script_enabled", "medium", "server scripts enabled — Python execution via UI, audit who has Script Manager role"),
]

TRIVIAL_DB_PASSWORDS = ("admin", "root", "password", "123456", "frappe")

# ---- permissions.py: FRAP-PERM-005 ------------------------------------------
# Fields whose VALUE is money or a money modifier. Writable at permlevel 0 by a
# non-admin role means anyone with that role can change what a thing costs --
# discount a sale to zero, alter a rate after approval -- with no separate
# field-level gate. Frappe's answer to that is permlevel, which is exactly what
# this checks for.
#
# Matched on fieldtype first (authoritative, set by the framework), then on
# fieldname for the ones no fieldtype can distinguish: a Percent field is only
# sensitive when it is a discount, not when it is a completion bar.
MONEY_FIELDTYPES = ("Currency",)
MONEY_FIELDNAME_HINTS = ("discount", "rate", "price", "amount", "margin", "commission")

# A name hint only counts on a fieldtype that can actually HOLD a number.
# Confirmed live: "orders_selling_price_list" is a Link to a Price List --
# it names which price list to use, it is not a price. Matching the hint
# against every fieldtype flagged it as a money field.
NUMERIC_FIELDTYPES = ("Currency", "Float", "Int", "Percent")


# ---- report.py --------------------------------------------------------------
# frapsec severity -> SARIF level
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

# severity -> HTML badge color (also fixes severity display order)
SEVERITY_COLORS = {"critical": "#d32f2f", "high": "#f57c00", "medium": "#fbc02d", "low": "#7cb342", "info": "#90a4ae"}

# DocType permission rights shown in the permission matrix
PERMISSION_RIGHTS = ("read", "write", "create", "delete", "submit", "cancel", "amend",
                     "report", "export", "share", "email", "print")
