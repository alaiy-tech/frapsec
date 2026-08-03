"""Rule registry. A rule is a function (app: App) -> list[Finding], registered via @rule.

Each rule's category is its own module name (api, business, database, hooks,
permissions, tenancy) -- no manual per-rule tagging needed. `--only` filters
by this category. Categories match the rule file layout, not spec's smaller
4-mode list (api/permissions/config/business) -- database and hooks are
real, distinct categories with their own rules; forcing them into one of
the 4 named modes would just be a worse, lossier label for the same thing.
"""
from ..model import App, Finding

_RULES = []
CATEGORIES = ("api", "business", "database", "hooks", "permissions", "tenancy")


def rule(fn):
    fn._frapsec_category = fn.__module__.rsplit(".", 1)[-1]
    _RULES.append(fn)
    return fn


def run_all(apps: list[App], only: set[str] | None = None) -> list[Finding]:
    from . import api, business, database, hooks, permissions, tenancy  # noqa: F401 — importing registers rules
    # secrets: hand-rolled regex dropped in favor of `frapsec/secrets_scan.py`
    # (detect-secrets) -- wired into cli.py, not the @rule pipeline.
    findings = []
    for app in apps:
        for r in _RULES:
            if only is not None and r._frapsec_category not in only:
                continue
            findings.extend(r(app))

    # tenancy.cross_company_query needs a BENCH-WIDE doctype index (the
    # risky call is usually a connector querying a core doctype it doesn't
    # itself define) -- not a plain @rule, called directly with all apps.
    if only is None or "tenancy" in only:
        company_doctypes = tenancy.company_doctypes_in(apps)
        for app in apps:
            findings.extend(tenancy.cross_company_query(app, company_doctypes))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.severity, 5))
    return findings
