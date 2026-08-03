"""Rule registry. A rule is a function (app: App) -> list[Finding], registered via @rule."""
from ..model import App, Finding

_RULES = []


def rule(fn):
    _RULES.append(fn)
    return fn


def run_all(apps: list[App]) -> list[Finding]:
    from . import api, business, hooks, permissions, tenancy  # noqa: F401 — importing registers rules
    # secrets: hand-rolled regex dropped in favor of `frapsec/secrets_scan.py`
    # (detect-secrets) -- wired into cli.py, not the @rule pipeline.
    findings = []
    for app in apps:
        for r in _RULES:
            findings.extend(r(app))

    # tenancy.cross_company_query needs a BENCH-WIDE doctype index (the
    # risky call is usually a connector querying a core doctype it doesn't
    # itself define) -- not a plain @rule, called directly with all apps.
    company_doctypes = tenancy.company_doctypes_in(apps)
    for app in apps:
        findings.extend(tenancy.cross_company_query(app, company_doctypes))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.severity, 5))
    return findings
