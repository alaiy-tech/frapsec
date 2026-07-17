"""Rule registry. A rule is a function (app: App) -> list[Finding], registered via @rule."""
from ..model import App, Finding

_RULES = []


def rule(fn):
    _RULES.append(fn)
    return fn


def run_all(apps: list[App]) -> list[Finding]:
    from . import api, business, hooks, permissions  # noqa: F401 — importing registers rules
    findings = []
    for app in apps:
        for r in _RULES:
            findings.extend(r(app))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.severity, 5))
    return findings
