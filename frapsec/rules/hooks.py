"""Rules over parsed hooks.py."""
from pathlib import Path

from . import rule
from .catalog import DESTRUCTIVE_JOB_WORDS, SENSITIVE_HOOKS
from ..model import App, Finding


@rule
def sensitive_hooks(app: App) -> list[Finding]:
    hooks_file = str(Path(app.path) / app.name / "hooks.py")
    findings = []
    for key, (sev, why) in SENSITIVE_HOOKS.items():
        val = app.hooks.get(key)
        if val:
            findings.append(Finding(
                rule_id="FRAP-HOOK-001", severity=sev, app=app.name,
                message=f"hooks.py defines {key} ({_summ(val)}): {why}",
                file=hooks_file,
            ))
    return findings


@rule
def guest_website_context(app: App) -> list[Finding]:
    """website_route_rules / portal exposure is guest-reachable by design — inventory it."""
    routes = app.hooks.get("website_route_rules") or []
    return [
        Finding(
            rule_id="FRAP-HOOK-002", severity="info", app=app.name,
            message=f"website route (guest-reachable): {r.get('from_route')} -> {r.get('to_route')}",
            file=str(Path(app.path) / app.name / "hooks.py"),
        )
        for r in routes if isinstance(r, dict)
    ]


@rule
def scheduler_inventory(app: App) -> list[Finding]:
    """Scheduler jobs run as Administrator — flag ones whose names suggest destructive scope."""
    events = app.hooks.get("scheduler_events") or {}
    findings = []
    for freq, jobs in events.items() if isinstance(events, dict) else []:
        for job in jobs if isinstance(jobs, list) else []:
            if isinstance(job, str) and any(d in job.lower() for d in DESTRUCTIVE_JOB_WORDS):
                findings.append(Finding(
                    rule_id="FRAP-HOOK-003", severity="medium", app=app.name,
                    message=f"scheduler job ({freq}) with destructive name runs as Administrator: {job}",
                    file=str(Path(app.path) / app.name / "hooks.py"),
                ))
    return findings


def _summ(val) -> str:
    if isinstance(val, dict):
        return f"{len(val)} entries"
    if isinstance(val, list):
        return f"{len(val)} entries"
    return str(val)[:60]
