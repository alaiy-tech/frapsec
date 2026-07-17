"""Permission-model rules over DocType JSON."""
from . import rule
from .catalog import WRITE_PERMS
from ..model import App, Finding


@rule
def guest_doctype_access(app: App) -> list[Finding]:
    findings = []
    for dt in app.doctypes:
        for perm in dt.permissions:
            if perm.get("role") != "Guest":
                continue
            granted = [p for p in WRITE_PERMS if perm.get(p)]
            if granted:
                findings.append(Finding(
                    rule_id="FRAP-PERM-001", severity="critical", app=app.name,
                    message=f"DocType '{dt.name}' grants Guest: {', '.join(granted)}.",
                    file=dt.file,
                ))
            elif perm.get("read"):
                findings.append(Finding(
                    rule_id="FRAP-PERM-002", severity="medium", app=app.name,
                    message=f"DocType '{dt.name}' grants Guest read access.",
                    file=dt.file,
                ))
    return findings


@rule
def write_without_read(app: App) -> list[Finding]:
    return [
        Finding(
            rule_id="FRAP-PERM-003", severity="low", app=app.name,
            message=f"DocType '{dt.name}': role '{perm.get('role')}' has write-level perms "
                    "without read — usually a misconfiguration.",
            file=dt.file,
        )
        for dt in app.doctypes for perm in dt.permissions
        if not perm.get("read") and any(perm.get(p) for p in WRITE_PERMS)
    ]
