"""Permission-model rules over DocType JSON."""
from . import rule
from .catalog import ADMIN_TIER_ROLES, WRITE_PERMS
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


@rule
def sensitive_field_permission(app: App) -> list[Finding]:
    """A Password field at permlevel 0 (not specially elevated) writable by
    a role other than the framework's built-in admin-tier roles. Password
    fields at permlevel 0 inherit the DocType's normal write permission --
    any role with plain write access can set/see them via the API, not just
    admins. Scoped to fieldtype Password only (highest signal, no guessing
    at which Currency/Float fields count as "sensitive" by name).

    if_owner rows are skipped: that scopes write to the user's OWN document
    only -- "any user can set their own OAuth token" is normal self-service
    design (confirmed on frappe/core: Google Calendar/Contacts integration
    docs, one per user, if_owner=1 -- both initial hits were this exact
    legitimate pattern, 0 real bugs), not "anyone can touch anyone's secret".
    """
    findings = []
    for dt in app.doctypes:
        if not dt.password_fields:
            continue
        for perm in dt.permissions:
            role = perm.get("role")
            if role in ADMIN_TIER_ROLES or not perm.get("write") or perm.get("if_owner"):
                continue
            if int(perm.get("permlevel") or 0) != 0:
                continue
            findings.append(Finding(
                rule_id="FRAP-PERM-004", severity="high", app=app.name,
                message=f"DocType '{dt.name}': role '{role}' has write access to "
                        f"password field(s) {', '.join(dt.password_fields)} at permlevel 0 — "
                        "raise the field's permlevel or restrict write to an admin-tier role",
                file=dt.file,
            ))
    return findings
