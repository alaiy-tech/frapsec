"""Permission-model rules over DocType JSON."""
from . import rule
from .catalog import (ADMIN_TIER_ROLES, MONEY_FIELDNAME_HINTS, MONEY_FIELDTYPES,
                      NUMERIC_FIELDTYPES, WRITE_PERMS)
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


def _money_fields_at_permlevel_zero(dt) -> list[str]:
    """Money-carrying fields left at permlevel 0.

    Fieldtype is authoritative where it can be -- a Currency field always holds
    money. Fieldname is the fallback for the ones no fieldtype distinguishes: a
    Percent field matters when it is a discount and does not when it is a
    progress bar, and only the name says which.
    """
    out = []
    for f in dt.fields:
        if int(f.get("permlevel") or 0) != 0:
            continue  # already gated behind a permlevel -- the intended fix
        name = (f.get("fieldname") or "").lower()
        ftype = f.get("fieldtype")
        is_money = ftype in MONEY_FIELDTYPES or (
            ftype in NUMERIC_FIELDTYPES and any(h in name for h in MONEY_FIELDNAME_HINTS)
        )
        if is_money:
            if f.get("read_only"):
                continue  # cannot be written through the form at all
            out.append(f.get("fieldname"))
    return out


@rule
def money_field_writable_at_permlevel_zero(app: App) -> list[Finding]:
    """A non-admin role can write a price or discount field with no field-level gate.

    Frappe's mechanism for "this role may edit the document but not THIS field"
    is permlevel: a field above 0 needs a matching permlevel row to be written.
    A money field left at permlevel 0 in a DocType a non-admin role can write
    means that role can change what something costs -- discount a sale to zero,
    alter a rate after approval -- and nothing in the permission model stops it.

    Deliberately narrow. Only DocTypes that actually grant write to a non
    admin-tier role are considered, read-only fields are skipped since they
    cannot be written through the form regardless, and any field already raised
    above permlevel 0 is skipped because that IS the fix. Reports the roles and
    fields rather than a verdict: whether a Sales User should be able to
    discount is a business decision, and the point is to surface that nobody has
    made it explicitly.
    """
    findings = []
    for dt in app.doctypes:
        money = _money_fields_at_permlevel_zero(dt)
        if not money:
            continue
        roles = []
        for perm in dt.permissions:
            role = perm.get("role")
            if not role or role in ADMIN_TIER_ROLES:
                continue
            if perm.get("write") and not perm.get("if_owner"):
                roles.append(role)
        if not roles:
            continue
        shown = ", ".join(sorted(set(money))[:6])
        more = "" if len(set(money)) <= 6 else f" (+{len(set(money)) - 6} more)"
        findings.append(Finding(
            rule_id="FRAP-PERM-005", severity="medium", app=app.name,
            message=f"DocType '{dt.name}': role(s) {', '.join(sorted(set(roles)))} can write "
                    f"money field(s) {shown}{more} at permlevel 0 — no field-level gate, so "
                    "that role can change prices or discounts; raise the field's permlevel if "
                    "it should need a separate grant",
            file=dt.file,
        ))
    return findings
