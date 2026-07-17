"""Site configuration audit. Separate from app rules — operates on Site, not App."""
from ..model import Finding, Site

# key present and truthy -> finding
_FLAG_RULES = [
    ("developer_mode", "critical", "developer_mode is on — arbitrary code execution via UI, never in production"),
    ("allow_tests", "high", "allow_tests is on — test endpoints exposed"),
    ("ignore_csrf", "high", "ignore_csrf is on — CSRF protection disabled"),
    ("disable_website_cache", "info", "website cache disabled — performance, not security"),
    ("mute_emails", "info", "emails are muted"),
    ("server_script_enabled", "medium", "server scripts enabled — Python execution via UI, audit who has Script Manager role"),
]


def run_config(sites: list[Site]) -> list[Finding]:
    findings = []
    for site in sites:
        cfg = site.config
        for key, sev, msg in _FLAG_RULES:
            if cfg.get(key):
                findings.append(_f(site, "FRAP-CONF-001", sev, f"{site.name}: {msg}"))
        if not cfg.get("encryption_key"):
            findings.append(_f(site, "FRAP-CONF-002", "medium",
                               f"{site.name}: no encryption_key — password fields fall back to unencrypted storage"))
        if cfg.get("db_password") and cfg["db_password"] in ("admin", "root", "password", "123456", "frappe"):
            findings.append(_f(site, "FRAP-CONF-003", "critical",
                               f"{site.name}: trivial db_password"))
        if cfg.get("admin_password"):
            findings.append(_f(site, "FRAP-CONF-004", "high",
                               f"{site.name}: admin_password stored in site_config.json"))
        cors = cfg.get("allow_cors")
        if cors == "*" or (isinstance(cors, list) and "*" in cors):
            findings.append(_f(site, "FRAP-CONF-005", "high",
                               f"{site.name}: allow_cors is '*' — any origin can call the API with credentials"))
    return findings


def _f(site: Site, rule_id: str, sev: str, msg: str) -> Finding:
    return Finding(rule_id=rule_id, severity=sev, message=msg, file=site.file)
