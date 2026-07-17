# frapsec

Framework-aware security scanner for Frappe/ERPNext benches. Static — never imports Frappe, just reads the bench.

## Usage

```
pip install -e .
frapsec scan bench /path/to/bench                 # apps + sites config audit
frapsec scan app apps/myapp --format sarif        # CI: exit 1 on critical/high
frapsec scan app apps/myapp --diff origin/main    # PR mode: changed files only
frapsec scan site sites/site1.local               # config audit for one site
frapsec scan app apps/myapp --format html > report.html
frapsec permissions apps/myapp                    # role -> DocType permission matrix
```

Semgrep layer (bundled Frappe security rules) runs automatically when `semgrep` is on PATH (Linux/WSL/CI); skipped otherwise. `--no-semgrep` to disable, `--semgrep-rules DIR` to override.

Full command-by-command usage with example output: [docs/USAGE.md](docs/USAGE.md).
Architecture and tech stack: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Layout

- `frapsec/discovery.py` — bench/app/site walker: hooks.py (AST), DocType JSON, `@frappe.whitelist` endpoints, site_config
- `frapsec/model.py` — App / Site / DocType / Endpoint / Finding
- `frapsec/rules/` — one file per category; add a rule with the `@rule` decorator
- `frapsec/semgrep_rules/` — vendored from frappe/semgrep-rules (MIT), ids renamed `frapsec-*`
- `frapsec/report.py` — text / JSON / SARIF / HTML + permission matrix

## Native rules

| ID | Sev | What |
|----|-----|------|
| FRAP-API-001 | crit/high/info | guest endpoint — critical if it reads request data with no HMAC verification, info if HMAC-verified webhook |
| FRAP-API-002 | medium | whitelisted method hits `frappe.db` with no permission check |
| FRAP-PERM-001/2 | crit/med | Guest role has write/read DocType perms |
| FRAP-PERM-003 | low | role has write perms without read |
| FRAP-HOOK-001 | high–info | sensitive hooks: override_whitelisted_methods, auth_hooks, override_doctype_class, before_request, … |
| FRAP-HOOK-002 | info | website route inventory (guest-reachable) |
| FRAP-HOOK-003 | medium | destructive-sounding scheduler job (runs as Administrator) |
| FRAP-BIZ-001 | high | `frappe.set_user("Administrator")` |
| FRAP-BIZ-002 | med/info | `ignore_permissions=True` — medium in whitelisted endpoints, info in background code |
| FRAP-BIZ-003 | high | direct `docstatus` mutation (bypasses submit/cancel) |
| FRAP-BIZ-004 | medium | webhook/handler inserts docs with no existence check (replay → duplicates) |
| FRAP-CONF-001..005 | crit–info | developer_mode, allow_tests, ignore_csrf, missing encryption_key, trivial db_password, admin_password in config, CORS `*` |

Plus 13 semgrep rules: SQLi (f-string/.format), eval/exec RCE, SSTI, path traversal, format-string injection, set_user audit, multitenancy breakage, redis flushall, local-proxy override, manual commit, test whitelist protection.

## Test

```
python tests/test_smoke.py
```
