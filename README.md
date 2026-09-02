# frapsec

Framework-aware security scanner for Frappe/ERPNext benches. Static by default — never imports Frappe, just reads the bench. Optional dynamic mode confirms findings against a real site.

## Usage

```
pip install -e .
frapsec scan bench /path/to/bench                 # apps + sites config audit
frapsec scan app apps/myapp --format sarif        # CI: exit 1 on critical/high
frapsec scan app apps/myapp --diff origin/main    # PR mode: changed files only
frapsec scan site sites/site1.local               # config audit for one site
frapsec scan app apps/myapp --format html > report.html
frapsec permissions apps/myapp                    # role -> DocType permission matrix
frapsec verify findings.json --site URL --confirm # dynamic: confirm findings against a real site
```

Full command-by-command usage with example output: [docs/USAGE.md](docs/USAGE.md).
Architecture and tech stack: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Changelog: [CHANGELOG.md](CHANGELOG.md).

## Scan layers (all default-on, each independently skippable)

| Layer | Tool | Skip flag |
|---|---|---|
| Native AST rules | frapsec's own (`rules/`) | always on |
| Pattern rules | semgrep, 15 security rules vendored+tuned | `--no-semgrep` |
| Python security lint | bandit | `--no-bandit` |
| Secrets | detect-secrets | `--no-secrets-scan` |
| Config audit | frapsec's own | always on |

A separate `semgrep_rules_lint/` set (i18n, JS style, code-quality — not security) exists but is **not** loaded by default; pass `--semgrep-rules frapsec/semgrep_rules_lint` to opt in.

## Layout

- `frapsec/discovery.py` — bench/app/site walker: hooks.py (AST), DocType JSON, `@frappe.whitelist` endpoints, site_config
- `frapsec/callgraph.py` — same-app reachability graph (import-aware, resolves `enqueue()`/`get_attr()` string dispatch)
- `frapsec/model.py` — App / Site / DocType / Endpoint / Finding
- `frapsec/rules/` — one file per category; add a rule with the `@rule` decorator; tunables live in `rules/catalog.py`
- `frapsec/semgrep_rules/` — vendored security subset of frappe/semgrep-rules (MIT), ids renamed `frapsec-*`
- `frapsec/semgrep_rules_lint/` — vendored non-security subset (opt-in only)
- `frapsec/bandit_scan.py`, `frapsec/secrets_scan.py`, `frapsec/semgrep.py` — optional shell-out layers, same pattern: skip with a stderr notice if the tool isn't installed
- `frapsec/dynamic/` — the only package that makes network calls; `verify` confirms static findings against a real site with real credentials
- `frapsec/baseline.py` — accept current findings, re-scans show only new ones
- `frapsec/tui.py` — rich terminal rendering (banner, mode indicator, colored tables)
- `frapsec/report.py` — text / JSON / SARIF / HTML + permission matrix

## Native rules

| ID | Sev | What |
|----|-----|------|
| FRAP-API-001 | crit/high/info | guest endpoint — critical if it writes from unverified request data, info if HMAC-verified webhook |
| FRAP-API-002 | medium | whitelisted method hits `frappe.db` with no permission check |
| FRAP-API-003 | high | whitelisted method returns a decrypted secret (`get_password()`) to the caller |
| FRAP-API-004 | high | `frappe.get_attr()` on a value traced to a DocType field — dynamic dispatch on stored data |
| FRAP-PERM-001/2 | crit/med | Guest role has write/read DocType perms |
| FRAP-PERM-003 | low | role has write perms without read |
| FRAP-HOOK-001 | high–info | sensitive hooks: override_whitelisted_methods, auth_hooks, override_doctype_class, before_request, … |
| FRAP-HOOK-002 | info | website route inventory (guest-reachable) |
| FRAP-HOOK-003 | medium | destructive-sounding scheduler job (runs as Administrator) |
| FRAP-BIZ-001 | high/med/info | `frappe.set_user("Administrator")` — graded by call-graph reachability + try/finally scoping |
| FRAP-BIZ-002 | med/info | `ignore_permissions=True` — graded by call-graph reachability from a whitelisted endpoint |
| FRAP-BIZ-003 | high | direct `docstatus` mutation (bypasses submit/cancel) |
| FRAP-BIZ-004 | medium | webhook/handler inserts docs with no existence check (replay → duplicates) |
| FRAP-CONF-001..005 | crit–info | developer_mode, allow_tests, ignore_csrf, missing encryption_key, trivial db_password, admin_password in config, CORS `*` |

Secrets are handled by detect-secrets (not a native rule) — see the scan layers table above.

## Test

```
python tests/test_rules.py    # 30 positive/negative rule cases
python tests/test_smoke.py    # end-to-end CLI + discovery
python tests/test_baseline.py
python tests/test_dynamic.py  # dynamic mode against a local mock server, no real site needed
```

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

Running a modified version as a network service means publishing your changes.
