# frapsec

Framework-aware security scanner for Frappe/ERPNext benches. Static — never imports Frappe, just reads the bench.

## Usage

```
pip install -e .
frapsec scan bench /path/to/bench
frapsec scan app /path/to/bench/apps/myapp --format sarif
```

Exit code 1 when critical/high findings exist (CI-friendly).

## Layout

- `frapsec/discovery.py` — walks bench/app, parses hooks.py (AST), DocType JSON, `@frappe.whitelist` endpoints
- `frapsec/model.py` — App / DocType / Endpoint / Finding dataclasses
- `frapsec/rules/` — one file per category; add a rule with the `@rule` decorator
- `frapsec/report.py` — text / JSON / SARIF output

## Rules so far

| ID | Sev | What |
|----|-----|------|
| FRAP-API-001 | high | `allow_guest=True` endpoint |
| FRAP-API-002 | medium | whitelisted method hits `frappe.db` with no permission check |
| FRAP-PERM-001 | critical | Guest role has write-level DocType perms |
| FRAP-PERM-002 | medium | Guest role has read DocType perm |
| FRAP-PERM-003 | low | role has write perms without read |

## Test

```
python tests/test_smoke.py
```
