# Changelog

Severity/grading changes are called out explicitly — a CI gate pinned to a version can shift behavior on upgrade, so treat any grading change as a compatibility break, not a patch.

## 0.2.0

**Grading changes (may change your CI gate's pass/fail):**
- FRAP-BIZ-001 (`set_user("Administrator")`): now reachability-graded via call graph — `info` if unreachable from any endpoint, `medium` if reachable+scoped (try/finally restore), `high` if reachable+unscoped. Previously flat `high`.
- FRAP-BIZ-002 (`ignore_permissions=True`): now reachability-graded — `medium` if reachable from a whitelisted endpoint (directly or transitively), `info` otherwise. Previously only checked the immediate function's own decorator.
- FRAP-API-001 (guest APIs): `critical` now requires a write consequence (was blanket-critical for any guest endpoint reading request data). No-argument guest endpoints downgraded to `info`.

**Added:**
- Dynamic mode: `frapsec verify` confirms static findings against a real site (`frapsec/dynamic/`).
- Call-graph reachability (`frapsec/callgraph.py`) — import-aware, resolves `enqueue()`/`get_attr()` string-dispatch targets.
- Baseline file (`--baseline`/`--update-baseline`).
- Secrets scanning via detect-secrets (`frapsec/secrets_scan.py`). Replaced the
  hand-rolled FRAP-SECRET-001/002 regex rules, which no longer exist.
- Full semgrep-rules vendoring — 47 rules across 10 source files (was 13, security-subset only).
- Rich terminal UI: banner, mode indicator, colored tables, spinner.
- HTML report (Jinja2), permission matrix command, PR diff mode.

**Fixed:**
- Two name-collision false positives in the call graph (bare-name matching merged unrelated same-named functions across files) — now import-aware, matches by (file, line) at the seed step too.
- Semgrep `_SKIP` list broken by the `frapsec-*` id rename (dup findings leaking through, fixed).
- Two semgrep rule false positives at the rule-definition level (`setup.py` file-traversal, non-test file matching `test_*.py`).

## 0.1.0

Initial scaffold: discovery, native AST rules (API/permissions/hooks/business/config), semgrep security subset (13 rules), text/JSON/SARIF output, GitHub Actions workflow.
