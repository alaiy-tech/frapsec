# frapsec — architecture & tech stack

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.10+, stdlib `ast` | Frappe apps are Python; `ast` reads source without executing it — no Frappe install, no database, no running site |
| Rules | plain functions + `@rule` decorator | no rule-engine framework; a rule is `(App) -> list[Finding]` |
| Pattern layer | semgrep (vendored `frappe/semgrep-rules`, MIT) | SQLi/RCE/SSTI/traversal patterns semgrep already does well — no reason to reimplement pattern matching in `ast` |
| Reachability | hand-rolled same-app call graph (`callgraph.py`) | no off-the-shelf Python call-graph library resolves Frappe's dynamic-dispatch patterns (`frappe.enqueue("dotted.path")`, `get_attr`) — those needed custom edges |
| Output | `jinja2` (HTML), `rich` (terminal table/colors), stdlib `json` | jinja2/rich are the standard choice for each; no custom templating or ANSI-code hand-rolling |
| Dynamic verification | `requests` | one HTTP client, only imported when `verify` actually runs |
| Tests | plain `assert`-based scripts, no framework | no fixtures/plugins needed for this size of test suite |

No database, no daemon, no server. `frapsec` is a single process: read files in, print findings out.

## Data flow

```
discovery.py                 rules/*.py                    report.py / tui.py
─────────────                ──────────                    ──────────────────
walk bench/app/site      →   App/Site objects          →   list[Finding]     →   text/json/sarif/html
(ast.parse, json.load)       run through @rule funcs       sorted by severity     or rich terminal table
                              + semgrep subprocess
                                   ↓
                          callgraph.py: same-app
                          call graph, answers
                          "reachable from an
                          endpoint?" — used by
                          BIZ-001/BIZ-002 grading
```

`dynamic/` is deliberately separate from this pipeline — it's the only part of frapsec that makes network calls, and it only ever *consumes* a prior scan's JSON output, never triggers its own discovery.

## Package layout

```
frapsec/
  model.py          App, Site, DocType, Endpoint, Finding — the shared data shapes
  discovery.py       walks a bench/app/site, builds the model (pure ast/json, no execution)
  callgraph.py       same-app reachability graph; Reachability.contains(file, name)
  baseline.py        accept-current-findings so re-scans show only new ones
  semgrep.py         shells out to `semgrep`, converts results into Finding
  report.py          text / json / sarif / html renderers, severity sort shared by all of them
  tui.py             rich terminal rendering: banner, mode indicator, colored tables, spinner
  cli.py             argparse wiring — the only file that knows about command-line flags
  rules/
    __init__.py       @rule registry, run_all()
    catalog.py         every tunable list/severity/color lives here, not scattered in rule logic
    api.py             FRAP-API-001..004 (guest APIs, missing perm checks, secret leaks, dynamic dispatch)
    business.py        FRAP-BIZ-001..004 (admin impersonation, ignore_permissions, docstatus, idempotency)
    hooks.py           FRAP-HOOK-001..003 (sensitive hooks, routes, scheduler jobs)
    permissions.py     FRAP-PERM-001..003 (DocType permission table checks)
    config.py          FRAP-CONF-001..005 (site_config.json audit)
    secrets.py         FRAP-SECRET-001..002 (hardcoded credentials)
  semgrep_rules/      vendored + tuned semgrep YAML (MIT, frappe/semgrep-rules)
  templates/          HTML report Jinja2 template
  dynamic/
    __init__.py         verify() orchestration
    client.py           the one module that makes HTTP calls (login, call_endpoint)
```

## Design rules that shaped this

- **Static and dynamic are structurally separate.** `dynamic/` is the only package that imports `requests` or touches a network socket. Everything else in frapsec is guaranteed side-effect-free by construction, not by convention.
- **Tunable values live in one file** (`rules/catalog.py`) — severities, hook lists, password blocklists, colors. Rule *logic* files stay pure control flow.
- **Reachability is a signal, not a verdict.** `callgraph.py` documents its own limits in its docstring (name-based, not fully import-resolved) rather than pretending to be a real static analyzer.
- **Every severity claim gets re-validated against real code** (`frappe/` core, `alaiy_os`, the Shopify connector) before being trusted — see the project's internal ROADMAP for the running log of false positives found and fixed this way.
