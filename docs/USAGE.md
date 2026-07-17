# frapsec — command usage

---

## `scan bench|app|site <path>`

Static analysis. Reads source only — never executes anything, never needs a running site.

```
frapsec scan <bench|app|site> <path> [flags]
```

**Positional arguments**

| Arg | Required | Meaning |
|---|---|---|
| `bench\|app\|site` | yes | scan target type. `bench` = walk `apps/` + `sites/`. `app` = one app dir. `site` = one `sites/<name>` dir, config only, no code |
| `path` | yes | path to that bench/app/site directory |

**Flags**

| Flag | Default | Meaning |
|---|---|---|
| `--format text\|json\|sarif\|html` | `text` | output format. `text` on a real terminal renders a colored table automatically |
| `--no-semgrep` | off | skip the semgrep layer entirely |
| `--semgrep-rules DIR` | bundled rules | use a different semgrep rules directory instead of frapsec's own |
| `--diff REF` | none | PR mode — only report findings in files that differ from git ref `REF` (e.g. `origin/main`). Runs `git diff --name-only REF` inside `path`, so `path` must be a git repo |
| `--baseline PATH` | none | only report findings not already recorded in the baseline file at `PATH` |
| `--update-baseline` | off | write every current finding into `--baseline` as accepted, print a count, exit (does not print the findings) |
| `--plain` | off | force plain text even on a real terminal — no colors, no table |

**Requirements**: semgrep on `PATH` for the semgrep layer (auto-skipped with a stderr notice if missing — scan still runs, just without those 13 rules). `--format html` needs `jinja2` (already a hard dependency). `--diff` needs `git` on `PATH`.

**Exit code**: `1` if any `critical`/`high` finding exists, `0` otherwise — CI-friendly.

**Example**

```
frapsec scan app /path/to/bench/apps/myapp
```

```
[MEDIUM  ] FRAP-API-002  api/sync.py:73
           get_sync_status hits the database with no visible permission check.
[MEDIUM  ] FRAP-BIZ-001  shopify/order/utils.py:26
           _as_administrator() switches session to Administrator (scoped) — verify caller path.
...
39 finding(s).
```

---

## `permissions <path>`

Dumps the role → DocType permission matrix. No judgment, just the raw data from DocType JSON.

```
frapsec permissions <path> [--format text|json]
```

| Arg/Flag | Default | Meaning |
|---|---|---|
| `path` | required | app directory |
| `--format text\|json` | `text` | `json` gives `{role: {doctype: [rights]}}` |

**Example**

```
frapsec permissions /path/to/bench/apps/myapp
```

```
System Manager
  Shopify Connector Settings    read, write, create, delete, share, print
  Shopify Sync Log              read, report
```

---

## `verify <findings.json>`

**Dynamic mode.** Confirms specific static findings against a REAL running site using real credentials — the only frapsec command that makes network calls.

```
frapsec verify <findings.json> --site URL --confirm [auth flags] [--format text|json]
```

| Arg/Flag | Required | Meaning |
|---|---|---|
| `findings_json` | yes | path to JSON produced by `frapsec scan ... --format json` |
| `--site URL` | yes | e.g. `https://staging.example.com` |
| `--confirm` | yes | hard-required — omitting it refuses to run, since this makes real network calls |
| `--api-key` | one auth pair required | Frappe API key. Prefer env var `FRAPSEC_API_KEY` over this flag — a flag value can leak via shell history/`ps` |
| `--api-secret` | " | pairs with `--api-key`. Prefer env var `FRAPSEC_API_SECRET` |
| `--username` | alternative to api-key/secret | session login instead of a token. Prefer env var `FRAPSEC_USERNAME` |
| `--password` | " | pairs with `--username`. Prefer env var `FRAPSEC_PASSWORD` |
| `--format text\|json` | `text` | `json` dumps the full findings list with `.verified` filled in |

**Credentials — exactly one pair required**: (`--api-key` + `--api-secret`) OR (`--username` + `--password`), each with an equivalent env var (`FRAPSEC_API_KEY`, `FRAPSEC_API_SECRET`, `FRAPSEC_USERNAME`, `FRAPSEC_PASSWORD`) that's checked first if the flag is empty.

**Hard refusals** (exit before any network call):
- No `--confirm` → refuses, tells you to pass it.
- No usable credential pair → refuses, lists what's missing.
- `--username Administrator` (any case) → refuses outright. Administrator can reach everything, so every result comes back `REACHABLE` and proves nothing about any other role.

**What it actually does**: for every finding in the JSON that has an `endpoint` (only `FRAP-API-001..004` set this), sends one `GET /api/method/<endpoint>` per distinct endpoint and classifies the response:

| Result | HTTP | Meaning |
|---|---|---|
| `reachable` | 200 | this account really can call it — static guess confirmed |
| `blocked` | 401 / 403 / 417 with a PermissionError | this role genuinely can't reach it |
| `error` | anything else, or a network failure | inconclusive — check manually |

Findings with no `endpoint` (hooks, config, business-logic rules) are left untouched — `verify` cannot scan a site on its own, only confirm what a prior static scan already flagged.

**Requirements**: `requests` (only imported when `verify` runs, not a hard install dependency). The site must be reachable from wherever you run frapsec.

**Example**

```
export FRAPSEC_API_KEY=...
export FRAPSEC_API_SECRET=...
frapsec scan app /path/to/bench/apps/myapp --format json > findings.json
frapsec verify findings.json --site https://staging.example.com --confirm
```

```
REACHABLE 1   BLOCKED 1

Result      Rule           Was     Endpoint
REACHABLE   FRAP-API-002   medium  myapp.api.sync.get_sync_status
BLOCKED     FRAP-API-001   info    myapp.api.webhooks.handle_webhook

2 endpoint(s) checked.
```

**Rules, not just flags**:
- Only run against a staging/test site, never production.
- Use a disposable, low-privilege test user — create one in the site's UI, generate its API key from that user's own profile page, not Administrator's.
- Revoke/regenerate the key afterward if it was ever typed anywhere that gets logged (chat, CI logs, shell history).
