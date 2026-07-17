# frapsec — command usage

5 commands. Each one below: what it does, one command to run, what you get back.

---

## `scan bench`

Scans every app in a bench plus every site's config.

```
frapsec scan bench /path/to/bench
```

Output: one findings table, all apps + sites merged, sorted by severity.

---

## `scan app`

Scans one app only.

```
frapsec scan app /path/to/bench/apps/myapp
```

Output:

```
[MEDIUM  ] FRAP-API-002  api/sync.py:73
           get_sync_status hits the database with no visible permission check.
[MEDIUM  ] FRAP-BIZ-001  shopify/order/utils.py:26
           _as_administrator() switches session to Administrator (scoped) — verify caller path.
...
39 finding(s).
```

Add `--format html > report.html` for a browser report, `--format sarif` for GitHub code scanning, `--format json` for scripting.

---

## `scan site`

Checks one site's `site_config.json` only — no app code.

```
frapsec scan site /path/to/bench/sites/mysite.local
```

Output: config findings only (`developer_mode`, weak passwords, CORS, etc).

---

## `permissions`

Dumps the role → DocType permission matrix for one app. No security judgment, just the raw data.

```
frapsec permissions /path/to/bench/apps/myapp
```

Output:

```
System Manager
  Shopify Connector Settings    read, write, create, delete, share, print
  Shopify Sync Log              read, report
```

---

## `verify`

**Dynamic mode.** Takes the JSON from a `scan` run and confirms specific findings against a REAL running site, using real credentials. Makes actual network calls — see [Safety](#safety) below.

Two steps:

```
frapsec scan app /path/to/bench/apps/myapp --format json > findings.json
frapsec verify findings.json --site https://staging.example.com --confirm
```

Credentials: set `FRAPSEC_API_KEY` / `FRAPSEC_API_SECRET` (or `FRAPSEC_USERNAME` / `FRAPSEC_PASSWORD`) as environment variables first — never pass a real secret as a plain `--api-key` argument, it ends up in shell history.

Output:

```
REACHABLE 1   BLOCKED 1

Result      Rule           Was     Endpoint
REACHABLE   FRAP-API-002   medium  myapp.api.sync.get_sync_status
BLOCKED     FRAP-API-001   info    myapp.api.webhooks.handle_webhook

2 endpoint(s) checked.
```

`REACHABLE` = the static finding is now confirmed real for that account. `BLOCKED` = that role genuinely can't reach it.

### Safety

- `--confirm` is required — omitting it refuses to run.
- Never use Administrator — the tool refuses it outright, since Administrator can reach everything, so every result comes back `REACHABLE` and proves nothing.
- Use a disposable, low-privilege test user instead — create one in the site's UI, generate its API key under that user's own profile.
- Only ever run this against a staging/test site, never production.
