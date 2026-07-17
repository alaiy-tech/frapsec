"""Verify static findings against a REAL site — DAST-adjacent, explicitly
separate from the rest of frapsec, which never executes anything.

This is the one place in frapsec that makes network calls to a live system.
It exists to close the gap static analysis can't: a static finding says
"this pattern looks reachable"; this package actually calls the endpoint
with real (low-privilege) credentials and records what happened. It never
sends a payload beyond the endpoint's own required args, never tries more
than one request per finding, and only ever targets findings that already
carry an `endpoint` (set exclusively by the FRAP-API-* rules) -- it cannot
"blind scan" a site on its own.

Safety model: GET-only by default. A whitelisted method can still have
side effects even on GET (Frappe doesn't distinguish), so this still
requires the caller to pass a real --confirm flag and use a disposable/
low-privilege API key, never Administrator credentials.
"""
import requests

from .client import call_endpoint, login
from ..model import Finding


def verify(findings: list[Finding], site_url: str, *,
           api_key: str = "", api_secret: str = "", username: str = "", password: str = "") -> list[Finding]:
    """Mutates and returns `findings`: each one with an `endpoint` gets
    `.verified` set to "reachable", "blocked", or "error" — see
    client.call_endpoint. Findings with no `endpoint` (non-API rules) are
    left untouched. One request per distinct endpoint, however many
    findings reference it.

    Auth: pass either (api_key, api_secret) or (username, password) — not
    both. Whichever role that account has is the role every "reachable"
    result reflects, so use the LOWEST-privilege account the finding needs
    to test, never Administrator (which can reach everything, making every
    result "reachable" and telling you nothing about who else could).
    """
    session = requests.Session()
    if api_key and api_secret:
        session.headers["Authorization"] = f"token {api_key}:{api_secret}"
    elif username and password:
        login(session, site_url, username, password)
    else:
        raise ValueError("verify() needs either (api_key, api_secret) or (username, password)")

    cache: dict[str, str] = {}
    for f in findings:
        if not f.endpoint:
            continue
        if f.endpoint not in cache:
            cache[f.endpoint] = call_endpoint(session, site_url, f.endpoint)
        f.verified = cache[f.endpoint]
    return findings
