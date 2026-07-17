"""The one module in frapsec that makes HTTP calls to a live site."""
import requests

_TIMEOUT = 15


def login(session: requests.Session, site_url: str, usr: str, pwd: str) -> None:
    """Session-cookie auth via Frappe's own /api/method/login, for callers
    who have a username/password rather than an API key/secret pair. Raises
    on failure so the caller doesn't silently "verify" with no session.
    """
    url = f"{site_url.rstrip('/')}/api/method/login"
    resp = session.post(url, data={"usr": usr, "pwd": pwd}, timeout=_TIMEOUT)
    if resp.status_code != 200:
        raise RuntimeError(f"login failed: HTTP {resp.status_code} — {resp.text[:200]}")


def call_endpoint(session: requests.Session, site_url: str, endpoint: str) -> str:
    """GET the endpoint, classify the result: "reachable" (200, no perm
    error), "blocked" (401/403, or a 417 whose exc_type is a PermissionError
    — Frappe's own validation-error status), or "error" (anything else,
    including network failures)."""
    url = f"{site_url.rstrip('/')}/api/method/{endpoint}"
    try:
        resp = session.get(url, timeout=_TIMEOUT)
    except requests.RequestException as e:
        return f"error: {e.__class__.__name__}"

    if resp.status_code == 200:
        return "reachable"
    if resp.status_code in (401, 403):
        return "blocked"
    if resp.status_code == 417:
        try:
            exc_type = resp.json().get("exc_type", "")
        except ValueError:
            exc_type = ""
        return "blocked" if "Permission" in exc_type else f"error: 417 {exc_type}"
    return f"error: HTTP {resp.status_code}"
