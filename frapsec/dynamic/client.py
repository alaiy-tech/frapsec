"""The one function in frapsec that makes an HTTP call to a live site."""
import requests

_TIMEOUT = 15


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
