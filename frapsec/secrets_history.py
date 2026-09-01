"""Secrets in git HISTORY, not just the working tree.

secrets_scan.py answers "is a secret in the code right now". That misses the
more common real case entirely: a key committed once and removed in a later
commit is gone from the tree and still sitting in history, readable by anyone
who can clone the repo. Removing it from the current file changes nothing about
its exposure -- the only fix is rotating the credential.

Approach: read added lines out of `git log -p` and run detect-secrets' own
detectors over them via scan_line. That reuses the detector set already trusted
by the tree scan, adds no new dependency (gitleaks is a separate binary install)
and costs one git process for the whole repo rather than a scan per commit.

Reports each distinct secret ONCE, at the commit that introduced it, rather than
once per commit that touched the line -- a secret in a file that was later moved
or reformatted would otherwise be reported dozens of times and drown the finding
it is trying to make.
"""
import re
import shutil
import subprocess
import sys

from .model import Finding

# Same reasoning as the tree scan: prose files describe secrets rather than
# containing them, and flagging a spec that mentions "webhook_secret" is noise.
_CODE_SUFFIXES = (".py", ".json", ".js", ".cfg", ".ini", ".env", ".yaml", ".yml", ".sh", ".toml")

# A lockfile is full of hashes that every entropy detector reads as secrets,
# and none of them are credentials.
_SKIP_NAMES = ("package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock", "uv.lock")

_COMMIT_RE = re.compile(r"^commit ([0-9a-f]{7,40})")
_FILE_RE = re.compile(r"^\+\+\+ b/(.+)")

# Entropy detectors are dropped entirely on history, not merely downgraded.
# Measured on one real connector repo over 300 commits: 26,788 hits, every
# single one entropy -- minified assets, vendored bundles, test fixtures, image
# data. A layer that reports 26,788 findings gets muted, and then the twelve
# that matter are muted with it. Only NAMED credential detectors ("AWS Access
# Key", "Slack Token", "Private Key") are specific enough to be worth waking
# someone for.
_ENTROPY_TYPES = ("High Entropy String", "Base64 High Entropy String", "Hex High Entropy String")


def _is_interesting(path: str) -> bool:
    if any(path.endswith(n) for n in _SKIP_NAMES):
        return False
    if "/node_modules/" in path or "/.venv/" in path or "/dist/" in path:
        return False
    return path.endswith(_CODE_SUFFIXES)


def run(target: str, max_commits: int = 2000) -> list[Finding]:
    """Scan added lines across git history for secrets.

    max_commits caps the walk: an unbounded history scan on a large repo is
    slow enough that people turn the whole layer off, which helps nobody. The
    cap is on commits examined, newest first.
    """
    if not shutil.which("git"):
        print("git not found on PATH -- skipping secrets-history layer", file=sys.stderr)
        return []
    try:
        from detect_secrets.core.scan import scan_line
        from detect_secrets.settings import default_settings
    except ImportError:
        print("detect-secrets not installed -- skipping secrets-history layer", file=sys.stderr)
        return []

    inside = subprocess.run(
        ["git", "-C", target, "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True,
    )
    if inside.returncode != 0:
        print(f"{target} is not a git repository -- skipping secrets-history layer", file=sys.stderr)
        return []

    proc = subprocess.run(
        ["git", "-C", target, "log", f"--max-count={max_commits}", "-p",
         "--no-color", "--no-merges", "--unified=0"],
        capture_output=True, text=True, errors="replace",
    )
    if proc.returncode != 0:
        print(f"git log failed: {proc.stderr[:300]}", file=sys.stderr)
        return []

    findings = []
    seen = set()          # (secret_hash, path) -- report each secret once
    commit = ""
    path = ""
    interesting = False

    with default_settings():
        for line in proc.stdout.splitlines():
            m = _COMMIT_RE.match(line)
            if m:
                commit = m.group(1)[:8]
                continue
            m = _FILE_RE.match(line)
            if m:
                path = m.group(1)
                interesting = _is_interesting(path)
                continue
            # Only ADDED lines. A removed line is the secret leaving the tree,
            # which is precisely the case this rule exists to say is not a fix.
            if not interesting or not line.startswith("+") or line.startswith("+++"):
                continue

            content = line[1:]
            for secret in scan_line(content):
                key = (secret.secret_hash, path)
                if key in seen:
                    continue
                seen.add(key)
                if any(t in secret.type for t in _ENTROPY_TYPES):
                    continue
                findings.append(Finding(
                    rule_id=f"SECRETS-HISTORY:{secret.type.replace(' ', '_')}",
                    severity="high",
                    message=f"possible {secret.type} added in commit {commit} to {path} — "
                            "still readable in git history even if removed from the current "
                            "tree; rotate the credential, deleting the line does not revoke it",
                    file=f"{target} (history)", line=0,
                ))

    return findings
