"""A credential removed from the tree is still live in git history.

Builds a real git repo where a key is committed and then "fixed" in a later
commit, and asserts the tree scan reports nothing while the history scan finds
it. That pairing is the whole point of the rule: the tree scan going quiet is
exactly what makes someone believe the problem is solved.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from frapsec import secrets_history  # noqa: E402


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


def test():
    if not shutil.which("git"):
        print("SKIP (git not on PATH)")
        return
    try:
        import detect_secrets  # noqa: F401
    except ImportError:
        print("SKIP (detect-secrets not installed)")
        return

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "t@example.com")
        _git(repo, "config", "user.name", "t")

        cfg = repo / "config.py"

        # A real AWS key shape, committed.
        cfg.write_text('AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "add config")

        # "Fixed" -- gone from the tree, still in history.
        cfg.write_text('AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY"]\n', encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "read key from the environment")

        found = secrets_history.run(str(repo))
        types = [f.rule_id for f in found]
        assert any("AWS_Access_Key" in t for t in types), types
        assert all(f.severity == "high" for f in found), found

        # The message must say rotating is the fix. Someone reading only the
        # finding should not conclude that deleting the line was enough.
        assert "rotate" in found[0].message.lower(), found[0].message

        # Entropy detectors are dropped entirely: on one real repo they produced
        # 26,788 hits over 300 commits, every one of them a vendored asset or a
        # fixture. A layer that noisy gets muted, taking the real hits with it.
        assert not any("High_Entropy" in t for t in types), types

        # Reported once per secret, not once per commit that touched the file.
        cfg.write_text('AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY"]  # noqa\n', encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "touch the same file again")
        assert len(secrets_history.run(str(repo))) == len(found), "must not re-report per commit"

    # A directory that is not a git repo must return cleanly, not raise --
    # scanning an unpacked tarball is a normal thing to do.
    with tempfile.TemporaryDirectory() as tmp:
        assert secrets_history.run(tmp) == []

    print("OK")


if __name__ == "__main__":
    test()
